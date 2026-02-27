"""
SIEM-Compatible Logging Formatters for PRAHO Platform

This module provides custom log formatters and filters for:
- Structured JSON logging (ECS/OCSF compatible)
- Audit trail formatting
- Request context injection
- SIEM integration support
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import traceback
from datetime import datetime
from typing import Any, ClassVar

from django.conf import settings

# =============================================================================
# THREAD-LOCAL STORAGE FOR REQUEST CONTEXT
# =============================================================================


_audit_context = threading.local()


def set_audit_context(**kwargs: Any) -> None:
    """Set audit context for the current thread"""
    for key, value in kwargs.items():
        setattr(_audit_context, key, value)


def get_audit_context() -> dict[str, Any]:
    """Get audit context for the current thread"""
    return {
        "request_id": getattr(_audit_context, "request_id", None),
        "user_id": getattr(_audit_context, "user_id", None),
        "user_email": getattr(_audit_context, "user_email", None),
        "ip_address": getattr(_audit_context, "ip_address", None),
        "session_id": getattr(_audit_context, "session_id", None),
        "customer_id": getattr(_audit_context, "customer_id", None),
    }


def clear_audit_context() -> None:
    """Clear audit context for the current thread"""
    for attr in ["request_id", "user_id", "user_email", "ip_address", "session_id", "customer_id"]:
        if hasattr(_audit_context, attr):
            delattr(_audit_context, attr)


# =============================================================================
# LOG FILTERS
# =============================================================================


class AuditContextFilter(logging.Filter):
    """
    Add audit context to log records.

    This filter injects request-specific context (request ID, user info,
    IP address) into log records for correlation and tracing.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add audit context to log record"""
        context = get_audit_context()

        # Add context attributes to record
        record.request_id = context.get("request_id", "-")
        record.user_id = context.get("user_id", "-")
        record.user_email = context.get("user_email", "-")
        record.ip_address = context.get("ip_address", "-")
        record.session_id = context.get("session_id", "-")
        record.customer_id = context.get("customer_id", "-")

        # Add hostname for distributed systems
        record.hostname = socket.gethostname()

        # Add environment
        record.environment = getattr(settings, "ENVIRONMENT", "production")

        return True


# =============================================================================
# SIEM JSON FORMATTER
# =============================================================================


class SIEMJSONFormatter(logging.Formatter):
    """
    SIEM-compatible JSON log formatter.

    Produces structured JSON logs compatible with:
    - Elastic Common Schema (ECS)
    - Open Cybersecurity Schema Framework (OCSF)
    - Splunk HEC
    - Graylog GELF
    """

    # Mapping from Python log levels to severity numbers
    SEVERITY_MAP: ClassVar[dict[str, int]] = {
        "DEBUG": 7,
        "INFO": 6,
        "WARNING": 4,
        "ERROR": 3,
        "CRITICAL": 2,
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hostname = socket.gethostname()
        self.application = "praho-platform"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as SIEM-compatible JSON"""
        # Build the structured log entry
        log_entry = self._build_base_entry(record)

        # Add error information if present
        if record.exc_info:
            log_entry["error"] = self._format_exception(record)

        # Add extra fields from record
        log_entry.update(self._extract_extra_fields(record))

        return json.dumps(log_entry, default=str, ensure_ascii=False)

    def _build_base_entry(self, record: logging.LogRecord) -> dict[str, Any]:
        """Build base log entry structure"""
        timestamp = datetime.utcfromtimestamp(record.created).isoformat() + "Z"

        return {
            # Timestamp (ISO 8601 format for SIEM compatibility)
            "@timestamp": timestamp,
            "timestamp": timestamp,
            # Event identification
            "event": {
                "created": timestamp,
                "kind": "event",
                "category": self._get_event_category(record),
                "type": [self._get_event_type(record)],
                "severity": self.SEVERITY_MAP.get(record.levelname, 6),
            },
            # Log metadata
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
            },
            # Source code location
            "log.origin": {
                "file": {
                    "name": record.filename,
                    "line": record.lineno,
                },
                "function": record.funcName,
            },
            # Host information
            "host": {
                "name": self.hostname,
            },
            # Service information
            "service": {
                "name": self.application,
                "type": "django",
            },
            # Message
            "message": record.getMessage(),
            # Process/thread information
            "process": {
                "pid": record.process,
                "thread": {
                    "id": record.thread,
                    "name": record.threadName,
                },
            },
            # Request context (if available)
            "trace": {
                "id": getattr(record, "request_id", None),
            },
            "user": {
                "id": getattr(record, "user_id", None),
                "email": getattr(record, "user_email", None),
            },
            "source": {
                "ip": getattr(record, "ip_address", None),
            },
            "session": {
                "id": getattr(record, "session_id", None),
            },
            # PRAHO-specific fields
            "praho": {
                "customer_id": getattr(record, "customer_id", None),
                "environment": getattr(record, "environment", "production"),
            },
        }

    def _format_exception(self, record: logging.LogRecord) -> dict[str, Any]:
        """Format exception information"""
        exc_info = record.exc_info
        if not exc_info or not exc_info[0]:
            return {}

        exc_type, exc_value, exc_tb = exc_info

        return {
            "type": exc_type.__name__ if exc_type else "Unknown",
            "message": str(exc_value) if exc_value else "",
            "stack_trace": "".join(traceback.format_exception(*exc_info)) if exc_tb else "",
        }

    def _get_event_category(self, record: logging.LogRecord) -> str:  # noqa: PLR0911
        """Determine event category from logger name"""
        logger_name = record.name.lower()

        if "auth" in logger_name or "user" in logger_name or "login" in logger_name:
            return "authentication"
        elif "security" in logger_name:
            return "security"
        elif "audit" in logger_name:
            return "audit"
        elif "database" in logger_name or "db" in logger_name:
            return "database"
        elif "web" in logger_name or "request" in logger_name:
            return "web"
        elif "file" in logger_name:
            return "file"
        elif "network" in logger_name:
            return "network"

        return "process"

    def _get_event_type(self, record: logging.LogRecord) -> str:
        """Determine event type from log level"""
        level = record.levelname.upper()

        if level in ("ERROR", "CRITICAL"):
            return "error"
        elif level in {"WARNING", "DEBUG"}:
            return "info"

        return "info"

    def _extract_extra_fields(self, record: logging.LogRecord) -> dict[str, Any]:
        """Extract extra fields added to the log record"""
        standard_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "message",
            "request_id",
            "user_id",
            "user_email",
            "ip_address",
            "session_id",
            "customer_id",
            "hostname",
            "environment",
        }

        extra = {
            key: value
            for key, value in record.__dict__.items()
            if key not in standard_attrs and not key.startswith("_")
        }

        if extra:
            return {"extra": extra}
        return {}


# =============================================================================
# AUDIT LOG FORMATTER
# =============================================================================


class AuditLogFormatter(logging.Formatter):
    """
    Specialized formatter for immutable audit logs.

    Produces a tamper-evident log format with:
    - Hash chain for integrity verification
    - Structured event data
    - Compliance metadata
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hostname = socket.gethostname()
        self.sequence = 0
        self.previous_hash = ""

    def format(self, record: logging.LogRecord) -> str:
        """Format audit log record with integrity chain"""
        import hashlib  # noqa: PLC0415

        self.sequence += 1
        timestamp = datetime.utcfromtimestamp(record.created).isoformat() + "Z"

        # Build audit entry
        audit_entry = {
            "@timestamp": timestamp,
            "sequence": self.sequence,
            "event": {
                "id": f"audit-{self.sequence}-{record.created}",
                "action": getattr(record, "action", record.funcName),
                "category": self._determine_category(record),
                "outcome": "success" if record.levelno < logging.ERROR else "failure",
            },
            "message": record.getMessage(),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
            },
            "host": {
                "name": self.hostname,
            },
            "trace": {
                "id": getattr(record, "request_id", "-"),
            },
            "user": {
                "id": getattr(record, "user_id", None),
                "email": getattr(record, "user_email", None),
            },
            "source": {
                "ip": getattr(record, "ip_address", None),
            },
            "integrity": {
                "previous_hash": self.previous_hash,
                "sequence": self.sequence,
            },
        }

        # Compute hash for integrity chain
        entry_json = json.dumps(audit_entry, sort_keys=True, default=str)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()

        audit_entry["integrity"]["hash"] = entry_hash  # type: ignore[index]
        self.previous_hash = entry_hash

        return json.dumps(audit_entry, default=str, ensure_ascii=False)

    def _determine_category(self, record: logging.LogRecord) -> str:  # noqa: PLR0911
        """Determine audit category from log record"""
        message = record.getMessage().lower()

        if "login" in message or "logout" in message or "auth" in message:
            return "authentication"
        elif "permission" in message or "role" in message or "access" in message:
            return "authorization"
        elif "create" in message or "update" in message or "delete" in message:
            return "data_modification"
        elif "security" in message or "breach" in message or "attack" in message:
            return "security_event"
        elif "export" in message or "download" in message:
            return "data_access"
        elif "config" in message or "setting" in message:
            return "configuration"

        return "general"


# =============================================================================
# REQUEST ID FILTER (MOVED FROM common.logging FOR COMPLETENESS)
# =============================================================================


class RequestIDFilter(logging.Filter):
    """
    Add request ID to log records.

    This is a simplified version - the main implementation may be
    in apps.common.logging. This ensures the filter exists.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id attribute to log record"""
        if not hasattr(record, "request_id"):
            # Try to get from thread local storage
            record.request_id = getattr(_audit_context, "request_id", "-")
        return True


# =============================================================================
# COMPLIANCE LOG FORMATTER
# =============================================================================


class ComplianceLogFormatter(logging.Formatter):
    """
    Formatter for compliance-specific logging.

    Produces logs that meet regulatory requirements:
    - GDPR (EU)
    - Romanian fiscal code
    - ISO 27001
    - SOC 2
    """

    COMPLIANCE_FRAMEWORKS: ClassVar[dict[str, list[str]]] = {
        "authentication": ["ISO27001-A.9.4", "SOC2-CC6.1", "GDPR-Art32"],
        "authorization": ["ISO27001-A.9.2", "SOC2-CC6.2"],
        "data_modification": ["GDPR-Art30", "ISO27001-A.12.4"],
        "security_event": ["ISO27001-A.16", "SOC2-CC7.2"],
        "data_access": ["GDPR-Art15", "ISO27001-A.9.4"],
        "configuration": ["ISO27001-A.12.1", "SOC2-CC6.6"],
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log for compliance requirements"""
        timestamp = datetime.utcfromtimestamp(record.created).isoformat() + "Z"
        category = self._determine_category(record)
        frameworks = self.COMPLIANCE_FRAMEWORKS.get(category, [])

        compliance_entry = {
            "@timestamp": timestamp,
            "compliance": {
                "frameworks": frameworks,
                "category": category,
                "retention_required": True,
                "sensitive_data": self._contains_sensitive_data(record),
            },
            "event": {
                "action": getattr(record, "action", record.funcName),
                "outcome": "success" if record.levelno < logging.ERROR else "failure",
            },
            "message": record.getMessage(),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
            },
            "user": {
                "id": getattr(record, "user_id", None),
                "email": getattr(record, "user_email", None),
            },
            "source": {
                "ip": getattr(record, "ip_address", None),
            },
            "trace": {
                "id": getattr(record, "request_id", "-"),
            },
        }

        return json.dumps(compliance_entry, default=str, ensure_ascii=False)

    def _determine_category(self, record: logging.LogRecord) -> str:  # noqa: PLR0911
        """Determine compliance category"""
        message = record.getMessage().lower()

        if "login" in message or "logout" in message or "auth" in message:
            return "authentication"
        elif "permission" in message or "role" in message or "access" in message:
            return "authorization"
        elif "create" in message or "update" in message or "delete" in message:
            return "data_modification"
        elif "security" in message or "breach" in message:
            return "security_event"
        elif "export" in message or "download" in message:
            return "data_access"
        elif "config" in message or "setting" in message:
            return "configuration"

        return "general"

    def _contains_sensitive_data(self, record: logging.LogRecord) -> bool:
        """Check if log contains sensitive data indicators"""
        message = record.getMessage().lower()
        sensitive_indicators = [
            "password",
            "credit",
            "card",
            "ssn",
            "tax",
            "cui",
            "bank",
            "account",
            "secret",
            "token",
            "key",
            "credential",
        ]
        return any(indicator in message for indicator in sensitive_indicators)
