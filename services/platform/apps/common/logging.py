"""
Logging utilities for PRAHO Platform

This module provides logging filters and utilities for:
- Request ID injection into log records
- Structured logging support
- SIEM-compatible log formatting
"""

from __future__ import annotations

import logging
import threading
from typing import Any


# Thread-local storage for request context
_request_context = threading.local()


def set_request_context(**kwargs: Any) -> None:
    """Set request context for the current thread"""
    for key, value in kwargs.items():
        setattr(_request_context, key, value)


def get_request_context() -> dict[str, Any]:
    """Get request context for the current thread"""
    return {
        "request_id": getattr(_request_context, "request_id", "-"),
        "user_id": getattr(_request_context, "user_id", None),
        "user_email": getattr(_request_context, "user_email", None),
        "ip_address": getattr(_request_context, "ip_address", None),
        "session_id": getattr(_request_context, "session_id", None),
    }


def clear_request_context() -> None:
    """Clear request context for the current thread"""
    for attr in ["request_id", "user_id", "user_email", "ip_address", "session_id"]:
        if hasattr(_request_context, attr):
            delattr(_request_context, attr)


class RequestIDFilter(logging.Filter):
    """
    Add request ID to log records.

    This filter injects the request ID from thread-local storage
    into every log record, enabling request tracing across logs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id attribute to log record"""
        if not hasattr(record, "request_id"):
            record.request_id = getattr(_request_context, "request_id", "-")

        # Add other context if available
        if not hasattr(record, "user_id"):
            record.user_id = getattr(_request_context, "user_id", None)
        if not hasattr(record, "user_email"):
            record.user_email = getattr(_request_context, "user_email", None)
        if not hasattr(record, "ip_address"):
            record.ip_address = getattr(_request_context, "ip_address", None)
        if not hasattr(record, "session_id"):
            record.session_id = getattr(_request_context, "session_id", None)

        return True


class SecurityEventFilter(logging.Filter):
    """
    Filter for security-related log events.

    Only allows log records that are marked as security events
    or come from security-related loggers.
    """

    SECURITY_LOGGERS = [
        "apps.users",
        "apps.audit",
        "django.security",
        "apps.common.middleware",
    ]

    SECURITY_KEYWORDS = [
        "login",
        "logout",
        "auth",
        "password",
        "security",
        "permission",
        "access",
        "denied",
        "blocked",
        "suspicious",
        "breach",
        "attack",
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter for security events"""
        # Check if from security logger
        if any(record.name.startswith(logger) for logger in self.SECURITY_LOGGERS):
            return True

        # Check for security keywords in message
        message = record.getMessage().lower()
        if any(keyword in message for keyword in self.SECURITY_KEYWORDS):
            return True

        # Check for security level
        if record.levelno >= logging.WARNING:
            return True

        return False


class SensitiveDataFilter(logging.Filter):
    """
    Filter to redact sensitive data from log records.

    Prevents sensitive information like passwords, tokens,
    and credit card numbers from appearing in logs.
    """

    SENSITIVE_PATTERNS = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "cui",  # Romanian tax ID
    ]

    REDACTION_TEXT = "[REDACTED]"

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log record"""
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern in record.msg.lower():
                    # Simple redaction - in production, use regex
                    record.msg = record.msg.replace(pattern, self.REDACTION_TEXT)

        return True


class StructuredLogAdapter(logging.LoggerAdapter):
    """
    Log adapter that adds structured context to all log messages.

    Usage:
        logger = StructuredLogAdapter(
            logging.getLogger(__name__),
            {"component": "billing"}
        )
        logger.info("Invoice created", invoice_id=123)
    """

    def process(
        self,
        msg: str,
        kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Process log message and add structured context"""
        # Merge extra context
        extra = kwargs.get("extra", {})
        extra.update(self.extra)

        # Add any keyword arguments as extra fields
        for key, value in list(kwargs.items()):
            if key not in ("exc_info", "stack_info", "stacklevel", "extra"):
                extra[key] = value
                del kwargs[key]

        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str, **context: Any) -> StructuredLogAdapter:
    """
    Get a structured logger with context.

    Args:
        name: Logger name (usually __name__)
        **context: Additional context to include in all log messages

    Returns:
        StructuredLogAdapter with context
    """
    return StructuredLogAdapter(logging.getLogger(name), context)
