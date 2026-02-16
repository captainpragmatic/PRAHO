"""
SIEM (Security Information and Event Management) Integration Service

This module provides centralized logging for SIEM integration with:
- Structured JSON logging in CEF/LEEF compatible formats
- Real-time log forwarding to external SIEM systems
- Tamper-proof logging with cryptographic hash chains
- Log integrity verification
- Compliance with ISO 27001, SOC 2, GDPR, and Romanian regulations
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, StrEnum
from queue import Empty, Full, Queue
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

if TYPE_CHECKING:
    from apps.audit.models import AuditEvent

logger = logging.getLogger(__name__)


# =============================================================================
# SIEM LOG FORMATS
# =============================================================================


class SIEMFormat(StrEnum):
    """Supported SIEM log formats"""

    CEF = "cef"  # Common Event Format (ArcSight, Splunk)
    LEEF = "leef"  # Log Event Extended Format (IBM QRadar)
    JSON = "json"  # Generic JSON (ELK, Splunk, Graylog)
    SYSLOG = "syslog"  # RFC 5424 Syslog
    OCSF = "ocsf"  # Open Cybersecurity Schema Framework


class SIEMSeverity(int, Enum):
    """SIEM severity levels (CEF compatible)"""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 4
    HIGH = 7
    CRITICAL = 10


# =============================================================================
# SIEM CONFIGURATION
# =============================================================================


@dataclass
class SIEMConfig:
    """SIEM connection and logging configuration"""

    enabled: bool = False
    format: SIEMFormat = SIEMFormat.JSON

    # Transport configuration
    protocol: str = "tcp"  # tcp, udp, https, file
    host: str = "localhost"
    port: int = 514
    use_tls: bool = True

    # Authentication
    api_key: str = ""
    certificate_path: str = ""

    # Buffering and batching
    buffer_size: int = 1000
    batch_size: int = 100
    flush_interval: int = 5  # seconds

    # Retry configuration
    max_retries: int = 3
    retry_delay: int = 1  # seconds

    # Filtering
    min_severity: str = "low"
    include_categories: list[str] = field(default_factory=list)
    exclude_categories: list[str] = field(default_factory=list)

    # Hash chain for tamper-proofing
    enable_hash_chain: bool = True
    hash_algorithm: str = "sha256"

    # Vendor info for CEF format
    vendor: str = "PRAHO"
    product: str = "PlatformAudit"
    version: str = "1.0"


def get_siem_config() -> SIEMConfig:
    """Get SIEM configuration from Django settings"""
    siem_settings = getattr(settings, "SIEM_CONFIG", {})

    return SIEMConfig(
        enabled=siem_settings.get("ENABLED", False),
        format=SIEMFormat(siem_settings.get("FORMAT", "json")),
        protocol=siem_settings.get("PROTOCOL", "tcp"),
        host=siem_settings.get("HOST", "localhost"),
        port=siem_settings.get("PORT", 514),
        use_tls=siem_settings.get("USE_TLS", True),
        api_key=siem_settings.get("API_KEY", ""),
        certificate_path=siem_settings.get("CERTIFICATE_PATH", ""),
        buffer_size=siem_settings.get("BUFFER_SIZE", 1000),
        batch_size=siem_settings.get("BATCH_SIZE", 100),
        flush_interval=siem_settings.get("FLUSH_INTERVAL", 5),
        max_retries=siem_settings.get("MAX_RETRIES", 3),
        retry_delay=siem_settings.get("RETRY_DELAY", 1),
        min_severity=siem_settings.get("MIN_SEVERITY", "low"),
        include_categories=siem_settings.get("INCLUDE_CATEGORIES", []),
        exclude_categories=siem_settings.get("EXCLUDE_CATEGORIES", []),
        enable_hash_chain=siem_settings.get("ENABLE_HASH_CHAIN", True),
        hash_algorithm=siem_settings.get("HASH_ALGORITHM", "sha256"),
        vendor=siem_settings.get("VENDOR", "PRAHO"),
        product=siem_settings.get("PRODUCT", "PlatformAudit"),
        version=siem_settings.get("VERSION", "1.0"),
    )


# =============================================================================
# STRUCTURED LOG ENTRY
# =============================================================================


@dataclass
class SIEMLogEntry:
    """Structured log entry for SIEM integration"""

    # Core identifiers
    event_id: str
    timestamp: datetime

    # Event classification
    action: str
    category: str
    severity: str

    # Actor information
    user_id: str | None = None
    user_email: str | None = None
    actor_type: str = "user"

    # Source information
    source_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    session_id: str | None = None

    # Target information
    target_type: str | None = None
    target_id: str | None = None

    # Change tracking
    old_values: dict[str, Any] = field(default_factory=dict)
    new_values: dict[str, Any] = field(default_factory=dict)

    # Additional context
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # Compliance flags
    is_sensitive: bool = False
    requires_review: bool = False
    compliance_frameworks: list[str] = field(default_factory=list)

    # Hash chain for integrity
    previous_hash: str = ""
    entry_hash: str = ""
    sequence_number: int = 0

    # System information
    hostname: str = field(default_factory=socket.gethostname)
    application: str = "praho-platform"
    environment: str = field(default_factory=lambda: os.environ.get("DJANGO_ENV", "production"))

    def compute_hash(self, secret_key: str) -> str:
        """Compute HMAC hash for this log entry"""
        # Create canonical representation for hashing
        canonical_data = json.dumps(
            {
                "event_id": self.event_id,
                "timestamp": self.timestamp.isoformat(),
                "action": self.action,
                "category": self.category,
                "severity": self.severity,
                "user_id": self.user_id,
                "source_ip": self.source_ip,
                "target_type": self.target_type,
                "target_id": self.target_id,
                "description": self.description,
                "previous_hash": self.previous_hash,
                "sequence_number": self.sequence_number,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        return hmac.new(secret_key.encode(), canonical_data.encode(), hashlib.sha256).hexdigest()


# =============================================================================
# LOG FORMATTERS
# =============================================================================


class SIEMLogFormatter:
    """Base class for SIEM log formatters"""

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format log entry for SIEM"""
        raise NotImplementedError


class CEFFormatter(SIEMLogFormatter):
    """Common Event Format (CEF) formatter for ArcSight, Splunk"""

    SEVERITY_MAP: ClassVar[dict[str, int]] = {
        "low": 1,
        "medium": 4,
        "high": 7,
        "critical": 10,
    }

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format as CEF"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        severity = self.SEVERITY_MAP.get(entry.severity, 0)

        # Build extension fields
        extensions = [
            f"rt={int(entry.timestamp.timestamp() * 1000)}",
            f"src={entry.source_ip or 'unknown'}",
            f"suser={entry.user_email or 'system'}",
            f"suid={entry.user_id or 'system'}",
            f"cat={entry.category}",
            f"act={entry.action}",
            f"msg={self._escape_cef(entry.description)}",
            f"cs1={entry.request_id or ''}",
            "cs1Label=RequestID",
            f"cs2={entry.session_id or ''}",
            "cs2Label=SessionID",
            f"cs3={entry.target_type or ''}",
            "cs3Label=TargetType",
            f"cs4={entry.target_id or ''}",
            "cs4Label=TargetID",
            f"cs5={entry.entry_hash}",
            "cs5Label=EntryHash",
            f"cs6={','.join(entry.compliance_frameworks)}",
            "cs6Label=ComplianceFrameworks",
            f"cn1={entry.sequence_number}",
            "cn1Label=SequenceNumber",
            f"deviceExternalId={entry.event_id}",
            f"dhost={entry.hostname}",
            f"dvc={entry.hostname}",
        ]

        if entry.is_sensitive:
            extensions.append("cfp1=1 cfp1Label=IsSensitive")
        if entry.requires_review:
            extensions.append("cfp2=1 cfp2Label=RequiresReview")

        extension_str = " ".join(extensions)

        return (
            f"CEF:0|{config.vendor}|{config.product}|{config.version}|"
            f"{entry.action}|{entry.action}|{severity}|{extension_str}"
        )

    @staticmethod
    def _escape_cef(value: str) -> str:
        """Escape special characters for CEF format"""
        return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


class LEEFFormatter(SIEMLogFormatter):
    """Log Event Extended Format (LEEF) formatter for IBM QRadar"""

    SEVERITY_MAP: ClassVar[dict[str, int]] = {
        "low": 1,
        "medium": 4,
        "high": 7,
        "critical": 10,
    }

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format as LEEF 2.0"""
        # LEEF:Version|Vendor|Product|Version|EventID|
        sev = self.SEVERITY_MAP.get(entry.severity, 0)

        # Build attribute pairs
        attrs = [
            f"devTime={entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "devTimeFormat=yyyy-MM-dd HH:mm:ss",
            f"src={entry.source_ip or 'unknown'}",
            f"usrName={entry.user_email or 'system'}",
            f"identSrc={entry.user_id or 'system'}",
            f"cat={entry.category}",
            f"sev={sev}",
            f"msg={self._escape_leef(entry.description)}",
            f"requestID={entry.request_id or ''}",
            f"sessionID={entry.session_id or ''}",
            f"objectType={entry.target_type or ''}",
            f"objectId={entry.target_id or ''}",
            f"entryHash={entry.entry_hash}",
            f"seqNum={entry.sequence_number}",
        ]

        attr_str = "\t".join(attrs)

        return f"LEEF:2.0|{config.vendor}|{config.product}|{config.version}|" f"{entry.action}|{attr_str}"

    @staticmethod
    def _escape_leef(value: str) -> str:
        """Escape special characters for LEEF format"""
        return value.replace("\t", " ").replace("\n", " ").replace("\r", "")


class JSONFormatter(SIEMLogFormatter):
    """JSON formatter for ELK, Splunk HEC, Graylog"""

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format as structured JSON"""
        log_data = {
            "@timestamp": entry.timestamp.isoformat(),
            "@version": "1",
            "event": {
                "id": entry.event_id,
                "action": entry.action,
                "category": entry.category,
                "severity": entry.severity,
                "type": ["audit"],
                "outcome": "success" if entry.severity != "critical" else "failure",
            },
            "user": {
                "id": entry.user_id,
                "email": entry.user_email,
                "type": entry.actor_type,
            },
            "source": {
                "ip": entry.source_ip,
                "user_agent": entry.user_agent,
            },
            "target": {
                "type": entry.target_type,
                "id": entry.target_id,
            },
            "host": {
                "name": entry.hostname,
            },
            "service": {
                "name": entry.application,
                "environment": entry.environment,
            },
            "trace": {
                "id": entry.request_id,
            },
            "session": {
                "id": entry.session_id,
            },
            "message": entry.description,
            "praho": {
                "audit": {
                    "old_values": entry.old_values,
                    "new_values": entry.new_values,
                    "is_sensitive": entry.is_sensitive,
                    "requires_review": entry.requires_review,
                    "compliance_frameworks": entry.compliance_frameworks,
                    "hash_chain": {
                        "previous_hash": entry.previous_hash,
                        "entry_hash": entry.entry_hash,
                        "sequence_number": entry.sequence_number,
                    },
                    "metadata": entry.metadata,
                },
            },
        }

        return json.dumps(log_data, default=str, ensure_ascii=False)


class SyslogFormatter(SIEMLogFormatter):
    """RFC 5424 Syslog formatter"""

    SEVERITY_MAP: ClassVar[dict[str, int]] = {
        "low": 6,  # Informational
        "medium": 4,  # Warning
        "high": 3,  # Error
        "critical": 2,  # Critical
    }

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format as RFC 5424 Syslog"""
        # PRI = Facility * 8 + Severity (using LOCAL0 = 16)
        severity = self.SEVERITY_MAP.get(entry.severity, 6)
        pri = 16 * 8 + severity

        # Structured data
        sd = (
            f'[audit@{config.vendor.lower()} '
            f'eventId="{entry.event_id}" '
            f'action="{entry.action}" '
            f'category="{entry.category}" '
            f'userId="{entry.user_id or "-"}" '
            f'sourceIp="{entry.source_ip or "-"}" '
            f'targetType="{entry.target_type or "-"}" '
            f'targetId="{entry.target_id or "-"}" '
            f'requestId="{entry.request_id or "-"}" '
            f'entryHash="{entry.entry_hash}"]'
        )

        timestamp = entry.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        return (
            f"<{pri}>1 {timestamp} {entry.hostname} {entry.application} " f"- {entry.event_id} {sd} {entry.description}"
        )


class OCSFFormatter(SIEMLogFormatter):
    """Open Cybersecurity Schema Framework formatter"""

    SEVERITY_MAP: ClassVar[dict[str, int]] = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def format(self, entry: SIEMLogEntry, config: SIEMConfig) -> str:
        """Format as OCSF (Open Cybersecurity Schema Framework)"""
        severity_id = self.SEVERITY_MAP.get(entry.severity, 0)

        ocsf_event = {
            "activity_id": 1,  # Create
            "category_uid": 2,  # Audit Activity
            "class_uid": 2001,  # Audit Activity
            "severity_id": severity_id,
            "status_id": 1,  # Success
            "time": int(entry.timestamp.timestamp() * 1000),
            "type_uid": 200101,  # Audit Activity: Create
            "actor": {
                "user": {
                    "uid": entry.user_id,
                    "email_addr": entry.user_email,
                    "type": entry.actor_type,
                },
                "session": {
                    "uid": entry.session_id,
                },
            },
            "device": {
                "hostname": entry.hostname,
                "ip": entry.source_ip,
            },
            "metadata": {
                "version": "1.0.0",
                "product": {
                    "name": config.product,
                    "vendor_name": config.vendor,
                    "version": config.version,
                },
                "uid": entry.event_id,
                "correlation_uid": entry.request_id,
            },
            "message": entry.description,
            "observables": [
                {
                    "name": "action",
                    "type": "Other",
                    "value": entry.action,
                },
                {
                    "name": "category",
                    "type": "Other",
                    "value": entry.category,
                },
            ],
            "unmapped": {
                "old_values": entry.old_values,
                "new_values": entry.new_values,
                "compliance_frameworks": entry.compliance_frameworks,
                "hash_chain": {
                    "previous_hash": entry.previous_hash,
                    "entry_hash": entry.entry_hash,
                    "sequence_number": entry.sequence_number,
                },
            },
        }

        return json.dumps(ocsf_event, default=str, ensure_ascii=False)


# =============================================================================
# SIEM TRANSPORT
# =============================================================================


class SIEMTransport:
    """Transport layer for sending logs to SIEM systems"""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._socket: socket.socket | None = None
        self._lock = threading.Lock()

    def connect(self) -> bool:
        """Establish connection to SIEM"""
        try:
            with self._lock:
                if self._socket:
                    return True

                if self.config.protocol in ("tcp", "tls"):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)

                    if self.config.use_tls:
                        context = ssl.create_default_context()
                        if self.config.certificate_path:
                            context.load_cert_chain(self.config.certificate_path)
                        sock = context.wrap_socket(sock, server_hostname=self.config.host)

                    sock.connect((self.config.host, self.config.port))
                    self._socket = sock

                elif self.config.protocol == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(10)
                    self._socket = sock

                logger.info(f"✅ [SIEM] Connected to {self.config.host}:{self.config.port}")
                return True

        except Exception as e:
            logger.error(f"🔥 [SIEM] Connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close SIEM connection"""
        with self._lock:
            if self._socket:
                try:
                    self._socket.close()
                except OSError as exc:
                    logger.debug(f"⚠️ [SIEM] Socket close error during disconnect: {exc}")
                self._socket = None

    def send(self, message: str) -> bool:
        """Send log message to SIEM"""
        for attempt in range(self.config.max_retries):
            try:
                if not self._socket and not self.connect():
                    continue

                data = (message + "\n").encode("utf-8")

                with self._lock:
                    if self.config.protocol == "udp":
                        self._socket.sendto(data, (self.config.host, self.config.port))  # type: ignore[union-attr]
                    else:
                        self._socket.sendall(data)  # type: ignore[union-attr]

                return True

            except Exception as e:
                logger.warning(f"⚠️ [SIEM] Send attempt {attempt + 1} failed: {e}")
                self.disconnect()
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))

        return False

    def send_batch(self, messages: list[str]) -> int:
        """Send batch of messages, returns count of successful sends"""
        successful = 0
        for message in messages:
            if self.send(message):
                successful += 1
        return successful


# =============================================================================
# HASH CHAIN FOR TAMPER-PROOF LOGGING
# =============================================================================


class HashChainManager:
    """
    Manages cryptographic hash chain for tamper-proof logging.

    Each log entry's hash includes the previous entry's hash, creating
    an immutable chain that detects any tampering or deletion.
    """

    CACHE_KEY = "siem_hash_chain_state"
    LOCK_KEY = "siem_hash_chain_lock"

    def __init__(self, secret_key: str | None = None):
        self.secret_key = secret_key or settings.SECRET_KEY
        self._local_sequence = 0
        self._local_hash = ""

    def get_chain_state(self) -> tuple[int, str]:
        """Get current chain state (sequence number, last hash)"""
        state = cache.get(self.CACHE_KEY)
        if state:
            return state["sequence"], state["hash"]
        return self._local_sequence, self._local_hash

    def update_chain_state(self, sequence: int, hash_value: str) -> None:
        """Update chain state atomically"""
        cache.set(
            self.CACHE_KEY,
            {"sequence": sequence, "hash": hash_value},
            timeout=None,  # No expiry for hash chain
        )
        self._local_sequence = sequence
        self._local_hash = hash_value

    def compute_entry_hash(self, entry: SIEMLogEntry) -> tuple[str, int]:
        """
        Compute hash for log entry including chain link.
        Returns (hash, sequence_number).
        """
        # Get current chain state
        sequence, prev_hash = self.get_chain_state()
        new_sequence = sequence + 1

        # Set chain info on entry
        entry.previous_hash = prev_hash
        entry.sequence_number = new_sequence

        # Compute hash
        entry_hash = entry.compute_hash(self.secret_key)
        entry.entry_hash = entry_hash

        # Update chain state
        self.update_chain_state(new_sequence, entry_hash)

        return entry_hash, new_sequence

    def verify_chain(self, entries: list[SIEMLogEntry]) -> tuple[bool, list[str]]:
        """
        Verify integrity of a chain of log entries.
        Returns (is_valid, list_of_errors).
        """
        errors = []
        prev_hash = ""

        for i, entry in enumerate(entries):
            # Verify previous hash link
            if entry.previous_hash != prev_hash:
                errors.append(f"Entry {entry.event_id}: Previous hash mismatch at sequence {entry.sequence_number}")

            # Verify sequence number
            if i > 0 and entry.sequence_number != entries[i - 1].sequence_number + 1:
                errors.append(f"Entry {entry.event_id}: Sequence gap detected at {entry.sequence_number}")

            # Recompute and verify hash
            expected_hash = entry.compute_hash(self.secret_key)
            if entry.entry_hash != expected_hash:
                errors.append(f"Entry {entry.event_id}: Hash mismatch - possible tampering")

            prev_hash = entry.entry_hash

        return len(errors) == 0, errors


# =============================================================================
# SIEM SERVICE
# =============================================================================


class SIEMService:
    """
    Main SIEM integration service for centralized security logging.

    Features:
    - Multiple SIEM format support (CEF, LEEF, JSON, Syslog, OCSF)
    - Asynchronous log forwarding with buffering
    - Tamper-proof hash chain
    - Compliance framework tagging
    - Real-time security monitoring
    """

    FORMATTERS: ClassVar[dict[SIEMFormat, type[SIEMLogFormatter]]] = {
        SIEMFormat.CEF: CEFFormatter,
        SIEMFormat.LEEF: LEEFFormatter,
        SIEMFormat.JSON: JSONFormatter,
        SIEMFormat.SYSLOG: SyslogFormatter,
        SIEMFormat.OCSF: OCSFFormatter,
    }

    COMPLIANCE_FRAMEWORKS: ClassVar[dict[str, list[str]]] = {
        "authentication": ["ISO27001-A.9", "SOC2-CC6.1", "GDPR-Art32", "NIST-IA"],
        "authorization": ["ISO27001-A.9", "SOC2-CC6.2", "NIST-AC"],
        "data_protection": ["GDPR-Art17", "GDPR-Art20", "ISO27001-A.18"],
        "security_event": ["ISO27001-A.12.4", "SOC2-CC7.2", "NIST-IR"],
        "privacy": ["GDPR-Art7", "GDPR-Art12", "ISO27001-A.18.1"],
        "compliance": ["RO-eFact", "EU-VAT", "ISO27001-A.18"],
        "business_operation": ["SOC2-CC8.1", "ISO27001-A.12"],
        "system_admin": ["ISO27001-A.12.1", "SOC2-CC6.6", "NIST-CM"],
        "integration": ["ISO27001-A.14", "SOC2-CC6.7"],
        "account_management": ["ISO27001-A.9.2", "SOC2-CC6.2", "GDPR-Art5"],
    }

    def __init__(self, config: SIEMConfig | None = None):
        self.config = config or get_siem_config()
        self.formatter = self.FORMATTERS[self.config.format]()
        self.transport = SIEMTransport(self.config)
        self.hash_chain = HashChainManager()

        # Buffering for async forwarding
        self._buffer: Queue[str] = Queue(maxsize=self.config.buffer_size)
        self._flush_thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start background log forwarding"""
        if not self.config.enabled:
            logger.info("ℹ️ [SIEM] SIEM integration is disabled")  # noqa: RUF001
            return

        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        logger.info("✅ [SIEM] Background log forwarding started")

    def stop(self) -> None:
        """Stop background log forwarding"""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        self.transport.disconnect()
        logger.info("🛑 [SIEM] Background log forwarding stopped")

    def _flush_loop(self) -> None:
        """Background thread for flushing log buffer"""
        while self._running:
            try:
                self._flush_buffer()
                time.sleep(self.config.flush_interval)
            except Exception as e:
                logger.error(f"🔥 [SIEM] Flush loop error: {e}")

    def _flush_buffer(self) -> None:
        """Flush buffered logs to SIEM"""
        batch = []
        while not self._buffer.empty() and len(batch) < self.config.batch_size:
            try:
                batch.append(self._buffer.get_nowait())
            except Empty:
                break

        if batch:
            successful = self.transport.send_batch(batch)
            logger.debug(f"📤 [SIEM] Flushed {successful}/{len(batch)} log entries")

    def log_audit_event(self, audit_event: AuditEvent) -> bool:
        """
        Log an audit event to SIEM.

        Args:
            audit_event: AuditEvent model instance

        Returns:
            True if successfully queued/sent
        """
        if not self.config.enabled:
            return True  # Silently skip if disabled

        try:
            # Check severity filter
            if not self._passes_severity_filter(audit_event.severity):
                return True

            # Check category filter
            if not self._passes_category_filter(audit_event.category):
                return True

            # Convert to SIEM log entry
            entry = self._create_log_entry(audit_event)

            # Compute hash chain
            if self.config.enable_hash_chain:
                self.hash_chain.compute_entry_hash(entry)

            # Format for SIEM
            formatted = self.formatter.format(entry, self.config)

            # Queue for sending
            if self.config.protocol == "file":
                self._write_to_file(formatted)
            else:
                try:
                    self._buffer.put_nowait(formatted)
                except Full:
                    # Buffer full - send synchronously
                    return self.transport.send(formatted)

            return True

        except Exception as e:
            logger.error(f"🔥 [SIEM] Failed to log audit event: {e}")
            return False

    def _create_log_entry(self, audit_event: AuditEvent) -> SIEMLogEntry:
        """Convert AuditEvent to SIEMLogEntry"""
        compliance_frameworks = self.COMPLIANCE_FRAMEWORKS.get(audit_event.category, [])

        return SIEMLogEntry(
            event_id=str(audit_event.id),
            timestamp=audit_event.timestamp,
            action=audit_event.action,
            category=audit_event.category,
            severity=audit_event.severity,
            user_id=str(audit_event.user_id) if audit_event.user_id else None,
            user_email=audit_event.user.email if audit_event.user else None,
            actor_type=audit_event.actor_type,
            source_ip=audit_event.ip_address,
            user_agent=audit_event.user_agent,
            request_id=audit_event.request_id,
            session_id=audit_event.session_key,
            target_type=audit_event.content_type.model if audit_event.content_type else None,
            target_id=audit_event.object_id,
            old_values=audit_event.old_values,
            new_values=audit_event.new_values,
            description=audit_event.description,
            metadata=audit_event.metadata,
            is_sensitive=audit_event.is_sensitive,
            requires_review=audit_event.requires_review,
            compliance_frameworks=compliance_frameworks,
        )

    def _passes_severity_filter(self, severity: str) -> bool:
        """Check if severity passes minimum severity filter"""
        severity_order = ["low", "medium", "high", "critical"]
        min_idx = severity_order.index(self.config.min_severity)
        event_idx = severity_order.index(severity)
        return event_idx >= min_idx

    def _passes_category_filter(self, category: str) -> bool:
        """Check if category passes include/exclude filters"""
        if self.config.include_categories:
            return category in self.config.include_categories
        if self.config.exclude_categories:
            return category not in self.config.exclude_categories
        return True

    def _write_to_file(self, formatted: str) -> None:
        """Write log entry to file (for file-based SIEM integration)"""
        log_dir = getattr(settings, "SIEM_LOG_DIR", "/var/log/praho/siem")
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f"audit-{timezone.now().strftime('%Y-%m-%d')}.log")

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")

    def verify_log_integrity(self, start_date: datetime, end_date: datetime) -> tuple[bool, list[str]]:
        """
        Verify integrity of audit logs for a date range.

        Args:
            start_date: Start of verification period
            end_date: End of verification period

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        # Fetch events in order
        events = AuditEvent.objects.filter(timestamp__gte=start_date, timestamp__lte=end_date).order_by("timestamp")

        errors = []
        prev_hash = ""

        for event in events:
            entry = self._create_log_entry(event)

            # Get stored hash from metadata
            stored_hash = event.metadata.get("siem_hash", "")
            stored_sequence = event.metadata.get("siem_sequence", 0)
            stored_prev_hash = event.metadata.get("siem_prev_hash", "")

            if stored_hash:
                # Verify chain link
                if stored_prev_hash != prev_hash:
                    errors.append(f"Event {event.id}: Chain link broken at sequence {stored_sequence}")

                # Verify hash
                entry.previous_hash = stored_prev_hash
                entry.sequence_number = stored_sequence
                computed_hash = entry.compute_hash(self.hash_chain.secret_key)

                if stored_hash != computed_hash:
                    errors.append(f"Event {event.id}: Hash mismatch - possible tampering")

                prev_hash = stored_hash

        return len(errors) == 0, errors


# =============================================================================
# GLOBAL SIEM INSTANCE
# =============================================================================


_siem_service: SIEMService | None = None


def get_siem_service() -> SIEMService:
    """Get or create global SIEM service instance"""
    global _siem_service  # noqa: PLW0603
    if _siem_service is None:
        _siem_service = SIEMService()
    return _siem_service


def log_to_siem(audit_event: AuditEvent) -> bool:
    """Convenience function to log audit event to SIEM"""
    return get_siem_service().log_audit_event(audit_event)
