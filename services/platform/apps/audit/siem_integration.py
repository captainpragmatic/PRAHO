"""
SIEM (Security Information and Event Management) Integration Service.

Provides structured log export and real-time event streaming for
integration with external SIEM systems like Splunk, ELK, Datadog, etc.

Features:
- Structured JSON log format compatible with common SIEM systems
- Webhook-based real-time event delivery
- Batch export for historical data
- Configurable severity filtering
- Event enrichment with threat intelligence context

Standards:
- CEF (Common Event Format) compatible
- OCSF (Open Cybersecurity Schema Framework) aligned
- Syslog RFC 5424 compatible timestamps
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Final
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.utils import timezone

from apps.audit.models import AuditEvent

logger = logging.getLogger(__name__)


class SIEMProvider(Enum):
    """Supported SIEM providers."""

    GENERIC_WEBHOOK = "generic"
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    DATADOG = "datadog"
    SUMO_LOGIC = "sumo_logic"


class SIEMSeverity(Enum):
    """SIEM-compatible severity levels (maps to audit severity)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_audit_severity(cls, severity: str) -> "SIEMSeverity":
        """Convert audit event severity to SIEM severity."""
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(severity, cls.INFO)


@dataclass
class SIEMEvent:
    """
    Structured event format for SIEM integration.

    Follows OCSF (Open Cybersecurity Schema Framework) structure
    for maximum compatibility with modern SIEM systems.
    """

    # Event identification
    event_id: str
    event_time: str  # ISO 8601 format
    event_type: str
    event_category: str

    # Severity and classification
    severity: int
    severity_name: str

    # Actor information
    actor_type: str
    actor_id: str | None
    actor_email: str | None

    # Source information
    source_ip: str | None
    user_agent: str | None
    session_id: str | None

    # Target information
    target_type: str | None
    target_id: str | None

    # Event details
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    # PRAHO-specific fields
    praho_request_id: str | None = None
    praho_is_sensitive: bool = False
    praho_requires_review: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_cef(self) -> str:
        """
        Convert to CEF (Common Event Format) string.

        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        extension = " ".join(
            f"{k}={v}"
            for k, v in [
                ("src", self.source_ip),
                ("suser", self.actor_email),
                ("act", self.event_type),
                ("cat", self.event_category),
                ("msg", self.description.replace("|", "\\|")),
            ]
            if v
        )

        return f"CEF:0|PRAHO|Platform|1.0|{self.event_type}|" f"{self.description[:100]}|{self.severity}|{extension}"

    def to_syslog(self) -> str:
        """Convert to syslog RFC 5424 format."""
        priority = 8 + min(self.severity, 7)  # facility 1 (user) + severity
        return (
            f"<{priority}>1 {self.event_time} praho-platform {self.actor_email or '-'} "
            f"{self.praho_request_id or '-'} {self.event_type} "
            f'[praho category="{self.event_category}" severity="{self.severity_name}"] '
            f"{self.description}"
        )


@dataclass
class SIEMConfig:
    """Configuration for SIEM integration."""

    provider: SIEMProvider
    endpoint_url: str
    api_key: str | None = None
    api_secret: str | None = None
    min_severity: SIEMSeverity = SIEMSeverity.LOW
    include_sensitive: bool = False
    batch_size: int = 100
    timeout_seconds: int = 30
    verify_ssl: bool = True
    custom_headers: dict[str, str] = field(default_factory=dict)


class SIEMIntegrationService:
    """
    Service for exporting audit events to SIEM systems.

    Usage:
        config = SIEMConfig(
            provider=SIEMProvider.SPLUNK,
            endpoint_url="https://splunk.example.com:8088/services/collector",
            api_key="your-hec-token",
        )
        service = SIEMIntegrationService(config)

        # Export recent events
        result = service.export_events(since=timezone.now() - timedelta(hours=1))

        # Stream single event
        service.send_event(audit_event)
    """

    # Request timeout for SIEM endpoints
    DEFAULT_TIMEOUT: Final[int] = 30

    def __init__(self, config: SIEMConfig) -> None:
        """Initialize SIEM integration service."""
        self.config = config
        self._session = requests.Session()
        self._setup_session()

    def _setup_session(self) -> None:
        """Configure the HTTP session with authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PRAHO-Platform/1.0 SIEM-Integration",
        }

        # Provider-specific authentication
        if self.config.provider == SIEMProvider.SPLUNK:
            if self.config.api_key:
                headers["Authorization"] = f"Splunk {self.config.api_key}"

        elif self.config.provider == SIEMProvider.DATADOG:
            if self.config.api_key:
                headers["DD-API-KEY"] = self.config.api_key

        elif self.config.provider == SIEMProvider.ELASTICSEARCH:
            if self.config.api_key and self.config.api_secret:
                import base64

                credentials = f"{self.config.api_key}:{self.config.api_secret}"
                encoded = base64.b64encode(credentials.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        elif self.config.provider == SIEMProvider.SUMO_LOGIC:
            # Sumo Logic uses the URL for authentication
            pass

        elif self.config.provider == SIEMProvider.GENERIC_WEBHOOK:
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"

        # Add custom headers
        headers.update(self.config.custom_headers)
        self._session.headers.update(headers)

    def convert_to_siem_event(self, audit_event: AuditEvent) -> SIEMEvent:
        """Convert an AuditEvent to SIEM-compatible format."""
        severity = SIEMSeverity.from_audit_severity(audit_event.severity)

        return SIEMEvent(
            event_id=str(audit_event.id),
            event_time=audit_event.timestamp.isoformat(),
            event_type=audit_event.action,
            event_category=audit_event.category,
            severity=severity.value,
            severity_name=severity.name,
            actor_type=audit_event.actor_type,
            actor_id=str(audit_event.user_id) if audit_event.user_id else None,
            actor_email=audit_event.user.email if audit_event.user else None,
            source_ip=audit_event.ip_address,
            user_agent=audit_event.user_agent[:500] if audit_event.user_agent else None,
            session_id=audit_event.session_key,
            target_type=str(audit_event.content_type) if audit_event.content_type else None,
            target_id=audit_event.object_id,
            description=audit_event.description or f"{audit_event.action} action performed",
            metadata=audit_event.metadata or {},
            praho_request_id=audit_event.request_id,
            praho_is_sensitive=audit_event.is_sensitive,
            praho_requires_review=audit_event.requires_review,
        )

    def _format_for_provider(self, events: list[SIEMEvent]) -> tuple[str, dict[str, str]]:
        """Format events for specific SIEM provider."""
        headers: dict[str, str] = {}

        if self.config.provider == SIEMProvider.SPLUNK:
            # Splunk HEC format
            payload = "\n".join(json.dumps({"event": event.to_dict(), "time": event.event_time}) for event in events)
            return payload, headers

        elif self.config.provider == SIEMProvider.ELASTICSEARCH:
            # Elasticsearch bulk format
            lines = []
            for event in events:
                lines.append(json.dumps({"index": {"_index": "praho-audit"}}))
                lines.append(json.dumps(event.to_dict()))
            payload = "\n".join(lines) + "\n"
            headers["Content-Type"] = "application/x-ndjson"
            return payload, headers

        elif self.config.provider == SIEMProvider.DATADOG:
            # Datadog logs format
            payload = json.dumps(
                [
                    {
                        "ddsource": "praho-platform",
                        "service": "praho-audit",
                        "hostname": "praho-platform",
                        **event.to_dict(),
                    }
                    for event in events
                ]
            )
            return payload, headers

        else:
            # Generic JSON array
            payload = json.dumps([event.to_dict() for event in events])
            return payload, headers

    def _sign_payload(self, payload: str) -> str:
        """Generate HMAC signature for webhook payload."""
        if not self.config.api_secret:
            return ""

        signature = hmac.new(
            self.config.api_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        return f"sha256={signature}"

    def send_event(self, audit_event: AuditEvent) -> bool:
        """
        Send a single audit event to SIEM.

        Args:
            audit_event: The audit event to send

        Returns:
            True if successful, False otherwise
        """
        return self.send_events([audit_event])

    def send_events(self, audit_events: list[AuditEvent]) -> bool:
        """
        Send multiple audit events to SIEM.

        Args:
            audit_events: List of audit events to send

        Returns:
            True if successful, False otherwise
        """
        if not audit_events:
            return True

        # Filter by severity
        min_severity_value = self.config.min_severity.value
        filtered_events = [
            event
            for event in audit_events
            if SIEMSeverity.from_audit_severity(event.severity).value >= min_severity_value
        ]

        # Filter sensitive events if not included
        if not self.config.include_sensitive:
            filtered_events = [event for event in filtered_events if not event.is_sensitive]

        if not filtered_events:
            logger.debug("No events to send after filtering")
            return True

        # Convert to SIEM format
        siem_events = [self.convert_to_siem_event(event) for event in filtered_events]

        # Format for provider
        payload, extra_headers = self._format_for_provider(siem_events)

        # Add signature for webhooks
        if self.config.api_secret:
            extra_headers["X-PRAHO-Signature"] = self._sign_payload(payload)

        try:
            response = self._session.post(
                self.config.endpoint_url,
                data=payload,
                headers=extra_headers,
                timeout=self.config.timeout_seconds,
                verify=self.config.verify_ssl,
            )
            response.raise_for_status()

            logger.info(
                f"Successfully sent {len(siem_events)} events to SIEM",
                extra={
                    "provider": self.config.provider.value,
                    "event_count": len(siem_events),
                },
            )
            return True

        except requests.exceptions.RequestException as e:
            logger.error(
                f"Failed to send events to SIEM: {e}",
                extra={
                    "provider": self.config.provider.value,
                    "event_count": len(siem_events),
                    "error": str(e),
                },
            )
            return False

    def export_events(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        categories: list[str] | None = None,
        limit: int | None = None,
    ) -> tuple[int, int]:
        """
        Export historical events to SIEM in batches.

        Args:
            since: Start time for export (default: 24 hours ago)
            until: End time for export (default: now)
            categories: Optional list of categories to export
            limit: Maximum number of events to export

        Returns:
            Tuple of (events_sent, events_failed)
        """
        since = since or timezone.now() - timedelta(hours=24)
        until = until or timezone.now()

        queryset = AuditEvent.objects.filter(
            timestamp__gte=since,
            timestamp__lte=until,
        ).order_by("timestamp")

        if categories:
            queryset = queryset.filter(category__in=categories)

        if limit:
            queryset = queryset[:limit]

        events_sent = 0
        events_failed = 0
        batch: list[AuditEvent] = []

        for event in queryset.iterator():
            batch.append(event)

            if len(batch) >= self.config.batch_size:
                if self.send_events(batch):
                    events_sent += len(batch)
                else:
                    events_failed += len(batch)
                batch = []

        # Send remaining events
        if batch:
            if self.send_events(batch):
                events_sent += len(batch)
            else:
                events_failed += len(batch)

        logger.info(
            f"SIEM export completed",
            extra={
                "events_sent": events_sent,
                "events_failed": events_failed,
                "since": since.isoformat(),
                "until": until.isoformat(),
            },
        )

        return events_sent, events_failed


def get_siem_config_from_settings() -> SIEMConfig | None:
    """
    Load SIEM configuration from Django settings.

    Expected settings format:
        SIEM_INTEGRATION = {
            'enabled': True,
            'provider': 'splunk',
            'endpoint_url': 'https://splunk.example.com:8088/services/collector',
            'api_key': 'your-hec-token',
            'min_severity': 'medium',
            'include_sensitive': False,
        }
    """
    config = getattr(settings, "SIEM_INTEGRATION", None)
    if not config or not config.get("enabled"):
        return None

    provider_str = config.get("provider", "generic").lower()
    provider_map = {
        "generic": SIEMProvider.GENERIC_WEBHOOK,
        "splunk": SIEMProvider.SPLUNK,
        "elasticsearch": SIEMProvider.ELASTICSEARCH,
        "elastic": SIEMProvider.ELASTICSEARCH,
        "datadog": SIEMProvider.DATADOG,
        "sumo_logic": SIEMProvider.SUMO_LOGIC,
        "sumologic": SIEMProvider.SUMO_LOGIC,
    }

    severity_str = config.get("min_severity", "low").upper()
    severity_map = {
        "INFO": SIEMSeverity.INFO,
        "LOW": SIEMSeverity.LOW,
        "MEDIUM": SIEMSeverity.MEDIUM,
        "HIGH": SIEMSeverity.HIGH,
        "CRITICAL": SIEMSeverity.CRITICAL,
    }

    return SIEMConfig(
        provider=provider_map.get(provider_str, SIEMProvider.GENERIC_WEBHOOK),
        endpoint_url=config["endpoint_url"],
        api_key=config.get("api_key"),
        api_secret=config.get("api_secret"),
        min_severity=severity_map.get(severity_str, SIEMSeverity.LOW),
        include_sensitive=config.get("include_sensitive", False),
        batch_size=config.get("batch_size", 100),
        timeout_seconds=config.get("timeout_seconds", 30),
        verify_ssl=config.get("verify_ssl", True),
        custom_headers=config.get("custom_headers", {}),
    )
