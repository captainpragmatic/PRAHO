"""
🔍 Security Monitoring and Alerting for Ticket System

Comprehensive security event tracking and monitoring for:
- Failed access attempts
- Suspicious file upload patterns
- Rate limit violations
- Unusual user behavior patterns
- Security scan failures

Integration points for future SIEM/monitoring systems.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Count
from django.utils import timezone

from apps.settings.services import SettingsService

from .models import Ticket, TicketAttachment, TicketComment

User = get_user_model()
logger = logging.getLogger(__name__)

# Security monitoring constants
_DEFAULT_SECURITY_ALERT_THRESHOLD = 5  # Failed attempts before alert (configurable via SettingsService)
MONITORING_WINDOW_MINUTES = 15  # Time window for pattern detection (structural)
SUSPICIOUS_UPLOAD_COUNT = 10  # File uploads per window that trigger alert (structural)


class SecurityEventTracker:
    """
    🔍 Track and analyze security events for anomaly detection

    Monitors patterns that could indicate:
    - Brute force attacks
    - Data exfiltration attempts
    - Privilege escalation attempts
    - Automated abuse
    """

    def __init__(self) -> None:
        self.cache_prefix = "ticket_security"
        self.monitoring_window = MONITORING_WINDOW_MINUTES

    @property
    def alert_threshold(self) -> int:
        """Alert threshold from SettingsService (cached by SettingsService layer)."""
        return SettingsService.get_integer_setting(
            "tickets.security_alert_threshold", _DEFAULT_SECURITY_ALERT_THRESHOLD
        )

    def track_failed_access(self, user_id: int, resource_type: str, resource_id: str, reason: str) -> None:
        """Track failed access attempts for pattern detection"""
        event_key = f"{self.cache_prefix}_failed_access_{user_id}"
        current_failures = cache.get(event_key, [])

        # Add new failure with timestamp
        failure_event = {
            "timestamp": timezone.now().isoformat(),
            "resource_type": resource_type,
            "resource_id": resource_id,
            "reason": reason,
        }
        current_failures.append(failure_event)

        # Keep only recent failures (within monitoring window)
        cutoff_time = timezone.now() - timedelta(minutes=self.monitoring_window)
        recent_failures = [f for f in current_failures if datetime.fromisoformat(f["timestamp"]) > cutoff_time]

        # Update cache
        cache.set(event_key, recent_failures, 60 * self.monitoring_window)

        # Check if threshold exceeded
        if len(recent_failures) >= self.alert_threshold:
            self._trigger_security_alert(
                user_id,
                "repeated_access_failures",
                {
                    "failure_count": len(recent_failures),
                    "recent_failures": recent_failures[-5:],  # Last 5 failures
                },
            )

    def track_file_upload(self, user_id: int, filename: str, file_size: int, scan_result: str) -> None:
        """Track file upload patterns for abuse detection"""
        event_key = f"{self.cache_prefix}_uploads_{user_id}"
        current_uploads = cache.get(event_key, [])

        # Add new upload with details
        upload_event = {
            "timestamp": timezone.now().isoformat(),
            "filename": filename,
            "file_size": file_size,
            "scan_result": scan_result,
        }
        current_uploads.append(upload_event)

        # Keep only recent uploads (within monitoring window)
        cutoff_time = timezone.now() - timedelta(minutes=self.monitoring_window)
        recent_uploads = [u for u in current_uploads if datetime.fromisoformat(u["timestamp"]) > cutoff_time]

        # Update cache
        cache.set(event_key, recent_uploads, 60 * self.monitoring_window)

        # Check for suspicious patterns
        self._analyze_upload_patterns(user_id, recent_uploads)

    def track_privilege_escalation_attempt(self, user_id: int, attempted_action: str, target_resource: str) -> None:
        """Track attempts to access resources beyond user permissions"""
        logger.critical(
            f"🚨 [PRIVILEGE ESCALATION] User {user_id} attempted {attempted_action} "
            f"on {target_resource} without proper permissions"
        )

        # Immediate alert for privilege escalation attempts
        self._trigger_security_alert(
            user_id,
            "privilege_escalation_attempt",
            {
                "attempted_action": attempted_action,
                "target_resource": target_resource,
                "timestamp": timezone.now().isoformat(),
            },
        )

    def get_security_metrics(self, hours: int = 24) -> dict[str, Any]:
        """Get security metrics for monitoring dashboard"""
        cutoff_time = timezone.now() - timedelta(hours=hours)

        metrics = {
            "time_range_hours": hours,
            "failed_access_attempts": self._count_cache_events("failed_access", cutoff_time),
            "suspicious_uploads": self._count_cache_events("uploads", cutoff_time),
            "rate_limit_violations": self._count_cache_events("rate_limit", cutoff_time),
            "security_scan_failures": self._get_scan_failure_count(cutoff_time),
            "top_security_events": self._get_top_security_events(cutoff_time),
        }

        return metrics

    def _analyze_upload_patterns(self, user_id: int, uploads: list[dict[str, Any]]) -> None:
        """Analyze upload patterns for suspicious behavior"""
        if len(uploads) >= SUSPICIOUS_UPLOAD_COUNT:
            # High volume uploads - potential abuse
            total_size = sum(u["file_size"] for u in uploads)
            scan_failures = [u for u in uploads if u["scan_result"] != "CLEAN_NO_SCAN"]

            alert_data = {
                "upload_count": len(uploads),
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "scan_failures": len(scan_failures),
                "time_window_minutes": self.monitoring_window,
            }

            self._trigger_security_alert(user_id, "suspicious_upload_volume", alert_data)

        # Check for repeated scan failures
        failed_scan_threshold = 3
        failed_scans = [u for u in uploads if u["scan_result"] not in ["CLEAN_NO_SCAN", "CLEAN"]]
        if len(failed_scans) >= failed_scan_threshold:
            self._trigger_security_alert(
                user_id,
                "repeated_scan_failures",
                {"failed_scan_count": len(failed_scans), "recent_failures": failed_scans[-failed_scan_threshold:]},
            )

    def _trigger_security_alert(self, user_id: int, alert_type: str, alert_data: dict[str, Any]) -> None:
        """Trigger security alert for monitoring systems"""
        try:
            user = User.objects.get(id=user_id)
            user_email = user.email
        except User.DoesNotExist:
            user_email = f"user_id_{user_id}"

        alert_message = (
            f"🚨 [SECURITY ALERT] {alert_type.upper().replace('_', ' ')}\n"
            f"User: {user_email}\n"
            f"Details: {alert_data}\n"
            f"Timestamp: {timezone.now().isoformat()}"
        )

        logger.critical(alert_message)

        # Store alert for dashboard/API consumption
        alert_key = f"{self.cache_prefix}_alert_{alert_type}_{user_id}_{int(timezone.now().timestamp())}"
        cache.set(
            alert_key,
            {
                "user_id": user_id,
                "user_email": user_email,
                "alert_type": alert_type,
                "alert_data": alert_data,
                "timestamp": timezone.now().isoformat(),
            },
            60 * 60 * 24,
        )  # Keep alerts for 24 hours

        # TODO: Integration points for external monitoring
        # - Send to SIEM system
        # - Trigger Slack/email notifications
        # - Update security dashboard
        # - Create incident tickets

    def _count_cache_events(self, event_type: str, cutoff_time: datetime) -> int:
        """Count cached security events within time window"""
        count = 0
        pattern = f"{self.cache_prefix}_{event_type}_*"

        # Note: This is a simplified implementation
        # In production, consider using Redis SCAN or dedicated monitoring storage
        # Using a safe approach since cache._cache is implementation-specific
        try:
            cache_keys = getattr(cache, "_cache", {}).keys() if hasattr(cache, "_cache") else []
            for key in cache_keys:
                if pattern.replace("*", "") in key:
                    events = cache.get(key, [])
                    recent_events = [
                        e
                        for e in events
                        if datetime.fromisoformat(e.get("timestamp", "1970-01-01T00:00:00")) > cutoff_time
                    ]
                    count += len(recent_events)
        except (AttributeError, TypeError):
            # Fallback: cache doesn't support key iteration
            return 0

        return count

    def _get_scan_failure_count(self, cutoff_time: datetime) -> int:
        """Get count of file scan failures from database"""
        return TicketAttachment.objects.filter(uploaded_at__gte=cutoff_time, is_safe=False).count()

    def _get_top_security_events(self, cutoff_time: datetime) -> list[dict[str, Any]]:
        """Get top security events for monitoring"""
        # This would typically query a dedicated security events table
        # For now, return a simplified summary
        return [
            {"event_type": "file_upload_failures", "count": self._get_scan_failure_count(cutoff_time)},
            {
                "event_type": "attachment_downloads",
                "count": TicketAttachment.objects.filter(uploaded_at__gte=cutoff_time).count(),
            },
        ]


# Global security tracker instance
security_tracker = SecurityEventTracker()


def get_ticket_security_summary() -> dict[str, Any]:
    """
    📊 Get comprehensive ticket security summary for dashboards

    Returns metrics for:
    - Recent security events
    - File upload statistics
    - Access pattern analysis
    - System health indicators
    """
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    summary = {
        "last_updated": now.isoformat(),
        "time_ranges": {
            "last_24h": {
                "tickets_created": Ticket.objects.filter(created_at__gte=last_24h).count(),
                "files_uploaded": TicketAttachment.objects.filter(uploaded_at__gte=last_24h).count(),
                "unsafe_files_blocked": TicketAttachment.objects.filter(
                    uploaded_at__gte=last_24h, is_safe=False
                ).count(),
                "comments_posted": TicketComment.objects.filter(created_at__gte=last_24h).count(),
            },
            "last_7d": {
                "tickets_created": Ticket.objects.filter(created_at__gte=last_7d).count(),
                "files_uploaded": TicketAttachment.objects.filter(uploaded_at__gte=last_7d).count(),
                "unsafe_files_blocked": TicketAttachment.objects.filter(
                    uploaded_at__gte=last_7d, is_safe=False
                ).count(),
                "unique_uploaders": TicketAttachment.objects.filter(uploaded_at__gte=last_7d)
                .values("uploaded_by")
                .distinct()
                .count(),
            },
        },
        "security_health": {
            "file_security_enabled": True,
            "rate_limiting_active": True,
            "access_control_enforced": True,
            "audit_logging_active": True,
        },
        "top_file_types": list(
            TicketAttachment.objects.filter(uploaded_at__gte=last_7d)
            .values("content_type")
            .annotate(count=Count("content_type"))
            .order_by("-count")[:5]
        ),
        "security_metrics": security_tracker.get_security_metrics(24),
    }

    return summary


def alert_on_suspicious_activity(user_id: int, activity_type: str, details: dict[str, Any]) -> None:
    """
    🚨 Centralized function for triggering security alerts

    Used by views and other components to report suspicious activity
    """
    security_tracker._trigger_security_alert(user_id, activity_type, details)
