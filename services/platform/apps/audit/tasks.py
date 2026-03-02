"""
Asynchronous tasks for audit integrity monitoring.

These tasks are designed to run via Django-Q2 scheduler for:
- Periodic integrity verification
- File integrity monitoring
- Alert escalation
- Compliance reporting

Schedule configuration via management command:
    python manage.py run_integrity_check --schedule
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.audit.models import AuditAlert, AuditIntegrityCheck
from apps.audit.services import AuditIntegrityService
from apps.common.types import Ok

logger = logging.getLogger(__name__)

# Cache keys for file integrity monitoring
FILE_HASH_CACHE_PREFIX = "file_integrity_hash:"
_DEFAULT_FILE_HASH_CACHE_TIMEOUT = 86400 * 30  # 30 days
FILE_HASH_CACHE_TIMEOUT = _DEFAULT_FILE_HASH_CACHE_TIMEOUT

_DEFAULT_MAX_FILES_DISPLAYED = 5
MAX_FILES_DISPLAYED = _DEFAULT_MAX_FILES_DISPLAYED


def get_file_hash_cache_timeout() -> int:
    """Get file hash cache timeout from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("audit.file_hash_cache_timeout", _DEFAULT_FILE_HASH_CACHE_TIMEOUT)


def get_max_files_displayed() -> int:
    """Get max files displayed from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("audit.max_files_displayed", _DEFAULT_MAX_FILES_DISPLAYED)


def run_integrity_check(
    check_type: str = "all",
    period: str = "24h",
    send_alerts: bool = True,
) -> dict[str, Any]:
    """
    Run audit integrity check as an async task.

    Args:
        check_type: Type of check (hash_verification, sequence_check, gdpr_compliance, all)
        period: Time period to check (1h, 24h, 7d, etc.)
        send_alerts: Whether to send alerts for issues

    Returns:
        Dictionary with check results
    """
    # Parse period
    period_map = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "12h": timedelta(hours=12),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }

    delta = period_map.get(period, timedelta(hours=24))
    period_end = timezone.now()
    period_start = period_end - delta

    results: dict[str, Any] = {
        "task": "run_integrity_check",
        "check_type": check_type,
        "period": period,
        "started_at": timezone.now().isoformat(),
        "checks": [],
        "total_issues": 0,
        "status": "healthy",
    }

    check_types = ["hash_verification", "sequence_check", "gdpr_compliance"] if check_type == "all" else [check_type]

    for ct in check_types:
        try:
            result = AuditIntegrityService.verify_audit_integrity(
                period_start=period_start,
                period_end=period_end,
                check_type=ct,
            )

            if isinstance(result, Ok):
                check = result.value
                check_result = {
                    "type": ct,
                    "status": check.status,
                    "records_checked": check.records_checked,
                    "issues_found": check.issues_found,
                    "check_id": str(check.id),
                }
                results["checks"].append(check_result)
                results["total_issues"] += check.issues_found

                if check.status == "compromised":
                    results["status"] = "compromised"
                elif check.status == "warning" and results["status"] == "healthy":
                    results["status"] = "warning"

                logger.info(f"[Integrity Task] {ct} completed: {check.status} ({check.issues_found} issues)")
            else:
                logger.error(f"[Integrity Task] {ct} failed: {result.error}")
                results["checks"].append(
                    {
                        "type": ct,
                        "status": "error",
                        "error": result.error,
                    }
                )

        except Exception as e:
            logger.exception(f"[Integrity Task] {ct} exception: {e}")
            results["checks"].append(
                {
                    "type": ct,
                    "status": "error",
                    "error": str(e),
                }
            )

    results["completed_at"] = timezone.now().isoformat()

    # Send escalation alerts if critical
    if send_alerts and results["status"] == "compromised":
        _send_integrity_escalation_alert(results)

    return results


def run_file_integrity_check() -> dict[str, Any]:
    """
    Monitor critical application files for unauthorized changes.

    Tracks hashes of:
    - Configuration files
    - Security-related Python modules
    - Static assets integrity

    Returns:
        Dictionary with file integrity results
    """
    results: dict[str, Any] = {
        "task": "run_file_integrity_check",
        "started_at": timezone.now().isoformat(),
        "files_checked": 0,
        "changes_detected": [],
        "new_files": [],
        "missing_files": [],
        "status": "healthy",
    }

    # Define critical files to monitor
    base_dir = Path(settings.BASE_DIR)
    critical_patterns = [
        # Configuration files
        "config/settings/*.py",
        "config/urls.py",
        # Security modules
        "apps/common/security_decorators.py",
        "apps/common/validators.py",
        "apps/common/encryption.py",
        "apps/common/credential_vault.py",
        "apps/common/file_upload_security.py",
        "apps/users/mfa.py",
        "apps/audit/services.py",
        # Middleware
        "apps/common/middleware.py",
        # Authentication
        "apps/users/views.py",
        "apps/users/models.py",
    ]

    for pattern in critical_patterns:
        for file_path in base_dir.glob(pattern):
            if not file_path.is_file():
                continue

            results["files_checked"] += 1
            relative_path = str(file_path.relative_to(base_dir))

            try:
                # Calculate current hash
                current_hash = _calculate_file_hash(file_path)

                # Get stored hash
                cache_key = f"{FILE_HASH_CACHE_PREFIX}{relative_path}"
                stored_hash = cache.get(cache_key)

                if stored_hash is None:
                    # First time seeing this file
                    cache.set(cache_key, current_hash, FILE_HASH_CACHE_TIMEOUT)
                    results["new_files"].append(
                        {
                            "path": relative_path,
                            "hash": current_hash[:16] + "...",
                            "detected_at": timezone.now().isoformat(),
                        }
                    )
                    logger.info(f"[File Integrity] New file tracked: {relative_path}")

                elif stored_hash != current_hash:
                    # File has changed
                    results["changes_detected"].append(
                        {
                            "path": relative_path,
                            "previous_hash": stored_hash[:16] + "...",
                            "current_hash": current_hash[:16] + "...",
                            "detected_at": timezone.now().isoformat(),
                        }
                    )
                    results["status"] = "warning"

                    # Update stored hash
                    cache.set(cache_key, current_hash, FILE_HASH_CACHE_TIMEOUT)

                    logger.warning(f"[File Integrity] Change detected: {relative_path}")

            except Exception as e:
                logger.error(f"[File Integrity] Error checking {relative_path}: {e}")

    results["completed_at"] = timezone.now().isoformat()

    # Create integrity check record
    if results["changes_detected"]:
        _create_file_integrity_alert(results)

    # Log file integrity check to audit
    _log_file_integrity_check(results)

    return results


def _calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def _send_integrity_escalation_alert(results: dict[str, Any]) -> None:
    """Send escalation alert for critical integrity issues."""
    try:
        # Create critical alert
        alert = AuditAlert.objects.create(
            alert_type="data_integrity",
            severity="critical",
            title="CRITICAL: Audit Data Integrity Compromised",
            description=(
                f"Automated integrity check detected {results['total_issues']} issues "
                f"indicating possible data tampering or system compromise. "
                f"Immediate investigation required."
            ),
            evidence={
                "check_results": results,
                "detection_time": timezone.now().isoformat(),
                "affected_checks": [c["type"] for c in results["checks"] if c.get("status") == "compromised"],
            },
            metadata={
                "auto_generated": True,
                "escalation_required": True,
                "source": "integrity_monitoring_task",
            },
        )

        logger.critical(f"[Integrity Alert] Created critical alert {alert.id} for compromised audit data")

        # Send email notification to admins
        from apps.settings.services import SettingsService  # noqa: PLC0415

        if SettingsService.get_boolean_setting("audit.notify_on_critical_alerts", True):
            try:
                from apps.notifications.services import NotificationService  # noqa: PLC0415

                NotificationService.send_admin_alert(
                    subject="Audit Data Integrity Compromised",
                    message=(
                        f"Automated integrity check detected {results['total_issues']} issues "
                        f"indicating possible data tampering.\n\n"
                        f"Alert ID: {alert.id}\n"
                        f"Affected checks: {', '.join(c['type'] for c in results['checks'] if c.get('status') == 'compromised')}\n"
                        f"Immediate investigation required."
                    ),
                    alert_type="critical",
                    metadata={"alert_id": str(alert.id), "source": "integrity_monitoring"},
                )
            except Exception as e:
                logger.error(f"[Integrity Alert] Failed to send email notification: {e}")

    except Exception as e:
        logger.exception(f"[Integrity Alert] Failed to create escalation alert: {e}")


def _create_file_integrity_alert(results: dict[str, Any]) -> None:
    """Create alert for file integrity changes."""
    try:
        changed_files = [c["path"] for c in results["changes_detected"]]

        alert = AuditAlert.objects.create(
            alert_type="data_integrity",
            severity="high",
            title=f"File Integrity: {len(changed_files)} Critical Files Modified",
            description=(
                f"File integrity monitoring detected changes to critical "
                f"application files: {', '.join(changed_files[:MAX_FILES_DISPLAYED])}"
                + (
                    f" and {len(changed_files) - MAX_FILES_DISPLAYED} more"
                    if len(changed_files) > MAX_FILES_DISPLAYED
                    else ""
                )
            ),
            evidence={
                "changes": results["changes_detected"],
                "detection_time": timezone.now().isoformat(),
            },
            metadata={
                "auto_generated": True,
                "source": "file_integrity_monitoring",
                "requires_review": True,
            },
        )

        logger.warning(f"[File Integrity Alert] Created alert {alert.id} for {len(changed_files)} file changes")

        # Send email notification to admins
        from apps.settings.services import SettingsService  # noqa: PLC0415

        if SettingsService.get_boolean_setting("audit.notify_on_file_integrity_alerts", True):
            try:
                from apps.notifications.services import NotificationService  # noqa: PLC0415

                NotificationService.send_admin_alert(
                    subject=f"File Integrity: {len(changed_files)} Critical Files Modified",
                    message=(
                        f"File integrity monitoring detected changes to critical files:\n"
                        f"{chr(10).join('- ' + f for f in changed_files[:5])}\n\n"
                        f"Please review these changes immediately."
                    ),
                    alert_type="warning",
                    metadata={"alert_id": str(alert.id), "source": "file_integrity_monitoring"},
                )
            except Exception as e:
                logger.error(f"[File Integrity Alert] Failed to send email notification: {e}")

    except Exception as e:
        logger.exception(f"[File Integrity Alert] Failed to create alert: {e}")


def _log_file_integrity_check(results: dict[str, Any]) -> None:
    """Log file integrity check to audit system."""
    try:
        AuditIntegrityCheck.objects.create(
            check_type="file_integrity",
            period_start=timezone.now() - timedelta(hours=6),
            period_end=timezone.now(),
            status="warning" if results["changes_detected"] else "healthy",
            records_checked=results["files_checked"],
            issues_found=len(results["changes_detected"]),
            findings=results["changes_detected"],
            metadata={
                "new_files_tracked": len(results["new_files"]),
                "check_timestamp": timezone.now().isoformat(),
                "checker": "file_integrity_monitoring",
            },
        )
    except Exception as e:
        logger.error(f"[File Integrity] Failed to log check: {e}")


def cleanup_old_integrity_checks(days: int = 90) -> dict[str, Any]:
    """
    Clean up old integrity check records.

    Keeps:
    - All compromised/warning checks
    - Last 90 days of healthy checks

    Args:
        days: Number of days to keep healthy checks

    Returns:
        Dictionary with cleanup results
    """
    cutoff = timezone.now() - timedelta(days=days)

    # Only delete old healthy checks
    deleted_count = AuditIntegrityCheck.objects.filter(
        status="healthy",
        checked_at__lt=cutoff,
    ).delete()[0]

    logger.info(f"[Integrity Cleanup] Deleted {deleted_count} old healthy checks (older than {days} days)")

    return {
        "deleted_count": deleted_count,
        "cutoff_date": cutoff.isoformat(),
        "kept_statuses": ["warning", "compromised"],
    }


def generate_integrity_report(period_days: int = 30) -> dict[str, Any]:
    """
    Generate a summary report of integrity checks.

    Args:
        period_days: Number of days to include in report

    Returns:
        Dictionary with report data
    """
    cutoff = timezone.now() - timedelta(days=period_days)

    checks = AuditIntegrityCheck.objects.filter(checked_at__gte=cutoff)

    report = {
        "period_days": period_days,
        "generated_at": timezone.now().isoformat(),
        "total_checks": checks.count(),
        "by_status": {},
        "by_type": {},
        "total_issues": 0,
        "critical_events": [],
    }

    by_status: dict[str, int] = {}
    by_type: dict[str, dict[str, int]] = {}
    total_issues = 0

    # Aggregate by status
    for status in ["healthy", "warning", "compromised"]:
        count = checks.filter(status=status).count()
        by_status[status] = count

    # Aggregate by type
    for check_type in ["hash_verification", "sequence_check", "gdpr_compliance", "file_integrity"]:
        type_checks = checks.filter(check_type=check_type)
        type_entry = {
            "count": type_checks.count(),
            "issues": sum(c.issues_found for c in type_checks),
        }
        by_type[check_type] = type_entry
        total_issues += type_entry["issues"]

    report["by_status"] = by_status
    report["by_type"] = by_type
    report["total_issues"] = total_issues

    # Get critical events
    critical_checks = checks.filter(status="compromised").order_by("-checked_at")[:10]
    report["critical_events"] = [
        {
            "id": str(c.id),
            "type": c.check_type,
            "checked_at": c.checked_at.isoformat(),
            "issues": c.issues_found,
        }
        for c in critical_checks
    ]

    return report
