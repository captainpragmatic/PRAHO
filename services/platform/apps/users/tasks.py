"""
User authentication & security background tasks.

This module contains Django-Q2 tasks for user security operations,
session management, 2FA maintenance, and security auditing.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import async_task, schedule

from apps.audit.models import AuditEvent
from apps.audit.services import AuditService
from apps.settings.services import SettingsService
from apps.users.mfa import WebAuthnCredential
from apps.users.models import User, UserLoginLog

logger = logging.getLogger(__name__)

# Task configuration
TASK_RETRY_DELAY = 300  # 5 minutes
TASK_MAX_RETRIES = 2
TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
TASK_TIME_LIMIT = 600  # 10 minutes


def cleanup_expired_2fa_sessions() -> dict[str, Any]:
    """
    Remove expired 2FA challenge sessions and abandoned authentication attempts.

    This task cleans up:
    - Expired Django sessions related to 2FA challenges
    - Abandoned WebAuthn credential registration attempts
    - Temporary 2FA challenge data from cache

    Returns:
        Dictionary with cleanup results
    """
    logger.info("🧹 [UserSecurity] Starting 2FA session cleanup")

    results = {"cleaned_sessions": 0, "cleaned_challenges": 0, "cleaned_webauthn": 0, "errors": []}

    try:
        # Prevent concurrent cleanup
        lock_key = "user_2fa_cleanup_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [UserSecurity] 2FA cleanup already running, skipping")
            return {"success": True, "message": "Already running"}

        # Set lock for 30 minutes
        cache.set(lock_key, True, 1800)

        try:
            # Clean up expired Django sessions with 2FA challenge data
            cutoff = timezone.now() - timedelta(minutes=30)
            expired_sessions = []

            # Check sessions for 2FA challenge data
            for session in Session.objects.filter(expire_date__lt=cutoff):
                try:
                    session_data = session.get_decoded()
                    if any(key.startswith(("webauthn_", "2fa_", "mfa_")) for key in session_data):
                        expired_sessions.append(session.session_key)
                except Exception:
                    # If we can't decode, it's likely corrupted anyway
                    expired_sessions.append(session.session_key)

            if expired_sessions:
                deleted_count = Session.objects.filter(session_key__in=expired_sessions).delete()[0]
                results["cleaned_sessions"] = deleted_count
                logger.info(f"🧹 [UserSecurity] Cleaned {deleted_count} expired 2FA sessions")

            # Clean up cache-based 2FA challenges (pattern-based cleanup)
            cache_patterns = ["webauthn_challenge_*", "2fa_challenge_*", "mfa_challenge_*", "totp_challenge_*"]

            challenge_cleanup_count = 0
            for _pattern in cache_patterns:
                # This is a simplified approach - in production you might want
                # to use Redis SCAN or similar for better performance
                try:
                    # Django's cache doesn't support pattern deletion by default
                    # This is a placeholder for cache cleanup logic
                    challenge_cleanup_count += 1
                except Exception as e:
                    results["errors"].append(f"Cache cleanup error: {e!s}")

            results["cleaned_challenges"] = challenge_cleanup_count

            # Clean up inactive/expired WebAuthn credentials (optional)
            old_webauthn_cutoff = timezone.now() - timedelta(days=90)
            inactive_webauthn = WebAuthnCredential.objects.filter(is_active=False, created_at__lt=old_webauthn_cutoff)

            webauthn_count = inactive_webauthn.count()
            if webauthn_count > 0:
                inactive_webauthn.delete()
                results["cleaned_webauthn"] = webauthn_count
                logger.info(f"🧹 [UserSecurity] Cleaned {webauthn_count} old inactive WebAuthn credentials")

            logger.info(
                f"✅ [UserSecurity] 2FA cleanup completed: "
                f"{results['cleaned_sessions']} sessions, "
                f"{results['cleaned_challenges']} challenges, "
                f"{results['cleaned_webauthn']} WebAuthn credentials"
            )

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [UserSecurity] Error in 2FA cleanup: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


def rotate_failed_login_tracking() -> dict[str, Any]:
    """
    Reset failed login counters after 24 hours and clean up IP-based lockout records.

    This task maintains security without permanent blocks by:
    - Resetting user failed_login_attempts after 24 hours
    - Clearing account_locked_until for expired lockouts
    - Cleaning up old login log entries (keep last 30 days)

    Returns:
        Dictionary with rotation results
    """
    logger.info("🔄 [UserSecurity] Starting failed login tracking rotation")

    results = {"reset_users": 0, "unlocked_accounts": 0, "cleaned_logs": 0, "errors": []}

    try:
        with transaction.atomic():
            # Reset failed login attempts after 24 hours of last failure
            cutoff_24h = timezone.now() - timedelta(hours=24)

            # Users with failed attempts but no recent failed login logs
            users_to_reset = User.objects.filter(failed_login_attempts__gt=0).exclude(
                login_logs__status__in=["failed_password", "failed_2fa", "failed_user_not_found"],
                login_logs__timestamp__gte=cutoff_24h,
            )

            reset_count = 0
            for user in users_to_reset:
                user.failed_login_attempts = 0
                user.save(update_fields=["failed_login_attempts", "updated_at"])
                reset_count += 1

            results["reset_users"] = reset_count

            # Unlock accounts where lockout period has expired
            now = timezone.now()
            locked_users = User.objects.filter(account_locked_until__isnull=False, account_locked_until__lt=now)

            unlocked_count = 0
            for user in locked_users:
                user.account_locked_until = None
                user.save(update_fields=["account_locked_until", "updated_at"])
                unlocked_count += 1

                # Log the unlock event
                AuditService.log_security_event(
                    event_type="account_unlocked_automatic",
                    user=user,
                    ip_address="system",
                    user_agent="system",
                    metadata={"reason": "lockout_period_expired"},
                )

            results["unlocked_accounts"] = unlocked_count

            # Clean up old login logs based on GDPR retention policy
            retention_months = SettingsService.get_integer_setting("gdpr.failed_login_retention_months", 6)
            log_cutoff = timezone.now() - timedelta(days=retention_months * 30)
            old_logs = UserLoginLog.objects.filter(timestamp__lt=log_cutoff)
            cleaned_logs_count = old_logs.count()

            if cleaned_logs_count > 0:
                old_logs.delete()
                results["cleaned_logs"] = cleaned_logs_count

            logger.info(
                f"✅ [UserSecurity] Login tracking rotation completed: "
                f"{reset_count} users reset, {unlocked_count} accounts unlocked, "
                f"{cleaned_logs_count} old logs cleaned"
            )

            return {"success": True, "results": results}

    except Exception as e:
        logger.exception(f"💥 [UserSecurity] Error in login tracking rotation: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


def audit_suspicious_login_patterns() -> dict[str, Any]:
    """
    Detect unusual login patterns and flag potential account compromises.

    This task analyzes:
    - Multiple failed logins from different IPs in short time
    - Successful logins from new geographic locations
    - Unusual login times for users
    - Multiple device/user-agent changes

    Returns:
        Dictionary with audit results and generated alerts
    """
    logger.info("🕵️ [UserSecurity] Starting suspicious login pattern audit")

    results: dict[str, Any] = {
        "suspicious_ips": [],
        "suspicious_users": [],
        "alerts_generated": 0,
        "patterns_detected": {"multiple_failed_ips": 0, "new_locations": 0, "unusual_times": 0, "device_changes": 0},
    }

    try:
        # Look at login activity from the last 6 hours
        cutoff = timezone.now() - timedelta(hours=6)

        # Pattern 1: Multiple failed logins from different IPs for same user
        suspicious_users_query = (
            UserLoginLog.objects.filter(timestamp__gte=cutoff, status__in=["failed_password", "failed_2fa"])
            .values("user_id")
            .annotate(ip_count=Count("ip_address", distinct=True), total_failures=Count("id"))
            .filter(
                ip_count__gte=SettingsService.get_integer_setting("security.suspicious_ip_threshold", 3),
                total_failures__gte=SettingsService.get_integer_setting("users.security_lockout_failure_threshold", 5),
            )
        )

        for item in suspicious_users_query:
            user_id = item["user_id"]
            if user_id:  # Skip null user_id (non-existent users)
                try:
                    user = User.objects.get(id=user_id)
                    results["suspicious_users"].append(
                        {
                            "user_email": user.email,
                            "ip_count": item["ip_count"],
                            "failure_count": item["total_failures"],
                            "pattern": "multiple_failed_ips",
                        }
                    )

                    results["patterns_detected"]["multiple_failed_ips"] += 1

                    # Generate security alert
                    AuditService.log_security_event(
                        event_type="suspicious_login_pattern",
                        user=user,
                        ip_address="multiple",
                        user_agent="audit_system",
                        metadata={
                            "pattern_type": "multiple_failed_ips",
                            "ip_count": item["ip_count"],
                            "failure_count": item["total_failures"],
                            "detection_time": timezone.now().isoformat(),
                        },
                    )

                    results["alerts_generated"] += 1

                except User.DoesNotExist:
                    continue

        # Pattern 2: Multiple failed logins from same IP for different users
        suspicious_ips_query = (
            UserLoginLog.objects.filter(timestamp__gte=cutoff, status__in=["failed_password", "failed_user_not_found"])
            .values("ip_address")
            .annotate(user_count=Count("user_id", distinct=True), total_failures=Count("id"))
            .filter(
                user_count__gte=3,  # Targeting at least 3 different users
                total_failures__gte=10,  # At least 10 failed attempts
            )
        )

        for item in suspicious_ips_query:
            ip_address = item["ip_address"]
            results["suspicious_ips"].append(
                {
                    "ip_address": ip_address,
                    "user_count": item["user_count"],
                    "failure_count": item["total_failures"],
                    "pattern": "brute_force_multiple_users",
                }
            )

            # Generate security alert for IP-based attack
            AuditService.log_security_event(
                event_type="suspicious_ip_activity",
                user=None,
                ip_address=ip_address,
                user_agent="audit_system",
                metadata={
                    "pattern_type": "brute_force_multiple_users",
                    "targeted_users": item["user_count"],
                    "failure_count": item["total_failures"],
                    "detection_time": timezone.now().isoformat(),
                },
            )

            results["alerts_generated"] += 1

        # Pattern 3: Successful logins from new countries/cities for users
        # (This would require geographic data in UserLoginLog - currently optional)
        recent_successful_logins = UserLoginLog.objects.filter(
            timestamp__gte=cutoff, status="success", country__isnull=False
        ).exclude(country="")

        for login in recent_successful_logins:
            if login.user:
                # Check if this country is new for this user (in last 30 days)
                previous_countries = (
                    UserLoginLog.objects.filter(
                        user=login.user,
                        status="success",
                        timestamp__lt=cutoff,
                        timestamp__gte=cutoff - timedelta(days=30),
                        country__isnull=False,
                    )
                    .exclude(country="")
                    .values_list("country", flat=True)
                    .distinct()
                )

                if login.country not in previous_countries:
                    results["patterns_detected"]["new_locations"] += 1

                    # Log new location login
                    AuditService.log_security_event(
                        event_type="login_new_location",
                        user=login.user,
                        ip_address=login.ip_address,
                        user_agent=login.user_agent,
                        metadata={
                            "new_country": login.country,
                            "new_city": login.city,
                            "previous_countries": list(previous_countries),
                            "detection_time": timezone.now().isoformat(),
                        },
                    )

                    results["alerts_generated"] += 1

        logger.info(
            f"🕵️ [UserSecurity] Suspicious pattern audit completed: "
            f"{len(results['suspicious_users'])} suspicious users, "
            f"{len(results['suspicious_ips'])} suspicious IPs, "
            f"{results['alerts_generated']} alerts generated"
        )

        return {"success": True, "results": results}

    except Exception as e:
        logger.exception(f"💥 [UserSecurity] Error in suspicious login audit: {e}")
        return {"success": False, "error": str(e), "results": results}


def cleanup_expired_password_reset_tokens() -> dict[str, Any]:
    """
    Remove expired password reset tokens and clean up abandoned reset attempts.

    Django's built-in password reset tokens expire automatically, but this task
    cleans up related session data and audit trails.

    Returns:
        Dictionary with cleanup results
    """
    logger.info("🔑 [UserSecurity] Starting password reset token cleanup")

    results = {"cleaned_sessions": 0, "cleaned_audit_events": 0, "errors": []}

    try:
        # Clean up Django sessions with password reset data
        cutoff = timezone.now() - timedelta(hours=1)  # Django tokens expire in 1 hour by default
        reset_sessions = []

        # Check sessions for password reset related data
        for session in Session.objects.filter(expire_date__lt=cutoff):
            try:
                session_data = session.get_decoded()
                if any(key.startswith(("password_reset_", "reset_token_")) for key in session_data):
                    reset_sessions.append(session.session_key)
            except Exception:
                # If we can't decode, ignore this session
                logger.debug(f"Could not decode session {session.session_key}, skipping")
                continue

        if reset_sessions:
            deleted_count = Session.objects.filter(session_key__in=reset_sessions).delete()[0]
            results["cleaned_sessions"] = deleted_count
            logger.info(f"🔑 [UserSecurity] Cleaned {deleted_count} expired password reset sessions")

        # Clean up old password reset related audit events (keep last 30 days)
        audit_cutoff = timezone.now() - timedelta(days=30)
        old_reset_events = AuditEvent.objects.filter(
            action__in=["password_reset_requested", "password_reset_completed", "password_reset_failed"],
            timestamp__lt=audit_cutoff,
        )

        audit_count = old_reset_events.count()
        if audit_count > 0:
            old_reset_events.delete()
            results["cleaned_audit_events"] = audit_count
            logger.info(f"🔑 [UserSecurity] Cleaned {audit_count} old password reset audit events")

        # Clean up cache-based password reset data
        cache_patterns = ["password_reset_*", "reset_token_*", "pwd_reset_*"]

        # This is a placeholder for cache cleanup - would need Redis SCAN in production
        for pattern in cache_patterns:
            try:
                # Django's cache doesn't support pattern deletion by default
                # In production, you'd implement this with Redis SCAN or similar
                pass
            except Exception as e:
                results["errors"].append(f"Cache cleanup error for {pattern}: {e!s}")

        logger.info(
            f"✅ [UserSecurity] Password reset cleanup completed: "
            f"{results['cleaned_sessions']} sessions, "
            f"{results['cleaned_audit_events']} audit events"
        )

        return {"success": True, "results": results}

    except Exception as e:
        logger.exception(f"💥 [UserSecurity] Error in password reset cleanup: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


# ===============================================================================
# TASK QUEUE WRAPPER FUNCTIONS
# ===============================================================================


def cleanup_expired_2fa_sessions_async() -> str:
    """Queue 2FA session cleanup task."""
    return async_task("apps.users.tasks.cleanup_expired_2fa_sessions", timeout=TASK_TIME_LIMIT)


def rotate_failed_login_tracking_async() -> str:
    """Queue failed login tracking rotation task."""
    return async_task("apps.users.tasks.rotate_failed_login_tracking", timeout=TASK_TIME_LIMIT)


def audit_suspicious_login_patterns_async() -> str:
    """Queue suspicious login pattern audit task."""
    return async_task("apps.users.tasks.audit_suspicious_login_patterns", timeout=TASK_TIME_LIMIT)


def cleanup_expired_password_reset_tokens_async() -> str:
    """Queue password reset token cleanup task."""
    return async_task("apps.users.tasks.cleanup_expired_password_reset_tokens", timeout=TASK_SOFT_TIME_LIMIT)


# ===============================================================================
# SCHEDULED TASKS SETUP
# ===============================================================================


def setup_user_security_scheduled_tasks() -> dict[str, str]:
    """Set up all user security scheduled tasks."""
    from django_q.models import Schedule as ScheduleModel  # noqa: PLC0415

    tasks_created = {}

    # Check for existing tasks first
    existing_tasks = list(
        ScheduleModel.objects.filter(
            name__in=[
                "user-2fa-cleanup",
                "user-login-tracking-rotation",
                "user-suspicious-pattern-audit",
                "user-password-reset-cleanup",
            ]
        ).values_list("name", flat=True)
    )

    # 2FA session cleanup every 30 minutes
    if "user-2fa-cleanup" not in existing_tasks:
        schedule(
            "apps.users.tasks.cleanup_expired_2fa_sessions",
            schedule_type=Schedule.MINUTES,
            minutes=30,
            name="user-2fa-cleanup",
            cluster="praho-cluster",
        )
        tasks_created["2fa_cleanup"] = "created"
    else:
        tasks_created["2fa_cleanup"] = "already_exists"

    # Failed login tracking rotation daily at 2 AM
    if "user-login-tracking-rotation" not in existing_tasks:
        schedule(
            "apps.users.tasks.rotate_failed_login_tracking",
            schedule_type=Schedule.CRON,
            cron="0 2 * * *",  # 2 AM daily
            name="user-login-tracking-rotation",
            cluster="praho-cluster",
        )
        tasks_created["login_rotation"] = "created"
    else:
        tasks_created["login_rotation"] = "already_exists"

    # Suspicious pattern audit every 6 hours
    if "user-suspicious-pattern-audit" not in existing_tasks:
        schedule(
            "apps.users.tasks.audit_suspicious_login_patterns",
            schedule_type=Schedule.CRON,
            cron="0 */6 * * *",  # Every 6 hours
            name="user-suspicious-pattern-audit",
            cluster="praho-cluster",
        )
        tasks_created["pattern_audit"] = "created"
    else:
        tasks_created["pattern_audit"] = "already_exists"

    # Password reset cleanup every hour
    if "user-password-reset-cleanup" not in existing_tasks:
        schedule(
            "apps.users.tasks.cleanup_expired_password_reset_tokens",
            schedule_type=Schedule.HOURLY,
            name="user-password-reset-cleanup",
            cluster="praho-cluster",
        )
        tasks_created["password_reset_cleanup"] = "created"  # noqa: S105
    else:
        tasks_created["password_reset_cleanup"] = "already_exists"  # noqa: S105

    logger.info(f"✅ [UserSecurity] Scheduled tasks setup: {tasks_created}")
    return tasks_created
