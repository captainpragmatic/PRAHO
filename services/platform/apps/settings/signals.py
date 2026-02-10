"""
System Settings signals for PRAHO Platform
Handles setting change notifications and cache invalidation.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.audit.services import AuditService

from .models import SystemSetting
from .services import SettingsService

# Import NotificationService at top level to avoid PLC0415
try:
    from apps.notifications.services import NotificationService  # type: ignore
except ImportError:
    NotificationService = None

logger = logging.getLogger(__name__)


@receiver(post_save, sender=SystemSetting)
def handle_setting_saved(sender: Any, instance: SystemSetting, created: bool, **kwargs: Any) -> None:
    """
    🔄 Handle setting save events

    Actions:
    - Clear cache for the setting
    - Log audit event
    - Send notifications if needed
    """
    try:
        # Clear cache for the updated setting
        SettingsService._clear_setting_cache(instance.key)

        # Log audit event
        action = "create" if created else "update"
        AuditService.log_simple_event(
            event_type=action,
            user=None,
            content_object=instance,
            description=f"System setting {action}: {instance.key}",
            metadata={
                "setting_key": instance.key,
                "category": instance.category,
                "is_sensitive": instance.is_sensitive,
                "is_required": instance.is_required,
                "setting_value": instance.get_display_value() if not instance.is_sensitive else "(hidden)",
                "data_type": instance.data_type,
            },
        )

        logger.info(
            "✅ [Settings Signal] Setting %s %s: %s",
            instance.key,
            action,
            instance.get_display_value() if not instance.is_sensitive else "(hidden)",
        )

        # Send notifications for critical settings changes
        if _is_critical_setting(instance.key):
            _send_critical_setting_notification(instance, action)

    except Exception as e:
        logger.error("🔥 [Settings Signal] Error handling save for setting %s: %s", instance.key, str(e))


@receiver(post_delete, sender=SystemSetting)
def handle_setting_deleted(sender: Any, instance: SystemSetting, **kwargs: Any) -> None:
    """
    🗑️ Handle setting deletion events

    Actions:
    - Clear cache for the setting
    - Log audit event
    """
    try:
        # Clear cache for the deleted setting
        SettingsService._clear_setting_cache(instance.key)

        # Log audit event
        AuditService.log_simple_event(
            event_type="delete",
            user=None,
            content_object=instance,
            description=f"System setting deleted: {instance.key}",
            metadata={
                "setting_key": instance.key,
                "category": instance.category,
                "data_type": instance.data_type,
            },
        )

        logger.warning("⚠️ [Settings Signal] Setting %s deleted", instance.key)

        # Send notifications for critical settings deletion
        if _is_critical_setting(instance.key):
            _send_critical_setting_notification(instance, "deleted")

    except Exception as e:
        logger.error("🔥 [Settings Signal] Error handling deletion for setting %s: %s", instance.key, str(e))


def _is_critical_setting(key: str) -> bool:
    """
    🚨 Check if a setting is considered critical

    Critical settings are those that significantly affect system behavior
    and should trigger notifications when changed.
    """
    critical_settings = {
        "system.maintenance_mode",
        "security.require_2fa_for_admin",
        "users.mfa_required_for_staff",
        "billing.payment_grace_period_days",
        "domains.registration_enabled",
        "provisioning.auto_setup_enabled",
        "notifications.email_enabled",
    }

    return key in critical_settings


def _send_critical_setting_notification(setting: SystemSetting, action: str) -> None:
    """
    📧 Send notification for critical setting changes

    In a production environment, this would send notifications to:
    - System administrators
    - Audit team
    - Relevant stakeholders
    """
    try:
        # Check if NotificationService is available
        if NotificationService is None:
            logger.debug("⚠️ [Settings Signal] Notifications service not available for %s", setting.key)
            return

        # Prepare notification content
        subject = f"🚨 Critical Setting {action.title()}: {setting.key}"

        if action == "deleted":
            message = f"Critical system setting '{setting.key}' has been deleted."
        else:
            value_display = setting.get_display_value() if not setting.is_sensitive else "(hidden)"
            message = (
                f"Critical system setting '{setting.key}' has been {action}.\n"
                f"New value: {value_display}\n"
                f"Category: {setting.category_display}\n"
                f"Description: {setting.description}"
            )

        # Send to system administrators
        NotificationService.send_admin_notification(
            subject=subject,
            message=message,
            category="system_settings",
            priority="high",
            metadata={
                "setting_key": setting.key,
                "action": action,
                "category": setting.category,
            },
        )

        logger.info("📧 [Settings Signal] Critical setting notification sent for %s %s", setting.key, action)

    except Exception as e:
        logger.error("🔥 [Settings Signal] Error sending notification for %s: %s", setting.key, str(e))
