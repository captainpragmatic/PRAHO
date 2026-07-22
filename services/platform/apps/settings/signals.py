"""
System Settings signals for PRAHO Platform
Handles setting change notifications and cache invalidation.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.audit.services import AuditService

from .models import SystemSetting
from .services import SettingsService

# Import NotificationService at top level to avoid PLC0415
try:
    from apps.notifications.services import NotificationService as _NotificationService

    NotificationService: type | None = _NotificationService
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
        # Do not invalidate before the database value is visible to other
        # transactions; an early reader could otherwise repopulate the old value.
        transaction.on_commit(lambda key=instance.key: SettingsService._clear_setting_cache(key))

        # Service writes attach a transient context (actor, reason, change set,
        # old/new display values); direct ORM writes fall back to an unattributed event.
        context = instance._audit_context
        instance._audit_context = None

        action = "create" if created else "update"
        user = None
        metadata = {
            "setting_key": instance.key,
            "category": instance.category,
            "is_sensitive": instance.is_sensitive,
            "is_required": instance.is_required,
            "setting_value": instance.get_display_value() if not instance.is_sensitive else "(hidden)",
            "data_type": instance.data_type,
        }
        old_values: dict[str, Any] | None = None
        new_values: dict[str, Any] | None = None
        if context is not None:
            if context.get("user_id") is not None:
                from apps.users.models import User  # noqa: PLC0415  # Function-level cross-app import (ADR-0007)

                user = User.objects.filter(pk=context["user_id"]).first()
            metadata["reason"] = context.get("reason")
            metadata["change_set_id"] = context.get("change_set_id")
            old_values = {"value": context.get("old_value")}
            new_values = {"value": context.get("new_value")}

        # Savepoint isolation (customers/signals.py pattern): a DB-level audit failure
        # must not poison the caller's transaction — catching the Python exception alone
        # does not recover the connection.
        with transaction.atomic():
            AuditService.log_simple_event(
                event_type=action,
                user=user,
                content_object=instance,
                description=f"System setting {action}: {instance.key}",
                old_values=old_values,
                new_values=new_values,
                metadata=metadata,
            )

        transaction.on_commit(
            lambda: logger.info(
                "✅ [Settings Signal] Setting %s %s: %s",
                instance.key,
                action,
                instance.get_display_value() if not instance.is_sensitive else "(hidden)",
            )
        )

        # Notify only after the surrounding transaction commits — a later failure
        # in a multi-key change set must not alert on a rolled-back change.
        if _is_critical_setting(instance.key):
            transaction.on_commit(lambda: _send_critical_setting_notification(instance, action))

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
        transaction.on_commit(lambda key=instance.key: SettingsService._clear_setting_cache(key))

        # Log audit event
        with transaction.atomic():
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

    Critical settings significantly affect system behavior and trigger
    admin notifications when changed. The catalog owns the flag.
    """
    from .catalog import CRITICAL_KEYS  # noqa: PLC0415  # Deferred: keeps signal import light

    return key in CRITICAL_KEYS


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
        NotificationService.send_admin_alert(
            subject=subject,
            message=message,
            alert_type="critical",
            metadata={
                "setting_key": setting.key,
                "action": action,
                "category": setting.category,
            },
        )

        logger.info("📧 [Settings Signal] Critical setting notification sent for %s %s", setting.key, action)

    except Exception as e:
        logger.error("🔥 [Settings Signal] Error sending notification for %s: %s", setting.key, str(e))
