"""
Email Notification Signals for PRAHO Platform
Handle Anymail tracking signals and email lifecycle events.

Signal Handlers:
- Anymail post-send signals
- Anymail tracking signals (delivered, bounced, complained, opened, clicked)
- Email template change signals
"""

import logging
from typing import Any

from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.common.validators import log_security_event

logger = logging.getLogger(__name__)


# ===============================================================================
# ANYMAIL SIGNAL HANDLERS
# ===============================================================================


def setup_anymail_signals() -> None:
    """
    Set up Anymail signal handlers.

    This function should be called from apps.py ready() method.
    """
    try:
        from anymail.signals import (
            post_send,
            tracking,
        )

        # Connect signal handlers
        post_send.connect(handle_anymail_post_send)
        tracking.connect(handle_anymail_tracking)

        logger.info("Anymail signal handlers connected")

    except ImportError:
        logger.info("Anymail not installed - signal handlers not connected")


def handle_anymail_post_send(sender: Any, message: Any, status: Any, esp_name: str, **kwargs: Any) -> None:
    """
    Handle Anymail post-send signal.

    Called after an email is sent (or attempted) through Anymail.
    """
    try:
        message_id = status.message_id if status else None
        send_status = status.status if status else "unknown"

        # Log successful sends
        if send_status in ("sent", "queued"):
            logger.info(f"Email sent via {esp_name}: {message_id} - status: {send_status}")
        else:
            logger.warning(f"Email send issue via {esp_name}: {message_id} - status: {send_status}")

        # Log to audit if available
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            log_security_event(
                "email_sent",
                {
                    "esp": esp_name,
                    "message_id": message_id,
                    "status": send_status,
                    "recipients_count": len(message.to) if message else 0,
                },
            )

    except Exception as e:
        logger.exception(f"Error in post_send handler: {e}")


def handle_anymail_tracking(sender: Any, event: Any, esp_name: str, **kwargs: Any) -> None:
    """
    Handle Anymail tracking signal.

    Called when a tracking event is received (delivery, bounce, complaint, open, click).
    """
    from apps.notifications.services import EmailService

    try:
        event_type = event.event_type
        message_id = event.message_id
        recipient = event.recipient

        # Map Anymail event types to our internal types
        event_mapping = {
            "delivered": "delivered",
            "bounced": "bounced",
            "deferred": "soft_bounced",
            "complained": "complained",
            "opened": "opened",
            "clicked": "clicked",
            "unsubscribed": "unsubscribed",
        }

        internal_event = event_mapping.get(event_type)

        if internal_event and recipient:
            EmailService.handle_delivery_event(
                event_type=internal_event,
                message_id=message_id or "",
                recipient=recipient,
                timestamp=str(event.timestamp) if event.timestamp else None,
                metadata={
                    "esp": esp_name,
                    "event_type": event_type,
                    "reject_reason": getattr(event, "reject_reason", None),
                    "description": getattr(event, "description", None),
                    "click_url": getattr(event, "click_url", None),
                },
            )

            logger.info(f"Processed {event_type} tracking event for {recipient[:3]}*** via {esp_name}")

    except Exception as e:
        logger.exception(f"Error in tracking handler: {e}")


# ===============================================================================
# EMAIL TEMPLATE SIGNALS
# ===============================================================================


def clear_template_cache(template_key: str, locale: str) -> None:
    """Clear cached email template after update."""
    from django.core.cache import cache

    cache_key = f"email_template:{template_key}:{locale}"
    cache.delete(cache_key)
    logger.info(f"Cleared email template cache: {cache_key}")


@receiver(post_save, sender="notifications.EmailTemplate")
def handle_template_save(sender: Any, instance: Any, created: bool, **kwargs: Any) -> None:
    """Handle email template save - clear cache."""
    clear_template_cache(instance.key, instance.locale)

    if not created and not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        log_security_event(
            "email_template_updated",
            {
                "template_key": instance.key,
                "locale": instance.locale,
                "version": instance.version,
            },
        )


@receiver(post_delete, sender="notifications.EmailTemplate")
def handle_template_delete(sender: Any, instance: Any, **kwargs: Any) -> None:
    """Handle email template delete - clear cache."""
    clear_template_cache(instance.key, instance.locale)

    if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        log_security_event(
            "email_template_deleted",
            {
                "template_key": instance.key,
                "locale": instance.locale,
            },
        )


# ===============================================================================
# EMAIL LOG SIGNALS
# ===============================================================================


@receiver(post_save, sender="notifications.EmailLog")
def handle_email_log_status_change(sender: Any, instance: Any, created: bool, **kwargs: Any) -> None:
    """Handle email log status changes for monitoring."""
    if created:
        return  # Skip new entries

    # Track status changes for monitoring
    status = instance.status
    if status in ("bounced", "complained", "failed"):
        log_security_event(
            f"email_{status}",
            {
                "email_log_id": str(instance.id),
                "to_addr_hash": hash(instance.to_addr) % 10000,  # Partial hash for privacy
                "template_key": instance.template_key,
                "provider": instance.provider,
            },
        )
