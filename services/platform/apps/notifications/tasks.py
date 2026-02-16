"""
Async Email Tasks for PRAHO Platform
Background task processing for email sending via Django-Q2.

Tasks:
- send_email_task: Send a single email asynchronously
- send_bulk_emails_task: Send emails in batches
- process_email_queue: Process pending email queue
- retry_failed_emails: Retry emails that failed to send
- cleanup_old_email_logs: Clean up old email log entries
"""

import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)

# Task configuration
TASK_TIMEOUT = 300  # 5 minutes
_DEFAULT_MAX_RETRIES = 3  # Fallback — authoritative source is SettingsService
RETRY_DELAY_MINUTES = 5


def send_email_task(  # noqa: PLR0913
    email_log_id: str,
    to: list[str],
    subject: str,
    body_text: str,
    body_html: str | None = None,
    from_email: str | None = None,
    reply_to: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    tags: dict[str, str] | None = None,
    track_opens: bool = True,
    track_clicks: bool = True,
    retry_count: int = 0,
) -> dict[str, Any]:
    """
    Send an email asynchronously.

    This task is queued by EmailService._send_async() and executed by Django-Q2 workers.

    Args:
        email_log_id: UUID of the EmailLog entry
        to: List of recipient emails
        subject: Email subject
        body_text: Plain text body
        body_html: HTML body (optional)
        from_email: Sender email
        reply_to: Reply-to address
        cc: CC recipients
        bcc: BCC recipients
        tags: ESP metadata tags
        track_opens: Enable open tracking
        track_clicks: Enable click tracking
        retry_count: Current retry attempt number

    Returns:
        Dict with success status and message details
    """
    from_email = from_email or settings.DEFAULT_FROM_EMAIL

    try:
        # Get the email log entry
        try:
            email_log = EmailLog.objects.get(id=email_log_id)
        except EmailLog.DoesNotExist:
            logger.error(f"EmailLog not found: {email_log_id}")
            return {"success": False, "error": "EmailLog not found"}

        # Update status to sending
        email_log.status = "sending"
        email_log.save(update_fields=["status"])

        # Build the email message
        if body_html:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=body_text,
                from_email=from_email,
                to=to,
                cc=cc,
                bcc=bcc,
                reply_to=[reply_to] if reply_to else None,
            )
            msg.attach_alternative(body_html, "text/html")
        else:
            msg = EmailMessage(
                subject=subject,
                body=body_text,
                from_email=from_email,
                to=to,
                cc=cc,
                bcc=bcc,
                reply_to=[reply_to] if reply_to else None,
            )

        # Add ESP-specific metadata for Anymail
        # These attributes are supported when using Anymail backends
        try:
            if tags:
                msg.tags = list(tags.keys())
                msg.metadata = tags
            msg.track_opens = track_opens
            msg.track_clicks = track_clicks
        except AttributeError:
            # Standard Django EmailMessage doesn't support these
            pass

        # Send the email
        msg.send(fail_silently=False)

        # Update log with success
        email_log.status = "sent"
        email_log.sent_at = timezone.now()

        # Try to get message ID from anymail
        message_id = None
        if hasattr(msg, "anymail_status"):
            message_id = msg.anymail_status.message_id
            email_log.provider_id = message_id or ""
            email_log.provider_response = {
                "status": str(msg.anymail_status.status),
                "esp_response": getattr(msg.anymail_status, "esp_response", {}),
            }

        email_log.save()

        logger.info(f"Email sent successfully via async task: {subject[:50]}... to {to[0][:3]}***")

        return {
            "success": True,
            "message_id": message_id,
            "email_log_id": email_log_id,
        }

    except Exception as e:
        logger.exception(f"Async email sending failed: {e}")

        # Update log with failure
        try:
            email_log = EmailLog.objects.get(id=email_log_id)

            # Check if we should retry
            max_retries = SettingsService.get_integer_setting("notifications.email_max_retries", _DEFAULT_MAX_RETRIES)
            if retry_count < max_retries:
                # Schedule retry
                email_log.status = "queued"
                email_log.provider_response = {
                    **(email_log.provider_response or {}),
                    f"retry_{retry_count}_error": str(e),
                }
                email_log.save()

                # Queue retry task
                _schedule_email_retry(
                    email_log_id=email_log_id,
                    to=to,
                    subject=subject,
                    body_text=body_text,
                    body_html=body_html,
                    from_email=from_email,
                    reply_to=reply_to,
                    cc=cc,
                    bcc=bcc,
                    tags=tags,
                    track_opens=track_opens,
                    track_clicks=track_clicks,
                    retry_count=retry_count + 1,
                )

                return {
                    "success": False,
                    "error": str(e),
                    "retry_scheduled": True,
                    "retry_count": retry_count + 1,
                }

            else:
                # Max retries exceeded
                email_log.status = "failed"
                email_log.provider_response = {
                    **(email_log.provider_response or {}),
                    "final_error": str(e),
                    "retry_count": retry_count,
                }
                email_log.save()

                return {
                    "success": False,
                    "error": str(e),
                    "retry_scheduled": False,
                    "max_retries_exceeded": True,
                }

        except EmailLog.DoesNotExist:
            pass

        return {"success": False, "error": str(e)}


def _schedule_email_retry(  # noqa: PLR0913
    email_log_id: str,
    to: list[str],
    subject: str,
    body_text: str,
    body_html: str | None,
    from_email: str | None,
    reply_to: str | None,
    cc: list[str] | None,
    bcc: list[str] | None,
    tags: dict[str, str] | None,
    track_opens: bool,
    track_clicks: bool,
    retry_count: int,
) -> None:
    """Schedule an email retry with exponential backoff."""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        retry_config = getattr(settings, "EMAIL_RETRY", {})
        base_delay = retry_config.get("RETRY_DELAY_SECONDS", 60)
        use_exponential = retry_config.get("EXPONENTIAL_BACKOFF", True)

        # Calculate delay with exponential backoff
        delay = base_delay * (2**retry_count) if use_exponential else base_delay

        async_task(
            "apps.notifications.tasks.send_email_task",
            email_log_id=email_log_id,
            to=to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            from_email=from_email,
            reply_to=reply_to,
            cc=cc,
            bcc=bcc,
            tags=tags,
            track_opens=track_opens,
            track_clicks=track_clicks,
            retry_count=retry_count,
            schedule=timedelta(seconds=delay),
            task_name=f"email_retry_{retry_count}:{email_log_id[:8]}",
        )

        logger.info(f"Scheduled email retry {retry_count} for {email_log_id} in {delay}s")

    except ImportError:
        logger.error("Cannot schedule email retry - Django-Q2 not available")


def send_bulk_emails_task(
    template_key: str,
    recipients: list[dict[str, Any]],
    locale: str = "en",
    campaign_id: str | None = None,
) -> dict[str, Any]:
    """
    Send bulk emails using a template.

    Args:
        template_key: Email template key
        recipients: List of dicts with 'email' and 'context' keys
        locale: Template locale
        campaign_id: Optional campaign ID for tracking

    Returns:
        Dict with sent_count, failed_count, and errors
    """
    from apps.notifications.services import EmailService  # noqa: PLC0415

    sent_count = 0
    failed_count = 0
    errors: list[dict[str, str]] = []

    for recipient_data in recipients:
        email = recipient_data.get("email")
        context = recipient_data.get("context", {})

        if not email:
            failed_count += 1
            errors.append({"email": "unknown", "error": "Missing email address"})
            continue

        try:
            result = EmailService.send_template_email(
                template_key=template_key,
                recipient=email,
                context=context,
                locale=locale,
                async_send=False,  # Already in async task
            )

            if result.success:
                sent_count += 1
            else:
                failed_count += 1
                errors.append({"email": email, "error": result.error or "Unknown error"})

        except Exception as e:
            failed_count += 1
            errors.append({"email": email, "error": str(e)})

    # Update campaign if provided
    if campaign_id:
        try:
            from apps.notifications.models import EmailCampaign  # noqa: PLC0415

            campaign = EmailCampaign.objects.get(id=campaign_id)
            campaign.emails_sent = sent_count
            campaign.emails_failed = failed_count
            campaign.status = "sent" if failed_count == 0 else "failed"
            campaign.completed_at = timezone.now()
            campaign.save()
        except EmailCampaign.DoesNotExist:
            logger.warning(f"Campaign not found: {campaign_id}")

    logger.info(f"Bulk email task completed: {sent_count} sent, {failed_count} failed")

    return {
        "sent_count": sent_count,
        "failed_count": failed_count,
        "errors": errors[:20],  # Limit error details
    }


def process_email_queue() -> dict[str, Any]:
    """
    Process pending emails in the queue.

    This task can be scheduled to run periodically to process
    any emails that are stuck in 'queued' status.

    Returns:
        Dict with processed count and results
    """
    # Find emails that have been queued for too long
    # Note: sent_at is auto_now_add, so it represents creation/queue time
    cutoff = timezone.now() - timedelta(minutes=10)
    stuck_emails = EmailLog.objects.filter(
        status="queued",
        sent_at__lt=cutoff,  # sent_at = creation time for queued emails
    ).order_by("sent_at")[: min(500, max(1, SettingsService.get_integer_setting("notifications.email_batch_size", 50)))]

    processed = 0
    failed = 0

    for email_log in stuck_emails:
        try:
            # Re-queue the email
            from django_q.tasks import async_task  # noqa: PLC0415

            async_task(
                "apps.notifications.tasks.send_email_task",
                email_log_id=str(email_log.id),
                to=[email_log.to_addr],
                subject=email_log.subject,
                body_text=email_log.get_decrypted_body_text(),
                body_html=email_log.get_decrypted_body_html(),
                from_email=email_log.from_addr,
                reply_to=email_log.reply_to,
                retry_count=0,
                task_name=f"requeue:{email_log.id}",
            )
            processed += 1

        except Exception as e:
            logger.exception(f"Failed to requeue email {email_log.id}: {e}")
            failed += 1

    logger.info(f"Email queue processed: {processed} requeued, {failed} failed")

    return {
        "processed": processed,
        "failed": failed,
    }


def retry_failed_emails(max_age_hours: int = 24) -> dict[str, Any]:
    """
    Retry emails that failed to send within the last N hours.

    Args:
        max_age_hours: Only retry emails failed within this time window

    Returns:
        Dict with retry results
    """
    cutoff = timezone.now() - timedelta(hours=max_age_hours)

    failed_emails = EmailLog.objects.filter(
        status="failed",
        sent_at__gte=cutoff,
    ).order_by("sent_at")[: min(500, max(1, SettingsService.get_integer_setting("notifications.email_batch_size", 50)))]

    retried = 0
    skipped = 0

    for email_log in failed_emails:
        # Check if we've already retried too many times
        provider_response = email_log.provider_response or {}
        retry_count = provider_response.get("retry_count", 0)

        max_retries = SettingsService.get_integer_setting("notifications.email_max_retries", _DEFAULT_MAX_RETRIES)
        if retry_count >= max_retries:
            skipped += 1
            continue

        try:
            from django_q.tasks import async_task  # noqa: PLC0415

            async_task(
                "apps.notifications.tasks.send_email_task",
                email_log_id=str(email_log.id),
                to=[email_log.to_addr],
                subject=email_log.subject,
                body_text=email_log.get_decrypted_body_text(),
                body_html=email_log.get_decrypted_body_html(),
                from_email=email_log.from_addr,
                reply_to=email_log.reply_to,
                retry_count=retry_count + 1,
                task_name=f"retry_failed:{email_log.id}",
            )

            # Update status
            email_log.status = "queued"
            email_log.save(update_fields=["status"])
            retried += 1

        except Exception as e:
            logger.exception(f"Failed to retry email {email_log.id}: {e}")
            skipped += 1

    logger.info(f"Failed email retry: {retried} retried, {skipped} skipped")

    return {
        "retried": retried,
        "skipped": skipped,
    }


def cleanup_old_email_logs(retention_days: int = 90) -> dict[str, Any]:
    """
    Clean up old email log entries.

    Args:
        retention_days: Number of days to retain email logs

    Returns:
        Dict with cleanup results
    """
    cutoff = timezone.now() - timedelta(days=retention_days)

    # Count before deletion
    total_to_delete = EmailLog.objects.filter(sent_at__lt=cutoff).count()

    if total_to_delete == 0:
        return {"deleted": 0, "message": "No old email logs to clean up"}

    # Delete in batches to avoid locking issues
    batch_size = 1000
    deleted = 0

    while True:
        batch = EmailLog.objects.filter(sent_at__lt=cutoff).values_list("id", flat=True)[:batch_size]
        batch_ids = list(batch)

        if not batch_ids:
            break

        EmailLog.objects.filter(id__in=batch_ids).delete()
        deleted += len(batch_ids)

        logger.info(f"Deleted {len(batch_ids)} old email logs (total: {deleted})")

    logger.info(f"Email log cleanup completed: {deleted} entries deleted")

    return {
        "deleted": deleted,
        "retention_days": retention_days,
    }


# Whitelist of allowed filter fields for campaign audience
# This prevents SQL injection via audience_filter JSON
ALLOWED_CAMPAIGN_FILTER_FIELDS = frozenset(
    {
        # Basic customer fields
        "status",
        "customer_type",
        "created_at",
        "created_at__gte",
        "created_at__lte",
        "created_at__gt",
        "created_at__lt",
        # Location fields
        "country",
        "city",
        # Business fields
        "marketing_consent",
        "newsletter_consent",
        # Relationship fields (safe lookups)
        "services__status",
        "services__service_type",
    }
)


def _apply_safe_customer_filter(queryset, custom_filter: dict[str, Any]):
    """
    Apply a custom filter to customers queryset with whitelist validation.

    Only allows pre-approved filter fields to prevent SQL injection
    via malicious audience_filter JSON.
    """
    safe_filter = {}

    for key, value in custom_filter.items():
        if key in ALLOWED_CAMPAIGN_FILTER_FIELDS:
            # Additional value validation
            if isinstance(value, (str, int, bool, list)):
                safe_filter[key] = value
            else:
                logger.warning(f"Rejected filter value type for {key}: {type(value)}")
        else:
            logger.warning(f"Rejected unsafe campaign filter field: {key}")

    if safe_filter:
        return queryset.filter(**safe_filter)
    return queryset


def send_scheduled_campaign(campaign_id: str) -> dict[str, Any]:
    """
    Send a scheduled email campaign.

    Args:
        campaign_id: UUID of the EmailCampaign

    Returns:
        Dict with campaign results
    """
    from apps.notifications.models import EmailCampaign  # noqa: PLC0415
    from apps.notifications.services import EmailService  # noqa: PLC0415

    try:
        campaign = EmailCampaign.objects.select_related("template").get(id=campaign_id)
    except EmailCampaign.DoesNotExist:
        logger.error(f"Campaign not found: {campaign_id}")
        return {"success": False, "error": "Campaign not found"}

    if campaign.status != "scheduled":
        logger.warning(f"Campaign {campaign_id} is not scheduled (status: {campaign.status})")
        return {"success": False, "error": f"Campaign is not scheduled (status: {campaign.status})"}

    # Get recipients based on audience
    recipients = _get_campaign_recipients(campaign)

    if not recipients:
        campaign.status = "failed"
        campaign.completed_at = timezone.now()
        campaign.save()
        return {"success": False, "error": "No recipients for campaign"}

    # Send the campaign
    result = EmailService.send_campaign(campaign, recipients)

    return {
        "success": True,
        "campaign_id": campaign_id,
        **result,
    }


def _get_campaign_recipients(campaign) -> list[tuple[str, dict[str, Any]]]:
    """Get recipients for a campaign based on audience filter."""
    from apps.customers.models import Customer  # noqa: PLC0415

    audience = campaign.audience
    recipients = []

    # Base queryset
    customers = Customer.objects.filter(status="active")

    if audience == "all_customers":
        pass  # No additional filter
    elif audience == "active_customers":
        customers = customers.filter(status="active")
    elif audience == "inactive_customers":
        customers = customers.filter(status="inactive")
    elif audience == "overdue_payments":
        # Customers with overdue invoices
        from apps.billing.models import Invoice  # noqa: PLC0415

        overdue_customer_ids = Invoice.objects.filter(status="overdue").values_list("customer_id", flat=True).distinct()
        customers = customers.filter(id__in=overdue_customer_ids)
    elif audience == "custom_filter":
        # Apply custom filter from audience_filter JSON with WHITELIST validation
        custom_filter = campaign.audience_filter or {}
        if custom_filter:
            customers = _apply_safe_customer_filter(customers, custom_filter)

    # Check consent for non-transactional campaigns
    if not campaign.is_transactional and campaign.requires_consent:
        customers = customers.filter(marketing_consent=True)

    # Build recipient list with personalized context
    for customer in customers[: campaign.total_recipients or 10000]:
        context = {
            "customer_name": customer.get_display_name(),
            "customer_email": customer.primary_email,
        }
        recipients.append((customer.primary_email, context))

    return recipients
