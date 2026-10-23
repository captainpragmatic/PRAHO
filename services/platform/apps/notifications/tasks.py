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

from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone

from apps.notifications.delivery import (
    InvalidRetryMetadataError,
    budget_spent,
    claim_delivery,
    mark_exhausted,
    mark_permanent,
    record_failure,
    record_success,
    renew_claim,
    retry_delay,
    retry_index,
)
from apps.notifications.models import EmailLog, PendingDeliveryEvent
from apps.notifications.services import (
    PENDING_DELIVERY_EVENT_WINDOW,
    apply_pending_delivery_events,
    validate_email_log_subject,
)
from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)

# Task configuration
TASK_TIMEOUT = 300  # 5 minutes
_DEFAULT_MAX_RETRIES = 3  # Fallback — authoritative source is SettingsService
RETRY_DELAY_MINUTES = 5


def send_email_task(email_log_id: str) -> dict[str, Any]:
    """Send one stored email. The task carries only its id: the message is rebuilt from the row.

    Claim, rebuild (attachments made again from their sources and checked against the first send),
    re-check the claim immediately before the provider call, send, then record the outcome for this
    claim only. A message that can never be sent as written is a permanent failure.
    """
    from apps.notifications.attachments import (  # noqa: PLC0415  # Deferred: attachment sources import billing
        AttachmentRefusedError,
        regenerate_attachments,
    )
    from apps.notifications.services import compose_message, stored_message  # noqa: PLC0415  # Circular

    token = None
    try:
        email_log, refusal = claim_delivery(email_log_id)
        if refusal is not None:
            return refusal
        assert email_log is not None
        token = email_log.claim_token
        try:
            attachments = regenerate_attachments(email_log)
        except AttachmentRefusedError as refused:
            if not refused.permanent:
                raise
            return _refuse_permanently(email_log_id, token, str(refused))
        message = stored_message(email_log)
        msg = compose_message(message, attachments)

        # Immediately before the provider call: the claim is still ours (a worker that lost it sends nothing).
        if not renew_claim(email_log_id, token):
            return {"success": False, "error": "Claim lost before sending", "retry_scheduled": False}
        if msg.send(fail_silently=False) == 0:
            raise RuntimeError("Email provider accepted no recipients")

        message_id = None
        response: dict[str, Any] = {}
        if hasattr(msg, "anymail_status"):
            message_id = msg.anymail_status.message_id
            response = {
                "status": str(msg.anymail_status.status),
                "esp_response": getattr(msg.anymail_status, "esp_response", {}),
            }
        # Written only for the claim this worker holds; a reclaimed row is left to its new owner.
        record_success(email_log_id, token, provider_id=message_id or "", response=response)
        logger.info(f"Email sent successfully via async task: {message.subject[:50]}...")
        return {"success": True, "message_id": message_id, "email_log_id": email_log_id}

    except Exception as e:
        logger.exception(f"Async email sending failed: {e}")
        email_log, retry = record_failure(email_log_id, e, token)
        if email_log is None:
            return {"success": False, "error": str(e), "retry_scheduled": False}
        retry_scheduled = _schedule_email_retry(email_log_id, email_log.delivery_attempts) if retry else False
        return {
            "success": False,
            "error": str(e),
            "retry_scheduled": retry_scheduled,
            "retry_count": email_log.delivery_attempts,
            "max_retries_exceeded": bool((email_log.provider_response or {}).get("retry_exhausted")),
        }


def _refuse_permanently(email_log_id: str, token: Any, reason: str) -> dict[str, Any]:
    """A message that can never be sent as written: permanent, for the claim this worker holds."""
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is not None and row.status == "sending" and row.claim_token == token:
            mark_permanent(row, reason)
    logger.error(f"🔥 [Email] {email_log_id} refused permanently: {reason}")
    return {"success": False, "error": reason, "retry_scheduled": False}


def _schedule_email_retry(email_log_id: str, retry_count: int) -> bool:
    """Schedule the row's next attempt at its due time. The schedule carries only the id."""
    with transaction.atomic():
        email_log = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if email_log is None or validate_email_log_subject(email_log, email_log.subject) is not None:
            return False

        try:
            from django_q.models import Schedule  # noqa: PLC0415  # Deferred scheduler boundary.
            from django_q.tasks import schedule  # noqa: PLC0415  # Deferred: avoids circular import
        except ImportError:
            logger.error("Cannot schedule email retry - Django-Q2 not available")
            return False

        # The due time the failure write recorded (one backoff rule, delivery.retry_delay).
        due = email_log.next_attempt_at or timezone.now() + retry_delay(retry_count)
        if email_log.next_attempt_at is None:
            email_log.next_attempt_at = due
            email_log.save(update_fields=["next_attempt_at"])

        name = f"email-retry:{email_log_id}:{retry_count}"
        if Schedule.objects.filter(name=name).exists():
            return True
        schedule(
            "apps.notifications.tasks.send_email_task",
            email_log_id=email_log_id,
            next_run=due,
            schedule_type="O",
            repeats=1,
            name=name,
        )
        logger.info(f"Scheduled email retry {retry_count} for {email_log_id} at {due.isoformat()}")
        return True


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
    from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        EmailService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
            from apps.notifications.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                EmailCampaign,  # Deferred: django-q task  # Deferred: avoids circular import
            )

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


# A queued row is overdue (its task was lost) this long after it was due, or after it was created.
QUEUE_OVERDUE = timedelta(minutes=10)


def _batch() -> int:
    return min(500, max(1, SettingsService.get_integer_setting("notifications.email_batch_size", 50)))


def _enqueue_send(email_log: EmailLog, task_name: str) -> None:
    """Queue a stored email by id: the worker rebuilds it from the row."""
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: avoids circular import

    async_task("apps.notifications.tasks.send_email_task", email_log_id=str(email_log.id), task_name=task_name)


def process_email_queue() -> dict[str, Any]:
    """Re-enqueue `queued` emails whose task was lost: overdue rows only, each decided under its lock.

    A row re-enqueued here is given a fresh due time first, so the next pass does not enqueue it again
    unless that task is lost too. A row waiting on its scheduled retry is not overdue.
    """
    now = timezone.now()
    overdue = now - QUEUE_OVERDUE
    candidates = list(
        EmailLog.objects.filter(status="queued")
        .filter(Q(next_attempt_at__lte=overdue) | Q(next_attempt_at__isnull=True, sent_at__lt=overdue))
        .order_by("sent_at")
        .values_list("pk", flat=True)[: _batch()]
    )
    processed = failed = 0
    for pk in candidates:
        try:
            with transaction.atomic():
                email_log = EmailLog.objects.select_for_update().filter(pk=pk, status="queued").first()
                if email_log is None or (email_log.next_attempt_at or email_log.sent_at) > overdue:
                    continue  # Claimed, finished or rescheduled since the batch was read
                retry_index(email_log)  # Raises on corrupt retry metadata (marked permanent below)
                if budget_spent(email_log):
                    mark_exhausted(email_log)
                    failed += 1
                    continue
                if validate_email_log_subject(email_log, email_log.subject) is not None:
                    failed += 1
                    continue
                email_log.next_attempt_at = timezone.now()
                email_log.save(update_fields=["next_attempt_at"])
            _enqueue_send(email_log, f"requeue:{email_log.id}")
            processed += 1
        except InvalidRetryMetadataError as e:
            with transaction.atomic():
                locked = EmailLog.objects.select_for_update().filter(pk=pk, status="queued").first()
                if locked is not None:
                    mark_permanent(locked, str(e))
            failed += 1
        except Exception as e:
            logger.exception(f"Failed to requeue email {pk}: {e}")
            failed += 1

    callbacks = reconcile_pending_delivery_events()
    logger.info(
        f"Email queue processed: {processed} requeued, {failed} failed, "
        f"{callbacks['callbacks_applied']} buffered callbacks applied, {callbacks['callbacks_expired']} expired"
    )
    return {"processed": processed, "failed": failed}


def reconcile_pending_delivery_events() -> dict[str, int]:
    """Apply buffered callbacks whose message now carries their provider id; drop the unmatched past the window.

    A callback that missed the row can be buffered just after the send's success write committed, so the
    success write never sees it. This pass applies it under the row lock, one sweep interval later.
    """
    # Matched before the batch is cut, so unmatched callbacks never hold back one that can be applied.
    matched = list(
        EmailLog.objects.filter(provider_id__in=PendingDeliveryEvent.objects.values("provider_id"))
        .order_by("sent_at")
        .values_list("pk", flat=True)[: _batch()]
    )
    applied = 0
    for pk in matched:
        try:
            with transaction.atomic():
                email_log = EmailLog.objects.select_for_update().filter(pk=pk).first()
                if email_log is not None and email_log.provider_id:
                    apply_pending_delivery_events(email_log)
                    applied += 1
        except Exception as e:
            logger.exception(f"🔥 [Email] Failed to apply buffered callbacks for {pk}: {e}")
    # Only callbacks no message claims expire; a matched one waits for a later batch, however old.
    expired, _ = (
        PendingDeliveryEvent.objects.filter(created_at__lt=timezone.now() - PENDING_DELIVERY_EVENT_WINDOW)
        .exclude(provider_id__in=EmailLog.objects.exclude(provider_id="").values("provider_id"))
        .delete()
    )
    return {"callbacks_applied": applied, "callbacks_expired": expired}


def retry_failed_emails(max_age_hours: int = 24) -> dict[str, Any]:
    """Retry retryable `failed` emails from the last N hours, each decided and reopened under its lock.

    The row goes back to `queued` BEFORE its task is enqueued, so a task that finishes at once is never
    overwritten afterwards; an enqueue that fails leaves a due `queued` row for the queue sweep.
    """
    cutoff = timezone.now() - timedelta(hours=max_age_hours)
    # Negating a JSON comparison alone also drops rows with a missing key (SQL NULL).
    # Retain those legacy rows and exclude terminal failures before limiting the batch.
    candidates = list(
        EmailLog.objects.filter(status="failed", sent_at__gte=cutoff)
        .filter(Q(provider_response__permanent_failure__isnull=True) | ~Q(provider_response__permanent_failure=True))
        .filter(Q(provider_response__retry_exhausted__isnull=True) | ~Q(provider_response__retry_exhausted=True))
        .order_by("sent_at")
        .values_list("pk", flat=True)[: _batch()]
    )
    retried = skipped = 0
    for pk in candidates:
        try:
            with transaction.atomic():
                email_log = EmailLog.objects.select_for_update().filter(pk=pk, status="failed").first()
                response = email_log.provider_response if email_log is not None else None
                if email_log is None or not isinstance(response, dict) or response.get("permanent_failure") is True:
                    skipped += 1
                    continue
                if response.get("retry_exhausted") is True:
                    skipped += 1
                    continue
                if validate_email_log_subject(email_log, email_log.subject) is not None:
                    skipped += 1
                    continue
                retry_index(email_log)  # Raises on corrupt retry metadata (marked permanent below)
                if budget_spent(email_log):
                    mark_exhausted(email_log)
                    skipped += 1
                    continue
                email_log.status = "queued"
                email_log.next_attempt_at = timezone.now()
                email_log.save(update_fields=["status", "next_attempt_at"])
            _enqueue_send(email_log, f"retry_failed:{email_log.id}")
            retried += 1
        except InvalidRetryMetadataError as e:
            with transaction.atomic():
                locked = EmailLog.objects.select_for_update().filter(pk=pk, status="failed").first()
                if locked is not None:
                    mark_permanent(locked, str(e))
            skipped += 1
        except Exception as e:
            logger.exception(f"Failed to retry email {pk}: {e}")
            skipped += 1

    logger.info(f"Failed email retry: {retried} retried, {skipped} skipped")
    return {"retried": retried, "skipped": skipped}


def _protected_email_logs() -> Q:
    """Logs another model references with on_delete=PROTECT; deleting one raises and stops the batch."""
    protected = Q()
    for relation in EmailLog._meta.related_objects:
        if relation.on_delete is models.PROTECT:
            name = relation.field.name
            referenced = relation.related_model._base_manager.filter(**{f"{name}__isnull": False}).values(name)
            protected |= Q(pk__in=referenced)
    return protected


def cleanup_old_email_logs(retention_days: int = 90) -> dict[str, Any]:
    """
    Clean up old email log entries.

    Args:
        retention_days: Number of days to retain email logs

    Returns:
        Dict with cleanup results
    """
    cutoff = timezone.now() - timedelta(days=retention_days)
    # A log a record points at with PROTECT (a currency notice's proof of notice) stays.
    old = EmailLog.objects.filter(sent_at__lt=cutoff).exclude(_protected_email_logs())

    # Count before deletion
    total_to_delete = old.count()

    if total_to_delete == 0:
        return {"deleted": 0, "message": "No old email logs to clean up"}

    # Delete in batches to avoid locking issues
    batch_size = 1000
    deleted = 0

    while True:
        batch = old.values_list("id", flat=True)[:batch_size]
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
        # Relationship fields (safe lookups)
        "services__status",
        "services__service_type",
    }
)


def _apply_safe_customer_filter(queryset: object, custom_filter: dict[str, Any]) -> Any:
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
    # Fail closed: a filter that whitelisting emptied out must select nobody,
    # not fall through to an unfiltered broadcast.
    logger.error("🔥 [Notifications] Custom campaign filter had no valid fields; selecting no recipients")
    return queryset.none()


def send_scheduled_campaign(campaign_id: str) -> dict[str, Any]:
    """
    Send a scheduled email campaign.

    Args:
        campaign_id: UUID of the EmailCampaign

    Returns:
        Dict with campaign results
    """
    from apps.notifications.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        EmailCampaign,  # Deferred: django-q task  # Deferred: avoids circular import
    )
    from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        EmailService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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


def _get_campaign_recipients(campaign: object) -> list[tuple[str, dict[str, Any]]]:
    """Get recipients for a campaign based on audience filter."""
    from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        Customer,  # Circular: cross-app  # Deferred: avoids circular import
    )

    audience = campaign.audience
    recipients = []

    # Default manager already excludes soft-deleted customers. Apply status
    # constraints per audience so names and query semantics cannot contradict.
    customers = Customer.objects.all()

    if audience == "all_customers":
        pass  # No additional filter
    elif audience == "active_customers":
        customers = customers.filter(status=Customer.CustomerStatus.ACTIVE)
    elif audience == "inactive_customers":
        customers = customers.filter(status=Customer.CustomerStatus.INACTIVE)
    elif audience == "overdue_payments":
        # Customers with overdue invoices
        from apps.billing.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Invoice,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # document_kind filter: a credit note can reach `overdue` like any other
        # issued document, and would then recruit its customer into a chase list.
        overdue_customer_ids = (
            Invoice.objects.filter(status="overdue", document_kind="invoice")
            .values_list("customer_id", flat=True)
            .distinct()
        )
        customers = customers.filter(id__in=overdue_customer_ids)
    elif audience == "trial_expiring":
        # The model exposes this future audience, but no expiry window has been
        # defined. Fail closed rather than silently broadcasting to all customers.
        logger.warning("Campaign audience 'trial_expiring' is not implemented; selecting no recipients")
        customers = customers.none()
    elif audience == "custom_filter":
        # Apply custom filter from audience_filter JSON with WHITELIST validation.
        # An empty filter fails closed — custom_filter with no filter is a
        # misconfiguration, never a broadcast to every customer.
        custom_filter = campaign.audience_filter or {}
        if custom_filter:
            customers = _apply_safe_customer_filter(customers, custom_filter)
        else:
            logger.error("🔥 [Notifications] Campaign audience 'custom_filter' has no filter; selecting no recipients")
            customers = customers.none()
    else:
        logger.error("Unknown campaign audience %r; selecting no recipients", audience)
        customers = customers.none()

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
