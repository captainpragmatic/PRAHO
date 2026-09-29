"""Durable delivery of the saved voucher; jobs and logs contain identifiers only."""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal
from functools import partial
from typing import Any
from uuid import UUID, uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.debug import sensitive_variables

from .models import GiftCard, GiftCardDelivery, GiftCardPurchase

DELIVERY_LEASE = timedelta(minutes=10)
RESEND_COOLDOWN = timedelta(minutes=5)
RETRY_DELAY = timedelta(minutes=10)
MAX_DELIVERY_ATTEMPTS = 6
logger = logging.getLogger(__name__)


def _enqueue(delivery_id: UUID) -> None:
    from django_q.tasks import async_task  # noqa: PLC0415  # ADR-0007

    async_task("apps.promotions.gift_delivery.deliver_gift_card", str(delivery_id))


@transaction.atomic
def queue_purchase_delivery(purchase_id: UUID | str, *, resend: bool = False) -> list[GiftCardDelivery]:
    purchase = GiftCardPurchase.objects.select_for_update().get(pk=purchase_id)
    card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
    purchase.gift_card = card
    if not purchase.funded_at:
        raise ValidationError(_("Gift-card delivery requires verified payment."))
    if resend and not purchase.can_reveal_code:
        raise ValidationError(_("This gift card is unavailable for delivery."))
    recipients = [("voucher", card.recipient_email if purchase.is_gift else purchase.buyer_email)]
    if purchase.is_gift:
        recipients.append(("receipt", purchase.buyer_email))
    rows = []
    now = timezone.now()
    for purpose, target in recipients:
        row, created = GiftCardDelivery.objects.get_or_create(
            purchase=purchase,
            purpose=purpose,
            defaults={"target_email": target, "next_attempt_at": now},
        )
        dispatch = created
        if resend and not created and row.status in {"sent", "failed"}:
            latest = max((value for value in (row.sent_at, row.last_attempt_at) if value), default=None)
            if latest is not None and now - latest < RESEND_COOLDOWN:
                raise ValidationError(_("Please wait a few minutes before sending this gift card again."))
            row.status = "pending"  # fsm-bypass: Delivery state CharField
            row.next_attempt_at = now
            row.error_code = ""
            # Bound each requested delivery to six automatic attempts. The audit
            # trail retains prior attempts; a deliberate resend starts a new cycle.
            row.attempt_count = 0
            row.save(update_fields=["status", "next_attempt_at", "error_code", "attempt_count"])
            dispatch = True
        if dispatch:
            transaction.on_commit(partial(_enqueue, row.pk), robust=True)
        rows.append(row)
    return rows


def purchase_delivery_summary(purchase: GiftCardPurchase) -> dict[str, Any]:
    deliveries = sorted(purchase.deliveries.all(), key=lambda row: row.purpose)
    rows = [
        {
            "purpose": row.purpose,
            "status": row.status,
            "attempt_count": row.attempt_count,
            "sent_at": row.sent_at,
            "last_attempt_at": row.last_attempt_at,
            "next_attempt_at": row.next_attempt_at,
            "error_code": row.error_code,
        }
        for row in deliveries
    ]
    statuses = {row["status"] for row in rows}
    if not rows:
        status = "pending" if purchase.funded_at else "awaiting_payment"
    elif statuses == {"sent"}:
        status = "sent"
    elif "failed" in statuses:
        status = "failed"
    else:
        status = "pending"
    latest = max((value for row in deliveries for value in (row.sent_at, row.last_attempt_at) if value), default=None)
    next_resend_at = latest + RESEND_COOLDOWN if latest else None
    queued = bool(statuses.intersection({"pending", "sending"}))
    can_resend = (
        purchase.can_reveal_code and not queued and (next_resend_at is None or next_resend_at <= timezone.now())
    )
    return {
        "status": status,
        "deliveries": rows,
        "can_resend": can_resend,
        "resend_available_at": next_resend_at,
        "is_queued": queued,
    }


@sensitive_variables("delivery", "purchase", "card", "body")
def _message(delivery: GiftCardDelivery, purchase: GiftCardPurchase) -> EmailMessage:
    card = purchase.gift_card
    value = f"{Decimal(card.initial_value_cents) / 100:.2f} {card.currency_id}"
    if delivery.purpose == "voucher":
        body = _("Your gift card is ready.") + f"\n\n{value}\n{card.code}\n"
        if purchase.is_gift and card.personal_message:
            body += f"\n{card.personal_message}\n"
        if not purchase.is_gift:
            body += f"\n{_('Funding receipt')}: {purchase.receipt_number}\n"
        subject = _("Your gift card")
    else:
        subject = _("Gift-card purchase receipt")
        body = f"{_('Funding receipt')}: {purchase.receipt_number}\n{value}\n"
        body += _("Your recipient receives the gift card in a separate email.")
    return EmailMessage(
        subject=str(subject),
        body=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[delivery.target_email],
        headers={"Message-ID": f"<gift-delivery-{delivery.pk}-{delivery.attempt_count}@praho.local>"},
    )


@sensitive_variables("delivery", "purchase")
def _send(delivery: GiftCardDelivery, purchase: GiftCardPurchase) -> str:  # noqa: PLR0911  # Explicit delivery gates
    from apps.notifications.services import EmailRateLimiter, EmailSuppressionService  # noqa: PLC0415  # ADR-0007

    reserved = False
    try:
        validate_email(delivery.target_email)
        if EmailSuppressionService.is_suppressed(delivery.target_email):
            return "address_suppressed"
        allowed, _remaining = EmailRateLimiter.check_rate_limit()
        if not allowed:
            return "rate_limited"
        count = EmailRateLimiter.increment_counter()
        reserved = True
        if count > getattr(settings, "EMAIL_RATE_LIMIT", {}).get("MAX_PER_MINUTE", 50):
            return "rate_limited"
        if _message(delivery, purchase).send(fail_silently=False) != 1:
            return "provider_did_not_accept"
        reserved = False
        return ""
    except ValidationError:
        return "recipient_unavailable"
    except Exception:
        # Configured email backends have different exceptions. Their text may
        # contain the body or bearer code, so neither persist nor log it.
        return "provider_unavailable"
    finally:
        if reserved:
            # The minute bucket expires naturally. A failed release must not
            # expose the message or prevent recording the durable retry state.
            try:
                EmailRateLimiter.release_counter()
            except Exception:
                logger.warning(
                    "⚠️ [Promotions] Email rate-limit reservation release failed for delivery %s", delivery.pk
                )


def _stop_delivery(delivery: GiftCardDelivery, code: str) -> None:
    delivery.status = "failed"  # fsm-bypass: Delivery state CharField
    delivery.error_code = code
    delivery.next_attempt_at = None
    delivery.lease_until = None
    delivery.claim_token = None
    delivery.save(update_fields=["status", "error_code", "next_attempt_at", "lease_until", "claim_token"])


@sensitive_variables("purchase", "delivery")
def deliver_gift_card(delivery_id: UUID | str) -> bool:  # noqa: PLR0911  # Reject unavailable or premature jobs before I/O
    snapshot = GiftCardDelivery.objects.only("purchase_id").get(pk=delivery_id)
    with transaction.atomic():
        purchase = GiftCardPurchase.objects.select_for_update().get(pk=snapshot.purchase_id)
        purchase.gift_card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
        delivery = GiftCardDelivery.objects.select_for_update().get(pk=delivery_id)
        now = timezone.now()
        if delivery.status == "sent":
            return True
        if delivery.lease_until and delivery.lease_until > now:
            return False
        if delivery.status not in {"pending", "failed", "sending"}:
            return False
        if delivery.status != "sending" and (delivery.next_attempt_at is None or delivery.next_attempt_at > now):
            return False
        if not purchase.funded_at or (delivery.purpose == "voucher" and not purchase.can_reveal_code):
            _stop_delivery(delivery, "card_unavailable")
            return False
        if delivery.attempt_count >= MAX_DELIVERY_ATTEMPTS:
            _stop_delivery(delivery, "retry_limit_reached")
            return False
        token = uuid4()
        delivery.claim_token = token
        delivery.lease_until = now + DELIVERY_LEASE
        delivery.last_attempt_at = now
        delivery.attempt_count += 1
        delivery.status = "sending"  # fsm-bypass: Delivery state CharField
        delivery.save(update_fields=["claim_token", "lease_until", "last_attempt_at", "attempt_count", "status"])
    error = _send(delivery, purchase)
    with transaction.atomic():
        delivery = GiftCardDelivery.objects.select_for_update().get(pk=delivery_id)
        if delivery.claim_token != token:
            return False
        exhausted = error and delivery.attempt_count >= MAX_DELIVERY_ATTEMPTS
        delivery.error_code = "retry_limit_reached" if exhausted else error
        delivery.status = "failed" if error else "sent"  # fsm-bypass: Delivery state CharField
        delivery.sent_at = delivery.sent_at if error else timezone.now()
        delivery.lease_until = None
        delivery.claim_token = None
        permanent = exhausted or error in {"address_suppressed", "recipient_unavailable"}
        delay = RETRY_DELAY * (2 ** (delivery.attempt_count - 1))
        delivery.next_attempt_at = timezone.now() + delay if error and not permanent else None
        delivery.save(
            update_fields=[
                "error_code",
                "status",
                "sent_at",
                "lease_until",
                "claim_token",
                "next_attempt_at",
            ]
        )
    return not error
