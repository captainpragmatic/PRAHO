"""Recover already-recorded gift funding attempts through their existing contract."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.db import Error, transaction
from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone

from .gift_funding import start_funding
from .models import GiftCardDelivery, GiftCardFundingAttempt, GiftCardFundingRefund, GiftCardPurchase

RECHECK_INTERVAL = timedelta(minutes=10)
MAX_FUNDING_BATCH = 100
RECOVERABLE_FUNDING_STATES = (
    "reserved",
    "submitting",
    "unknown",
    "requires_payment_method",
    "requires_confirmation",
    "requires_action",
    "processing",
)


def reconcile_gift_funding(limit: int = MAX_FUNDING_BATCH) -> dict[str, Any]:
    """Retry only the persisted intent/key, including the existing 23-hour guard."""
    if type(limit) is not int or limit <= 0:
        raise ValueError("Gift funding reconciliation limit must be a positive integer")
    cutoff = timezone.now() - RECHECK_INTERVAL
    due = Q(checked_at__isnull=True) | Q(checked_at__lte=cutoff)
    candidates = GiftCardFundingAttempt.objects.filter(
        due,
        status__in=RECOVERABLE_FUNDING_STATES,
        purchase__funded_at__isnull=True,
    ).order_by(F("checked_at").asc(nulls_first=True), "created_at", "pk")
    identities = list(candidates.values_list("pk", flat=True)[: min(limit, MAX_FUNDING_BATCH)])
    report: dict[str, Any] = {"checked": 0, "funded": 0, "needs_review": 0, "errors": []}
    for identity in identities:
        # Conditional update claims the due interval atomically without holding a
        # row lock across provider I/O. A crashed worker becomes eligible again.
        claimed = GiftCardFundingAttempt.objects.filter(
            due,
            pk=identity,
            status__in=RECOVERABLE_FUNDING_STATES,
            purchase__funded_at__isnull=True,
        ).update(checked_at=timezone.now())
        if not claimed:
            continue
        report["checked"] += 1
        attempt = GiftCardFundingAttempt.objects.select_related("purchase").get(pk=identity)
        try:
            result = start_funding(attempt.purchase)
            if not result.get("success"):
                report["errors"].append({"attempt_id": str(identity), "code": "provider_unavailable"})
        except ValidationError:
            report["errors"].append({"attempt_id": str(identity), "code": "verification_required"})
            with transaction.atomic():
                attempt = GiftCardFundingAttempt.objects.select_for_update().get(pk=identity)
                if attempt.status in RECOVERABLE_FUNDING_STATES:
                    attempt.status = "needs_review"  # fsm-bypass: Durable gift funding state CharField
                    attempt.error_code = "funding_reconciliation_validation_failed"
                    attempt.save(update_fields=["status", "error_code"])
        except (Error, OSError, ValueError, ImportError):
            report["errors"].append({"attempt_id": str(identity), "code": "reconciliation_unavailable"})
        attempt.refresh_from_db()
        if attempt.status == "needs_review":
            report["needs_review"] += 1
        if GiftCardPurchase.objects.filter(pk=attempt.purchase_id, funded_at__isnull=False).exists():
            report["funded"] += 1
    return report


def setup_gift_scheduled_tasks() -> dict[str, str]:
    from django_q.models import Schedule  # noqa: PLC0415  # Schedule table available after app setup

    result = {}
    for kind in ("funding", "refund", "delivery"):
        name = f"gift-{kind}-reconciliation"
        function = "reconcile_gift_refunds" if kind == "refund" else f"reconcile_gift_{kind}"
        _schedule, created = Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": f"apps.promotions.tasks.{function}",
                "schedule_type": Schedule.CRON,
                "cron": "*/10 * * * *",
                "repeats": -1,
            },
        )
        result[name] = "created" if created else "already_exists"
    return result


def reconcile_gift_refunds(limit: int = MAX_FUNDING_BATCH) -> dict[str, Any]:
    from .gift_refunds import refresh_refund  # noqa: PLC0415  # Provider work remains outside transactions

    if type(limit) is not int or limit <= 0:
        raise ValueError("Gift refund reconciliation limit must be a positive integer")
    due = Q(checked_at__isnull=True) | Q(checked_at__lte=timezone.now() - RECHECK_INTERVAL)
    states = ("reserved", "submitting", "unknown", "pending", "requires_action")
    candidates = GiftCardFundingRefund.objects.filter(due, status__in=states).order_by(
        F("checked_at").asc(nulls_first=True),
        "created_at",
        "pk",
    )
    report: dict[str, Any] = {"checked": 0, "settled": 0, "needs_review": 0, "errors": []}
    for identity in list(candidates.values_list("pk", flat=True)[: min(limit, MAX_FUNDING_BATCH)]):
        if not GiftCardFundingRefund.objects.filter(due, pk=identity, status__in=states).update(
            checked_at=timezone.now()
        ):
            continue
        report["checked"] += 1
        try:
            refresh_refund(identity)
        except ValidationError:
            report["errors"].append({"refund_id": str(identity), "code": "verification_required"})
        except (Error, OSError, ValueError, ImportError):
            report["errors"].append({"refund_id": str(identity), "code": "reconciliation_unavailable"})
        refund = GiftCardFundingRefund.objects.get(pk=identity)
        report["settled"] += int(refund.status in {"succeeded", "failed", "canceled"})
        report["needs_review"] += int(refund.status == "needs_review")
    return report


def reconcile_gift_delivery(limit: int = MAX_FUNDING_BATCH) -> dict[str, Any]:
    """Repair missing outbox rows and claim due/abandoned sends in bounded batches."""
    from .gift_delivery import deliver_gift_card, queue_purchase_delivery  # noqa: PLC0415  # Delivery boundary

    if type(limit) is not int or limit <= 0:
        raise ValueError("Gift delivery reconciliation limit must be a positive integer")
    batch = min(limit, MAX_FUNDING_BATCH)
    report: dict[str, Any] = {"repaired": 0, "checked": 0, "sent": 0, "errors": []}
    deliveries = GiftCardDelivery.objects.filter(purchase_id=OuterRef("pk"))
    incomplete = (
        GiftCardPurchase.objects.filter(funded_at__isnull=False)
        .alias(
            has_voucher=Exists(deliveries.filter(purpose="voucher")),
            has_receipt=Exists(deliveries.filter(purpose="receipt")),
        )
        .filter(Q(has_voucher=False) | Q(is_gift=True, has_receipt=False))
        .order_by("funded_at", "pk")
    )
    for identity in list(incomplete.values_list("pk", flat=True)[:batch]):
        queue_purchase_delivery(identity)
        report["repaired"] += 1
    now = timezone.now()
    due = GiftCardDelivery.objects.filter(
        Q(status__in=["pending", "failed"], next_attempt_at__lte=now)
        | (Q(status="sending") & (Q(lease_until__lte=now) | Q(lease_until__isnull=True))),
    ).order_by(F("next_attempt_at").asc(nulls_first=True), "created_at", "pk")
    for identity in list(due.values_list("pk", flat=True)[:batch]):
        report["checked"] += 1
        try:
            report["sent"] += int(deliver_gift_card(identity))
        except (Error, OSError, ValueError, ImportError):
            report["errors"].append({"delivery_id": str(identity), "code": "delivery_unavailable"})
    return report
