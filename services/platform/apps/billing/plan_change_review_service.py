"""Append Payment-first facts; process their business effects after commit."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.db import connection, transaction
from django.utils import timezone

from apps.customers.models import Customer

from .invoice_models import Invoice
from .payment_models import Payment
from .plan_change_models import PlanChange
from .plan_change_review_models import PlanChangeReviewEvent
from .refund_models import Refund, resolved_invoice_id_of

MAX_SOURCE_ID_LENGTH = 64


def _enqueue(event_id: str) -> None:
    from django_q.tasks import async_task  # noqa: PLC0415 -- Queue only after the source fact commits.

    async_task("apps.billing.plan_change_review_service.process_financial_review", event_id)


def _append(*, using: str, **fact: Any) -> PlanChangeReviewEvent | None:
    # No business FK, lock or synchronous worker belongs in a Payment-first
    # writer. A later quote must independently validate its paid coverage.
    if not PlanChange.objects.using(using).filter(customer_id=fact["customer_id"]).exists():
        return None
    fingerprint = hashlib.sha256(json.dumps(fact, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    event, _created = PlanChangeReviewEvent.objects.using(using).get_or_create(fact_key=fingerprint, defaults=fact)
    if event.processed_at is None:
        transaction.on_commit(lambda: _enqueue(str(event.pk)), using=using, robust=True)
    return event


def record_payment_review(payment: Payment, *, using: str) -> PlanChangeReviewEvent | None:
    if payment.status not in {"disputed", "refunded", "partially_refunded"}:
        return None
    source = (payment.meta or {}).get("dispute_id") if payment.status == "disputed" else None
    if not isinstance(source, str) or not source or len(source) > MAX_SOURCE_ID_LENGTH:
        source = str(payment.pk)
    return _append(
        using=using,
        source_kind="payment",
        source_id=source,
        reason="dispute" if payment.status == "disputed" else "refund",
        customer_id=payment.customer_id,
        payment_id=payment.pk,
        invoice_id=payment.invoice_id,
        proforma_id=payment.proforma_id,
    )


def record_refund_review(refund: Refund, *, using: str) -> PlanChangeReviewEvent | None:
    if refund.status in {"cancelled", "rejected", "failed"}:
        return None
    return _append(
        using=using,
        source_kind="refund",
        source_id=str(refund.pk),
        reason="refund",
        customer_id=refund.customer_id,
        payment_id=refund.payment_id,
        invoice_id=resolved_invoice_id_of(refund),
        proforma_id=None,
    )


def process_financial_review(event_id: str) -> None:
    """Resume the durable event after its original writer has committed."""
    from .plan_change_lifecycle import _cancel_context  # noqa: PLC0415 -- Existing document-first admission.

    if connection.in_atomic_block:
        raise RuntimeError("Financial review must release its source transaction before document admission")
    event = PlanChangeReviewEvent.objects.get(pk=event_id)
    if event.processed_at is not None:
        return
    # Serialize discovery against commercial commitment, then release Customer
    # before entering ANY existing document context. Each document owns a
    # separate transaction; no second document is acquired while Customer is held.
    with transaction.atomic():
        Customer.all_objects.select_for_update(of=("self",), no_key=True).get(pk=event.customer_id)
        identifiers = list(
            PlanChange.objects.filter(customer_id=event.customer_id)
            .exclude(status__in=("cancelled", "expired"))
            .order_by("pk")
            .values_list("pk", flat=True)
        )
    original_proforma = (
        Invoice.objects.filter(pk=event.invoice_id).values_list("converted_from_proforma_id", flat=True).first()
        if event.invoice_id is not None
        else None
    )
    proforma_ids = {str(pk) for pk in (event.proforma_id, original_proforma) if pk is not None}
    for identifier in identifiers:
        with _cancel_context(identifier) as change, transaction.atomic():
            locked = PlanChangeReviewEvent.objects.select_for_update(of=("self",)).get(pk=event_id)
            if locked.processed_at is not None or str(identifier) in locked.reviewed_changes:
                continue
            if not _affected(change, locked, proforma_ids):
                continue
            if change.status != "paid_review":
                change.review_reason = f"Financial {locked.reason} invalidated accepted plan coverage."
                change.require_review()
                change.save(update_fields=["review_reason", "status", "updated_at"])
            locked.reviewed_changes = [*locked.reviewed_changes, str(identifier)]
            locked.save(update_fields=["reviewed_changes", "updated_at"])
    with transaction.atomic():
        locked = PlanChangeReviewEvent.objects.select_for_update(of=("self",)).get(pk=event_id)
        if locked.processed_at is None:
            locked.processed_at = timezone.now()
            locked.save(update_fields=["processed_at", "updated_at"])


def _affected(change: PlanChange, event: PlanChangeReviewEvent, proforma_ids: set[str]) -> bool:
    if change.customer_id != event.customer_id:
        return False
    if (event.invoice_id is not None and change.invoice_id == event.invoice_id) or (
        change.proforma_id is not None and str(change.proforma_id) in proforma_ids
    ):
        return True
    evidence = change.quote_snapshot.get("coverage", {})
    if not isinstance(evidence, dict):
        return False
    for source in evidence.values():
        if not isinstance(source, dict):
            continue
        kind, document_id = source.get("document_kind"), str(source.get("document_id"))
        if (kind in {"invoice", "initial_order"} and document_id == str(event.invoice_id)) or (
            kind == "proforma" and document_id in proforma_ids
        ):
            return True
    return False


def sweep_financial_reviews(*, limit: int = 50) -> int:
    """Recover a committed source fact whose process-local enqueue was lost."""
    identifiers = list(
        PlanChangeReviewEvent.objects.filter(processed_at__isnull=True)
        .order_by("created_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    for identifier in identifiers:
        process_financial_review(str(identifier))
    return len(identifiers)
