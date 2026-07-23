"""
Data migration: backfill Refund rows from legacy meta["refunds"] JSON.

Context: PR #134 removed the meta.refunds JSON fallback from refund_service.py
so that the Refund model is the sole source of truth for refunded amounts.
Legacy orders/invoices that stored refunds only in meta["refunds"] (not as
Refund model rows) would appear as "unrefunded" — reopening over-refund risk.

This migration creates Refund rows for every entry in meta["refunds"] that
does not already have a matching row, then clears meta["refunds"] from the
parent entity.
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter

from django.db import migrations, transaction

logger = logging.getLogger(__name__)


def _get_or_create_ron_currency(apps):
    """Return (or create) the RON Currency row using the historical model."""
    Currency = apps.get_model("billing", "Currency")
    ron, _ = Currency.objects.get_or_create(
        code="RON",
        defaults={"symbol": "lei", "decimals": 2},
    )
    return ron


def _get_legacy_refund_entries(entity, entity_field: str) -> tuple[dict, list]:
    """Return validated legacy refund entries without discarding malformed evidence."""
    meta = entity.meta if isinstance(entity.meta, dict) else {}
    legacy_refunds = meta.get("refunds", [])
    if not legacy_refunds:
        return meta, []
    if not isinstance(legacy_refunds, list):
        logger.warning(
            "Skipping malformed meta.refunds collection on %s id=%s: %r",
            entity_field,
            entity.pk,
            legacy_refunds,
        )
        return meta, []
    return meta, legacy_refunds


def _gateway_refund_state(refund_model, entity_filter: dict, gateway_refund_id: str) -> str:
    """Classify an existing gateway ID as completed, conflicting, or absent."""
    gateway_matches = refund_model.objects.filter(gateway_refund_id=gateway_refund_id)
    if gateway_matches.filter(**entity_filter, status="completed").exists():
        return "completed"
    if gateway_matches.exists():
        return "conflicting"
    return "absent"


def _legacy_refund_reconciliation_state(
    refund_model,
    entity_filter: dict,
    entry: dict,
    existing_amount_counts: Counter,
    legacy_amount_occurrences: Counter,
) -> str:
    """Return completed, conflicting, or absent for one legacy entry."""
    gateway_refund_id = entry.get("refund_id", "")
    if gateway_refund_id:
        return _gateway_refund_state(refund_model, entity_filter, gateway_refund_id)

    amount_cents = entry["amount_cents"]
    legacy_amount_occurrences[amount_cents] += 1
    if legacy_amount_occurrences[amount_cents] <= existing_amount_counts[amount_cents]:
        return "completed"
    return "absent"


def _backfill_entity_refunds(refund_model, entity, entity_field: str, ron_currency) -> int:
    """
    Process one Order or Invoice entity.

    Returns the number of Refund rows created for this entity.
    """
    meta, legacy_refunds = _get_legacy_refund_entries(entity, entity_field)
    if not legacy_refunds:
        return 0

    # Determine the original amount for reference.
    original_amount_cents = getattr(entity, "total_cents", None) or getattr(entity, "subtotal_cents", 0)

    # Determine the currency — orders carry a currency FK, invoices do too.
    currency = getattr(entity, "currency", None) or ron_currency

    customer = entity.customer
    created_count = 0
    entity_filter = {entity_field: entity}
    existing_amount_counts = Counter(
        refund_model.objects.filter(**entity_filter, status="completed").values_list("amount_cents", flat=True)
    )
    legacy_amount_occurrences: Counter[int] = Counter()
    unresolved_entries = []

    for entry in legacy_refunds:
        if not isinstance(entry, dict):
            logger.warning(
                "Skipping malformed meta.refunds entry on %s id=%s: %r",
                entity_field,
                entity.pk,
                entry,
            )
            unresolved_entries.append(entry)
            continue

        amount_cents = entry.get("amount_cents")
        if not amount_cents or not isinstance(amount_cents, int) or amount_cents <= 0:
            logger.warning(
                "Skipping meta.refunds entry with invalid amount_cents on %s id=%s: %r",
                entity_field,
                entity.pk,
                entry,
            )
            unresolved_entries.append(entry)
            continue

        gateway_refund_id = entry.get("refund_id", "")
        # Dedupe exact gateway IDs. Without an ID, preserve multiplicity: each
        # pre-existing completed same-amount row consumes at most one legacy entry.
        reconciliation_state = _legacy_refund_reconciliation_state(
            refund_model,
            entity_filter,
            entry,
            existing_amount_counts,
            legacy_amount_occurrences,
        )
        if reconciliation_state != "absent":
            unresolved_entries.extend({"completed": [], "conflicting": [entry]}[reconciliation_state])
            logger.log(
                {"completed": logging.INFO, "conflicting": logging.WARNING}[reconciliation_state],
                "Skipping %s meta.refunds entry on %s id=%s (refund_id=%s, amount_cents=%s)",
                reconciliation_state,
                entity_field,
                entity.pk,
                gateway_refund_id or "N/A",
                amount_cents,
            )
            continue

        reason_raw = entry.get("reason", "customer_request")
        # Guard against invalid reason values — fall back to customer_request.
        valid_reasons = {
            "customer_request",
            "error_correction",
            "dispute",
            "service_failure",
            "duplicate_payment",
            "fraud",
            "cancellation",
            "downgrade",
            "administrative",
        }
        reason = reason_raw if reason_raw in valid_reasons else "customer_request"

        create_kwargs: dict = {
            "customer": customer,
            "amount_cents": amount_cents,
            "currency": currency,
            "original_amount_cents": original_amount_cents,
            "status": "completed",
            "refund_type": "partial",
            "reason": reason,
            "reference_number": f"LEGACY-{uuid.uuid4().hex[:12]}",
            "gateway_refund_id": gateway_refund_id,
        }
        if entity_field == "order":
            create_kwargs["order"] = entity
        else:
            create_kwargs["invoice"] = entity

        refund_model.objects.create(**create_kwargs)
        created_count += 1

    if unresolved_entries != legacy_refunds:
        # Remove only entries reconciled into Refund rows. Malformed evidence is
        # retained for an operator rather than silently discarded.
        entity.meta = dict(meta)
        if unresolved_entries:
            entity.meta["refunds"] = unresolved_entries
        else:
            entity.meta.pop("refunds", None)
        entity.save(update_fields=["meta"])

    return created_count


def backfill_refunds_from_meta(apps, schema_editor):
    """
    Forward migration: create Refund rows from meta["refunds"] JSON entries.

    Processing order:
      1. All Order objects whose meta contains a non-empty "refunds" list.
      2. All Invoice objects whose meta contains a non-empty "refunds" list.
    """
    Order = apps.get_model("orders", "Order")
    Invoice = apps.get_model("billing", "Invoice")
    Refund = apps.get_model("billing", "Refund")

    ron_currency = _get_or_create_ron_currency(apps)

    orders_processed = 0
    invoices_processed = 0
    refunds_created = 0

    # --- Orders ---
    for order in Order.objects.filter(meta__has_key="refunds").iterator():
        try:
            with transaction.atomic():
                n = _backfill_entity_refunds(Refund, order, "order", ron_currency)
            if n > 0:
                refunds_created += n
                orders_processed += 1
        except Exception:
            logger.exception(
                "Failed to backfill refunds for Order id=%s — skipping",
                order.pk,
            )

    # --- Invoices ---
    for invoice in Invoice.objects.filter(meta__has_key="refunds").iterator():
        try:
            with transaction.atomic():
                n = _backfill_entity_refunds(Refund, invoice, "invoice", ron_currency)
            if n > 0:
                refunds_created += n
                invoices_processed += 1
        except Exception:
            logger.exception(
                "Failed to backfill refunds for Invoice id=%s — skipping",
                invoice.pk,
            )

    logger.info(
        "Backfill complete: %d orders processed, %d invoices processed, %d Refund rows created.",
        orders_processed,
        invoices_processed,
        refunds_created,
    )


def reverse_backfill_refunds_from_meta(apps, schema_editor):
    """
    Reverse migration: reconstruct meta["refunds"] from LEGACY- Refund rows,
    then delete those rows.

    NOTE: This reverse is best-effort. It cannot recover the original
    gateway_refund_id / reason if they were empty, and it does not restore
    any other meta["refunds"] keys that may have existed (e.g. created_at).
    """
    Refund = apps.get_model("billing", "Refund")

    legacy_refunds = Refund.objects.filter(reference_number__startswith="LEGACY-").select_related(
        "order", "invoice"
    )

    for refund in legacy_refunds.iterator():
        entry = {
            "refund_id": refund.gateway_refund_id,
            "amount_cents": refund.amount_cents,
            "reason": refund.reason,
            "status": refund.status,
            "refund_type": refund.refund_type,
            "reference_number": refund.reference_number,
        }

        entity = refund.order if refund.order_id else refund.invoice
        if entity is None:
            continue

        meta = entity.meta if isinstance(entity.meta, dict) else {}
        meta.setdefault("refunds", []).append(entry)
        entity.meta = meta
        entity.save(update_fields=["meta"])

    deleted_count, _ = Refund.objects.filter(reference_number__startswith="LEGACY-").delete()
    logger.info("Reverse migration: restored meta.refunds on entities and deleted %d LEGACY- Refund rows.", deleted_count)


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0023_update_payment_status_constraint"),
        ("orders", "0007_orderitem_product_slug"),
    ]

    operations = [
        migrations.RunPython(
            backfill_refunds_from_meta,
            reverse_code=reverse_backfill_refunds_from_meta,
        ),
    ]
