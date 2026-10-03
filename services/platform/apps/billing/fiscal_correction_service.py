"""Recording the fiscal correction a completed refund owes.

Completion RECORDS; it never issues. The refund has already moved money, and nothing about
invoicing - a provider being slow, a number failing to allocate - may roll that back. So the
completion hook writes one `FiscalCorrection` row in its own savepoint and walks away, and the
recovery sweep below finds any completed refund whose hook did not.

Nothing here takes a row lock. The tender gateway branch completes a refund in a transaction
that holds only the refund's lock, while settlement elsewhere locks document, then payment,
then refund; a lock taken from inside the hook could close a cycle with either. Duplicate
creation is ruled out by the unique source links instead, which serialise concurrent inserts
on the index without ordering against anything else.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db import transaction

from apps.common.validators import log_security_event

from .fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from .invoice_models import DOCUMENT_KIND_CREDIT_NOTE, DOCUMENT_KIND_INVOICE, Invoice
from .refund_models import resolved_invoice_id_of

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from .refund_models import Refund

logger = logging.getLogger(__name__)

# Rotation state for `sweep_fiscal_corrections`; its docstring explains why it exists.
_SWEEP_CURSOR_KEY = "billing:fiscal-correction-sweep-cursor"


def _is_fiscal_document(invoice: Invoice | None) -> bool:
    """Whether `invoice` is an issued, numbered invoice that a correction could reduce."""
    return (
        invoice is not None
        and invoice.document_kind == DOCUMENT_KIND_INVOICE
        and bool(invoice.number)
        and invoice.status != "draft"
    )


def record_obligation(refund: Refund) -> FiscalCorrection | None:
    """Record the fiscal correction a completed refund owes, once per source.

    A refund that is one leg of a tender command answers to the command: one customer
    instruction is one correction however many tenders carried the money back. Any other
    refund answers for itself.

    The original is the one invoice the refund belongs to under the shared resolution rule, the
    same one every balance and projection counts it against.
    """
    from apps.promotions.models import TenderRefundLeg  # noqa: PLC0415  # ADR-0007 cross-app import

    if refund.status != "completed":
        return None

    leg = TenderRefundLeg.objects.select_related("command").filter(refund_id=refund.pk).first()
    command = leg.command if leg is not None else None
    source: dict[str, Any] = {"source_command": command} if command is not None else {"source_refund": refund}

    existing = FiscalCorrection.objects.filter(**source).first()
    if existing is not None:
        return existing

    # The shared resolution rule, so the obligation lands on the invoice the money math counts the
    # refund against. Links that disagree are resolved by precedence and logged there.
    original_id = resolved_invoice_id_of(refund)
    if original_id is None and command is not None:
        original_id = command.invoice_id
    original = Invoice.objects.filter(pk=original_id).first() if original_id is not None else None
    if _is_fiscal_document(original):
        defaults: dict[str, Any] = {"original": original}
    else:
        # fsm-bypass: born not-required. With no fiscal document there was never anything pending
        # to settle, so this is the row's initial state rather than a transition it skipped.
        defaults = {"state": STATE_NOT_REQUIRED, "not_required_reason": REASON_NO_FISCAL_DOCUMENT}

    # `get_or_create` already retries the read when its insert loses a unique-index race, and
    # it runs the insert in its own savepoint, so the losing completion converges on the
    # winner's row instead of failing.
    correction, created = FiscalCorrection.objects.get_or_create(**source, defaults=defaults)
    if created:
        logger.info(
            f"✅ [Fiscal Correction] Recorded {correction.state} correction {correction.pk} "
            f"for refund {refund.pk}" + (f" (command {command.pk})" if command is not None else "")
        )
    return correction


def attach_provider_credit_note(credit_note: Invoice) -> FiscalCorrection | None:
    """Settle the obligation an issued provider storno answers for, by linking its credit note.

    The provider's whole-document storno is only ever allowed when ONE settled refund (or one
    tender command) accounts for the entire invoice, so exactly one pending obligation can
    match. Anything else is not a link this code may guess: none means the obligation has not
    been recorded yet (the sweep links it once it is), several means an operator must decide.

    Locks only the obligation rows. The caller is finalising the credit note and holds its
    issuance lock, never the original's, and every writer of an obligation's state comes
    through here or the sweep.
    """
    if credit_note.document_kind != DOCUMENT_KIND_CREDIT_NOTE or not credit_note.number:
        return None
    original_id = credit_note.reverses_invoice_id
    if original_id is None:
        return None

    already = FiscalCorrection.objects.filter(credit_note=credit_note).first()
    if already is not None:
        return already

    candidates = list(
        FiscalCorrection.objects.select_for_update()
        .filter(original_id=original_id, state=STATE_PENDING)
        .order_by("created_at", "pk")[:2]
    )
    if not candidates:
        logger.warning(
            f"⚠️ [Fiscal Correction] Credit note {credit_note.number} reverses invoice {original_id}, "
            f"which has no pending correction yet; the recovery sweep will link it once recorded."
        )
        return None
    if len(candidates) > 1:
        logger.error(
            f"🔥 [Fiscal Correction] Credit note {credit_note.number} reverses invoice {original_id}, "
            f"which has several pending corrections; an operator must decide which one it settles."
        )
        log_security_event(
            event_type="fiscal_correction_ambiguous_credit_note",
            details={"credit_note_id": str(credit_note.pk), "original_id": str(original_id)},
        )
        return None

    correction = candidates[0]
    correction.attach_credit_note(credit_note)
    correction.save(update_fields=["state", "credit_note", "updated_at"])
    logger.info(
        f"✅ [Fiscal Correction] Correction {correction.pk} settled by provider credit note {credit_note.number}"
    )
    return correction


def _unrecorded_completed_refunds() -> QuerySet[Refund]:
    """Completed refunds that answer to no correction, directly or through their tender command."""
    from .refund_models import Refund  # noqa: PLC0415  # Avoid a model import cycle

    return (
        Refund.objects.filter(status="completed", fiscal_correction__isnull=True)
        .exclude(tender_leg__command__fiscal_correction__isnull=False)
        # `pk` breaks ties, so a page that ends between two equal timestamps resumes correctly.
        .order_by("created_at", "pk")
    )


def sweep_fiscal_corrections(limit: int = 200) -> dict[str, int]:
    """Recover what the completion hook could not do, idempotently.

    1. Record the obligation for every completed refund that has none. The hook misses a refund
       when its recording failed (the savepoint rolled back and only a log line remains), when
       a refund reached `completed` without a `save()` that this process saw, or when a row was
       created already completed. Keyed by the refund-and-command identity, so a second run, or a
       second leg of a command already recorded, converges on the existing row.
    2. Link any issued provider credit note still unlinked to the pending obligation it settles:
       a storno can be issued before its obligation was recorded, and then had nothing to attach to.

    A refund the recorder refuses (linked to several invoices) stays a candidate and is raised
    again on every run. The cursor rotates through candidates, so a handful of those can never
    occupy every run while a recoverable refund behind them waits; this is the arrangement
    `sweep_pending_issuances` uses, with the same `(created_at, pk)` keyset.
    """
    from django.core.cache import cache  # noqa: PLC0415

    from .issuers.tasks import _cursor_for, _resume_after  # noqa: PLC0415  # Shared keyset paging

    candidates = _unrecorded_completed_refunds()
    cursor = cache.get(_SWEEP_CURSOR_KEY)
    owed = list(_resume_after(candidates, cursor)[:limit])
    if not owed and cursor:
        owed = list(candidates[:limit])
    # Advanced BEFORE the work, so a crash part-way still moves past what was examined.
    cache.set(_SWEEP_CURSOR_KEY, _cursor_for(owed[-1]) if owed else None, timeout=None)

    results = {"examined": len(owed), "recorded": 0, "unresolved": 0, "linked": 0}
    for refund in owed:
        try:
            with transaction.atomic():
                correction = record_obligation(refund)
        except Exception:
            logger.exception(f"🔥 [Fiscal Correction] Sweep could not record the correction for refund {refund.pk}")
            correction = None
        results["recorded" if correction is not None else "unresolved"] += 1

    unlinked_notes = (
        Invoice.objects.filter(
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            number__isnull=False,
            settled_fiscal_correction__isnull=True,
            reverses_invoice__fiscal_corrections__state=STATE_PENDING,
        )
        .distinct()
        .order_by("pk")[:limit]
    )
    for credit_note in list(unlinked_notes):
        try:
            with transaction.atomic():
                linked = attach_provider_credit_note(credit_note)
        except Exception:
            logger.exception(f"🔥 [Fiscal Correction] Sweep could not link credit note {credit_note.pk}")
            linked = None
        if linked is not None:
            results["linked"] += 1

    if results["examined"] or results["linked"]:
        logger.info(
            f"🐢 [Fiscal Correction] Swept {results['examined']} refund(s): {results['recorded']} recorded, "
            f"{results['unresolved']} unresolved; {results['linked']} credit note(s) linked"
        )
    return results
