"""Issuing the built-in storno credit note a fiscal correction owes (ADR-0053).

A1 records the obligation when a refund completes. This module settles it, one correction at a
time, as a Django-Q task and an hourly sweep. Each step is its own transaction and is resumed
independently, by correction id:

1. **Allocation.** Under a lock on the correction, then on its original, decide how much this
   refund credits and freeze it. Corrections of one original are decided in refund-completion
   order, because each one's amount depends on what the earlier ones credited.
2. **Issuance.** Draft, lines, number and `issue()` in one transaction, so a rollback leaves
   neither a numbered draft nor a gap in the series. A failure keeps the allocation and retries it.
3. **Delivery**, after the issuance commits: the credit note is emailed to the customer (the first
   successful send dates it for D390) and, in Romania, filed with e-Factura once its original is
   accepted. Neither can undo the note; each is retried until it succeeds.

Built-in originals only. A provider (SmartBill) original keeps its existing storno path until A3,
so its corrections are left exactly as A1 records them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from .efactura.settings import ro_local_date
from .fiscal_correction_allocation import AllocationRefusedError, Components, allocate, owed_reduction
from .fiscal_correction_models import (
    EFACTURA_FAILED,
    EFACTURA_RETRYABLE,
    EFACTURA_SUBMITTED,
    FAILURE_ALLOCATION_REFUSED,
    FAILURE_ISSUANCE_ERROR,
    FAILURE_SECOND_CREDIT_NOTE,
    REASON_COVERED_BY_COLLECTIONS,
    REASON_FULLY_CREDITED,
    STATE_ALLOCATED,
    STATE_ATTACHED,
    STATE_COMMUNICATED,
    STATE_FAILED,
    STATE_ISSUED,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from .invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Invoice,
    InvoiceLine,
    sequence_family_of,
)
from .refund_models import FULLY_COLLECTED_INVOICE_STATES, collected_cents_for_invoice, refunds_for_invoice

logger = logging.getLogger(__name__)

TASK_PATH = "apps.billing.fiscal_correction_worker.process_fiscal_correction"
TASK_TIMEOUT_SECONDS = 300
_SWEEP_CURSOR_KEY = "billing:fiscal-correction-issuance-cursor"

# States in which an earlier correction has decided its amount, so a later one can build on it.
_DECIDED_STATES = frozenset({STATE_ALLOCATED, STATE_ISSUED, STATE_COMMUNICATED, STATE_NOT_REQUIRED, STATE_ATTACHED})


class _SecondCreditNoteError(Exception):
    """The original already has a credit note; A2 cannot write a second (A3 lifts this)."""


@dataclass(frozen=True)
class _Source:
    """What a correction answers for: its completed refunds, or None while a command is unfinished."""

    refund_ids: tuple[Any, ...]
    refunded_cents: int
    completed_at: datetime


def queue_fiscal_correction(correction_id: Any) -> None:
    """Hand one correction to the worker. Losing this enqueue costs only time: the sweep finds it."""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task(TASK_PATH, str(correction_id), timeout=TASK_TIMEOUT_SECONDS)
    except Exception:
        logger.exception(f"🔥 [Storno] Could not queue fiscal correction {correction_id}; the sweep will pick it up")


def process_fiscal_correction(correction_id: str) -> dict[str, str]:
    """Take one correction as far as it can go. Idempotent: replaying it changes nothing settled."""
    outcome = {"allocation": _run_step(correction_id, _advance_allocation, FAILURE_ALLOCATION_REFUSED)}
    outcome["issuance"] = _run_step(correction_id, _advance_issuance, FAILURE_ISSUANCE_ERROR)
    if FiscalCorrection.objects.filter(pk=correction_id, state__in=[STATE_ISSUED, STATE_COMMUNICATED]).exists():
        # After the issuing transaction commits, never inside it: an email or an ANAF upload is not
        # something a rollback can take back. Outside any transaction this runs immediately.
        transaction.on_commit(lambda: deliver_credit_note(correction_id))
    return outcome


def _run_step(correction_id: str, step: Any, failure_code: str) -> str:
    """Run one step; an unexpected error is recorded on the correction, outside the failed transaction."""
    try:
        return str(step(correction_id))
    except Exception as exc:
        logger.exception(f"🔥 [Storno] Fiscal correction {correction_id}: {step.__name__} failed")
        _record_failure(correction_id, failure_code, f"{type(exc).__name__}: {exc}")
        return "failed"


def _record_failure(correction_id: str, code: str, error: str) -> None:
    """Mark the correction failed, keeping whatever allocation it already holds."""
    with transaction.atomic():
        correction = FiscalCorrection.objects.select_for_update().filter(pk=correction_id).first()
        if correction is None or correction.state not in {STATE_PENDING, STATE_ALLOCATED, STATE_FAILED}:
            return
        correction.fail(code=code, error=error)
        correction.save()


# ===============================================================================
# 1. ALLOCATION
# ===============================================================================


def _source_of(correction: FiscalCorrection) -> _Source | None:
    """The completed refunds this correction answers for.

    A tender command's correction waits for the command to complete: a `failed` command is one an
    operator can resume, so crediting its completed legs now would freeze an amount the resumed legs
    later make too small.
    """
    from .refund_models import Refund  # noqa: PLC0415  # Avoid a model import cycle

    if correction.source_command_id is not None:
        command = correction.source_command
        if command is None or command.status != "completed":
            return None
        refunds = list(Refund.objects.filter(tender_leg__command_id=command.pk, status="completed"))
    else:
        refunds = list(Refund.objects.filter(fiscal_correction=correction, status="completed"))
    if not refunds:
        return None
    return _Source(
        refund_ids=tuple(refund.pk for refund in refunds),
        refunded_cents=sum(refund.amount_cents for refund in refunds),
        completed_at=max(refund.processed_at or refund.created_at for refund in refunds),
    )


def _completion_key(correction: FiscalCorrection, source: _Source | None) -> tuple[datetime, datetime, str]:
    """Refund-completion order, with the correction's own creation and id to break ties."""
    completed = source.completed_at if source is not None else timezone.now()
    return (completed, correction.created_at, str(correction.pk))


def _earlier_undecided(correction: FiscalCorrection, original: Invoice, key: tuple[datetime, datetime, str]) -> str:
    """Why an earlier refund on this original must be decided first, or "" if none must."""
    for other in FiscalCorrection.objects.filter(original=original).exclude(pk=correction.pk):
        other_source = _source_of(other)
        if _completion_key(other, other_source) >= key:
            continue
        decided = other.state in _DECIDED_STATES or (other.state == STATE_FAILED and other.is_allocated)
        if not decided:
            return f"earlier correction {other.pk} is {other.state}"
    unrecorded = (
        refunds_for_invoice(original)
        .filter(status="completed", fiscal_correction__isnull=True, processed_at__lt=key[0])
        .exclude(tender_leg__command__fiscal_correction__isnull=False)
    )
    first = unrecorded.order_by("processed_at").first()
    return f"earlier refund {first.pk} has no recorded correction yet" if first is not None else ""


def _credited_so_far(original: Invoice, *, excluding: FiscalCorrection) -> Components:
    """What other corrections already credit: their allocations, and any note no allocation backs."""
    allocated = (
        FiscalCorrection.objects.filter(original=original, allocated_at__isnull=False)
        .exclude(pk=excluding.pk)
        .aggregate(
            base=models.Sum("base_cents", default=0),
            tax=models.Sum("tax_cents", default=0),
            discount=models.Sum("discount_cents", default=0),
        )
    )
    other_notes = (
        Invoice.objects.filter(reverses_invoice=original)
        .exclude(settled_fiscal_correction__allocated_at__isnull=False)
        .aggregate(
            base=models.Sum("subtotal_cents", default=0),
            tax=models.Sum("tax_cents", default=0),
            discount=models.Sum("discount_cents", default=0),
        )
    )
    return Components(
        base_cents=-(allocated["base"] + other_notes["base"]),
        tax_cents=-(allocated["tax"] + other_notes["tax"]),
        discount_cents=-(allocated["discount"] + other_notes["discount"]),
    )


def _refunded_by_earlier(original: Invoice, correction: FiscalCorrection, key: tuple[datetime, datetime, str]) -> int:
    """Cents returned by the refunds of corrections decided before this one."""
    total = 0
    for other in FiscalCorrection.objects.filter(original=original).exclude(pk=correction.pk):
        other_source = _source_of(other)
        if other_source is not None and _completion_key(other, other_source) < key:
            total += other_source.refunded_cents
    return total


def _single_rate(original: Invoice) -> Decimal | None:
    rates = set(original.lines.values_list("tax_rate", flat=True))
    return Decimal(rates.pop()) if len(rates) == 1 else None


def _advance_allocation(correction_id: str) -> str:  # noqa: PLR0911  # One return per distinct outcome
    """Decide and freeze what this correction credits, or that it credits nothing."""
    from .refund_models import Refund  # noqa: PLC0415  # Avoid a model import cycle

    with transaction.atomic():
        correction = FiscalCorrection.objects.select_for_update().filter(pk=correction_id).first()
        if correction is None or correction.state not in {STATE_PENDING, STATE_FAILED} or correction.is_allocated:
            return "skipped"
        if correction.original_id is None:
            return "skipped"
        original = Invoice.objects.select_for_update().get(pk=correction.original_id)
        if original.issuer_provider != ISSUER_BUILTIN:
            # A provider's document is corrected at the provider (A3), not here.
            return "provider"
        source = _source_of(correction)
        if source is None:
            return "waiting_for_source"
        key = _completion_key(correction, source)
        waiting = _earlier_undecided(correction, original, key)
        if waiting:
            logger.info(f"🐢 [Storno] Correction {correction.pk} waits: {waiting}")
            return "waiting_for_earlier"

        refund_currencies = set(Refund.objects.filter(pk__in=source.refund_ids).values_list("currency_id", flat=True))
        if refund_currencies != {original.currency_id}:
            correction.fail(
                code=FAILURE_ALLOCATION_REFUSED,
                error=f"currency_mismatch: refunds in {sorted(refund_currencies)}, invoice in {original.currency_id}",
            )
            correction.save()
            return "refused"

        credited = _credited_so_far(original, excluding=correction)
        whole = Components(original.subtotal_cents, original.tax_cents, original.discount_cents)
        remaining = whole.minus(credited)
        collected = collected_cents_for_invoice(original)
        if original.status in FULLY_COLLECTED_INVOICE_STATES:
            # The same floor as `net_collected_cents_for_invoice`: a paid invoice was collected in full.
            collected = max(collected, original.total_cents)
        held_before = collected - _refunded_by_earlier(original, correction, key)
        gross = owed_reduction(
            refund_cents=source.refunded_cents,
            net_collected_before_cents=held_before,
            remaining_total_cents=remaining.total_cents,
        )
        if gross == 0:
            reason = REASON_FULLY_CREDITED if remaining.total_cents <= 0 else REASON_COVERED_BY_COLLECTIONS
            correction.mark_not_required(reason)
            correction.save()
            logger.info(f"✅ [Storno] Correction {correction.pk} needs no credit note: {reason}")
            return "not_required"

        if not original.lines.exists():
            correction.fail(code=FAILURE_ALLOCATION_REFUSED, error="original_has_no_lines: nothing to restate")
            correction.save()
            return "refused"
        try:
            allocation = allocate(
                gross_cents=gross,
                remaining=remaining,
                rate=_single_rate(original),
                untouched=credited == Components(0, 0, 0),
            )
        except AllocationRefusedError as refused:
            correction.fail(code=FAILURE_ALLOCATION_REFUSED, error=f"{refused.code}: {refused}")
            correction.save()
            logger.error(f"🔥 [Storno] Correction {correction.pk} cannot be allocated: {refused.code}: {refused}")
            return "refused"

        correction.allocate(
            base_cents=allocation.base_cents,
            tax_cents=allocation.tax_cents,
            discount_cents=allocation.discount_cents,
            at=timezone.now(),
        )
        correction.save()
        logger.info(f"✅ [Storno] Correction {correction.pk} allocated {allocation.total_cents} cents")
        return "allocated"


# ===============================================================================
# 2. ISSUANCE
# ===============================================================================


def _advance_issuance(correction_id: str) -> str:
    """Draft, lines, number and issue in ONE transaction, against the frozen allocation."""
    try:
        with transaction.atomic():
            correction = FiscalCorrection.objects.select_for_update().filter(pk=correction_id).first()
            # Checked before the original is locked: a replay, or a worker that lost the race, must
            # see the note already issued here rather than park itself against its own note below.
            if correction is None or correction.state not in {STATE_ALLOCATED, STATE_FAILED}:
                return "skipped"
            if not correction.is_allocated or correction.original_id is None:
                return "skipped"
            original = Invoice.objects.select_for_update().get(pk=correction.original_id)
            if Invoice.objects.filter(reverses_invoice=original).exists():
                raise _SecondCreditNoteError
            note = _issue_credit_note(correction, original)
            correction.record_issued(note)
            correction.owe_efactura()
            correction.save()
    except _SecondCreditNoteError:
        message = (
            "The original already has a credit note and a second one cannot be written until the "
            "one-reversal-per-original rule is lifted (A3). Parked with its allocation; retried by the sweep."
        )
        logger.warning(f"⚠️ [Storno] Correction {correction_id}: {message}")
        _record_failure(correction_id, FAILURE_SECOND_CREDIT_NOTE, message)
        return "parked"
    logger.info(f"✅ [Storno] Correction {correction_id} issued credit note {note.number}")
    return "issued"


def _issue_credit_note(correction: FiscalCorrection, original: Invoice) -> Invoice:
    """Create, number and issue the note. Runs inside the caller's transaction, all or nothing."""
    from .credit_note_lines import mirror_lines_negated  # noqa: PLC0415  # Keeps the import graph acyclic
    from .numbering_service import InvoiceNumberingService  # noqa: PLC0415
    from .tax_evidence import capture_credit_note_evidence  # noqa: PLC0415

    assert correction.base_cents is not None and correction.tax_cents is not None  # allocated
    assert correction.discount_cents is not None and correction.total_cents is not None
    note = Invoice.objects.create(
        customer_id=original.customer_id,
        currency_id=original.currency_id,
        number=None,
        status="draft",
        document_kind=DOCUMENT_KIND_CREDIT_NOTE,
        reverses_invoice=original,
        issuer_provider=ISSUER_BUILTIN,
        subtotal_cents=correction.base_cents,
        tax_cents=correction.tax_cents,
        total_cents=correction.total_cents,
        discount_cents=correction.discount_cents,
        # Written before `issue()`, so the decision is never later than the document it describes.
        vat_evidence=capture_credit_note_evidence(
            original,
            subtotal_cents=correction.base_cents,
            tax_cents=correction.tax_cents,
            total_cents=correction.total_cents,
        ),
        # The original's rate, all four fields, so `issue()` consumes it rather than today's rate.
        exchange_to_ron=original.exchange_to_ron,
        exchange_rate_as_of=original.exchange_rate_as_of,
        exchange_rate_source=original.exchange_rate_source,
        exchange_rate_source_reference=original.exchange_rate_source_reference,
        # A correction inherits the fiscal identity of the document it corrects.
        **{field: getattr(original, field) for field in sorted(Invoice._BILLING_SNAPSHOT_FIELDS)},
        meta={"fiscal_correction_id": str(correction.pk)},
    )
    whole_original = (correction.base_cents, correction.tax_cents, correction.discount_cents) == (
        -original.subtotal_cents,
        -original.tax_cents,
        -original.discount_cents,
    )
    if whole_original:
        # Only an allocation made while nothing was credited can equal the whole original.
        mirror_lines_negated(original, note)
    else:
        _write_single_line(note, original, correction)

    # Numbered from the original's family; an archived series answers to the live one.
    scope = sequence_family_of(original.sequence_scope)
    note.number = InvoiceNumberingService.get_next_number(scope=scope)
    note.sequence_scope = scope
    note.issue()
    note.save()
    return note


def _write_single_line(note: Invoice, original: Invoice, correction: FiscalCorrection) -> None:
    """One negated line carrying exactly the allocation.

    Through `bulk_create`, which skips `InvoiceLine.save()`: that recomputes the VAT from the base,
    and for a gross like 10.00 at 21% (base 8.26) it would write 1.73 instead of the allocated 1.74,
    so the line would stop matching the header and the customer would be credited 9.99.
    """
    assert correction.base_cents is not None and correction.tax_cents is not None  # allocated
    assert correction.discount_cents is not None
    template = original.lines.order_by("sort_order", "pk").first()
    assert template is not None  # Allocation refuses an original without lines.
    gross_before_discount = correction.base_cents + correction.discount_cents  # both <= 0
    InvoiceLine.objects.bulk_create(
        [
            InvoiceLine(
                invoice=note,
                kind=template.kind,
                description=f"Storno factura {original.number} / Credit for invoice {original.number}"[:500],
                quantity=Decimal("1.000"),
                unit_price_cents=gross_before_discount,
                tax_rate=template.tax_rate,
                tax_cents=correction.tax_cents,
                line_total_cents=gross_before_discount + correction.tax_cents,
                unit_code=template.unit_code,
                tax_category_code=template.tax_category_code,
                discount_amount_cents=0,
                sort_order=0,
            )
        ]
    )


# ===============================================================================
# 3. DELIVERY (after the issuance commits)
# ===============================================================================


def deliver_credit_note(correction_id: str) -> dict[str, str]:
    """Email the issued note, then file it with e-Factura. Each is resumed independently."""
    return {
        "communication": _run_delivery_step(correction_id, _advance_communication),
        "efactura": _run_delivery_step(correction_id, _advance_efactura),
    }


def _run_delivery_step(correction_id: str, step: Any) -> str:
    try:
        return str(step(correction_id))
    except Exception:
        logger.exception(f"🔥 [Storno] Fiscal correction {correction_id}: {step.__name__} failed; the sweep retries")
        return "failed"


def _send_credit_note_email(note: Invoice) -> tuple[bool, str]:
    """Send the note's PDF to the customer, synchronously: success here means it was sent."""
    from apps.customers.services import get_customer_locale  # noqa: PLC0415  # ADR-0007 cross-app import
    from apps.notifications.services import EmailService  # noqa: PLC0415  # ADR-0007 cross-app import

    from .pdf_generators import generate_invoice_pdf  # noqa: PLC0415

    customer = note.customer
    original = note.reverses_invoice
    assert original is not None  # A credit note always reverses an invoice.
    recipient = note.bill_to_email or customer.primary_email
    if not recipient:
        return False, "No email address for the customer"
    assert note.issued_at is not None  # Issued before delivery is attempted.
    context = {
        "customer_name": customer.get_display_name(),
        "credit_note_number": note.number,
        "credit_note_date": ro_local_date(note.issued_at).isoformat(),
        "original_number": original.number,
        "original_date": ro_local_date(original.issued_at).isoformat() if original.issued_at else "",
        "total_credited": f"{abs(note.total):.2f}",
        "currency": note.currency.code,
    }
    result = EmailService.send_template_email(
        template_key="credit_note_issued",
        recipient=recipient,
        context=context,
        # The customer's primary user's language, Romanian by default; there is no locale on Customer.
        locale=get_customer_locale(customer),
        customer=customer,
        priority="high",
        attachments=[(f"storno_{note.number}.pdf", generate_invoice_pdf(note), "application/pdf")],
        async_send=False,
    )
    return bool(result.success), str(result.error or "")


def _advance_communication(correction_id: str) -> str:
    """Send once; the first success dates the note. A failure is counted and left for the sweep."""
    correction = FiscalCorrection.objects.select_related("credit_note").filter(pk=correction_id).first()
    if correction is None or correction.state != STATE_ISSUED or correction.credit_note is None:
        return "skipped"
    try:
        # Its own savepoint, with the exception caught outside it: the send writes rows of its own,
        # and on PostgreSQL an error swallowed without a savepoint aborts whatever encloses it.
        with transaction.atomic():
            sent, error = _send_credit_note_email(correction.credit_note)
    except Exception as exc:
        logger.exception(f"🔥 [Storno] Sending credit note {correction.credit_note_id} failed")
        sent, error = False, f"{type(exc).__name__}: {exc}"

    with transaction.atomic():
        locked = FiscalCorrection.objects.select_for_update().get(pk=correction_id)
        if locked.state != STATE_ISSUED:
            # Another worker recorded the first send; its date stands.
            return "already_communicated"
        if sent:
            sent_at = timezone.now()
            locked.record_communicated(at=sent_at, fiscal_date=ro_local_date(sent_at))
        else:
            locked.record_communication_failure(error or "The email was not sent")
        locked.save()
    if not sent:
        logger.warning(f"⚠️ [Storno] Credit note for correction {correction_id} not sent yet: {error}")
        return "failed"
    return "communicated"


def _advance_efactura(correction_id: str) -> str:
    """File the note with ANAF through the service's own gate; record where it stands."""
    from .efactura.service import GATE_READY, EFacturaService, credit_note_submission_gate  # noqa: PLC0415

    correction = FiscalCorrection.objects.select_related("credit_note").filter(pk=correction_id).first()
    if (
        correction is None
        or correction.state not in {STATE_ISSUED, STATE_COMMUNICATED}
        or correction.efactura_status not in EFACTURA_RETRYABLE
        or correction.credit_note is None
    ):
        return "skipped"
    note = correction.credit_note
    gate = credit_note_submission_gate(note)
    error = ""
    if gate != GATE_READY:
        outcome = gate
    elif not getattr(settings, "EFACTURA_ENABLED", False):
        # Nothing is filed while e-Factura is switched off; the submission stays owed.
        return "disabled"
    else:
        result = EFacturaService().submit_invoice(note)
        outcome = EFACTURA_SUBMITTED if result.success else (result.gate or EFACTURA_FAILED)
        error = "" if result.success else result.error_message

    with transaction.atomic():
        locked = FiscalCorrection.objects.select_for_update().get(pk=correction_id)
        if locked.efactura_status not in EFACTURA_RETRYABLE:
            return str(locked.efactura_status)
        if (locked.efactura_status, locked.efactura_error) != (outcome, error[:2000]):
            locked.record_efactura(outcome, error)
            locked.save()
    return outcome


# ===============================================================================
# RECOVERY
# ===============================================================================


def _unfinished_corrections() -> models.QuerySet[FiscalCorrection]:
    """Every correction with a step still to take, on a built-in original."""
    issuance_owed = models.Q(
        state__in=[STATE_PENDING, STATE_ALLOCATED, STATE_FAILED], original__issuer_provider=ISSUER_BUILTIN
    )
    communication_owed = models.Q(state=STATE_ISSUED)
    efactura_owed = models.Q(state__in=[STATE_ISSUED, STATE_COMMUNICATED], efactura_status__in=EFACTURA_RETRYABLE)
    return FiscalCorrection.objects.filter(issuance_owed | communication_owed | efactura_owed).order_by(
        "created_at", "pk"
    )


def sweep_fiscal_correction_issuance(limit: int = 200) -> dict[str, int]:
    """Resume every unfinished correction, each step on its own, by correction id.

    Never re-allocates and never renumbers: allocation and issuance both refuse a correction that
    has already passed them. The cursor rotates through candidates like the other billing sweeps,
    so a few parked corrections cannot hold every run while a recoverable one waits behind them.
    """
    from django.core.cache import cache  # noqa: PLC0415

    from .issuers.tasks import _cursor_for, _resume_after  # noqa: PLC0415  # Shared keyset paging

    candidates = _unfinished_corrections()
    cursor = cache.get(_SWEEP_CURSOR_KEY)
    batch = list(_resume_after(candidates, cursor).values_list("pk", "created_at")[:limit])
    if not batch and cursor:
        batch = list(candidates.values_list("pk", "created_at")[:limit])
    if batch:
        last_pk, last_created = batch[-1]
        cache.set(_SWEEP_CURSOR_KEY, _cursor_for(_CursorRow(last_pk, last_created)), timeout=None)
    else:
        cache.set(_SWEEP_CURSOR_KEY, None, timeout=None)

    results = {"examined": len(batch), "errors": 0}
    for correction_id, _created in batch:
        try:
            process_fiscal_correction(str(correction_id))
        except Exception:
            results["errors"] += 1
            logger.exception(f"🔥 [Storno] Sweep could not advance correction {correction_id}")
    if batch:
        logger.info(f"🐢 [Storno] Swept {results['examined']} correction(s), {results['errors']} error(s)")
    return results


@dataclass(frozen=True)
class _CursorRow:
    pk: Any
    created_at: datetime
