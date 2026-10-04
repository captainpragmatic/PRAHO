"""Issuing the storno credit note a fiscal correction owes (ADR-0053).

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

A provider (SmartBill) original is allocated the same way and issued at the provider instead
(ADR-0048). Its reverse call carries no amount, so it is used only when this correction credits the
whole original and nothing has credited it before; any other correction waits as `manual_required`
for staff to issue it at the provider and record it. The provider files its own documents with
e-Factura, so no submission is owed for them here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from django.db import models, transaction
from django.db.models.functions import Coalesce
from django.utils import timezone

from apps.common.types import Err
from apps.common.validators import log_security_event

from .efactura.settings import ro_local_date
from .fiscal_correction_allocation import AllocationRefusedError, Components, allocate, owed_reduction
from .fiscal_correction_models import (
    EFACTURA_FAILED,
    EFACTURA_NOT_APPLICABLE,
    EFACTURA_PENDING,
    EFACTURA_RETRYABLE,
    EFACTURA_SUBMITTED,
    FAILURE_ALLOCATION_REFUSED,
    FAILURE_ISSUANCE_ERROR,
    REASON_COVERED_BY_COLLECTIONS,
    REASON_FULLY_CREDITED,
    STATE_ALLOCATED,
    STATE_ATTACHED,
    STATE_COMMUNICATED,
    STATE_FAILED,
    STATE_ISSUED,
    STATE_MANUAL_REQUIRED,
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
from .refund_models import collected_cents_for_invoice, refunds_for_invoice

logger = logging.getLogger(__name__)

TASK_PATH = "apps.billing.fiscal_correction_worker.process_fiscal_correction"
TASK_TIMEOUT_SECONDS = 300
_SWEEP_CURSOR_KEY = "billing:fiscal-correction-issuance-cursor"
# A sender's claim on the communication; longer than any synchronous send, short enough to recover.
COMMUNICATION_CLAIM_LEASE = timedelta(minutes=5)
EFACTURA_FIRST_BACKOFF = timedelta(hours=1)
EFACTURA_MAX_BACKOFF = timedelta(days=7)
# 2 ** 8 hours is past the week, so no larger exponent can change the result.
_MAX_BACKOFF_EXPONENT = 8

# States in which an earlier correction no longer competes for issuance. One waiting for staff is
# out of the race: its document is issued at the provider, numbered there, whenever staff get to it.
_ISSUANCE_SETTLED_STATES = frozenset(
    {STATE_ISSUED, STATE_COMMUNICATED, STATE_NOT_REQUIRED, STATE_ATTACHED, STATE_MANUAL_REQUIRED}
)
# States in which an earlier correction has decided its amount, so a later one can build on it.
_DECIDED_STATES = frozenset(
    {STATE_ALLOCATED, STATE_ISSUED, STATE_COMMUNICATED, STATE_NOT_REQUIRED, STATE_ATTACHED, STATE_MANUAL_REQUIRED}
)
_AT_PROVIDER = "at_provider"
# The security event a correction raises when it needs staff at the provider.
MANUAL_STORNO_EVENT = "provider_partial_refund_needs_manual_correction"


@dataclass(frozen=True)
class _Source:
    """What a correction answers for: its completed refunds, or None while a command is unfinished."""

    refund_ids: tuple[Any, ...]
    refunded_cents: int
    completed_at: datetime


def queue_fiscal_correction(correction_id: Any) -> bool:
    """Hand one correction to the worker; whether it was queued. A lost enqueue costs only time: the sweep finds it."""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task(TASK_PATH, str(correction_id), timeout=TASK_TIMEOUT_SECONDS)
    except Exception:
        logger.exception(f"🔥 [Storno] Could not queue fiscal correction {correction_id}; the sweep will pick it up")
        return False
    return True


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
        .filter(status="completed", fiscal_correction__isnull=True)
        .annotate(completed_at=Coalesce("processed_at", "created_at"))
        .filter(completed_at__lt=key[0])
        .exclude(tender_leg__command__fiscal_correction__isnull=False)
    )
    first = unrecorded.order_by("completed_at").first()
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
    # A note that answers to an allocation is counted through it, never twice: settled, or still a
    # provider draft its correction is issuing. An unnumbered draft credits nothing.
    other_notes = (
        Invoice.objects.filter(reverses_invoice=original, number__isnull=False)
        .exclude(settled_fiscal_correction__allocated_at__isnull=False)
        .exclude(provider_issuance__fiscal_correction__isnull=False)
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


def _held_before(original: Invoice, correction: FiscalCorrection, source: _Source) -> int:
    """What the ledger held against `original` just before this correction's refunds completed.

    As of that moment, not as of whenever the worker runs: a payment arriving later, a dispute, or the
    invoice becoming paid afterwards must not change the answer.

    * Collected: payments by what was true then (`collected_cents_for_invoice(as_of=...)`).
    * The paid floor (`net_collected_cents_for_invoice` floors a paid invoice at its total, for a
      ledger that cannot show every payment) applies only if the invoice was paid by then. `paid_at`
      is set once, by `mark_as_paid`, and nothing clears it: refunding moves a paid invoice to
      partially_refunded or refunded and back, never to an unpaid state.
    * Returned already: the refunds of the corrections ordered before this one, by the worker's own
      `_completion_key`, so refunds sharing a timestamp are subtracted in the order their corrections
      are decided and never twice or not at all.
    * Every other completed refund of this invoice is placed by its completion time, and counts if
      it completed before this one: the completed legs of a tender command that has not finished
      (its correction has no source yet, though the money has left), a refund with no correction on
      this invoice (one completed while the invoice was a draft is recorded not-required with no
      original), and a refund whose correction is on another original.
    """
    collected = collected_cents_for_invoice(original, as_of=source.completed_at)
    if original.paid_at is not None and original.paid_at <= source.completed_at:
        collected = max(collected, original.total_cents)

    key = _completion_key(correction, source)
    returned = 0
    keyed_refund_ids = set(source.refund_ids)
    for other in FiscalCorrection.objects.filter(original=original).exclude(pk=correction.pk):
        other_source = _source_of(other)
        if other_source is None:
            continue  # An unfinished tender command: its completed legs fall to the time rule below.
        keyed_refund_ids.update(other_source.refund_ids)
        if _completion_key(other, other_source) < key:
            returned += other_source.refunded_cents
    outside = (
        refunds_for_invoice(original)
        .filter(status="completed")
        .exclude(pk__in=keyed_refund_ids)
        .annotate(completed_at=Coalesce("processed_at", "created_at"))
        .filter(completed_at__lt=source.completed_at)
        .aggregate(total=models.Sum("amount_cents", default=0))["total"]
    )
    return collected - returned - int(outside)


def _earlier_not_issued(correction: FiscalCorrection, original: Invoice) -> str:
    """Why an earlier correction on this original must settle before this one issues, or ""."""
    key = _completion_key(correction, _source_of(correction))
    for other in FiscalCorrection.objects.filter(original=original).exclude(pk=correction.pk):
        if other.state not in _ISSUANCE_SETTLED_STATES and _completion_key(other, _source_of(other)) < key:
            return f"earlier correction {other.pk} is {other.state}"
    return ""


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
        held_before = _held_before(original, correction, source)
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
                credited=credited,
                rate=_single_rate(original),
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
            vat_residue_cents=allocation.vat_residue_cents,
        )
        correction.save()
        if allocation.vat_residue_cents:
            # Owner decision (ADR-0053): the note stays valid and the cent or two is recorded, not hidden.
            logger.warning(
                f"⚠️ [Storno] Correction {correction.pk} leaves {allocation.vat_residue_cents} cent(s) of VAT of "
                f"invoice {original.number} un-reversed, so that its credit note stays within BR-CO-14"
            )
        logger.info(f"✅ [Storno] Correction {correction.pk} allocated {allocation.total_cents} cents")
        return "allocated"


# ===============================================================================
# 2. ISSUANCE
# ===============================================================================


def _advance_issuance(correction_id: str) -> str:
    """Issue the frozen allocation: built-in here, at the provider, or by staff at the provider."""
    with transaction.atomic():
        correction = FiscalCorrection.objects.select_for_update().filter(pk=correction_id).first()
        # Checked before the original is locked: a replay, or a worker that lost the race, must
        # see the note already issued here rather than wait on a correction it settled itself.
        if correction is None or correction.state not in {STATE_ALLOCATED, STATE_FAILED}:
            return "skipped"
        if not correction.is_allocated or correction.original_id is None:
            return "skipped"
        if Invoice.objects.filter(pk=correction.original_id, issuer_provider=ISSUER_BUILTIN).exists():
            route = _issue_builtin(correction)
        else:
            route = _route_provider_correction(correction)
    if route == _AT_PROVIDER:
        # Only now, with the transaction closed: the provider call refuses to run inside one (ADR-0045).
        return _issue_at_provider(correction_id)
    return route


def _issue_builtin(correction: FiscalCorrection) -> str:
    """Number and issue the built-in note, under the original's lock, in the caller's transaction."""
    assert correction.original_id is not None  # The caller skips a correction with no original.
    original = Invoice.objects.select_for_update().get(pk=correction.original_id)
    # In refund-completion order, like allocation: notes of one original are numbered in the order
    # their refunds completed, whichever worker reaches this line first.
    waiting = _earlier_not_issued(correction, original)
    if waiting:
        logger.info(f"🐢 [Storno] Correction {correction.pk} waits to issue: {waiting}")
        return "waiting_for_earlier"
    note = _issue_credit_note(correction, original)
    correction.record_issued(note)
    correction.owe_efactura()
    correction.save()
    logger.info(f"✅ [Storno] Correction {correction.pk} issued credit note {note.number}")
    return "issued"


def _route_provider_correction(correction: FiscalCorrection) -> str:
    """A provider original: reverse it whole at the provider, or hand the correction to staff.

    Runs under the correction's lock and never takes the original's. Reversal locks the original
    and then its issuance, and recording the outcome locks the issuance and then this correction;
    taking the original here as well would close that cycle. The original's issuer and the
    allocation are both frozen, so nothing read here can change, and reversal re-checks the
    whole-document rule under its own lock before anything is sent.
    """
    from .issuers.service import whole_document_storno_refusal  # noqa: PLC0415  # Keeps imports acyclic

    assert correction.original_id is not None  # The caller skips a correction with no original.
    original = Invoice.objects.get(pk=correction.original_id)
    waiting = _earlier_not_issued(correction, original)
    if waiting:
        logger.info(f"🐢 [Storno] Correction {correction.pk} waits to issue: {waiting}")
        return "waiting_for_earlier"
    refusal = whole_document_storno_refusal(correction, original)
    if refusal is None:
        return _AT_PROVIDER

    correction.require_manual_issuance()
    correction.save()
    logger.error(
        f"🔥 [Storno] Correction {correction.pk} credits {correction.total_cents} cents of provider invoice "
        f"{original.number}, which the provider's reverse cannot express ({refusal}). Issue it at the provider "
        f"and record it against the correction."
    )
    details = {
        "fiscal_correction_id": str(correction.pk),
        "invoice_number": str(original.number),
        "issuer_provider": str(original.issuer_provider),
        "customer_id": str(original.customer_id),
        "credit_cents": str(correction.total_cents),
    }
    # Raised once the hand-over commits, never for one that rolled back.
    transaction.on_commit(lambda: log_security_event(event_type=MANUAL_STORNO_EVENT, details=details))
    return "manual_required"


def _issue_at_provider(correction_id: str) -> str:
    """Reverse the original at its provider for this correction; the outcome settles the correction."""
    from .issuers.service import issue_storno_for_correction  # noqa: PLC0415  # Keeps imports acyclic

    try:
        result = issue_storno_for_correction(correction_id)
    except Exception:
        # The issuance record says what happened at the provider; the sweep resumes from it.
        logger.exception(f"🔥 [Storno] Correction {correction_id}: the provider reversal failed")
        return "failed"
    if isinstance(result, Err):
        logger.warning(f"⚠️ [Storno] Correction {correction_id} not reversed at the provider yet: {result.error}")
        return "provider_waiting"
    logger.info(f"✅ [Storno] Correction {correction_id} reversed at the provider as {result.unwrap()}")
    return "issued"


def _issue_credit_note(correction: FiscalCorrection, original: Invoice) -> Invoice:
    """Create, number and issue the note. Runs inside the caller's transaction, all or nothing."""
    from .numbering_service import InvoiceNumberingService  # noqa: PLC0415

    note = draft_credit_note(correction, original, issuer_provider=ISSUER_BUILTIN)
    # Numbered from the original's family; an archived series answers to the live one.
    scope = sequence_family_of(original.sequence_scope)
    note.number = InvoiceNumberingService.get_next_number(scope=scope)
    note.sequence_scope = scope
    note.issue()
    note.save()
    return note


def draft_credit_note(
    correction: FiscalCorrection, original: Invoice, *, issuer_provider: str, evidence_at: datetime | None = None
) -> Invoice:
    """The unnumbered credit note carrying exactly the correction's allocation, lines included.

    Runs inside the caller's transaction; the caller numbers and issues it, or rolls it back.
    `evidence_at` dates the restated VAT decision for a note issued before it is recorded here.
    """
    from .credit_note_lines import mirror_lines_negated  # noqa: PLC0415  # Keeps the import graph acyclic
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
        issuer_provider=issuer_provider,
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
            calculated_at=evidence_at,
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
    """Send the note's PDF to the customer, synchronously: success here means it was sent.

    The PDF is the document's own (ADR-0048): PRAHO's rendering of a built-in note, the provider's
    of a provider note. A provider fetch the rate gate defers raises, and is retried like a failed send.
    """
    from apps.customers.services import get_customer_locale  # noqa: PLC0415  # ADR-0007 cross-app import
    from apps.notifications.services import EmailService  # noqa: PLC0415  # ADR-0007 cross-app import

    from .issuers.documents import get_invoice_pdf_bytes  # noqa: PLC0415

    pdf = get_invoice_pdf_bytes(note)
    if isinstance(pdf, Err):
        return False, f"The credit note's PDF is not available: {pdf.error}"
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
        attachments=[(f"storno_{note.number}.pdf", pdf.unwrap(), "application/pdf")],
        async_send=False,
    )
    return bool(result.success), str(result.error or "")


def _claim_communication(correction_id: str) -> FiscalCorrection | None:
    """Claim the send in a short transaction of its own, committed before anything is sent."""
    with transaction.atomic():
        # `of=("self",)`: PostgreSQL refuses FOR UPDATE on the nullable side of the credit-note join.
        locked = (
            FiscalCorrection.objects.select_for_update(of=("self",))
            .select_related("credit_note")
            .filter(pk=correction_id)
        )
        correction = locked.first()
        if correction is None or correction.credit_note is None:
            return None
        if not correction.claim_communication(now=timezone.now(), lease=COMMUNICATION_CLAIM_LEASE):
            return None
        correction.save(update_fields=["communication_claimed_at", "updated_at"])
        return correction


def _advance_communication(correction_id: str) -> str:
    """Claim, send outside any transaction, then record the first success once.

    Claim-then-send: the claim commits before the email leaves, so a second worker racing this one
    finds it and does not send again. A claim whose sender died is retaken after the lease.
    Delivery is at least once (ADR-0053): a sender that dies after the email left but before the
    success is recorded gets it sent again once the lease lapses.
    """
    correction = _claim_communication(correction_id)
    if correction is None or correction.credit_note is None:
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
            # A sender whose claim had lapsed recorded the first send meanwhile; its date stands.
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
    from .efactura.service import (  # noqa: PLC0415  # Kept out of the model import graph
        GATE_READY,
        EFacturaService,
        credit_note_submission_gate,
        is_efactura_enabled,
    )

    correction = FiscalCorrection.objects.select_related("credit_note").filter(pk=correction_id).first()
    if (
        correction is None
        or correction.state not in {STATE_ISSUED, STATE_COMMUNICATED}
        or correction.efactura_status not in EFACTURA_RETRYABLE
        or correction.credit_note is None
    ):
        return "skipped"
    if correction.efactura_next_attempt_at is not None and correction.efactura_next_attempt_at > timezone.now():
        return "backing_off"
    note = correction.credit_note
    gate = credit_note_submission_gate(note)
    error = ""
    if not is_efactura_enabled():
        # The service files nothing while e-Factura is switched off, so there is no submission owed
        # to wait for; held as `waiting_for_original` it would be re-checked forever.
        outcome = EFACTURA_NOT_APPLICABLE
    elif gate != GATE_READY:
        outcome = gate
    else:
        result = EFacturaService().submit_invoice(note)
        if result.success and result.registered_with_anaf:
            outcome, error = EFACTURA_SUBMITTED, ""
        elif result.success:
            # `success` also answers for another worker's upload still in flight: ANAF has registered
            # nothing yet, so the submission stays owed and is looked at again after the backoff.
            outcome = EFACTURA_PENDING
            error = f"An upload is in flight ({result.document_status or 'unknown'}); not registered yet"
        else:
            outcome, error = (result.gate or EFACTURA_FAILED), result.error_message

    with transaction.atomic():
        locked = FiscalCorrection.objects.select_for_update().get(pk=correction_id)
        if locked.efactura_status not in EFACTURA_RETRYABLE:
            return str(locked.efactura_status)
        retry_at = (
            timezone.now() + efactura_backoff(locked.efactura_attempts + 1) if outcome in EFACTURA_RETRYABLE else None
        )
        locked.record_efactura(outcome, error, next_attempt_at=retry_at)
        locked.save()
    return outcome


def efactura_backoff(attempt: int) -> timedelta:
    """How long to wait after the `attempt`-th held or failed filing: doubling, capped at a week.

    The correction stays visible in `waiting_for_original` or `failed` with its next attempt time;
    it is only re-checked less and less often, rather than every hour forever.
    """
    # The exponent is capped before it is used: 2 ** 35 hours already overflows a timedelta, and an
    # attempt that raises is never recorded, so every later sweep would raise again.
    doubled: timedelta = EFACTURA_FIRST_BACKOFF * (2 ** min(max(0, attempt - 1), _MAX_BACKOFF_EXPONENT))
    return min(doubled, EFACTURA_MAX_BACKOFF)


# ===============================================================================
# RECOVERY
# ===============================================================================


def _unfinished_corrections() -> models.QuerySet[FiscalCorrection]:
    """Every correction with a step still to take.

    Not one whose provider reversal waits for a person: an unknown outcome or a spent submission
    budget is the reconciliation queue's, and a live claim is its worker's or the abandoned-claim
    sweep's. Retrying them hourly would only be refused again. `manual_required` is not here either:
    staff settle it.
    """
    from .issuers.models import MAX_SUBMISSIONS, IssuanceState  # noqa: PLC0415  # Kept out of the model graph

    provider_waits_for_a_person = models.Q(
        provider_issuance__state__in=[IssuanceState.OUTCOME_UNKNOWN.value, IssuanceState.CLAIMED.value]
    ) | models.Q(
        provider_issuance__state__in=[IssuanceState.PENDING.value, IssuanceState.FAILED.value],
        provider_issuance__submissions__gte=MAX_SUBMISSIONS,
    )
    issuance_owed = models.Q(state__in=[STATE_PENDING, STATE_ALLOCATED, STATE_FAILED]) & ~provider_waits_for_a_person
    communication_owed = models.Q(state=STATE_ISSUED)
    efactura_owed = models.Q(state__in=[STATE_ISSUED, STATE_COMMUNICATED], efactura_status__in=EFACTURA_RETRYABLE) & (
        models.Q(efactura_next_attempt_at__isnull=True) | models.Q(efactura_next_attempt_at__lte=timezone.now())
    )
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
