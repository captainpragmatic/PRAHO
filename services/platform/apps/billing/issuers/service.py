"""Orchestrating one external issuance attempt.

The shape follows ADR-0045, for the same reason that ADR exists: a provider
mutation that is not bracketed by committed local state can leave the provider
holding something PRAHO has no record of.

    PHASE 0  refuse to run inside a transaction at all
    PHASE 1  [txn] claim the attempt, freeze the payload           COMMIT
    PHASE 2  ---- network ----  (no transaction open)
    PHASE 3  [txn] record the outcome                               COMMIT

The reason PHASE 1 commits before the call: SmartBill has no idempotency key and
no way to look up a document by our reference. If the process dies mid-call and we
never wrote that an attempt began, nobody can ever find out whether an invoice
exists. The claim row is the only thread back.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any, assert_never

from django.db import connection, transaction

from apps.billing.credit_note_lines import mirror_lines_negated
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    DOCUMENT_KIND_INVOICE,
    ISSUER_BUILTIN,
    SEQUENCE_SCOPE_DEFAULT,
    Invoice,
)
from apps.billing.tax_evidence import capture_credit_note_evidence
from apps.common.types import Err, Ok, Result

from .base import Ambiguous, Issued, PreparedDocument, Rejected
from .models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance
from .policy import resolve_issuer
from .smartbill.client import RateGateWait

if TYPE_CHECKING:
    from apps.billing.fiscal_correction_models import FiscalCorrection

    from .base import IssueOutcome

logger = logging.getLogger(__name__)


class IssuanceTransactionError(RuntimeError):
    """Raised when issuance is attempted inside an enclosing transaction."""


def _refuse_if_inside_transaction() -> None:
    """Fail closed before any row is written or any call is made.

    Inside an enclosing atomic block the claim would only be a savepoint, so an
    outer rollback would erase PRAHO's record of a call the provider already saw —
    the exact orphan ADR-0045 was written about.
    """
    if connection.in_atomic_block or not transaction.get_autocommit():
        raise IssuanceTransactionError(
            "External issuance must not run inside a transaction: the claim has to "
            "commit before the provider call, or a rollback hides an issued document."
        )


def issue_invoice_externally(  # noqa: PLR0911  # One return per distinct refusal; collapsing them hides which guard fired
    invoice_id: int,
) -> Result[str, str]:
    """Issue one already-persisted, unnumbered invoice through its provider."""
    _refuse_if_inside_transaction()

    try:
        invoice = Invoice.objects.select_related("currency", "customer").get(pk=invoice_id)
    except Invoice.DoesNotExist:
        return Err(f"Invoice {invoice_id} does not exist")

    if invoice.document_kind != DOCUMENT_KIND_INVOICE:
        # A credit note reaches `pending` legitimately - pacing hands its claim back
        # that way - and the issuance sweep looks only at state and a missing number,
        # so without this it would be POSTed to /invoice instead of /invoice/reverse.
        # That mints a BRAND NEW fiscal document with negative amounts while the
        # invoice it was supposed to reverse stays outstanding, and a SmartBill
        # invoice that is not last in its series cannot be deleted afterwards.
        return Err("A credit note is issued through the reversal endpoint, not as a new invoice")

    if invoice.number:
        # Already numbered. Re-issuing would create a second legal document.
        return Ok(invoice.number)

    issuer = resolve_issuer(invoice)

    # Built BEFORE claiming, so the durable record contains the real request. If the
    # process dies mid-call, that payload is the only thread back to whatever may
    # exist at a provider that offers no lookup by our reference.
    prepared_result = issuer.prepare(invoice)
    if isinstance(prepared_result, Err):
        reason = "; ".join(prepared_result.error)
        logger.warning(f"⚠️ [Issuance] Invoice {invoice_id} cannot be mapped: {reason}")
        return Err(reason)
    prepared = prepared_result.unwrap()

    attempt_id = uuid.uuid4()
    claim_result = _claim(invoice, issuer.provider, attempt_id, prepared)
    if isinstance(claim_result, Err):
        return claim_result
    issuance_id = claim_result.unwrap()

    # ---- no transaction is open here, deliberately ----
    try:
        outcome = issuer.submit(prepared, attempt_id=attempt_id)
    except RateGateWait as deferred:
        return _defer_claim(issuance_id, deferred)

    return _finalize(invoice.pk, issuance_id, attempt_id, outcome)


def _claim(
    invoice: Invoice,
    provider: str,
    attempt_id: uuid.UUID,
    prepared: PreparedDocument,
) -> Result[uuid.UUID, str]:
    """Take exclusive ownership, freeze the payload, and commit before any call."""
    with transaction.atomic():
        issuance, _created = ProviderIssuance.objects.select_for_update().get_or_create(
            invoice=invoice,
            defaults={"provider": provider},
        )

        if issuance.state == IssuanceState.ISSUED.value:
            return Err("This invoice has already been issued by the provider")
        if issuance.state == IssuanceState.OUTCOME_UNKNOWN.value:
            # The whole point of that state: a human must look before anyone retries.
            return Err(
                "A previous attempt had an unknown outcome. A document may exist at the "
                "provider; reconcile it manually before issuing again."
            )
        if issuance.state == IssuanceState.CLAIMED.value:
            if issuance.claim_is_live:
                return Err("Another worker holds a live claim on this invoice")
            # An abandoned claim is quarantined, never retried. A crash immediately
            # before the POST and one immediately after the provider created the
            # document leave identical durable state, so expiry proves nothing.
            issuance.mark_outcome_unknown(
                reason="A worker abandoned this claim mid-flight; the provider may hold a document."
            )
            issuance.save()
            logger.error(
                f"🔥 [Issuance] Invoice {invoice.pk} had an abandoned claim; quarantined "
                f"for manual reconciliation rather than retried."
            )
            return Err("A previous attempt was abandoned mid-flight; reconcile it manually")

        # The budget is only real where ownership is taken. It lived in the sweep's WHERE
        # clause alone, so two sweeps running before a worker drained the queue enqueued
        # the same row twice and each task claimed independently - a live probe reached
        # five submissions against a cap of three. Checked AFTER the branches above so a
        # row that may hold a document at the provider is still routed to a human, and
        # before the claim so the counters and the provider's own words survive intact.
        if issuance.submissions >= MAX_SUBMISSIONS:
            return Err(
                f"This document has spent its {MAX_SUBMISSIONS} submission attempts; "
                f"an operator must decide what happens next."
            )

        issuance.claim(token=attempt_id, payload=prepared.payload, payload_hash=prepared.digest)
        issuance.save()
        return Ok(issuance.pk)


def _defer_claim(issuance_id: uuid.UUID, deferred: RateGateWait) -> Result[str, str]:
    """Hand the claim back so pacing costs a wait rather than a manual reconciliation.

    Without this the claim simply stays `claimed` until its lease expires and is then
    quarantined into `outcome_unknown` - a state only a human can leave. That would
    make an ordinary burst of traffic, which the rate gate exists to absorb, generate
    manual work per invoice. The gate refuses before anything is sent, so returning
    to `pending` is safe here and nowhere else; the sweep retries it.
    """
    with transaction.atomic():
        issuance = ProviderIssuance.objects.select_for_update().get(pk=issuance_id)
        if issuance.state != IssuanceState.CLAIMED.value:
            # Someone else already moved it on; leave their decision alone.
            return Err(f"Issuance is {issuance.state}, not deferred")
        issuance.release_unsent(reason=f"Paced by the provider rate gate until {deferred.available_at.isoformat()}")
        issuance.save()
    logger.info(f"🐢 [Issuance] Deferred until {deferred.available_at.isoformat()}; claim released for retry")
    return Err(f"Deferred by pacing until {deferred.available_at.isoformat()}")


def _converge_issued_payments(invoice: Invoice) -> Result[None, str]:
    """Converge pre-issuance credit and its usage cycle after legal issuance."""
    from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415
    from apps.promotions.locking import lock_document_context  # noqa: PLC0415

    if invoice.document_kind != DOCUMENT_KIND_INVOICE:
        return Ok(None)
    lock_document_context(invoice)
    payment_ids = list(invoice.payments.filter(status="succeeded").order_by("pk").values_list("pk", flat=True))
    for payment_id in payment_ids:
        convergence = PaymentSuccessService.converge_local_paid_document(payment_id)
        if convergence.is_err():
            return Err(convergence.unwrap_err())
    return Ok(None)


def _finalize(
    invoice_id: int,
    issuance_id: uuid.UUID,
    attempt_id: uuid.UUID,
    outcome: IssueOutcome,
) -> Result[str, str]:
    """Record what the provider did, under a lock, only if we still own the attempt.

    Reloaded rather than reused: between the claim and here a lease may have expired
    and another actor may have quarantined or reconciled this row. Writing a stale
    in-memory object over that decision would undo it silently.
    """
    with transaction.atomic():
        issuance = ProviderIssuance.objects.select_for_update().get(pk=issuance_id)
        invoice = Invoice.objects.select_for_update().get(pk=invoice_id)

        if issuance.state != IssuanceState.CLAIMED.value or issuance.claim_token != attempt_id:
            # Someone else moved this on. Keep the response as evidence, but do not
            # reopen or overwrite their decision.
            logger.error(
                f"🔥 [Issuance] Lost ownership of invoice {invoice_id} before finalising "
                f"(state={issuance.state}). Outcome recorded as evidence only."
            )
            return Err("Lost ownership of this issuance attempt; outcome not applied")

        # Reaching `_finalize` at all means `submit` returned rather than raising
        # `RateGateWait`, so a request did leave the machine. This is the honest place
        # to spend the retry budget.
        issuance.submissions += 1

        if isinstance(outcome, Issued):
            issuance.mark_issued(
                series=outcome.series,
                number=outcome.number,
                document_id=outcome.provider_document_id,
                response={"digest": outcome.response_digest},
            )
            issuance.save()

            # The number must land via the issue transition: `number` is a locked
            # fiscal-snapshot field and is only writable there.
            invoice.number = outcome.legal_number
            if issuance.provider == ISSUER_BUILTIN:
                # The built-in issuer numbers from the default family; a provider's series is its own.
                invoice.sequence_scope = SEQUENCE_SCOPE_DEFAULT
            invoice.issue()
            invoice.save()
            # Money may already have been recorded against this document while it was
            # an unnumbered draft - customer credit applied at creation, typically.
            # `mark_as_paid` only accepts an issued invoice, so that convergence has
            # to happen here, the moment the document legally exists.
            settlement = _converge_issued_payments(invoice)
            if settlement.is_err():
                transaction.set_rollback(True)
                return Err(settlement.unwrap_err())
            _settle_correction_with(invoice)
            logger.info(f"✅ [Issuance] Invoice {invoice_id} issued as {outcome.legal_number}")
            return Ok(outcome.legal_number)

        if isinstance(outcome, Rejected):
            reason = "; ".join(outcome.errors) or "Provider refused"
            issuance.mark_failed(error=reason)
            issuance.save()
            logger.warning(f"⚠️ [Issuance] Invoice {invoice_id} refused: {reason}")
            return Err(reason)

        if not isinstance(outcome, Ambiguous):
            # Exhaustiveness: adding a fourth outcome fails type-checking rather than
            # silently falling through to a default that would probably be wrong.
            assert_never(outcome)

        issuance.mark_outcome_unknown(reason=outcome.reason)
        issuance.save()
        logger.error(
            f"🔥 [Issuance] Invoice {invoice_id} has an UNKNOWN outcome: {outcome.reason}. "
            f"A document may exist at the provider. Manual reconciliation required; "
            f"this will NOT be retried automatically."
        )
        return Err(f"Outcome unknown, manual reconciliation required: {outcome.reason}")


def _settle_correction_with(document: Invoice) -> None:
    """Settle the fiscal correction a just-numbered storno was issued for.

    In its own savepoint, with the exception caught outside it: the provider has already issued
    this document, and losing PRAHO's record of THAT would be far worse than a correction left
    allocated, which its next worker run settles from this issuance without calling the provider.
    """
    if document.document_kind != DOCUMENT_KIND_CREDIT_NOTE:
        return
    try:
        with transaction.atomic():
            _record_issued_for(document)
    except Exception:
        logger.exception(
            f"🔥 [Issuance] Credit note {document.pk} is issued but its fiscal correction could not be "
            f"settled; the correction's next run settles it from this issuance."
        )


def _record_issued_for(document: Invoice) -> FiscalCorrection | None:
    """Move the correction this provider storno belongs to onto it. Idempotent."""
    from apps.billing.fiscal_correction_models import (  # noqa: PLC0415  # Keeps the model graph acyclic
        STATE_ALLOCATED,
        STATE_FAILED,
        FiscalCorrection,
    )

    correction_id = (
        ProviderIssuance.objects.filter(invoice=document).values_list("fiscal_correction_id", flat=True).first()
    )
    if correction_id is None:
        logger.error(
            f"🔥 [Issuance] Credit note {document.pk} answers to no fiscal correction; "
            f"it cannot settle one until an operator links it."
        )
        return None
    correction = FiscalCorrection.objects.select_for_update().get(pk=correction_id)
    if correction.credit_note_id == document.pk:
        return correction
    if correction.state not in {STATE_ALLOCATED, STATE_FAILED}:
        logger.error(
            f"🔥 [Issuance] Credit note {document.number} was issued for correction {correction.pk}, which is "
            f"{correction.state}; it is not linked until an operator decides."
        )
        return None
    correction.record_issued(document)
    correction.save()
    logger.info(f"✅ [Issuance] Correction {correction.pk} settled by provider credit note {document.number}")
    return correction


def reconcile_confirmed_issued(
    issuance_id: uuid.UUID,
    *,
    series: str,
    number: str,
    operator_note: str,
) -> Result[str, str]:
    """An operator checked the provider and found the document. Adopt its number.

    The only way out of `outcome_unknown` towards a numbered invoice, and it is
    deliberately manual: the provider exposes no lookup by our reference, so the
    identification is a human judgement that must be recorded as such.

    Takes an id rather than an instance, and reloads under a lock: two operators
    working the same queue would otherwise both pass a state check on their own
    stale copies, and the later save would silently overwrite the first adopted
    number with a different one.

    No `_refuse_if_inside_transaction` here, unlike its neighbours: that guard exists so
    a claim COMMITS before a provider call, and this command makes no call - an operator
    already checked by hand. Refusing an enclosing transaction only forced the caller to
    write the attribution for this act in a SEPARATE one, which is how a legal fiscal
    number could be assigned with no record of who decided it.
    """
    if not (number or "").strip():
        return Err("A provider document number is required to adopt a document")
    if not (operator_note or "").strip():
        return Err("A note recording what was checked at the provider is required")

    with transaction.atomic():
        issuance = ProviderIssuance.objects.select_for_update().get(pk=issuance_id)
        if issuance.state != IssuanceState.OUTCOME_UNKNOWN.value:
            return Err(f"Issuance is {issuance.state}, not awaiting reconciliation")

        legal_number = f"{series.strip()}-{number.strip()}" if series.strip() else number.strip()
        clash = Invoice.objects.filter(number=legal_number).exclude(pk=issuance.invoice_id).exists()
        if clash:
            # Adopting the same provider document onto a second invoice would create
            # two PRAHO records claiming one legal number.
            return Err(f"Number {legal_number} is already adopted by another invoice")

        invoice = Invoice.objects.select_for_update().get(pk=issuance.invoice_id)
        issuance.reconcile_as_issued(series=series.strip(), number=number.strip(), operator_note=operator_note.strip())
        issuance.save()

        invoice.number = legal_number
        invoice.issue()
        invoice.save()
        # The same convergence `_finalize` performs the moment a document legally exists,
        # and for the same reason: money may already be recorded against what was an
        # unnumbered draft. Without it an invoice already covered by payment or customer
        # credit stays `issued` at a zero balance, so `paid_at` is never set, payment
        # history and pending-service activation never run, and the issue signal can
        # schedule reminders for a customer who owes nothing. It is a no-op for a credit
        # note, which `update_status_from_payments` refuses to collect.
        settlement = _converge_issued_payments(invoice)
        if settlement.is_err():
            transaction.set_rollback(True)
            return Err(settlement.unwrap_err())
        _settle_correction_with(invoice)
    logger.info(f"✅ [Issuance] Invoice {invoice.pk} reconciled to {legal_number} by operator")
    return Ok(legal_number)


def issue_storno_for_correction(  # noqa: PLR0911  # One return per distinct refusal or outcome
    correction_id: Any,
) -> Result[str, str]:
    """Reverse a provider-issued invoice for one fiscal correction, creating its credit note.

    `/invoice/reverse` carries no amounts: it reverses the whole document or nothing. So it serves
    exactly one correction, the one crediting the whole original before anything else credited it
    (`whole_document_storno_refusal`); every other correction of a provider invoice is issued by
    staff at the provider. Keyed by the correction, never by the original: the correction says
    which refund this document answers for, and its issuance is unique to it.

    The reversal is a real document with its own legal number, so it becomes its own Invoice row
    (negative, `document_kind=credit_note`) rather than a flag on the original.

    Eligibility, the credit-note row and the claim are decided under a row lock on the original.
    The existence of a credit-note row is *not* the "already reversed" test: a crash between
    creating that row and hearing back from the provider would otherwise wedge the correction
    permanently. The authority is the claim's durable state, which resumes a `pending`/`failed`
    attempt and refuses one that is live, already issued, or ambiguous.
    """
    from apps.billing.fiscal_correction_models import FiscalCorrection  # noqa: PLC0415  # Keeps imports acyclic

    _refuse_if_inside_transaction()

    correction = FiscalCorrection.objects.filter(pk=correction_id).first()
    if correction is None or correction.original_id is None:
        return Err(f"Fiscal correction {correction_id} has no original to reverse")
    original = Invoice.objects.select_related("currency", "customer").get(pk=correction.original_id)

    # Provenance and document kind are frozen at creation, so these cannot change under us and
    # are worth answering before doing any work.
    immutable_refusal = _ineligible_by_provenance(original)
    if immutable_refusal is not None:
        return Err(immutable_refusal)

    # The provider already issued this correction's document and only the settling failed: settle
    # it from that record. Calling the provider again would be refused, or worse, reverse twice.
    issued = ProviderIssuance.objects.filter(
        fiscal_correction=correction, state=IssuanceState.ISSUED.value, invoice__number__isnull=False
    ).first()
    if issued is not None:
        with transaction.atomic():
            note = Invoice.objects.select_for_update().get(pk=issued.invoice_id)
            _record_issued_for(note)
        return Ok(str(note.number))

    issuer = resolve_issuer(original)

    # Mapping reads settings and the frozen snapshot. It makes no network call and writes
    # nothing, so it stays outside the lock rather than widening it.
    prepared_result = issuer.prepare_storno(original)
    if isinstance(prepared_result, Err):
        return Err("; ".join(prepared_result.error))
    prepared = prepared_result.unwrap()

    attempt_id = uuid.uuid4()
    opened = _open_storno_attempt(correction.pk, original, issuer.provider, attempt_id, prepared)
    if isinstance(opened, Err):
        return Err(opened.error)
    credit_note_pk, issuance_id = opened.unwrap()

    # ---- no transaction is open here, deliberately ----
    try:
        outcome = issuer.submit_storno(prepared, attempt_id=attempt_id)
    except RateGateWait as deferred:
        return _defer_claim(issuance_id, deferred)

    return _finalize(credit_note_pk, issuance_id, attempt_id, outcome)


def _open_storno_attempt(
    correction_id: Any,
    original: Invoice,
    provider: str,
    attempt_id: uuid.UUID,
    prepared: PreparedDocument,
) -> Result[tuple[int, uuid.UUID], str]:
    """Settle eligibility, materialise the credit note and claim it under one lock.

    The original is locked, then the issuance (inside `_claim`), the order `_finalize` and
    `adopt_provider_document` use. The correction is read without a lock: its allocation is
    written once and never changes, and `_finalize` locks it after the issuance, so locking it
    here, ahead of the issuance, could deadlock against an attempt being recorded.
    """
    from apps.billing.fiscal_correction_models import FiscalCorrection  # noqa: PLC0415  # Keeps imports acyclic

    with transaction.atomic():
        locked = Invoice.objects.select_for_update().get(pk=original.pk)
        correction = FiscalCorrection.objects.get(pk=correction_id)

        refusal = whole_document_storno_refusal(correction, locked)
        if refusal is not None:
            # Nothing is written above this line today, but returning Err from inside
            # an atomic block is how this codebase has leaked partial writes before.
            # The rollback is unconditional so a later edit that adds a write above
            # cannot quietly start committing it.
            transaction.set_rollback(True)
            return Err(refusal)

        credit_note = _get_or_create_credit_note(locked, correction)

        # Durable state, not row existence, is what proves a reversal happened. The
        # distinction is the whole point: a row can exist because an earlier attempt
        # died before it ever reached the provider, and that correction must stay
        # reversible. `_claim` would refuse this case too, but in the vocabulary of
        # issuing a document rather than of reversing one.
        issued_already = ProviderIssuance.objects.filter(invoice=credit_note, state=IssuanceState.ISSUED.value).exists()
        if issued_already:
            transaction.set_rollback(True)
            return Err(f"This correction has already been reversed by credit note {credit_note.display_number}")

        claim_result = _claim(credit_note, provider, attempt_id, prepared)
        if isinstance(claim_result, Err):
            # Deliberately NOT rolled back. `_claim` quarantines an abandoned claim by
            # writing `outcome_unknown`, and the credit-note row is the document that
            # state belongs to; discarding either would destroy the only durable
            # evidence an operator has to reconcile against.
            return Err(claim_result.error)

        # Only now. Holding the claim proves this reversal was `pending` or `failed` -
        # not claimed, issued, or outcome_unknown - so it cannot be a document the provider
        # may already hold. It also puts the write after the ProviderIssuance lock, which
        # is the order `_finalize` and `adopt_provider_document` use; repairing before the
        # claim took Invoice -> ProviderIssuance and could deadlock against them.
        _repair_unissued_reversal(original, credit_note)

        return Ok((credit_note.pk, claim_result.unwrap()))


def _ineligible_by_provenance(original: Invoice) -> str | None:
    """Refusals that depend only on frozen fields, so no lock is needed to trust them."""
    if original.document_kind != DOCUMENT_KIND_INVOICE:
        # SmartBill refuses this too ("Factura este de tip storno"), but spending an
        # attempt to be told so is worse than knowing.
        return "A credit note cannot itself be reversed"
    if original.issuer_provider == ISSUER_BUILTIN:
        # A built-in invoice is corrected by its own built-in storno (ADR-0053), issued by the
        # fiscal-correction worker. There is no provider document to reverse.
        return "Built-in invoices are not reversed at a provider; no provider document exists to correct"
    return None


def whole_document_storno_refusal(correction: FiscalCorrection, original: Invoice) -> str | None:
    """Why `/invoice/reverse` must not issue this correction, or None when it is exactly right.

    It reverses the whole document and carries no amount, so it is right for one correction only:
    the one whose frozen allocation is the whole original (base, VAT and discount) while nothing
    else has credited it. A partial, or the remainder after one, would be credited the entire
    invoice; those are issued by staff at the provider instead. Decided by amount, from the
    allocation, never by the invoice's refund status or by counting refunds: the allocation already
    says what the refund caused, overpayments and tender legs included.

    Called by the worker under the correction's lock, and again under the original's lock right
    before anything is sent.
    """
    from apps.billing.fiscal_correction_models import FiscalCorrection  # noqa: PLC0415  # Keeps imports acyclic

    frozen = _ineligible_by_provenance(original)
    if frozen is not None:
        return frozen
    if correction.original_id != original.pk or not correction.is_allocated:
        return "The correction has no allocation against this invoice yet"
    whole = (-original.subtotal_cents, -original.tax_cents, -original.discount_cents)
    if (correction.base_cents, correction.tax_cents, correction.discount_cents) != whole:
        return (
            f"The correction credits {abs(correction.total_cents or 0)} of the invoice's {original.total_cents} "
            f"cents. A provider reversal carries no amount and would credit the whole document."
        )
    if (
        FiscalCorrection.objects.filter(original=original, allocated_at__isnull=False)
        .exclude(pk=correction.pk)
        .exists()
    ):
        return (
            "Another correction already credits part of this invoice; a whole-document reversal would credit it twice"
        )
    other_notes = (
        Invoice.objects.filter(reverses_invoice=original, number__isnull=False)
        .exclude(provider_issuance__fiscal_correction=correction)
        .exists()
    )
    if other_notes:
        return "This invoice already carries a credit note; a whole-document reversal would credit it twice"
    return None


# Copied from the original at creation, and the two that a row created by an older
# implementation can be missing. `subtotal/tax/total_cents` and the `bill_to_*` set have
# been written on the create path since the first version, so they cannot be stale.
_REVERSAL_FIELDS_TO_REPAIR = (
    "exchange_to_ron",
    "exchange_rate_as_of",
    "exchange_rate_source",
    "exchange_rate_source_reference",
)


def _repair_unissued_reversal(original: Invoice, credit_note: Invoice) -> None:
    """Restore what an earlier attempt never wrote, while it is still repairable.

    A reversal left pending by an interrupted or rate-gated attempt predates the fields
    added since. `_freeze_fx` consumes a snapshot only when it finds all four fields, so
    a note missing them resolves TODAY's rate at issuance and books the correction against
    a different rate from the document it reverses - the residue the copy exists to
    prevent. The same row can carry `discount_cents=0` against negated GROSS lines, which
    makes the header contradict its own lines for every reader that recovers the discount
    as the difference.

    Only while unnumbered. A numbered credit note is a legal document: whatever it says is
    what was filed, so repairing it would rewrite history rather than finish an attempt.

    Written through the queryset so the protected `status` FSMField is never re-entered.
    """
    if credit_note.number:
        return

    repairs: dict[str, Any] = {}
    if credit_note.discount_cents != -original.discount_cents:
        repairs["discount_cents"] = -original.discount_cents
    for field in _REVERSAL_FIELDS_TO_REPAIR:
        expected = getattr(original, field)
        if getattr(credit_note, field) != expected:
            repairs[field] = expected
    if not repairs:
        return

    # Compare-and-swap. The guard above read an unlocked copy, so between that read and
    # this write another worker may have numbered and locked this document. Putting the
    # state in the WHERE clause is what makes the check and the write one decision -
    # PostgreSQL re-evaluates it after granting the row lock. `queryset.update()` bypasses
    # `Invoice.save()`, so the locked-invoice guard would never have caught it.
    applied = Invoice.objects.filter(pk=credit_note.pk, number__isnull=True, locked_at__isnull=True).update(**repairs)
    if not applied:
        logger.info(f"⏭️ [Issuance] Reversal {credit_note.pk} was issued concurrently; left as filed.")
        return
    # `.update()` fires no signals, so nothing else would record that a financial document
    # was rewritten.
    logger.info(f"✅ [Issuance] Repaired unissued reversal {credit_note.pk} from {original.pk}: {sorted(repairs)}")
    for field, value in repairs.items():
        setattr(credit_note, field, value)


def _get_or_create_credit_note(original: Invoice, correction: FiscalCorrection) -> Invoice:
    """The reversal document `correction` issues, created once and reused thereafter.

    Found through the correction's issuance, never through the original: an original may carry
    several credit notes, and which one a retry resumes is the correction's to say. Called under
    `select_for_update` on the original and backed by the issuance's unique correction link, so
    concurrent callers converge on a single credit note instead of each minting one.
    """
    issuance = ProviderIssuance.objects.select_related("invoice").filter(fiscal_correction=correction).first()
    existing = issuance.invoice if issuance is not None else None
    if existing is not None:
        # Resuming has to repair what the interrupted attempt never wrote, not just
        # reuse the row. An earlier implementation created the credit note without
        # lines; numbering that document reverses the header while line-based VAT and
        # EC-Sales reporting see no correction at all - which reads as settled and is
        # worse than no credit note. Idempotent: a note that already has lines is left
        # exactly as it is, including one already issued.
        if not existing.lines.exists():
            mirror_lines_negated(original, existing)
        # The FX/discount repair deliberately does NOT happen here. This function runs
        # before the reversal's own issuance state has been looked at, so a credit note in
        # `outcome_unknown` - the state that exists precisely because the provider may hold
        # a numbered document we never heard about - would be rewritten anyway, and the
        # refusal that follows is deliberately not rolled back. It runs once a claim is
        # held instead; see `_open_storno_attempt`.
        return existing

    credit_note = Invoice.objects.create(
        customer=original.customer,
        currency=original.currency,
        number=None,
        status="draft",
        document_kind=DOCUMENT_KIND_CREDIT_NOTE,
        reverses_invoice=original,
        issuer_provider=original.issuer_provider,
        subtotal_cents=-original.subtotal_cents,
        tax_cents=-original.tax_cents,
        total_cents=-original.total_cents,
        # Negated with the rest. Left at zero the header would contradict its own
        # lines: they mirror the GROSS amounts while the subtotal is stored NET, so
        # the discount is the difference and dropping it makes the document stop
        # adding up for every reader that recovers it that way.
        discount_cents=-original.discount_cents,
        # The original's rate, not today's. A reversal restates the SAME taxable base,
        # so re-resolving at the reversal date books a different RON amount from the
        # document being reversed and leaves a residue that nets to nothing and shows
        # up on no report. All four fields, because `_freeze_fx` consumes a snapshot
        # only when it considers it complete.
        exchange_to_ron=original.exchange_to_ron,
        exchange_rate_as_of=original.exchange_rate_as_of,
        exchange_rate_source=original.exchange_rate_source,
        exchange_rate_source_reference=original.exchange_rate_source_reference,
        # The reversal inherits the original's fiscal identity: it is a correction
        # to that document, not a new commercial event.
        bill_to_name=original.bill_to_name,
        bill_to_tax_id=original.bill_to_tax_id,
        bill_to_email=original.bill_to_email,
        bill_to_address1=original.bill_to_address1,
        bill_to_city=original.bill_to_city,
        bill_to_region=original.bill_to_region,
        bill_to_postal=original.bill_to_postal,
        bill_to_country=original.bill_to_country,
        # The correction's own decision record (version 3): the original's decision restated with
        # this note's signed amounts. A copy of the original's would claim the note charged VAT.
        vat_evidence=capture_credit_note_evidence(
            original,
            subtotal_cents=-original.subtotal_cents,
            tax_cents=-original.tax_cents,
            total_cents=-original.total_cents,
        ),
        meta={"fiscal_correction_id": str(correction.pk)},
    )
    mirror_lines_negated(original, credit_note)
    ProviderIssuance.objects.create(
        invoice=credit_note, provider=original.issuer_provider, fiscal_correction=correction
    )
    return credit_note
