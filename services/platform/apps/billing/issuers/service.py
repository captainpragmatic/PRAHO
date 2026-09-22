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
from copy import deepcopy
from typing import TYPE_CHECKING, assert_never

from django.db import connection, transaction

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    DOCUMENT_KIND_INVOICE,
    ISSUER_BUILTIN,
    Invoice,
    InvoiceLine,
)
from apps.common.types import Err, Ok, Result

from .base import Ambiguous, Issued, PreparedDocument, Rejected
from .models import IssuanceState, ProviderIssuance
from .policy import resolve_issuer
from .smartbill.client import RateGateWait

if TYPE_CHECKING:
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


def issue_invoice_externally(invoice_id: int) -> Result[str, str]:
    """Issue one already-persisted, unnumbered invoice through its provider."""
    _refuse_if_inside_transaction()

    try:
        invoice = Invoice.objects.select_related("currency", "customer").get(pk=invoice_id)
    except Invoice.DoesNotExist:
        return Err(f"Invoice {invoice_id} does not exist")

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
            invoice.issue()
            invoice.save()
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
    """
    _refuse_if_inside_transaction()

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
    logger.info(f"✅ [Issuance] Invoice {invoice.pk} reconciled to {legal_number} by operator")
    return Ok(legal_number)


def issue_storno_for_invoice(invoice_id: int) -> Result[str, str]:
    """Reverse a provider-issued invoice, creating the credit note it produces.

    `/invoice/reverse` carries no amounts: it reverses the whole document or
    nothing. A partial refund therefore has no representation at the provider and
    is refused here rather than approximated by reversing too much - the difference
    between a customer being credited what they are owed and being credited the
    entire invoice.

    The reversal is a real document with its own legal number, so it becomes its
    own Invoice row (negative, `document_kind=credit_note`) rather than a flag on
    the original. Reporting that sums invoice rows then sees the correction without
    needing to know this integration exists.

    Eligibility, the credit-note row and the claim are all decided under a row lock
    on the original, so two workers cannot each conclude they are the first.
    Crucially, the existence of a credit-note row is *not* the "already reversed"
    test: a crash between creating that row and hearing back from the provider
    would otherwise wedge the invoice permanently. The authority is the claim's
    durable state, which resumes a `pending`/`failed` attempt and refuses only one
    that is live, already issued, or ambiguous.
    """
    _refuse_if_inside_transaction()

    try:
        original = Invoice.objects.select_related("currency", "customer").get(pk=invoice_id)
    except Invoice.DoesNotExist:
        return Err(f"Invoice {invoice_id} does not exist")

    # Provenance and document kind are frozen at creation, so these cannot change
    # under us and are worth answering before doing any work. They also produce the
    # refusal that actually tells an operator what to do instead, which a generic
    # "this issuer cannot reverse" from the gateway does not.
    immutable_refusal = _ineligible_by_provenance(original)
    if immutable_refusal is not None:
        return Err(immutable_refusal)

    issuer = resolve_issuer(original)

    # Mapping reads settings and the frozen snapshot. It makes no network call and
    # writes nothing, so it stays outside the lock rather than widening it.
    prepared_result = issuer.prepare_storno(original)
    if isinstance(prepared_result, Err):
        return Err("; ".join(prepared_result.error))
    prepared = prepared_result.unwrap()

    attempt_id = uuid.uuid4()
    opened = _open_storno_attempt(original, issuer.provider, attempt_id, prepared)
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
    original: Invoice,
    provider: str,
    attempt_id: uuid.UUID,
    prepared: PreparedDocument,
) -> Result[tuple[int, uuid.UUID], str]:
    """Settle eligibility, materialise the credit note and claim it under one lock."""
    with transaction.atomic():
        locked = Invoice.objects.select_for_update().get(pk=original.pk)

        refusal = _storno_refusal_reason(locked)
        if refusal is not None:
            # Nothing is written above this line today, but returning Err from inside
            # an atomic block is how this codebase has leaked partial writes before.
            # The rollback is unconditional so a later edit that adds a write above
            # cannot quietly start committing it.
            transaction.set_rollback(True)
            return Err(refusal)

        credit_note = _get_or_create_credit_note(locked)

        # Durable state, not row existence, is what proves a reversal happened. The
        # distinction is the whole point: a row can exist because an earlier attempt
        # died before it ever reached the provider, and that invoice must stay
        # reversible. `_claim` would refuse this case too, but in the vocabulary of
        # issuing a document rather than of reversing one.
        issued_already = ProviderIssuance.objects.filter(invoice=credit_note, state=IssuanceState.ISSUED.value).exists()
        if issued_already:
            transaction.set_rollback(True)
            return Err(f"This invoice has already been reversed by credit note {credit_note.display_number}")

        claim_result = _claim(credit_note, provider, attempt_id, prepared)
        if isinstance(claim_result, Err):
            # Deliberately NOT rolled back. `_claim` quarantines an abandoned claim by
            # writing `outcome_unknown`, and the credit-note row is the document that
            # state belongs to; discarding either would destroy the only durable
            # evidence an operator has to reconcile against.
            return Err(claim_result.error)

        return Ok((credit_note.pk, claim_result.unwrap()))


def _ineligible_by_provenance(original: Invoice) -> str | None:
    """Refusals that depend only on frozen fields, so no lock is needed to trust them."""
    if original.document_kind != DOCUMENT_KIND_INVOICE:
        # SmartBill refuses this too ("Factura este de tip storno"), but spending an
        # attempt to be told so is worse than knowing.
        return "A credit note cannot itself be reversed"
    if original.issuer_provider == ISSUER_BUILTIN:
        return "Built-in invoices are corrected through the e-Factura credit-note path"
    return None


def _storno_refusal_reason(original: Invoice) -> str | None:
    """Why this invoice must not be reversed at the provider, or None.

    Re-checks the frozen refusals under the lock as well. They cannot have changed,
    but this is the function the lock exists to make authoritative, and a reader
    should not have to know that two callers split the question between them.
    """
    frozen = _ineligible_by_provenance(original)
    if frozen is not None:
        return frozen
    if original.status != "refunded":
        # The decisive constraint. `/invoice/reverse` takes no amounts, so there is
        # no way to express "reverse 40 of 100". Reversing the whole document for a
        # partial refund would credit the customer money they were not refunded.
        return (
            f"Only a fully refunded invoice can be reversed at the provider "
            f"(this one is {original.status!r}). A partial refund has no representation "
            f"in SmartBill's storno, which reverses the whole document or nothing."
        )
    return _split_correction_refusal(original)


def _split_correction_refusal(original: Invoice) -> str | None:
    """Refuse a whole-document reversal unless one settled refund accounts for it.

    Reaching `refunded` does not imply a single refund got it there. An invoice
    refunded in two instalments may already have had the first corrected by hand in
    the provider's own interface, and a reversal - which carries no amount and
    credits the entire document - would then credit the customer twice.

    Only *settled* refunds are counted. Counting attempts would let a failed or
    cancelled refund wedge the invoice forever, which is the same defect that
    testing row existence caused above.
    """
    settled = list(original.refunds.filter(status="completed"))
    expected_cents = abs(original.total_cents)

    if len(settled) != 1:
        return (
            f"This invoice reached 'refunded' through {len(settled)} settled refunds. "
            f"A provider reversal credits the whole document in one step, which "
            f"over-credits the customer if any part of it was already corrected by "
            f"hand. Issue this correction in the provider's own interface."
        )

    only = settled[0]
    if only.amount_cents != expected_cents:
        return (
            f"The settled refund is {only.amount_cents} cents against an invoice total "
            f"of {expected_cents} cents. A provider reversal carries no amount and "
            f"would credit the whole document."
        )
    return None


def _get_or_create_credit_note(original: Invoice) -> Invoice:
    """The reversal document for `original`, created once and reused thereafter.

    Called under `select_for_update` on the original and backed by a uniqueness
    constraint on `reverses_invoice`, so concurrent callers converge on a single
    credit note instead of each minting one for the same invoice.
    """
    existing = Invoice.objects.filter(reverses_invoice=original).first()
    if existing is not None:
        # Resuming has to repair what the interrupted attempt never wrote, not just
        # reuse the row. An earlier implementation created the credit note without
        # lines; numbering that document reverses the header while line-based VAT and
        # EC-Sales reporting see no correction at all - which reads as settled and is
        # worse than no credit note. Idempotent: a note that already has lines is left
        # exactly as it is, including one already issued.
        if not existing.lines.exists():
            _mirror_lines_negated(original, existing)
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
        vat_evidence=deepcopy(original.vat_evidence),
    )
    _mirror_lines_negated(original, credit_note)
    ProviderIssuance.objects.get_or_create(invoice=credit_note, defaults={"provider": original.issuer_provider})
    return credit_note


def _mirror_lines_negated(original: Invoice, credit_note: Invoice) -> None:
    """Copy the original's lines with the money negated and the quantities intact.

    A credit note without lines is a total with no composition. The VAT report and
    the D390/EC-Sales builders attribute amounts by walking `InvoiceLine` rows for
    their rate and tax category, so a line-less correction is invisible to every one
    of them however correct the header totals are.

    Quantities stay positive and the per-unit money goes negative. Negating the
    quantity instead would reverse the same total while corrupting the mapper's
    discount line, whose `numberOfItems` counts the ordinary lines preceding it.

    `discount_amount_cents` is copied unchanged: it is a magnitude rather than a
    signed amount, and the e-Factura builder refuses a negative one.
    """
    InvoiceLine.objects.bulk_create(
        [
            InvoiceLine(
                invoice=credit_note,
                kind=line.kind,
                service=line.service,
                billing_cycle=line.billing_cycle,
                description=line.description,
                quantity=line.quantity,
                unit_price_cents=-line.unit_price_cents,
                tax_rate=line.tax_rate,
                tax_cents=-line.tax_cents,
                line_total_cents=-line.line_total_cents,
                domain_name=line.domain_name,
                period_start=line.period_start,
                period_end=line.period_end,
                unit_code=line.unit_code,
                tax_category_code=line.tax_category_code,
                note=line.note,
                discount_amount_cents=line.discount_amount_cents,
                seller_item_id=line.seller_item_id,
                sort_order=line.sort_order,
            )
            for line in original.lines.all().order_by("sort_order", "pk")
        ]
    )
