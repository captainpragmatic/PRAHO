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
from typing import TYPE_CHECKING, assert_never

from django.db import connection, transaction

from apps.billing.invoice_models import Invoice
from apps.common.types import Err, Ok, Result

from .base import Ambiguous, Issued, PreparedDocument, Rejected
from .models import IssuanceState, ProviderIssuance
from .policy import resolve_issuer

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
    outcome = issuer.submit(prepared, attempt_id=attempt_id)

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
