"""Recording the fiscal correction a completed refund owes, and the provider storno staff issued for one.

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
from dataclasses import dataclass
from datetime import date, datetime, time
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from .fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_MANUAL_REQUIRED,
    STATE_NOT_REQUIRED,
    FiscalCorrection,
)
from .invoice_models import DOCUMENT_KIND_INVOICE, Invoice
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

    Records the obligation for every completed refund that has none. The hook misses a refund
    when its recording failed (the savepoint rolled back and only a log line remains), when a
    refund reached `completed` without a `save()` that this process saw, or when a row was
    created already completed. Keyed by the refund-and-command identity, so a second run, or a
    second leg of a command already recorded, converges on the existing row. Every storno, a
    provider's included, is issued from its correction (ADR-0053), so none exists to link back.

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

    results = {"examined": len(owed), "recorded": 0, "unresolved": 0}
    for refund in owed:
        try:
            with transaction.atomic():
                correction = record_obligation(refund)
        except Exception:
            logger.exception(f"🔥 [Fiscal Correction] Sweep could not record the correction for refund {refund.pk}")
            correction = None
        results["recorded" if correction is not None else "unresolved"] += 1

    if results["examined"]:
        logger.info(
            f"🐢 [Fiscal Correction] Swept {results['examined']} refund(s): {results['recorded']} recorded, "
            f"{results['unresolved']} unresolved"
        )
    return results


@dataclass(frozen=True)
class ProviderStornoRecord:
    """A credit note staff issued at the provider and sent to the customer, as they read it."""

    series: str
    number: str
    issued_on: date
    communicated_on: date
    currency_code: str
    # Magnitudes, as the allocation's are compared: the sign a screen shows is not the question.
    base_cents: int
    tax_cents: int
    evidence: str


def record_provider_storno(correction_id: Any, record: ProviderStornoRecord) -> Invoice:
    """Settle a `manual_required` correction with the storno staff issued at the provider.

    The provider's API cannot issue a partial storno (A3 research), so staff issue it in the
    provider's own interface and send it themselves. This records that document: a locked credit
    note with the provider's number and issue date, carrying exactly the correction's allocation,
    and the correction moves straight to `communicated`, dated by the staff-entered communication
    date, which places it in its D390 period (OPANAF 705/2020) and is backed by the evidence reference.

    Nothing is trusted that can be checked: the amounts and currency must be the allocation's
    (codex 12), the dates must be possible, and the number must be new. Raises `ValidationError`
    keyed by what to correct; the transaction then rolls back whole.
    """
    from django.utils import timezone  # noqa: PLC0415

    from .efactura.settings import ro_local_date  # noqa: PLC0415
    from .fiscal_correction_worker import draft_credit_note  # noqa: PLC0415  # Keeps the import graph acyclic
    from .issuers.models import ProviderIssuance  # noqa: PLC0415

    with transaction.atomic():
        # The correction, then its original: the order allocation takes them in.
        correction = FiscalCorrection.objects.select_for_update().filter(pk=correction_id).first()
        if correction is None or correction.state != STATE_MANUAL_REQUIRED or correction.original_id is None:
            raise ValidationError({"__all__": _("This correction is no longer waiting for a provider document.")})
        original = Invoice.objects.select_for_update().select_related("currency").get(pk=correction.original_id)

        errors = _provider_storno_errors(correction, original, record, today=ro_local_date(timezone.now()))
        legal_number = f"{record.series}-{record.number}" if record.series else record.number
        if Invoice.objects.filter(number=legal_number).exists():
            errors.setdefault("number", _("Another document already has this number."))
        if errors:
            raise ValidationError(errors)

        note = draft_credit_note(correction, original, issuer_provider=original.issuer_provider)
        note.number = legal_number
        note.issued_at = _bucharest_noon(record.issued_on)
        note.tax_point_date = record.issued_on
        note.issue()
        note.save()

        issuance = ProviderIssuance.objects.create(
            invoice=note, provider=original.issuer_provider, fiscal_correction=correction
        )
        issuance.record_issued_by_staff(series=record.series, number=record.number, operator_note=record.evidence)
        issuance.save()

        correction.record_provider_document(
            note,
            communicated_at=_bucharest_noon(record.communicated_on),
            fiscal_date=record.communicated_on,
            evidence=record.evidence,
        )
        correction.save()
    logger.info(f"✅ [Fiscal Correction] Correction {correction_id} settled by provider document {legal_number}")
    return note


def _provider_storno_errors(
    correction: FiscalCorrection, original: Invoice, record: ProviderStornoRecord, *, today: date
) -> dict[str, Any]:
    """What is wrong with a recorded provider storno, keyed by the field to correct."""
    from .efactura.settings import ro_local_date  # noqa: PLC0415

    errors: dict[str, Any] = {}
    if record.currency_code.strip().upper() != original.currency.code:
        errors["currency_code"] = _("The credit note must be in the invoice's currency, %(code)s.") % {
            "code": original.currency.code
        }
    if abs(record.base_cents) != abs(correction.base_cents or 0):
        errors["base_amount"] = _("The taxable base must be exactly the amount this correction credits.")
    if abs(record.tax_cents) != abs(correction.tax_cents or 0):
        errors["tax_amount"] = _("The VAT must be exactly the amount this correction credits.")
    original_date = ro_local_date(original.issued_at) if original.issued_at else original.tax_point_date
    if original_date is not None and record.issued_on < original_date:
        errors["issued_on"] = _("A storno cannot be dated before the invoice it corrects.")
    elif record.issued_on > today:
        errors["issued_on"] = _("The issue date cannot be in the future.")
    if record.communicated_on < record.issued_on:
        errors["communicated_on"] = _("The credit note cannot have been sent before it was issued.")
    elif record.communicated_on > today:
        errors["communicated_on"] = _("The communication date cannot be in the future.")
    if not record.evidence.strip():
        errors["evidence"] = _("Say where the proof of sending is kept.")
    return errors


def _bucharest_noon(day: date) -> datetime:
    """A recorded calendar day as an instant: noon in Bucharest is that day in every zone PRAHO reads."""
    from .efactura.settings import ROMANIA_TIMEZONE  # noqa: PLC0415

    return datetime.combine(day, time(12), tzinfo=ROMANIA_TIMEZONE)
