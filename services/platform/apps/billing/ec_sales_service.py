"""Monthly outgoing intra-Community service supplies, with an exhaustive reconciliation.

One operating entity owns this invoice ledger. This service reads frozen invoice
facts only; D390 serialization and supplier/declarant validation are separate.

A storno credit note is a supply line with a negative base, declared in the month it
reached the customer (its correction's `fiscal_date`, OPANAF 705/2020), not in its
original's month and not by its own tax point (ADR-0053).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import date, datetime, time, timedelta
from decimal import ROUND_HALF_UP, Decimal
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.billing.document_adjustments import UnsupportedDocumentAdjustmentError, validate_no_unsupported_adjustments
from apps.billing.efactura.settings import ro_local_date
from apps.billing.fiscal_correction_models import STATE_COMMUNICATED, STATE_NOT_REQUIRED, FiscalCorrection
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Invoice, InvoiceLine
from apps.billing.refund_models import Refund
from apps.billing.tax_evidence import (
    CONSULTATION_REFERENCE_EVIDENCE_VERSION,
    CREDIT_NOTE_EVIDENCE_VERSION,
    TaxEvidenceError,
    VATDecision,
    evidence_rules_version,
    read_vat_evidence,
    vat_country,
    vat_identity,
)
from apps.common.eu_vat_validator import EU_COUNTRIES, validate_vat_format
from apps.common.financial_arithmetic import calculate_line_totals

SERVICE_COUNTRIES = EU_COUNTRIES - {"RO"}
SUPPORTED_KINDS = {"service", "setup"}
MIN_YEAR = 2020
MAX_YEAR = 2100
MONTHS_PER_YEAR = 12
PARTNER_NAME_LIMIT = 200
UNRESOLVED_REFUNDS = {"pending", "processing", "approved", "completed"}
# A completed refund whose correction reached one of these settled it: a note the customer received,
# which is declared in its own month, or a decision that the invoice needed no correction at all.
SETTLED_CORRECTION_STATES = (STATE_COMMUNICATED, STATE_NOT_REQUIRED)
BUCHAREST = ZoneInfo("Europe/Bucharest")


@dataclass(frozen=True, order=True)
class ReportingPeriod:
    year: int
    month: int

    def __post_init__(self) -> None:
        if not (MIN_YEAR <= self.year <= MAX_YEAR and 1 <= self.month <= MONTHS_PER_YEAR) or (self.year, self.month) < (
            2020,
            2,
        ):
            raise ValueError("D390 v3 periods start in February 2020 and end in 2100.")

    @property
    def start(self) -> date:
        return date(self.year, self.month, 1)

    @property
    def end(self) -> date:
        return (self.start + timedelta(days=32)).replace(day=1)

    @property
    def label(self) -> str:
        return f"{self.year:04d}-{self.month:02d}"

    @classmethod
    def previous(cls) -> ReportingPeriod:
        previous = ro_local_date(timezone.now()).replace(day=1) - timedelta(days=1)
        return cls(previous.year, previous.month)


@dataclass(frozen=True)
class SupplyContribution:
    invoice_id: int
    invoice_number: str
    line_id: int
    description: str
    # The date that places the line in its month: an invoice's tax point, a credit note's fiscal date.
    tax_point_date: date
    country: str
    vat_body: str
    partner_name: str
    currency: str
    gross_cents: int
    discount_cents: int
    exchange_rate: Decimal
    base_ron: Decimal
    vies_status: str = "not_recorded"
    consultation_reference: str = ""
    operation: str = "P"


@dataclass(frozen=True)
class ReviewException:
    invoice_id: int
    invoice_number: str
    line_id: int | None
    codes: tuple[str, ...]
    detail: str
    tax_point_date: date | None = None
    currency: str = ""
    gross_cents: int | None = None


@dataclass(frozen=True)
class PartnerSupply:
    country: str
    vat_body: str
    partner_name: str
    contributions: tuple[SupplyContribution, ...]
    base_ron: Decimal
    rounded_ron: int
    rounding_difference: Decimal
    operation: str = "P"

    @property
    def fully_netted(self) -> bool:
        """Credit notes cancelled the month's supplies to the ban: no row is declared for it.

        D390 has no zero row, so the group is left out of the XML and kept everywhere else.
        `_group_supplies` builds a zero group only from an exact zero that a credit note made,
        and `assert_reconciled` holds every zero group to that.
        """
        return self.rounded_ron == 0


@dataclass(frozen=True)
class RefundSettlement:
    """A refund as the declaration sees it: settled for one invoice, or a correction still to land."""

    refund_id: str
    status: str
    amount_cents: int
    # The payment the money went back to, directly or through a tender leg; "" when none is recorded.
    payment_id: str
    raised_on: date
    correction_id: str
    correction_state: str
    correction_original_id: int | None
    fiscal_date: date | None
    settled: bool

    def could_land_in(self, period: ReportingPeriod) -> bool:
        """Whether this refund's correction may still be declared in `period`.

        A correction lands in the month its credit note reaches the customer, which is never before
        the refund was raised. So an unsettled refund holds every month from the one it was raised
        in, and never the original's closed month before it.
        """
        return not self.settled and self.raised_on < period.end


@dataclass(frozen=True)
class ECSalesReport:
    period: ReportingPeriod
    partners: tuple[PartnerSupply, ...]
    contributions: tuple[SupplyContribution, ...]
    exceptions: tuple[ReviewException, ...]
    candidate_line_ids: tuple[int, ...]
    source_fingerprint: str

    @property
    def base_ron(self) -> Decimal:
        return sum((partner.base_ron for partner in self.partners), Decimal(0))

    @property
    def rounded_ron(self) -> int:
        return sum(partner.rounded_ron for partner in self.partners)

    @property
    def rounding_difference(self) -> Decimal:
        return Decimal(self.rounded_ron) - self.base_ron

    @property
    def declared_partners(self) -> tuple[PartnerSupply, ...]:
        """The groups that become XML rows: every one but a group netted to exactly nothing."""
        return tuple(partner for partner in self.partners if not partner.fully_netted)

    @property
    def can_export(self) -> bool:
        return bool(self.declared_partners) and not self.exceptions

    def assert_reconciled(self) -> None:
        actual = [line.line_id for line in self.contributions]
        actual.extend(exc.line_id for exc in self.exceptions if exc.line_id is not None)
        if len(actual) != len(set(actual)) or sorted(actual) != sorted(self.candidate_line_ids):
            raise ValueError("Candidate reconciliation failed: every line must occur exactly once.")
        grouped = [line for partner in self.partners for line in partner.contributions]
        if sorted(grouped, key=lambda line: line.line_id) != sorted(self.contributions, key=lambda line: line.line_id):
            raise ValueError("Partner contributions do not match the reconciled invoice lines.")
        for partner in self.partners:
            base = sum((line.base_ron for line in partner.contributions), Decimal(0))
            rounded = int(base.quantize(Decimal(1), rounding=ROUND_HALF_UP))
            if (partner.base_ron, partner.rounded_ron, partner.rounding_difference) != (
                base,
                rounded,
                Decimal(rounded) - base,
            ):
                raise ValueError("Partner totals do not reconcile to the included invoice lines.")
            # A zero row cannot be declared, so a zero group must be a real cancellation: an exact
            # zero that a credit note made, never a rounding loss or a fully discounted supply.
            if partner.fully_netted and (base != 0 or not any(line.base_ron < 0 for line in partner.contributions)):
                raise ValueError("A partner group rounding to zero lei must be fully netted by a credit note.")


def _candidate(invoice: Invoice, line: InvoiceLine | None) -> bool:
    data = invoice.vat_evidence if isinstance(invoice.vat_evidence, dict) else {}
    explicit = data.get("scenario") == "eu_b2b_reverse" or str(data.get("category")) in {"AE", "K"}
    if explicit or (line and line.tax_category_code in {"AE", "K"}):
        return True
    try:
        decision = read_vat_evidence(invoice)
    except TaxEvidenceError:
        decision = None
    if decision and not decision.is_business and not decision.vat_number and not invoice.bill_to_tax_id:
        return False
    countries = {vat_country(invoice.bill_to_country), vat_country(str(data.get("country_code", "")))}
    for number, country in (
        (invoice.bill_to_tax_id, invoice.bill_to_country),
        (str(data.get("vat_number", "")), str(data.get("country_code", ""))),
    ):
        if number:
            countries.add(vat_identity(number, country)[0])
    zero_or_adjustment = line is None or line.tax_cents == 0 or line.tax_rate == 0 or line.kind not in SUPPORTED_KINDS
    return bool(countries & SERVICE_COUNTRIES) and zero_or_adjustment


def _identity_problems(invoice: Invoice, decision: VATDecision | None) -> list[str]:
    problems: list[str] = []
    if not decision or decision.category != "AE":
        problems.append("missing_reverse_charge_decision: A recorded reverse-charge decision is required.")
    if decision:
        proof = invoice.vat_evidence.get("vies")
        # An absent snapshot is the version-1 "not recorded" shape whatever the version; only a
        # recorded consultation that lacks its reference is a policy failure. A credit note's proof
        # is its original's, so it answers to the rules its original was written under.
        if (
            decision.category == "AE"
            and evidence_rules_version(invoice.vat_evidence) >= CONSULTATION_REFERENCE_EVIDENCE_VERSION
            and isinstance(proof, dict)
            and (
                not isinstance(proof.get("consultation_reference"), str) or not proof["consultation_reference"].strip()
            )
        ):
            problems.append("missing_consultation_reference: A version-2 reverse-charge supply requires a reference.")
        if decision.country != vat_country(invoice.bill_to_country) or not decision.is_business:
            problems.append("identity_mismatch: Invoice country or business identity disagrees with the decision.")
        try:
            if vat_identity(decision.vat_number, decision.country) != vat_identity(
                invoice.bill_to_tax_id, invoice.bill_to_country
            ):
                problems.append("identity_mismatch: Invoice and decision VAT numbers disagree.")
        except ValueError:
            problems.append("missing_vat_identity: Invoice and decision require a VAT number.")
        if (decision.subtotal_cents, decision.tax_cents, decision.total_cents) != (
            invoice.subtotal_cents,
            invoice.tax_cents,
            invoice.total_cents,
        ):
            problems.append("decision_amount_mismatch: Recorded decision amounts disagree with the invoice.")
    try:
        country, body = vat_identity(invoice.bill_to_tax_id, invoice.bill_to_country)
        if country not in SERVICE_COUNTRIES or country != vat_country(invoice.bill_to_country):
            problems.append(
                "unsupported_country: VAT issuing country must match an EU service customer outside Romania."
            )
        elif not validate_vat_format(country, body).is_valid:
            problems.append("invalid_vat_number: Partner VAT number fails local format/checksum validation.")
    except ValueError:
        problems.append("missing_vat_identity: Partner VAT number is required.")
    if not invoice.bill_to_name.strip() or len(invoice.bill_to_name.strip()) > PARTNER_NAME_LIMIT:
        problems.append("invalid_partner_name: Partner name is required and must fit 200 characters.")
    return problems


def _document_problems(invoice: Invoice, lines: list[InvoiceLine], decision: VATDecision | None) -> list[str]:
    problems: list[str] = []
    if invoice.tax_point_date is None:
        problems.append("missing_tax_point: Period unknown; this invoice is shown in every month until reviewed.")
    if not invoice.issued_at or not invoice.locked_at:
        problems.append("missing_issue_evidence: Issuance is not fully recorded.")
    if decision and invoice.issued_at and _late_decision(invoice):
        problems.append("late_tax_decision: VAT decision was recorded after invoice issuance.")
    problems.extend(_identity_problems(invoice, decision))
    problems.extend(_vies_problems(invoice))
    # The direction is a property of the document, not of a line. The header's sign is
    # already pinned by `invoice_subtotal_sign_matches_kind` and the reconciliation below
    # only sums the lines, so a document mixing +200 and -100 satisfies both while quietly
    # understating the partner's base by 100. One wrong-facing term excludes the WHOLE
    # document: declaring the remainder would report it as if the excluded line had never
    # been billed. Zero lines are `_line_problems`' business and are left alone here.
    reversing = invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE
    if any((line.subtotal_cents > 0) if reversing else (line.subtotal_cents < 0) for line in lines):
        problems.append("line_direction_mismatch: Every line must point the way the document kind implies.")
    gross = sum(line.subtotal_cents for line in lines)
    # Compared as magnitudes. A correction points the other way, so the literal
    # comparison reads `0 > -10000` as True and reports every reversal as broken
    # while leaving the partner's declared base at the full original amount. The
    # reconciliation on the next line is already sign-symmetric.
    if (
        abs(invoice.discount_cents) > abs(gross)
        or gross - invoice.discount_cents != invoice.subtotal_cents
        or invoice.subtotal_cents + invoice.tax_cents != invoice.total_cents
    ):
        problems.append("totals_mismatch: Line bases less the recorded discount must reconcile to invoice totals.")
    if invoice.tax_cents != 0:
        problems.append("nonzero_tax: Reverse-charge supplies must have zero invoice tax.")
    try:
        validate_no_unsupported_adjustments(
            meta=invoice.meta, line_discount_cents=(line.discount_amount_cents for line in lines)
        )
    except UnsupportedDocumentAdjustmentError as exc:
        problems.append(f"unsupported_adjustment: {exc}")
    if invoice.discount_cents and any(
        line.kind not in SUPPORTED_KINDS or line.tax_category_code != "AE" or line.tax_rate != 0 for line in lines
    ):
        problems.append("mixed_discount: Document discount allocation across categories is unsupported.")
    if invoice.currency_id != "RON" and (
        invoice.exchange_to_ron is None
        or not invoice.exchange_to_ron.is_finite()
        or invoice.exchange_to_ron <= 0
        or not invoice.exchange_rate_as_of
        or not invoice.exchange_rate_source
        or not invoice.exchange_rate_source_reference
        or (invoice.tax_point_date and invoice.exchange_rate_as_of > invoice.tax_point_date)
    ):
        problems.append("missing_exchange_rate: A positive, dated, frozen exchange rate with provenance is required.")
    return problems


def _decided_at(evidence: dict[str, object]) -> str:
    """When the recorded decision was taken: a credit note restates its original's, taken earlier."""
    credit = evidence.get("version") == CREDIT_NOTE_EVIDENCE_VERSION
    value = evidence["reverses_calculated_at" if credit else "calculated_at"]
    if not isinstance(value, str):
        raise TypeError("Decision time is not recorded")
    return value


def _late_decision(invoice: Invoice) -> bool:
    """Whether the recorded decision came after the document it decides.

    A credit note's decision is its original's, taken at `reverses_calculated_at`: it is late when
    that came after the ORIGINAL was issued, however long after the original the note follows. The
    note's own snapshot restates it before the note is issued, and is late if written afterwards.
    """
    evidence = invoice.vat_evidence
    calculated_at = parse_datetime(evidence["calculated_at"])
    if calculated_at and invoice.issued_at and calculated_at > invoice.issued_at:
        return True
    if evidence.get("version") != CREDIT_NOTE_EVIDENCE_VERSION:
        return False
    original = invoice.reverses_invoice
    decided_at = parse_datetime(evidence["reverses_calculated_at"])
    return original is None or original.issued_at is None or decided_at is None or decided_at > original.issued_at


def _vies_problems(invoice: Invoice) -> list[str]:
    """Review contrary or stale captured proof without querying today's VIES status."""
    proof = invoice.vat_evidence.get("vies")
    if proof is None:
        return []
    try:
        if not isinstance(proof, dict) or type(proof["is_valid"]) is not bool:
            raise ValueError("Malformed validation proof")
        if not isinstance(proof.get("consultation_reference", ""), str):
            raise ValueError("Malformed consultation reference")
        if not proof["is_valid"]:
            raise ValueError("Captured VAT validation was negative")
        if vat_identity(proof["vat_number"], proof["country_code"]) != vat_identity(
            invoice.bill_to_tax_id, invoice.bill_to_country
        ):
            raise ValueError("Captured VAT validation refers to a different identity")
        checked_at = parse_datetime(proof["validated_at"])
        # A credit note's proof is its original's: current when the original was decided, and judged
        # by the rules its original was written under, not by the note's later restatement.
        calculated_at = parse_datetime(_decided_at(invoice.vat_evidence))
        if evidence_rules_version(invoice.vat_evidence) >= CONSULTATION_REFERENCE_EVIDENCE_VERSION:
            max_age = invoice.vat_evidence.get("evidence_max_age_days", 30)
            if type(max_age) is not int or max_age < 1:
                raise ValueError("Malformed evidence maximum age")
            expires_at = checked_at + timedelta(days=max_age) if checked_at else None
        else:
            expires_at = parse_datetime(proof["expires_at"]) if proof.get("expires_at") else None
            if proof.get("expires_at") and expires_at is None:
                raise ValueError("Malformed validation expiry")
        if (
            not checked_at
            or not calculated_at
            or checked_at > calculated_at
            or (expires_at and expires_at < calculated_at)
        ):
            raise ValueError("Captured VAT validation was not current at calculation time")
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        return [f"conflicting_vat_validation: {exc}."]
    return []


def _settlement(refund: Refund, invoice: Invoice) -> RefundSettlement:
    """How far `refund` has been settled for `invoice`.

    Settled only by a correction decided against THIS invoice: a credit note of it that reached the
    customer, or a validated finding that it needed none. A correction on another invoice, or one
    that found no fiscal document at all, was never decided against this supply.
    """
    from apps.promotions.models import TenderRefundLeg  # noqa: PLC0415  # ADR-0007 cross-app import

    correction = (
        FiscalCorrection.objects.filter(
            Q(source_refund_id=refund.pk) | Q(source_command__legs__refund_id=refund.pk)
        ).first()
        if refund.status == "completed"
        else None
    )
    payment_id = refund.payment_id or (
        TenderRefundLeg.objects.filter(refund_id=refund.pk).values_list("payment_id", flat=True).first()
    )
    return RefundSettlement(
        refund_id=str(refund.pk),
        status=refund.status,
        amount_cents=refund.amount_cents,
        payment_id="" if payment_id is None else str(payment_id),
        raised_on=ro_local_date(refund.created_at),
        correction_id="" if correction is None else str(correction.pk),
        correction_state="" if correction is None else correction.state,
        correction_original_id=None if correction is None else correction.original_id,
        fiscal_date=None if correction is None else correction.fiscal_date,
        settled=correction is not None
        and correction.original_id == invoice.pk
        and correction.state in SETTLED_CORRECTION_STATES,
    )


def _refund_evidence(invoice: Invoice) -> tuple[list[RefundSettlement], list[dict[str, str]]]:
    """Find refund events even when recorded against the payment or source order.

    Returns each refund with how far it is settled for this invoice, and the legacy order
    metadata that no refund row explains.
    """
    order_links = Q(invoice=invoice)
    related = (
        Q(invoice=invoice)
        | Q(payment__invoice=invoice)
        | Q(order__invoice=invoice)
        | Q(order__id__in=invoice.orders.values("pk"))
    )
    proforma_id = invoice.converted_from_proforma_id or (invoice.meta or {}).get("proforma_id")
    if proforma_id:
        related |= Q(order__proforma_id=proforma_id) | Q(payment__proforma_id=proforma_id)
        order_links |= Q(proforma_id=proforma_id)
    order_id = (invoice.meta or {}).get("order_id")
    if order_id:
        related |= Q(order_id=order_id)
        order_links |= Q(pk=order_id)
    settlements = [
        _settlement(refund, invoice)
        for refund in Refund.objects.filter(related, status__in=UNRESOLVED_REFUNDS).distinct().order_by("pk")
    ]
    legacy = [
        {
            "order_id": str(order.pk),
            "status": "legacy_metadata",
            "refunds": json.dumps(order.meta["refunds"], sort_keys=True),
        }
        for order in invoice.orders.model.objects.filter(order_links).only("pk", "meta").order_by("pk")
        if isinstance(order.meta, dict) and order.meta.get("refunds")
    ]
    return settlements, legacy


def _discount_allocations(lines: list[InvoiceLine], discount: int) -> dict[int, int]:
    """Allocate a supported single-category document discount once, in cents."""
    gross = sum(line.subtotal_cents for line in lines)
    if not discount or not gross:
        return dict.fromkeys((line.pk for line in lines), 0)
    allocated = {line.pk: discount * line.subtotal_cents // gross for line in lines}
    remainders = sorted(lines, key=lambda line: (-(discount * line.subtotal_cents % gross), line.pk))
    for line in remainders[: discount - sum(allocated.values())]:
        allocated[line.pk] += 1
    return allocated


def _require_legal_number(invoice: Invoice) -> str:
    """Return the invoice's legal number, refusing to report a document without one.

    A statutory declaration must identify every document it reports. An unissued or
    malformed row reaching this point is a data-integrity fault, not something to
    paper over with a placeholder, and `assert` is not adequate here because it
    disappears under `python -O`.
    """
    number = (invoice.number or "").strip()
    if not number:
        raise ValueError(f"Invoice pk={invoice.pk} has no legal number and cannot be reported in EC Sales.")
    return number


def _exception(invoice: Invoice, line: InvoiceLine | None, problems: list[str]) -> ReviewException:
    distinct = list(dict.fromkeys(problems))
    return ReviewException(
        invoice.pk,
        _require_legal_number(invoice),
        line.pk if line else None,
        tuple(problem.split(":", 1)[0] for problem in distinct),
        " ".join(problem.partition(": ")[2] or problem for problem in distinct),
        invoice.tax_point_date,
        invoice.currency_id,
        line.subtotal_cents if line else None,
    )


def _settling_correction(invoice: Invoice) -> FiscalCorrection | None:
    """The correction a credit note settles, if any. A reverse one-to-one raises when absent."""
    correction: FiscalCorrection | None = getattr(invoice, "settled_fiscal_correction", None)
    return correction


def _correction_source(correction: FiscalCorrection | None) -> dict[str, object]:
    """What places a credit note in a month, so a note reaching its customer changes the fingerprint."""
    if correction is None:
        return {"id": None}
    return {
        "id": str(correction.pk),
        "state": correction.state,
        "original_id": correction.original_id,
        "communicated_at": correction.communicated_at,
        "fiscal_date": correction.fiscal_date,
    }


def _documents_in(period: ReportingPeriod) -> Q:
    """Invoices by tax point; credit notes by the month they reached the customer.

    A note not yet communicated has no month: it is shown, blocked, in every month from its own
    tax point on until it is sent, and never declared. Its tax point never places it otherwise, or a
    note issued in June and sent in July would be counted in both.
    """
    credit = Q(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
    communicated = Q(settled_fiscal_correction__state=STATE_COMMUNICATED)
    # Spelt out: `state` is NOT NULL, so Django negates it without an `IS NULL` arm, and a note with
    # no correction row (NULL through the outer join) would fail both branches and vanish.
    uncommunicated = Q(settled_fiscal_correction__isnull=True) | ~communicated
    tax_point_unknown = Q(tax_point_date__isnull=True)
    return (
        (~credit & (Q(tax_point_date__gte=period.start, tax_point_date__lt=period.end) | tax_point_unknown))
        | (
            credit
            & communicated
            & Q(
                settled_fiscal_correction__fiscal_date__gte=period.start,
                settled_fiscal_correction__fiscal_date__lt=period.end,
            )
        )
        | (credit & uncommunicated & (Q(tax_point_date__lt=period.end) | tax_point_unknown))
    )


def aggregate_ec_services(period: ReportingPeriod) -> ECSalesReport:  # noqa: PLR0915  # One reconciliation pass
    """Reconcile each candidate exactly once, then aggregate RON before rounding."""
    invoices = (
        Invoice.objects.exclude(status="draft")
        .exclude(status="void", issued_at__isnull=True, locked_at__isnull=True)
        .filter(_documents_in(period))
        .select_related("settled_fiscal_correction", "reverses_invoice")
        .prefetch_related("lines", "payments")
        .order_by("pk")
    )
    included: list[SupplyContribution] = []
    exceptions: list[ReviewException] = []
    candidates: list[int] = []
    source: list[object] = []
    handled_invoice_ids: set[int] = set()
    for invoice in invoices:
        lines = sorted(invoice.lines.all(), key=lambda line: line.pk)
        candidate_lines = [line for line in lines if _candidate(invoice, line)]
        if not candidate_lines and (lines or not _candidate(invoice, None)):
            continue
        handled_invoice_ids.add(invoice.pk)
        candidates.extend(line.pk for line in candidate_lines)
        try:
            decision = read_vat_evidence(invoice)
            problems = _document_problems(invoice, lines, decision)
        except TaxEvidenceError as exc:
            problems = [f"invalid_evidence: {exc}"]
        placed_on = invoice.tax_point_date
        correction = None
        if invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE:
            correction = _settling_correction(invoice)
            if correction is None or correction.state != STATE_COMMUNICATED or correction.fiscal_date is None:
                placed_on = None
                problems.append(
                    "uncommunicated_credit_note: The credit note has not reached the customer, so it has no "
                    "D390 month yet; it is declared in the month it is sent."
                )
            else:
                placed_on = correction.fiscal_date
        try:
            settlements, legacy_order_refunds = _refund_evidence(invoice)
        except (ValidationError, ValueError, TypeError, AttributeError):
            settlements, legacy_order_refunds = [], []
            problems.append("invalid_refund_links: Source document links cannot be reconciled.")
        refunded_payments = [
            payment for payment in invoice.payments.all() if payment.status in {"refunded", "partially_refunded"}
        ]
        refunded_payment = bool(refunded_payments)
        legacy_refunds = isinstance(invoice.meta, dict) and invoice.meta.get("refunds")
        # A refunded status or payment is a refund's footprint, and only refund rows explain it: each
        # one settled or holding the month its correction can land in. A refunded invoice needs at least
        # one. A refunded payment needs a completed refund of its own; another payment's refund says
        # nothing about the money this one returned.
        explained_payments = {
            settlement.payment_id
            for settlement in settlements
            if settlement.status == "completed" and settlement.payment_id
        }
        unexplained_refund = (invoice.status in {"refunded", "partially_refunded"} and not settlements) or any(
            str(payment.pk) not in explained_payments for payment in refunded_payments
        )
        if (
            invoice.status == "void"
            or legacy_refunds
            or legacy_order_refunds
            or unexplained_refund
            or any(settlement.could_land_in(period) for settlement in settlements)
        ):
            problems.append(
                "unresolved_fiscal_adjustment: Void or refund event requires review; a refund is deducted only "
                "by its credit note, in the month the customer received it."
            )
        source.append(
            {
                "invoice": {
                    field.name: getattr(invoice, field.attname)
                    for field in invoice._meta.concrete_fields
                    if field.name in Invoice._LOCKED_FIELDS
                    or field.name in {"id", "number", "status", "meta", "converted_from_proforma", "currency"}
                },
                "lines": [
                    {field.name: getattr(line, field.attname) for field in line._meta.concrete_fields} for line in lines
                ],
                "refunds": [asdict(settlement) for settlement in settlements],
                "legacy_order_refunds": legacy_order_refunds,
                "refunded_payment": refunded_payment,
                "correction": _correction_source(correction),
            }
        )
        if not lines:
            exceptions.append(
                _exception(invoice, None, [*problems, "missing_lines: Invoice has no contributing lines."])
            )
        allocations = _discount_allocations(lines, invoice.discount_cents) if not problems else {}
        for line in candidate_lines:
            line_problems = problems + _line_problems(line)
            if line_problems:
                exceptions.append(_exception(invoice, line, line_problems))
                continue
            country, body = vat_identity(invoice.bill_to_tax_id, invoice.bill_to_country)
            rate = Decimal(1) if invoice.currency_id == "RON" else invoice.exchange_to_ron
            assert rate is not None and placed_on is not None
            invoice_number = _require_legal_number(invoice)
            discount = allocations[line.pk]
            included.append(
                SupplyContribution(
                    invoice.pk,
                    invoice_number,
                    line.pk,
                    line.description,
                    placed_on,
                    country,
                    body,
                    invoice.bill_to_name.strip(),
                    invoice.currency_id,
                    line.subtotal_cents,
                    discount,
                    rate,
                    Decimal(line.subtotal_cents - discount) / 100 * rate,
                    f"{invoice.vat_evidence['vies'].get('source', 'unknown')}:valid"
                    if invoice.vat_evidence.get("vies")
                    else "not_recorded",
                    (invoice.vat_evidence.get("vies") or {}).get("consultation_reference", ""),
                )
            )
    adjustment_exceptions, adjustment_source = _other_period_adjustments(period, handled_invoice_ids)
    exceptions.extend(adjustment_exceptions)
    source.extend(adjustment_source)
    partners, final_included = _group_supplies(included, exceptions)
    fingerprint = hashlib.sha256(
        json.dumps({"period": asdict(period), "source": source}, sort_keys=True, default=str).encode()
    ).hexdigest()
    report = ECSalesReport(
        period,
        tuple(partners),
        tuple(final_included),
        tuple(sorted(exceptions, key=lambda exc: (exc.invoice_id, exc.line_id or 0))),
        tuple(candidates),
        fingerprint,
    )
    report.assert_reconciled()
    return report


def _line_problems(line: InvoiceLine) -> list[str]:
    problems = []
    if line.kind not in SUPPORTED_KINDS:
        problems.append("unsupported_line_kind: Only service and setup supplies are supported.")
    if line.tax_category_code != "AE" or line.tax_rate != 0 or line.tax_cents != 0:
        problems.append("line_evidence_mismatch: Line category, rate and tax must record zero-tax reverse charge.")
    totals = calculate_line_totals(line.subtotal_cents, line.tax_rate)
    if (
        line.quantity <= 0
        # Zero, not negative. A negated line is the correction; only an empty one is
        # meaningless, and it is meaningless in either direction.
        or line.subtotal_cents == 0
        or totals.tax_cents != line.tax_cents
        or totals.line_total_cents != line.line_total_cents
    ):
        problems.append("line_amount_mismatch: Supply amounts must reconcile to the stored line total.")
    return problems


def _group_supplies(
    included: list[SupplyContribution], exceptions: list[ReviewException]
) -> tuple[list[PartnerSupply], list[SupplyContribution]]:
    """Net and round once per VAT identity and operation, and reject conflicting names before rendering.

    A credit note's negative lines net against the month's supplies to the same partner. A negative
    net is declared as such. A net of exactly zero made by a credit note is kept as a fully netted
    group, which the XML leaves out; anything else that rounds to zero lei needs review.
    """
    grouped: dict[tuple[str, str, str], list[SupplyContribution]] = defaultdict(list)
    for contribution in included:
        grouped[(contribution.country, contribution.vat_body, contribution.operation)].append(contribution)
    partners: list[PartnerSupply] = []
    final_included: list[SupplyContribution] = []
    for (country, body, _operation), contributions in sorted(grouped.items()):
        names = {line.partner_name for line in contributions}
        base = sum((line.base_ron for line in contributions), Decimal(0))
        rounded = int(base.quantize(Decimal(1), rounding=ROUND_HALF_UP))
        fully_netted = base == 0 and any(line.base_ron < 0 for line in contributions)
        if len(names) != 1 or (rounded == 0 and not fully_netted):
            code = "conflicting_partner_names" if len(names) != 1 else "zero_rounded_base"
            exceptions.extend(
                ReviewException(
                    line.invoice_id,
                    line.invoice_number,
                    line.line_id,
                    (code,),
                    "Partner names must agree, and a monthly base that rounds to zero lei must be fully "
                    "netted by a credit note.",
                    line.tax_point_date,
                    line.currency,
                    line.gross_cents,
                )
                for line in contributions
            )
            continue
        partners.append(
            PartnerSupply(country, body, names.pop(), tuple(contributions), base, rounded, Decimal(rounded) - base)
        )
        final_included.extend(contributions)
    return partners, final_included


def _other_period_adjustments(period: ReportingPeriod, handled: set[int]) -> tuple[list[ReviewException], list[object]]:
    """Hold this month for refunds on older supplies whose correction could still land in it.

    A refund raised in or before this month and not yet settled (its credit note not yet with the
    customer, or no decision that none is owed) may be declared in this month or a later one, so
    each such month is held. The original's own month, closed before the refund, is not. Once the
    note is sent it is declared in its month as a supply line of its own and holds nothing.

    Every refund is judged against each invoice it links to. Nothing is skipped as settled before
    that: a correction closed with no original, or decided against another invoice, settles nothing
    for this one.
    """
    end = datetime.combine(period.end, time.min, BUCHAREST)
    exceptions: list[ReviewException] = []
    source: list[object] = []
    alerted: set[int] = set()
    refunds = (
        Refund.objects.filter(status__in=UNRESOLVED_REFUNDS, created_at__lt=end)
        .select_related("payment", "order")
        .order_by("pk")
    )
    for refund in refunds:
        links = Q(pk=refund.invoice_id)
        proforma_ids = set()
        if refund.payment:
            links |= Q(pk=refund.payment.invoice_id)
            proforma_ids.add(refund.payment.proforma_id)
        if refund.order:
            links |= Q(pk=refund.order.invoice_id) | Q(meta__order_id=str(refund.order_id))
            proforma_ids.add(refund.order.proforma_id)
        for proforma_id in proforma_ids - {None}:
            links |= Q(converted_from_proforma_id=proforma_id) | Q(meta__proforma_id=str(proforma_id))
        invoices = Invoice.objects.filter(links).exclude(status="draft").prefetch_related("lines").order_by("pk")
        for invoice in invoices:
            if invoice.pk in handled or not any(_candidate(invoice, line) for line in invoice.lines.all()):
                continue
            settlement = _settlement(refund, invoice)
            if not settlement.could_land_in(period):
                continue
            source.append(
                {
                    **asdict(settlement),
                    "created_at": refund.created_at,
                    "processed_at": refund.processed_at,
                    "gateway_processed_at": refund.gateway_processed_at,
                    "invoice_id": invoice.pk,
                    "tax_point": invoice.tax_point_date,
                    "vat_evidence": invoice.vat_evidence,
                }
            )
            if invoice.pk in alerted:
                continue
            exceptions.append(
                _exception(
                    invoice,
                    None,
                    [
                        "outside_period_adjustment: A refund of a supply from an earlier month is not settled yet; "
                        "its credit note may be declared in this month. Settle it, or have the accountant "
                        "determine the treatment."
                    ],
                )
            )
            alerted.add(invoice.pk)
    return exceptions, source
