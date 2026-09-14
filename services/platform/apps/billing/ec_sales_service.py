"""Monthly outgoing intra-Community service supplies, with an exhaustive reconciliation.

One operating entity owns this invoice ledger. This service reads frozen invoice
facts only; D390 serialization and supplier/declarant validation are separate.
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
from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.billing.refund_models import Refund
from apps.billing.tax_evidence import TaxEvidenceError, VATDecision, read_vat_evidence, vat_country, vat_identity
from apps.common.eu_vat_validator import EU_COUNTRIES, validate_vat_format
from apps.common.financial_arithmetic import calculate_line_totals

SERVICE_COUNTRIES = EU_COUNTRIES - {"RO"}
SUPPORTED_KINDS = {"service", "setup"}
MIN_YEAR = 2020
MAX_YEAR = 2100
MONTHS_PER_YEAR = 12
PARTNER_NAME_LIMIT = 200
UNRESOLVED_REFUNDS = {"pending", "processing", "approved", "completed"}


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
    def can_export(self) -> bool:
        return bool(self.partners) and not self.exceptions

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
    if decision and invoice.issued_at:
        calculated_at = parse_datetime(invoice.vat_evidence["calculated_at"])
        if calculated_at and calculated_at > invoice.issued_at:
            problems.append("late_tax_decision: VAT decision was recorded after invoice issuance.")
    problems.extend(_identity_problems(invoice, decision))
    problems.extend(_vies_problems(invoice))
    gross = sum(line.subtotal_cents for line in lines)
    if (
        invoice.discount_cents > gross
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
        if proof.get("source") == "vies" and proof.get("is_active") is not True:
            raise ValueError("Captured VIES validation did not establish active VAT status")
        if vat_identity(proof["vat_number"], proof["country_code"]) != vat_identity(
            invoice.bill_to_tax_id, invoice.bill_to_country
        ):
            raise ValueError("Captured VAT validation refers to a different identity")
        checked_at = parse_datetime(proof["validated_at"])
        calculated_at = parse_datetime(invoice.vat_evidence["calculated_at"])
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
    except (KeyError, TypeError, ValueError) as exc:
        return [f"conflicting_vat_validation: {exc}."]
    return []


def _refund_evidence(invoice: Invoice) -> list[dict[str, str]]:
    """Find unresolved events even when recorded against the payment or source order."""
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
    evidence = [
        {"id": str(refund.pk), "status": refund.status, "amount_cents": str(refund.amount_cents)}
        for refund in Refund.objects.filter(related, status__in=UNRESOLVED_REFUNDS).distinct().order_by("pk")
    ]
    evidence.extend(
        {
            "order_id": str(order.pk),
            "status": "legacy_metadata",
            "refunds": json.dumps(order.meta["refunds"], sort_keys=True),
        }
        for order in invoice.orders.model.objects.filter(order_links).only("pk", "meta").order_by("pk")
        if isinstance(order.meta, dict) and order.meta.get("refunds")
    )
    return evidence


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


def _exception(invoice: Invoice, line: InvoiceLine | None, problems: list[str]) -> ReviewException:
    distinct = list(dict.fromkeys(problems))
    return ReviewException(
        invoice.pk,
        invoice.number,
        line.pk if line else None,
        tuple(problem.split(":", 1)[0] for problem in distinct),
        " ".join(problem.partition(": ")[2] or problem for problem in distinct),
        invoice.tax_point_date,
        invoice.currency_id,
        line.subtotal_cents if line else None,
    )


def aggregate_ec_services(period: ReportingPeriod) -> ECSalesReport:
    """Reconcile each candidate exactly once, then aggregate RON before rounding."""
    invoices = (
        Invoice.objects.exclude(status="draft")
        .exclude(status="void", issued_at__isnull=True, locked_at__isnull=True)
        .filter(Q(tax_point_date__gte=period.start, tax_point_date__lt=period.end) | Q(tax_point_date__isnull=True))
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
        try:
            refunds = _refund_evidence(invoice)
        except (ValidationError, ValueError, TypeError, AttributeError):
            refunds = []
            problems.append("invalid_refund_links: Source document links cannot be reconciled.")
        refunded_payment = any(
            payment.status in {"refunded", "partially_refunded"} for payment in invoice.payments.all()
        )
        legacy_refunds = isinstance(invoice.meta, dict) and invoice.meta.get("refunds")
        if (
            invoice.status in {"void", "refunded", "partially_refunded"}
            or refunds
            or refunded_payment
            or legacy_refunds
        ):
            problems.append(
                "unresolved_fiscal_adjustment: Void/refund event requires review; payment refunds are not fiscal credit notes."
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
                "refunds": refunds,
                "refunded_payment": refunded_payment,
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
            assert rate is not None and invoice.tax_point_date is not None
            discount = allocations[line.pk]
            included.append(
                SupplyContribution(
                    invoice.pk,
                    invoice.number,
                    line.pk,
                    line.description,
                    invoice.tax_point_date,
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
        or line.subtotal_cents <= 0
        or totals.tax_cents != line.tax_cents
        or totals.line_total_cents != line.line_total_cents
    ):
        problems.append("line_amount_mismatch: Positive supply amounts must reconcile to the stored line total.")
    return problems


def _group_supplies(
    included: list[SupplyContribution], exceptions: list[ReviewException]
) -> tuple[list[PartnerSupply], list[SupplyContribution]]:
    """Round once per VAT identity and reject conflicting names before rendering."""
    grouped: dict[tuple[str, str, str], list[SupplyContribution]] = defaultdict(list)
    for contribution in included:
        grouped[(contribution.country, contribution.vat_body, contribution.operation)].append(contribution)
    partners: list[PartnerSupply] = []
    final_included: list[SupplyContribution] = []
    for (country, body, _operation), contributions in sorted(grouped.items()):
        names = {line.partner_name for line in contributions}
        base = sum((line.base_ron for line in contributions), Decimal(0))
        rounded = int(base.quantize(Decimal(1), rounding=ROUND_HALF_UP))
        if len(names) != 1 or rounded <= 0:
            code = "conflicting_partner_names" if len(names) != 1 else "zero_rounded_base"
            exceptions.extend(
                ReviewException(
                    line.invoice_id,
                    line.invoice_number,
                    line.line_id,
                    (code,),
                    "Partner names must agree and the monthly rounded base must be positive.",
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
    """Surface current-month refund events on older supplies without assigning a tax period.

    An accountant must decide whether these are current adjustments or corrections
    to an earlier declaration. Event dates are used for review alerts only.
    """
    start = datetime.combine(period.start, time.min, ZoneInfo("Europe/Bucharest"))
    end = datetime.combine(period.end, time.min, ZoneInfo("Europe/Bucharest"))
    event_dates = (
        Q(created_at__gte=start, created_at__lt=end)
        | Q(processed_at__gte=start, processed_at__lt=end)
        | Q(gateway_processed_at__gte=start, gateway_processed_at__lt=end)
    )
    exceptions: list[ReviewException] = []
    source: list[object] = []
    alerted: set[int] = set()
    refunds = (
        Refund.objects.filter(event_dates, status__in=UNRESOLVED_REFUNDS)
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
            source.append(
                {
                    "refund_id": str(refund.pk),
                    "status": refund.status,
                    "amount_cents": refund.amount_cents,
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
                        "outside_period_adjustment: Refund event recorded in this month affects a supply with another tax point. "
                        "The accountant must determine the fiscal adjustment or rectificative treatment."
                    ],
                )
            )
            alerted.add(invoice.pk)
    return exceptions, source
