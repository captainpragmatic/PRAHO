"""Turning a PRAHO invoice into a SmartBill payload, or refusing to.

Refusing is half the job. SmartBill's API models *commercial* invoicing — price,
quantity, VAT percentage — while e-Factura models *legal* invoicing: why is this
transaction taxed the way it is. There is no EN16931 tax-category field (BT-151)
and no exemption-reason field (BT-120/121) anywhere in the request. A 0% rate can
therefore answer "how much" but never "why", and for a reverse charge the "why" is
the mandatory part.

So anything whose fiscal meaning cannot be expressed is refused rather than
approximated. A blocked invoice is a staff alert. An invoice filed with ANAF under
the wrong VAT category is a compliance problem discovered by an inspector.

The second job is arithmetic. SmartBill recomputes totals from price x quantity and
will not accept ours. Any divergence means the legal document disagrees with
PRAHO's ledger, so the expected result is reproduced locally and the payload is
refused unless it matches to the cent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apps.billing.invoice_models import Invoice

# Only a plain positive rate can be expressed unambiguously through an API that
# carries no category and no exemption reason.
#
#   S  standard/reduced positive rate      -> supported
#   AE EU B2B reverse charge               -> refused: needs BT-151=AE and a reason
#   Z  zero-rated                          -> refused: a 0% rate does not say why
#   O  outside scope of VAT                -> refused: same
#
# V3 exposes `isReverseCharge` on a VAT rate, which is promising evidence that AE
# could be supported, but it proves SmartBill *distinguishes* such rates internally,
# not what XML it emits. Widening this set requires inspecting a generated document.
SUPPORTED_TAX_CATEGORIES = frozenset({"S"})

# SmartBill supports 2-4 and silently caps higher values. Only 2 is certified here,
# because its VAT calculation method is account-configurable and untested at others.
SUPPORTED_PRECISION = 2

BUCHAREST_SECTORS = frozenset({f"Sector {n}" for n in range(1, 7)})

# SmartBill's discount-line encoding. A value discount must be NEGATIVE: a positive
# one is accepted and silently INCREASES the total.
DISCOUNT_TYPE_VALUE = 1


@dataclass(frozen=True)
class SmartBillAccountConfig:
    """Strings that must match the SmartBill account exactly.

    `seriesName`, `taxName` and `measuringUnitName` are account-coupled: `buc` and
    `BUC` are different values. They are never invented — they come from the
    operator's configuration and are checked against live discovery in preflight.
    """

    invoice_series: str
    tax_names: Mapping[str, str] = field(default_factory=dict)
    """Maps a PRAHO fiscal meaning to the account's rate name, keyed "category:rate"
    (for example "S:21.00" -> "Normala"). Keyed by meaning, not by percentage alone:
    two configured rates can share a percentage with different fiscal meaning."""

    measuring_unit: str = "buc"
    language: str = "RO"
    precision: int = 2
    company_vat_code: str = ""


@dataclass(frozen=True)
class MappedInvoice:
    """A payload plus what we expect SmartBill to compute from it."""

    payload: dict[str, Any]
    expected_total_cents: int
    expected_net_cents: int
    expected_vat_cents: int
    tax_name: str


def _money(cents: int) -> Decimal:
    return (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"))


def _tax_key(category: str, rate_percent: Decimal) -> str:
    return f"{category}:{rate_percent.quantize(Decimal('0.01'))}"


def _line_rate_percent(line: Any) -> Decimal:
    """`tax_rate` is stored as a fraction (0.2100); SmartBill wants a percentage."""
    return (Decimal(str(line.tax_rate)) * 100).quantize(Decimal("0.01"))


def _collect_refusals(invoice: Invoice, lines: list[Any]) -> list[str]:  # noqa: C901  # A checklist of fiscal refusals; splitting it scatters the reasoning it exists to keep together
    """Every reason this document must not be sent, gathered in one pass.

    All of them, not the first: an operator fixing one problem at a time against a
    provider that charges a fiscal number per attempt is a bad trade.
    """
    problems: list[str] = []

    if not lines:
        problems.append("Invoice has no lines")
        return problems

    if any(not (line.tax_category_code or "").strip() for line in lines):
        problems.append(
            "A line has no EN16931 tax category. Defaulting it to 'S' would invent a "
            "fiscal fact, which is exactly what this mapper refuses to do."
        )
    categories = {line.tax_category_code for line in lines if (line.tax_category_code or "").strip()}
    unsupported = categories - SUPPORTED_TAX_CATEGORIES
    if unsupported:
        problems.append(
            f"Tax category {sorted(unsupported)} cannot be expressed through SmartBill's API, "
            f"which has no BT-151 category and no BT-120/121 exemption reason. "
            f"Supported: {sorted(SUPPORTED_TAX_CATEGORIES)}"
        )

    rates = {_line_rate_percent(line) for line in lines}
    if len(rates) > 1:
        problems.append(
            f"Multiple VAT rates on one document ({sorted(rates)}); a single document "
            f"discount cannot be allocated across rates without distorting the VAT breakdown"
        )
    if any(rate <= 0 for rate in rates):
        problems.append(f"A zero or negative VAT rate has no unambiguous meaning here (rates: {sorted(rates)})")

    if any(getattr(line, "discount_amount_cents", 0) for line in lines):
        problems.append("Line-level discounts are unsupported; use the document discount")

    if any(Decimal(str(line.quantity)) <= 0 for line in lines):
        problems.append("A zero or negative quantity is accepted by SmartBill without error and must be refused here")

    if not (invoice.bill_to_name or "").strip():
        problems.append("Missing bill_to_name")

    region = (invoice.bill_to_region or "").strip()
    city = (invoice.bill_to_city or "").strip()
    if region.lower() in {"bucuresti", "bucurești", "bucharest"} and city not in BUCHAREST_SECTORS:
        problems.append(
            f"For Bucuresti the city must be one of Sector 1..6 (got {city!r}); "
            f"otherwise the e-Factura fails SPV validation"
        )

    if not (invoice.bill_to_country or "").strip():
        problems.append("Missing bill_to_country; assuming Romania would invent a fiscal fact")

    if invoice.currency_id != "RON" and invoice.exchange_to_ron is None:
        problems.append("Foreign-currency invoice has no frozen exchange rate")

    # P1-2: VAT registration is a recorded fact, not something to infer from the
    # presence of a tax ID — a Romanian company can hold a CUI without being
    # VAT-registered, and marking it as registered misstates the document.
    evidence = invoice.vat_evidence or {}
    if "is_business" not in evidence:
        problems.append(
            "No frozen VAT evidence on this invoice, so the buyer's VAT-registration "
            "status cannot be stated. SmartBill defaults isTaxPayer to false, which "
            "would misrepresent a registered company."
        )

    return problems


def build_invoice_payload(  # noqa: C901  # Payload assembly plus the pre-POST checks that must run before it
    invoice: Invoice,
    config: SmartBillAccountConfig,
) -> Result[MappedInvoice, tuple[str, ...]]:
    """Build the issuance payload, or return every reason it must not be sent."""
    lines = list(invoice.lines.all().order_by("sort_order", "id"))
    problems = _collect_refusals(invoice, lines)

    if not (config.invoice_series or "").strip():
        problems.append("No SmartBill invoice series configured")
    if not (config.measuring_unit or "").strip():
        problems.append("No SmartBill measuring unit configured")
    if config.precision != SUPPORTED_PRECISION:
        problems.append(
            f"Only precision {SUPPORTED_PRECISION} is certified. SmartBill's VAT calculation "
            f"method is account-configurable (per-line versus document total) and untested "
            f"here at other precisions."
        )

    tax_name = ""
    if lines and not problems:
        category = lines[0].tax_category_code or "S"
        rate_percent = _line_rate_percent(lines[0])
        key = _tax_key(category, rate_percent)
        tax_name = config.tax_names.get(key, "")
        if not tax_name:
            problems.append(
                f"No SmartBill tax name configured for {key}. Selecting a rate by percentage "
                f"alone is unsafe: two configured rates can share a percentage with different "
                f"fiscal meaning."
            )

    if problems:
        return Err(tuple(problems))

    rate_percent = _line_rate_percent(lines[0])
    products: list[dict[str, Any]] = [
        {
            "name": line.description or "Service",
            "code": getattr(line, "seller_item_id", "") or "",
            "isService": True,
            "quantity": float(Decimal(str(line.quantity))),
            "measuringUnitName": config.measuring_unit,
            "price": float(_money(line.unit_price_cents)),
            # products[].currency defaults to RON INDEPENDENTLY of the document
            # currency, so omitting it prices a EUR invoice in RON.
            "currency": invoice.currency_id,
            # Explicit, never defaulted: SmartBill treats prices as VAT-exclusive
            # unless told otherwise, and PRAHO stores them that way.
            "isTaxIncluded": False,
            "taxName": tax_name,
            "taxPercentage": float(rate_percent),
            "saveToDb": False,
        }
        for line in lines
    ]

    discount_cents = int(invoice.discount_cents or 0)
    if discount_cents:
        products.append(
            {
                "name": "Discount",
                "isDiscount": True,
                # Required. Omitting it makes SmartBill silently ignore the discount,
                # return 200, and issue the document at the unreduced total.
                "numberOfItems": len(lines),
                "discountType": DISCOUNT_TYPE_VALUE,
                # Must be negative. A positive value increases the total instead.
                "discountValue": float(-_money(discount_cents)),
                "currency": invoice.currency_id,
                "measuringUnitName": config.measuring_unit,
                "quantity": 1,
                "price": 0,
                "taxName": tax_name,
                "taxPercentage": float(rate_percent),
            }
        )

    client: dict[str, Any] = {
        "name": invoice.bill_to_name,
        "vatCode": invoice.bill_to_tax_id or "",
        # From the document's frozen VAT evidence, never inferred from the presence
        # of a tax ID: a company can hold a CUI without being VAT-registered.
        "isTaxPayer": bool((invoice.vat_evidence or {}).get("is_business")),
        "regCom": invoice.bill_to_registration_number or "",
        "address": invoice.bill_to_address1 or "",
        "city": invoice.bill_to_city or "",
        "county": invoice.bill_to_region or "",
        "country": invoice.bill_to_country or "RO",
        "email": invoice.bill_to_email or "",
        # No nomenclature sync: the document carries an immutable billing-party
        # snapshot rather than creating a second customer master at the provider.
        "saveToDb": False,
    }

    payload: dict[str, Any] = {
        "companyVatCode": config.company_vat_code,
        "seriesName": config.invoice_series,
        "isDraft": False,
        "client": client,
        "products": products,
        "precision": config.precision,
        "language": config.language,
        # PRAHO owns delivery: it keeps template control, locale, notification
        # history and the portal's record of what the customer was sent.
        "sendEmail": False,
    }
    if invoice.issued_at:
        payload["issueDate"] = invoice.issued_at.date().isoformat()
    if invoice.due_at:
        payload["dueDate"] = invoice.due_at.date().isoformat()
    if invoice.currency_id != "RON":
        frozen_rate = invoice.exchange_to_ron
        if frozen_rate is None:  # already refused above; keeps the guarantee local and checkable
            return Err(("Foreign-currency invoice has no frozen exchange rate",))
        payload["currency"] = invoice.currency_id
        # Romanian law requires the BNR rate for the RON accounting totals, and
        # PRAHO froze that rate at issuance. Per-line rates are omitted: they can
        # disagree with the document rate and produce inconsistent accounting values.
        payload["exchangeRate"] = float(frozen_rate)

    expected = _expected_totals(lines, rate_percent, discount_cents, config.precision)
    divergences = [
        f"{label} {expected[key]} vs ledger {ledger}"
        for label, key, ledger in (
            ("net", "net_cents", int(invoice.subtotal_cents)),
            ("VAT", "vat_cents", int(invoice.tax_cents)),
            ("total", "total_cents", int(invoice.total_cents)),
        )
        if expected[key] != ledger
    ]
    if divergences:
        # All three, not just the total: a taxable base of 10001 with 2099 VAT and one
        # of 10000 with 2100 VAT both sum to 12100, yet they are different documents
        # for VAT reporting.
        return Err(
            (
                "SmartBill would compute "
                + "; ".join(divergences)
                + ". Issuing would make the legal document disagree with our own record.",
            )
        )

    return Ok(
        MappedInvoice(
            payload=payload,
            expected_total_cents=expected["total_cents"],
            expected_net_cents=expected["net_cents"],
            expected_vat_cents=expected["vat_cents"],
            tax_name=tax_name,
        )
    )


def _expected_totals(
    lines: list[Any],
    rate_percent: Decimal,
    discount_cents: int,
    precision: int,
) -> dict[str, int]:
    """Reproduce SmartBill's arithmetic locally, at the precision it will use.

    Comparing this to PRAHO's stored cents before sending is the only way to catch a
    divergence while it is still cheap. Afterwards the document is issued, possibly
    already in SPV, and correcting it means a storno.
    """
    quantum = Decimal(1).scaleb(-precision)
    net = Decimal(0)
    for line in lines:
        unit = _money(line.unit_price_cents)
        quantity = Decimal(str(line.quantity))
        net += (unit * quantity).quantize(quantum, rounding=ROUND_HALF_UP)

    net -= _money(discount_cents)
    vat = (net * rate_percent / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    total = net + vat

    return {
        "net_cents": int((net * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP)),
        "vat_cents": int((vat * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP)),
        "total_cents": int((total * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP)),
    }
