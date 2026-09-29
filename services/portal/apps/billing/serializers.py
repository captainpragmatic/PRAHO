"""
Portal Billing Serializers - API Response Conversion Functions
Convert Platform API responses to portal dataclass instances.
"""

import re
from datetime import datetime
from decimal import Decimal
from typing import Any, cast

from django.utils.dateparse import parse_datetime

from .schemas import Currency, Invoice, InvoiceLine, InvoiceSummary, Proforma, ProformaLine


def create_currency_from_api(data: dict[str, Any]) -> Currency:
    """Create Currency dataclass from API response"""
    return Currency(
        id=data["id"],
        code=data["code"],
        name=data["name"],
        symbol=data.get("symbol", ""),
        decimal_places=data.get("decimals", 2),  # Fixed: API uses 'decimals' not 'decimal_places'
        is_active=data.get("is_active", True),
    )


def create_invoice_line_from_api(data: dict[str, Any]) -> InvoiceLine:
    """Create InvoiceLine dataclass from API response"""
    return InvoiceLine(
        id=cast(int, data.get("id")),
        invoice_id=cast(int, data.get("invoice_id", data.get("invoice"))),
        kind=data["kind"],
        service_id=data.get("service_id"),
        description=data["description"],
        quantity=Decimal(str(data["quantity"])),
        unit_price_cents=data["unit_price_cents"],
        tax_rate=Decimal(str(data["tax_rate"])),
        line_total_cents=data["line_total_cents"],
    )


def create_invoice_from_api(data: dict[str, Any], lines: list[dict[str, Any]] | None = None) -> Invoice:
    """Create Invoice dataclass from API response"""

    # Parse currency
    currency_data = data.get("currency", {})
    currency = create_currency_from_api(currency_data) if currency_data else None

    # Parse dates
    def parse_date_field(field_name: str) -> datetime | None:
        date_str = data.get(field_name)
        return parse_datetime(date_str) if date_str else None

    # Create invoice - only use fields available from platform API
    invoice = Invoice(
        amount_due=data.get("amount_due"),
        id=data["id"],
        number=data["number"],
        status=data["status"],
        currency=cast(Currency, currency),
        exchange_to_ron=None,  # Not provided by list API
        subtotal_cents=data.get("subtotal_cents", 0),  # Not in list API
        tax_cents=data.get("tax_cents", 0),  # Not in list API
        total_cents=data["total_cents"],
        issued_at=parse_date_field("issued_at"),
        due_at=parse_date_field("due_at"),
        created_at=cast(datetime, parse_datetime(data["created_at"])),
        updated_at=cast(datetime, parse_datetime(data["updated_at"])) if data.get("updated_at") else None,
        locked_at=parse_date_field("locked_at"),
        sent_at=parse_date_field("sent_at"),
        paid_at=parse_date_field("paid_at"),
        bill_to_name=data.get("bill_to_name", ""),
        bill_to_tax_id=data.get("bill_to_tax_id", ""),
        bill_to_email=data.get("bill_to_email", ""),
        bill_to_address1=data.get("bill_to_address1", ""),
        bill_to_address2=data.get("bill_to_address2", ""),
        bill_to_city=data.get("bill_to_city", ""),
        bill_to_region=data.get("bill_to_region", ""),
        bill_to_postal=data.get("bill_to_postal", ""),
        bill_to_country=data.get("bill_to_country", ""),
        efactura_id=data.get("efactura_id", ""),
        efactura_sent=data.get("efactura_sent", False),
        meta=data.get("meta", {}),
    )

    # Extract bill_to data if present (API returns nested dict, not flat fields)
    bill_to = data.get("bill_to", {})
    if bill_to:
        invoice.bill_to_name = bill_to.get("name", "") or invoice.bill_to_name
        invoice.bill_to_email = bill_to.get("email", "") or invoice.bill_to_email
        invoice.bill_to_tax_id = bill_to.get("tax_id", "") or invoice.bill_to_tax_id
        invoice.bill_to_address1 = bill_to.get("address", "") or invoice.bill_to_address1

    # Add line items if provided
    if lines:
        invoice.lines = [create_invoice_line_from_api(line_data) for line_data in lines]

    return invoice


def _currency_amounts_from_api(value: object, *, nonnegative: bool = False) -> dict[str, int]:
    """Historical amounts require explicit currency and integer minor units."""
    if not isinstance(value, dict):
        raise ValueError("Currency amounts must be grouped by their recorded currency")
    amounts = {}
    for code, amount in value.items():
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z]{3}", code):
            raise ValueError("A historical amount has no valid recorded currency")
        if not isinstance(amount, int) or isinstance(amount, bool) or (nonnegative and amount < 0):
            raise ValueError("Currency amounts must be valid integer minor units")
        amounts[code] = amount
    return dict(sorted(amounts.items()))


def create_invoice_summary_from_api(data: dict[str, Any]) -> InvoiceSummary:
    """Keep historical currency groups intact, including explicit legacy single-currency responses."""
    if "amount_due_by_currency" in data:
        amounts_due = _currency_amounts_from_api(data["amount_due_by_currency"], nonnegative=True)
    elif data.get("total_amount_due_cents") == 0 and data.get("currency_code") is None:
        amounts_due = {}
    else:
        amounts_due = _currency_amounts_from_api(
            {data.get("currency_code"): data.get("total_amount_due_cents")}, nonnegative=True
        )
    recorded_credit = _currency_amounts_from_api(data.get("credit_balance_by_currency", {}))
    spendable_credit = _currency_amounts_from_api(data.get("spendable_credit_by_currency", {}), nonnegative=True)
    if any(
        code not in recorded_credit or amount > max(recorded_credit[code], 0)
        for code, amount in spendable_credit.items()
    ):
        raise ValueError("Spendable credit cannot exceed the recorded balance in its currency")
    held_entries = data.get("held_credit_entries", [])
    if not isinstance(held_entries, list) or any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("delta_cents"), int)
        or isinstance(entry["delta_cents"], bool)
        for entry in held_entries
    ):
        raise ValueError("Historical credit holds must remain separate entries")
    spending_on_hold = bool(data.get("credit_spending_on_hold")) or any(
        entry["delta_cents"] < 0 for entry in held_entries
    )
    if spending_on_hold and any(spendable_credit.values()):
        raise ValueError("Credit awaiting review cannot be reported as spendable")
    single_code = next(iter(amounts_due)) if len(amounts_due) == 1 else None
    single_amount = amounts_due[single_code] if single_code else (None if amounts_due else 0)
    return InvoiceSummary(
        total_invoices=data["total_invoices"],
        draft_invoices=data["draft_invoices"],
        issued_invoices=data["issued_invoices"],
        overdue_invoices=data["overdue_invoices"],
        paid_invoices=data["paid_invoices"],
        total_amount_due_cents=single_amount,
        currency_code=single_code,
        recent_invoices=data.get("recent_invoices", []),
        amount_due_by_currency=amounts_due,
        credit_balance_by_currency=recorded_credit,
        spendable_credit_by_currency=spendable_credit,
        held_credit_entries=held_entries,
        credit_spending_on_hold=spending_on_hold,
    )


def create_proforma_line_from_api(data: dict[str, Any]) -> ProformaLine:
    """Create ProformaLine dataclass from API response"""
    return ProformaLine(
        id=cast(int, data.get("id")),  # Line items may not have IDs in detail API responses
        proforma_id=cast(int, data.get("proforma_id", data.get("proforma"))),
        kind=data["kind"],
        service_id=data.get("service_id"),
        description=data["description"],
        quantity=Decimal(str(data["quantity"])),
        unit_price_cents=data["unit_price_cents"],
        tax_rate=Decimal(str(data["tax_rate"])),
        line_total_cents=data["line_total_cents"],
    )


def create_proforma_from_api(data: dict[str, Any], lines: list[dict[str, Any]] | None = None) -> Proforma:
    """Create Proforma dataclass from API response"""

    # Parse currency
    currency_data = data.get("currency", {})
    currency = create_currency_from_api(currency_data) if currency_data else None

    # Parse dates
    def parse_date_field(field_name: str) -> datetime | None:
        date_str = data.get(field_name)
        return parse_datetime(date_str) if date_str else None

    # Create proforma - only use fields available from platform API
    proforma = Proforma(
        gift_reserved_cents=data.get("gift_reserved_cents", 0),
        cash_due_cents=data.get("cash_due_cents"),
        id=data["id"],
        number=data["number"],
        status=data["status"],
        subtotal_cents=data.get("subtotal_cents", 0),  # Not in list API
        tax_cents=data.get("tax_cents", 0),  # Not in list API
        total_cents=data["total_cents"],
        currency=cast(Currency, currency),
        valid_until=cast(datetime, parse_datetime(data["valid_until"])),
        created_at=cast(datetime, parse_datetime(data["created_at"])),
        notes=data.get("notes", ""),
        bill_to_name=data.get("bill_to_name", ""),
        bill_to_email=data.get("bill_to_email", ""),
        bill_to_tax_id=data.get("bill_to_tax_id", ""),
        bill_to_address1=data.get("bill_to_address1", ""),
        bill_to_city=data.get("bill_to_city", ""),
        bill_to_country=data.get("bill_to_country", ""),
        meta=data.get("meta", {}),
    )

    # Extract bill_to data if present (structured billing address block)
    bill_to = data.get("bill_to", {})
    if bill_to:
        proforma.bill_to_name = bill_to.get("name", "") or proforma.bill_to_name
        proforma.bill_to_email = bill_to.get("email", "") or proforma.bill_to_email
        proforma.bill_to_tax_id = bill_to.get("tax_id", "") or proforma.bill_to_tax_id
        # Address may be a single string or structured
        proforma.bill_to_address1 = bill_to.get("address", "") or proforma.bill_to_address1

    # Add line items if provided
    if lines:
        proforma.lines = [create_proforma_line_from_api(line_data) for line_data in lines]

    return proforma
