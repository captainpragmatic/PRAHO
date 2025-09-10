"""
Portal Billing Serializers - API Response Conversion Functions
Convert Platform API responses to portal dataclass instances.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any

from django.utils.dateparse import parse_datetime

from .schemas import Currency, Invoice, InvoiceLine, InvoiceSummary, Proforma, ProformaLine


def create_currency_from_api(data: dict[str, Any]) -> Currency:
    """Create Currency dataclass from API response"""
    return Currency(
        id=data['id'],
        code=data['code'],
        name=data['name'],
        symbol=data.get('symbol', ''),
        decimal_places=data.get('decimals', 2),  # Fixed: API uses 'decimals' not 'decimal_places'
        is_active=data.get('is_active', True)
    )


def create_invoice_line_from_api(data: dict[str, Any]) -> InvoiceLine:
    """Create InvoiceLine dataclass from API response"""
    return InvoiceLine(
        id=data['id'],
        invoice_id=data.get('invoice_id', data.get('invoice')),
        kind=data['kind'],
        service_id=data.get('service_id'),
        description=data['description'],
        quantity=Decimal(str(data['quantity'])),
        unit_price_cents=data['unit_price_cents'],
        tax_rate=Decimal(str(data['tax_rate'])),
        line_total_cents=data['line_total_cents']
    )


def create_invoice_from_api(data: dict[str, Any], lines: list[dict[str, Any]] | None = None) -> Invoice:
    """Create Invoice dataclass from API response"""
    
    # Parse currency
    currency_data = data.get('currency', {})
    currency = create_currency_from_api(currency_data) if currency_data else None
    
    # Parse dates
    def parse_date_field(field_name: str) -> datetime | None:
        date_str = data.get(field_name)
        return parse_datetime(date_str) if date_str else None
    
    # Create invoice - only use fields available from platform API
    invoice = Invoice(
        id=data['id'],
        number=data['number'],
        status=data['status'],
        currency=currency,
        exchange_to_ron=None,  # Not provided by list API
        subtotal_cents=data.get('subtotal_cents', 0),  # Not in list API
        tax_cents=data.get('tax_cents', 0),  # Not in list API
        total_cents=data['total_cents'],
        issued_at=None,  # Not provided by list API
        due_at=parse_date_field('due_at'),
        created_at=parse_datetime(data['created_at']),
        updated_at=parse_datetime(data.get('updated_at')) if data.get('updated_at') else None,
        locked_at=None,  # Not provided by list API
        sent_at=None,  # Not provided by list API
        paid_at=None,  # Not provided by list API
        bill_to_name=data.get('bill_to_name', ''),
        bill_to_tax_id=data.get('bill_to_tax_id', ''),
        bill_to_email=data.get('bill_to_email', ''),
        bill_to_address1=data.get('bill_to_address1', ''),
        bill_to_address2=data.get('bill_to_address2', ''),
        bill_to_city=data.get('bill_to_city', ''),
        bill_to_region=data.get('bill_to_region', ''),
        bill_to_postal=data.get('bill_to_postal', ''),
        bill_to_country=data.get('bill_to_country', ''),
        efactura_id=data.get('efactura_id', ''),
        efactura_sent=data.get('efactura_sent', False),
    )
    
    # Add line items if provided
    if lines:
        invoice.lines = [create_invoice_line_from_api(line_data) for line_data in lines]
    
    return invoice


def create_invoice_summary_from_api(data: dict[str, Any]) -> InvoiceSummary:
    """Create InvoiceSummary dataclass from API response"""
    return InvoiceSummary(
        total_invoices=data['total_invoices'],
        draft_invoices=data['draft_invoices'],
        issued_invoices=data['issued_invoices'],
        overdue_invoices=data['overdue_invoices'],
        paid_invoices=data['paid_invoices'],
        total_amount_due_cents=data['total_amount_due_cents'],
        currency_code=data['currency_code'],
        recent_invoices=data.get('recent_invoices', [])
    )


def create_proforma_line_from_api(data: dict[str, Any]) -> ProformaLine:
    """Create ProformaLine dataclass from API response"""
    return ProformaLine(
        id=data['id'],
        proforma_id=data.get('proforma_id', data.get('proforma')),
        kind=data['kind'],
        service_id=data.get('service_id'),
        description=data['description'],
        quantity=Decimal(str(data['quantity'])),
        unit_price_cents=data['unit_price_cents'],
        tax_rate=Decimal(str(data['tax_rate'])),
        line_total_cents=data['line_total_cents']
    )


def create_proforma_from_api(data: dict[str, Any], lines: list[dict[str, Any]] | None = None) -> Proforma:
    """Create Proforma dataclass from API response"""
    
    # Parse currency
    currency_data = data.get('currency', {})
    currency = create_currency_from_api(currency_data) if currency_data else None
    
    # Parse dates
    def parse_date_field(field_name: str) -> datetime | None:
        date_str = data.get(field_name)
        return parse_datetime(date_str) if date_str else None
    
    # Create proforma - only use fields available from platform API
    proforma = Proforma(
        id=data['id'],
        number=data['number'],
        status=data['status'],
        subtotal_cents=data.get('subtotal_cents', 0),  # Not in list API
        tax_cents=data.get('tax_cents', 0),  # Not in list API
        total_cents=data['total_cents'],
        currency=currency,
        valid_until=parse_datetime(data['valid_until']),
        created_at=parse_datetime(data['created_at']),
        notes=data.get('notes', '')
    )
    
    # Add line items if provided
    if lines:
        proforma.lines = [create_proforma_line_from_api(line_data) for line_data in lines]
    
    return proforma
