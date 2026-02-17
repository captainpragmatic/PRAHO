"""
Portal Billing Schemas - API Response Data Structures
Pure Python dataclasses for representing invoice data from Platform API.
NO DATABASE MODELS - API-only communication.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from django.utils import timezone


@dataclass
class Currency:
    """Currency data from Platform API"""

    id: int
    code: str
    name: str
    symbol: str = ""
    decimal_places: int = 2
    is_active: bool = True


@dataclass
class InvoiceLine:
    """Invoice line item from Platform API"""

    id: int
    invoice_id: int
    kind: str
    service_id: int | None
    description: str
    quantity: Decimal
    unit_price_cents: int
    tax_rate: Decimal
    line_total_cents: int

    @property
    def unit_price_display(self) -> str:
        """Format unit price for display"""
        return f"{self.unit_price_cents / 100:.2f}"

    @property
    def line_total_display(self) -> str:
        """Format line total for display"""
        return f"{self.line_total_cents / 100:.2f}"


@dataclass
class Invoice:
    """Invoice data from Platform API"""

    id: int
    number: str
    status: str
    currency: Currency
    exchange_to_ron: Decimal | None
    subtotal_cents: int
    tax_cents: int
    total_cents: int
    issued_at: datetime | None
    due_at: datetime | None
    created_at: datetime
    updated_at: datetime
    locked_at: datetime | None
    sent_at: datetime | None
    paid_at: datetime | None

    # Billing information
    bill_to_name: str = ""
    bill_to_tax_id: str = ""
    bill_to_email: str = ""
    bill_to_address1: str = ""
    bill_to_address2: str = ""
    bill_to_city: str = ""
    bill_to_region: str = ""
    bill_to_postal: str = ""
    bill_to_country: str = ""

    # Optional field - not always provided by platform API
    customer_id: int | None = None

    # E-factura integration
    efactura_id: str = ""
    efactura_sent: bool = False

    # Business methods
    @property
    def total_display(self) -> str:
        """Format total amount for display"""
        return f"{self.total_cents / 100:.2f} {self.currency.code}"

    @property
    def subtotal_display(self) -> str:
        """Format subtotal for display"""
        return f"{self.subtotal_cents / 100:.2f} {self.currency.code}"

    @property
    def tax_display(self) -> str:
        """Format tax amount for display"""
        return f"{self.tax_cents / 100:.2f} {self.currency.code}"

    @property
    def is_overdue(self) -> bool:
        """Check if invoice is overdue"""
        if not self.due_at or self.status in ["paid", "void", "refunded"]:
            return False
        return timezone.now().date() > self.due_at.date()

    @property
    def status_display(self) -> str:
        """Get status display with emoji"""
        status_map = {
            "draft": "📝 Draft",
            "issued": "📧 Issued",
            "paid": "✅ Paid",
            "overdue": "⚠️ Overdue",
            "void": "❌ Void",
            "refunded": "↩️ Refunded",
        }
        return status_map.get(self.status, f"❓ {self.status.title()}")


@dataclass
class InvoiceSummary:
    """Invoice summary data for dashboard widgets"""

    total_invoices: int
    draft_invoices: int
    issued_invoices: int
    overdue_invoices: int
    paid_invoices: int
    total_amount_due_cents: int
    currency_code: str
    recent_invoices: list[dict]

    @property
    def total_amount_due_display(self) -> str:
        """Format total amount due for display"""
        return f"{self.total_amount_due_cents / 100:.2f} {self.currency_code}"


@dataclass
class ProformaLine:
    """Proforma line item from Platform API"""

    id: int
    proforma_id: int
    kind: str
    service_id: int | None
    description: str
    quantity: Decimal
    unit_price_cents: int
    tax_rate: Decimal
    line_total_cents: int

    @property
    def unit_price_display(self) -> str:
        """Format unit price for display"""
        return f"{self.unit_price_cents / 100:.2f}"

    @property
    def line_total_display(self) -> str:
        """Format line total for display"""
        return f"{self.line_total_cents / 100:.2f}"


@dataclass
class Proforma:
    """Proforma data from Platform API"""

    id: int
    number: str
    status: str
    subtotal_cents: int
    tax_cents: int
    total_cents: int
    currency: Currency
    valid_until: datetime
    created_at: datetime
    notes: str = ""
    lines: list[ProformaLine] = None

    def __post_init__(self) -> None:
        if self.lines is None:
            self.lines = []

    @property
    def is_expired(self) -> bool:
        """Check if proforma is expired"""
        return self.valid_until < timezone.now()

    @property
    def subtotal_display(self) -> str:
        """Format subtotal for display"""
        return f"{self.subtotal_cents / 100:.2f}"

    @property
    def tax_display(self) -> str:
        """Format tax amount for display"""
        return f"{self.tax_cents / 100:.2f}"

    @property
    def total_display(self) -> str:
        """Format total for display"""
        return f"{self.total_cents / 100:.2f}"

    @property
    def status_display(self) -> str:
        """Get status display with emoji"""
        status_map = {"draft": "📝 Draft", "sent": "📧 Sent", "accepted": "✅ Accepted", "expired": "❌ Expired"}
        return status_map.get(self.status, f"❓ {self.status.title()}")
