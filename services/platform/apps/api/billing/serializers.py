# ===============================================================================
# BILLING API SERIALIZERS - CUSTOMER INVOICE AND PROFORMA DATA 💳
# ===============================================================================

from typing import Any, ClassVar

from django.utils import timezone
from rest_framework import serializers

from apps.billing.models import Currency, Invoice, InvoiceLine
from apps.billing.proforma_models import ProformaInvoice, ProformaLine

# ===============================================================================
# CURRENCY SERIALIZERS 💱
# ===============================================================================


class CurrencySerializer(serializers.ModelSerializer):
    """Currency serializer for invoice display"""

    class Meta:
        model = Currency
        fields: ClassVar = ["id", "code", "name", "symbol", "decimals"]


# ===============================================================================
# INVOICE SERIALIZERS 📄
# ===============================================================================


class InvoiceListSerializer(serializers.ModelSerializer):
    """Serializer for invoice list view - minimal data"""

    currency = CurrencySerializer(read_only=True)
    is_overdue = serializers.SerializerMethodField()
    amount_due = serializers.SerializerMethodField()

    class Meta:
        model = Invoice
        fields: ClassVar = [
            "id",
            "number",
            "status",
            "total_cents",
            "currency",
            "due_at",
            "created_at",
            "is_overdue",
            "amount_due",
        ]

    def get_is_overdue(self, obj: Invoice) -> bool:
        return obj.is_overdue()

    def get_amount_due(self, obj: Invoice) -> int:
        return obj.amount_due


class InvoiceLineSerializer(serializers.ModelSerializer):
    """Serializer for invoice line items"""

    unit_price = serializers.SerializerMethodField()
    line_total = serializers.SerializerMethodField()

    class Meta:
        model = InvoiceLine
        fields: ClassVar = [
            "description",
            "kind",
            "quantity",
            "unit_price_cents",
            "tax_rate",
            "line_total_cents",
            "unit_price",
            "line_total",
        ]

    def get_unit_price(self, obj: InvoiceLine) -> str:
        return str(obj.unit_price)

    def get_line_total(self, obj: InvoiceLine) -> str:
        return str(obj.line_total)


class InvoiceDetailSerializer(serializers.ModelSerializer):
    """Serializer for invoice detail view - complete data"""

    currency = CurrencySerializer(read_only=True)
    lines = InvoiceLineSerializer(many=True, read_only=True)
    subtotal = serializers.SerializerMethodField()
    tax_amount = serializers.SerializerMethodField()
    total = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()
    amount_due = serializers.SerializerMethodField()
    bill_to = serializers.SerializerMethodField()
    pdf_url = serializers.SerializerMethodField()

    class Meta:
        model = Invoice
        fields: ClassVar = [
            "id",
            "number",
            "status",
            "subtotal_cents",
            "tax_cents",
            "total_cents",
            "currency",
            "issued_at",
            "due_at",
            "created_at",
            "sent_at",
            "paid_at",
            "lines",
            "subtotal",
            "tax_amount",
            "total",
            "is_overdue",
            "amount_due",
            "bill_to",
            "pdf_url",
            "efactura_sent",
        ]

    def get_subtotal(self, obj: Invoice) -> str:
        return str(obj.subtotal)

    def get_tax_amount(self, obj: Invoice) -> str:
        return str(obj.tax_amount)

    def get_total(self, obj: Invoice) -> str:
        return str(obj.total)

    def get_is_overdue(self, obj: Invoice) -> bool:
        return obj.is_overdue()

    def get_amount_due(self, obj: Invoice) -> int:
        return obj.amount_due

    def get_bill_to(self, obj: Invoice) -> dict[str, Any]:
        """Format billing address for display"""
        address_parts = []
        if obj.bill_to_address1:
            address_parts.append(obj.bill_to_address1)
        if obj.bill_to_address2:
            address_parts.append(obj.bill_to_address2)
        if obj.bill_to_city:
            address_parts.append(obj.bill_to_city)
        if obj.bill_to_region:
            address_parts.append(obj.bill_to_region)
        if obj.bill_to_postal:
            address_parts.append(obj.bill_to_postal)
        if obj.bill_to_country:
            address_parts.append(obj.bill_to_country)

        return {
            "name": obj.bill_to_name,
            "tax_id": obj.bill_to_tax_id,
            "email": obj.bill_to_email,
            "address": ", ".join(address_parts) if address_parts else "",
        }

    def get_pdf_url(self, obj: Invoice) -> str:
        """Return PDF URL if available"""
        if obj.pdf_file:
            return f"/invoices/pdf/{obj.number}.pdf"
        return ""


# ===============================================================================
# INVOICE SUMMARY SERIALIZER 📊
# ===============================================================================


class InvoiceSummarySerializer(serializers.Serializer):
    """Serializer for customer invoice summary/dashboard widget"""

    def to_representation(self, instance: dict[str, Any]) -> dict[str, Any]:
        """Build invoice summary from queryset"""
        invoices_qs = instance["invoices_queryset"]

        # Calculate counts by status
        total_invoices = invoices_qs.count()
        draft_invoices = invoices_qs.filter(status="draft").count()
        issued_invoices = invoices_qs.filter(status="issued").count()
        overdue_invoices = invoices_qs.filter(status="overdue").count()
        paid_invoices = invoices_qs.filter(status="paid").count()

        # Calculate total amount due (issued + overdue)
        pending_invoices = invoices_qs.filter(status__in=["issued", "overdue"])
        total_amount_due_cents = sum(inv.total_cents for inv in pending_invoices)

        # Get currency (assume RON for now, could be enhanced)
        currency_code = "RON"

        # Get recent invoices
        recent_invoices_qs = invoices_qs.order_by("-created_at")[:5]
        recent_invoices = [
            {
                "number": invoice.number,
                "status": invoice.status,
                "total_cents": invoice.total_cents,
                "due_at": invoice.due_at,
                "is_overdue": invoice.is_overdue(),
                "created_at": invoice.created_at,
            }
            for invoice in recent_invoices_qs
        ]

        return {
            "total_invoices": total_invoices,
            "draft_invoices": draft_invoices,
            "issued_invoices": issued_invoices,
            "overdue_invoices": overdue_invoices,
            "paid_invoices": paid_invoices,
            "total_amount_due_cents": total_amount_due_cents,
            "currency_code": currency_code,
            "recent_invoices": recent_invoices,
        }


# ===============================================================================
# PROFORMA SERIALIZERS 📄
# ===============================================================================


class ProformaListSerializer(serializers.ModelSerializer):
    """Serializer for proforma list view - minimal data"""

    currency = CurrencySerializer(read_only=True)
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = ProformaInvoice
        fields: ClassVar = [
            "id",
            "number",
            "status",
            "total_cents",
            "currency",
            "valid_until",
            "created_at",
            "is_expired",
        ]

    def get_is_expired(self, obj: ProformaInvoice) -> bool:
        return obj.valid_until < timezone.now() if obj.valid_until else False


class ProformaLineSerializer(serializers.ModelSerializer):
    """Serializer for proforma line items"""

    unit_price = serializers.SerializerMethodField()
    line_total = serializers.SerializerMethodField()

    class Meta:
        model = ProformaLine
        fields: ClassVar = [
            "description",
            "kind",
            "quantity",
            "unit_price_cents",
            "tax_rate",
            "line_total_cents",
            "unit_price",
            "line_total",
        ]

    def get_unit_price(self, obj: ProformaLine) -> str:
        return str(obj.unit_price)

    def get_line_total(self, obj: ProformaLine) -> str:
        return str(obj.line_total)


class ProformaDetailSerializer(serializers.ModelSerializer):
    """Serializer for proforma detail view - complete data"""

    currency = CurrencySerializer(read_only=True)
    lines = ProformaLineSerializer(many=True, read_only=True)
    subtotal = serializers.SerializerMethodField()
    tax_amount = serializers.SerializerMethodField()
    total = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    bill_to = serializers.SerializerMethodField()
    pdf_url = serializers.SerializerMethodField()

    class Meta:
        model = ProformaInvoice
        fields: ClassVar = [
            "id",
            "number",
            "status",
            "subtotal_cents",
            "tax_cents",
            "total_cents",
            "currency",
            "valid_until",
            "created_at",
            "lines",
            "subtotal",
            "tax_amount",
            "total",
            "is_expired",
            "bill_to",
            "pdf_url",
            "notes",
        ]

    def get_subtotal(self, obj: ProformaInvoice) -> str:
        return str(obj.subtotal)

    def get_tax_amount(self, obj: ProformaInvoice) -> str:
        return str(obj.tax_amount)

    def get_total(self, obj: ProformaInvoice) -> str:
        return str(obj.total)

    def get_is_expired(self, obj: ProformaInvoice) -> bool:
        return obj.valid_until < timezone.now() if obj.valid_until else False

    def get_bill_to(self, obj: ProformaInvoice) -> dict[str, Any]:
        """Format billing address for display"""
        address_parts = []
        if obj.bill_to_address1:
            address_parts.append(obj.bill_to_address1)
        if obj.bill_to_address2:
            address_parts.append(obj.bill_to_address2)
        if obj.bill_to_city:
            address_parts.append(obj.bill_to_city)
        if obj.bill_to_region:
            address_parts.append(obj.bill_to_region)
        if obj.bill_to_postal:
            address_parts.append(obj.bill_to_postal)
        if obj.bill_to_country:
            address_parts.append(obj.bill_to_country)

        return {
            "name": obj.bill_to_name,
            "tax_id": obj.bill_to_tax_id,
            "email": obj.bill_to_email,
            "address": ", ".join(address_parts) if address_parts else "",
        }

    def get_pdf_url(self, obj: ProformaInvoice) -> str:
        """Return PDF URL if available"""
        if obj.pdf_file:
            return f"/proformas/pdf/{obj.number}.pdf"
        return ""
