# ===============================================================================
# BILLING API SERIALIZERS - CUSTOMER INVOICE AND PROFORMA DATA 💳
# ===============================================================================

from typing import Any, ClassVar

from django.utils import timezone
from rest_framework import serializers

from apps.billing.models import Currency, Invoice, InvoiceLine
from apps.billing.proforma_models import ProformaInvoice, ProformaLine


class GiftCardTenderSerializer(serializers.Serializer):
    document_type = serializers.ChoiceField(choices=("invoice", "proforma"))
    document_number = serializers.CharField(max_length=100)
    code = serializers.CharField(max_length=50)
    operation_key = serializers.UUIDField()
    amount_cents = serializers.IntegerField(min_value=1, max_value=100_000_000, required=False)


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
    domain_name = serializers.CharField(max_length=255, allow_blank=True)
    period_start = serializers.DateField(allow_null=True)
    period_end = serializers.DateField(allow_null=True)
    unit_code = serializers.CharField(max_length=10, allow_blank=True)
    seller_item_id = serializers.CharField(max_length=100, allow_blank=True)
    note = serializers.CharField(allow_blank=True)

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
            "domain_name",
            "period_start",
            "period_end",
            "unit_code",
            "seller_item_id",
            "note",
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
            "meta",
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
        from apps.billing.models import CreditLedger  # noqa: PLC0415  # ADR-0007

        invoices_qs = instance["invoices_queryset"]
        customer = instance["customer"]

        # Calculate counts by status
        total_invoices = invoices_qs.count()
        draft_invoices = invoices_qs.filter(status="draft").count()
        issued_invoices = invoices_qs.filter(status="issued").count()
        overdue_invoices = invoices_qs.filter(status="overdue").count()
        paid_invoices = invoices_qs.filter(status="paid").count()

        # The document owns its currency; partial cash and gift payments reduce its
        # authoritative remaining amount. Closed documents and credits are not debts.
        pending_invoices = invoices_qs.filter(status__in=["issued", "overdue"], document_kind="invoice")
        remaining_by_id = {}
        amount_due_by_currency: dict[str, int] = {}
        for invoice in pending_invoices:
            remaining = invoice.amount_due
            remaining_by_id[invoice.pk] = remaining
            if remaining:
                amount_due_by_currency[invoice.currency_id] = (
                    amount_due_by_currency.get(invoice.currency_id, 0) + remaining
                )
        amount_due_by_currency = dict(sorted(amount_due_by_currency.items()))
        currency_code = next(iter(amount_due_by_currency)) if len(amount_due_by_currency) == 1 else None
        total_amount_due_cents = (
            amount_due_by_currency[currency_code] if currency_code else (None if amount_due_by_currency else 0)
        )
        recorded_credit = CreditLedger.balances_for_customer(customer)
        currencies = Currency.objects.in_bulk(recorded_credit)
        spendable_credit = {
            code: CreditLedger.available_balance_for_customer(customer, currencies[code]) for code in recorded_credit
        }
        held_credit_entries = CreditLedger.held_entries_for_customer(customer)

        # Get recent invoices
        recent_invoices_qs = invoices_qs.order_by("-created_at")[:5]
        recent_invoices = [
            {
                "number": invoice.number,
                "status": invoice.status,
                "total_cents": invoice.total_cents,
                "currency_code": invoice.currency_id,
                "amount_due": remaining_by_id.get(invoice.pk, 0),
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
            "amount_due_by_currency": amount_due_by_currency,
            "credit_balance_by_currency": recorded_credit,
            "spendable_credit_by_currency": spendable_credit,
            "held_credit_entries": held_credit_entries,
            "credit_spending_on_hold": any(entry["delta_cents"] < 0 for entry in held_credit_entries),
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
    domain_name = serializers.CharField(max_length=255, allow_blank=True)
    period_start = serializers.DateField(allow_null=True)
    period_end = serializers.DateField(allow_null=True)
    unit_code = serializers.CharField(max_length=10, allow_blank=True)
    seller_item_id = serializers.CharField(max_length=100, allow_blank=True)
    note = serializers.CharField(allow_blank=True)

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
            "domain_name",
            "period_start",
            "period_end",
            "unit_code",
            "seller_item_id",
            "note",
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
    gift_reserved_cents = serializers.SerializerMethodField()
    cash_due_cents = serializers.SerializerMethodField()

    def get_gift_reserved_cents(self, obj: ProformaInvoice) -> int:
        from apps.promotions.gift_cards import reserved_value  # noqa: PLC0415

        return reserved_value(obj)

    def get_cash_due_cents(self, obj: ProformaInvoice) -> int:
        from apps.promotions.gift_cards import cash_due  # noqa: PLC0415

        return cash_due(obj)

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
            "meta",
            "gift_reserved_cents",
            "cash_due_cents",
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
