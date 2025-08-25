"""
Billing models for PRAHO Platform
Romanian invoice generation with VAT compliance and e-Factura support.
Aligned with PostgreSQL hosting panel schema v1 with separate proforma handling.
"""

import uuid
from decimal import Decimal
from typing import Any, Dict, Optional

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# CURRENCY & FX MODELS
# ===============================================================================

class Currency(models.Model):
    """Currency definitions with decimal precision"""
    code = models.CharField(max_length=3, primary_key=True)  # 'EUR', 'RON'
    symbol = models.CharField(max_length=10)
    decimals = models.SmallIntegerField(default=2)

    class Meta:
        db_table = 'currency'
        verbose_name = _('Currency')
        verbose_name_plural = _('Currencies')

    def __str__(self) -> str:
        return f"{self.code} ({self.symbol})"


class FXRate(models.Model):
    """Foreign exchange rates for currency conversion"""
    base_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name='base_rates')
    quote_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name='quote_rates')
    rate = models.DecimalField(max_digits=18, decimal_places=8)
    as_of = models.DateField()

    class Meta:
        db_table = 'fx_rate'
        unique_together = [['base_code', 'quote_code', 'as_of']]
        indexes = [
            models.Index(fields=['base_code', 'quote_code', '-as_of']),
        ]

    def __str__(self):
        return f"{self.base_code}/{self.quote_code} = {self.rate} ({self.as_of})"


# ===============================================================================
# INVOICE & PROFORMA SEQUENCING
# ===============================================================================

class InvoiceSequence(models.Model):
    """Invoice number sequencing for legal compliance"""
    scope = models.CharField(max_length=50, default='default', unique=True)
    last_value = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'invoice_sequence'
        verbose_name = _('Invoice Sequence')
        verbose_name_plural = _('Invoice Sequences')

    def get_next_number(self, prefix='INV'):
        """Get next invoice number and increment sequence atomically"""
        from django.db import transaction
        from django.db.models import F

        with transaction.atomic():
            # Atomic increment using F() expression to prevent race conditions
            InvoiceSequence.objects.filter(pk=self.pk).update(last_value=F('last_value') + 1)
            # Refresh the instance to get the updated value
            self.refresh_from_db()
            return f"{prefix}-{self.last_value:06d}"


class ProformaSequence(models.Model):
    """Proforma invoice number sequencing"""
    scope = models.CharField(max_length=50, default='default', unique=True)
    last_value = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'proforma_sequence'
        verbose_name = _('Proforma Sequence')
        verbose_name_plural = _('Proforma Sequences')

    def get_next_number(self, prefix='PRO'):
        """Get next proforma number and increment sequence atomically"""
        import logging

        from django.db import transaction
        from django.db.models import F

        logger = logging.getLogger(__name__)

        with transaction.atomic():
            # Atomic increment using F() expression to prevent race conditions
            old_value = self.last_value
            ProformaSequence.objects.filter(pk=self.pk).update(last_value=F('last_value') + 1)
            # Refresh the instance to get the updated value
            self.refresh_from_db()
            new_number = f"{prefix}-{self.last_value:06d}"

            logger.info(f"🔢 Generated proforma number {new_number} (was {old_value}, now {self.last_value})")
            return new_number


# ===============================================================================
# PROFORMA MODELS (SEPARATE FROM INVOICES)
# ===============================================================================

class ProformaInvoice(models.Model):
    """
    Proforma invoices - estimates/quotes before actual invoicing.
    Separate from Invoice model with different business logic.
    """

    # Core identification
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.RESTRICT,
        related_name='proforma_invoices'
    )
    number = models.CharField(max_length=50, unique=True, default='PRO-000')  # From ProformaSequence

    # Currency and amounts (cents for precision)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    subtotal_cents = models.BigIntegerField(default=0)
    tax_cents = models.BigIntegerField(default=0)
    total_cents = models.BigIntegerField(default=0)

    # Proforma-specific fields
    valid_until = models.DateTimeField(
        default=timezone.now,
        help_text=_('Proforma expires after this date')
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)

    # Billing address snapshot
    bill_to_name = models.CharField(max_length=255, default='')
    bill_to_tax_id = models.CharField(max_length=50, blank=True)
    bill_to_email = models.EmailField(blank=True)
    bill_to_address1 = models.CharField(max_length=255, blank=True)
    bill_to_address2 = models.CharField(max_length=255, blank=True)
    bill_to_city = models.CharField(max_length=100, blank=True)
    bill_to_region = models.CharField(max_length=100, blank=True)
    bill_to_postal = models.CharField(max_length=20, blank=True)
    bill_to_country = models.CharField(max_length=2, blank=True)

    # Files
    pdf_file = models.FileField(upload_to='proformas/pdf/', blank=True, null=True)

    class Meta:
        db_table = 'proforma_invoice'
        verbose_name = _('Proforma Invoice')
        verbose_name_plural = _('Proforma Invoices')
        indexes = [
            models.Index(fields=['customer']),
            models.Index(fields=['valid_until']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.number} - {self.customer}"

    @property
    def is_expired(self):
        return timezone.now() > self.valid_until

    @property
    def subtotal(self):
        return Decimal(self.subtotal_cents) / 100

    @property
    def tax_amount(self):
        return Decimal(self.tax_cents) / 100

    @property
    def total(self):
        return Decimal(self.total_cents) / 100

    def convert_to_invoice(self):
        """Convert this proforma to an actual invoice"""
        # Will implement this method in business logic


class ProformaLine(models.Model):
    """Proforma line items"""

    KIND_CHOICES = [
        ('service', _('Service')),
        ('setup', _('Setup Fee')),
        ('discount', _('Discount')),
        ('misc', _('Miscellaneous')),
    ]

    proforma = models.ForeignKey(ProformaInvoice, on_delete=models.CASCADE, related_name='lines')
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    service = models.ForeignKey(
        'provisioning.Service',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=12, decimal_places=3, default=Decimal('1.000'))
    unit_price_cents = models.BigIntegerField(default=0)
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        default=Decimal('0.0000')
    )
    line_total_cents = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'proforma_line'
        indexes = [
            models.Index(fields=['service']),
        ]

    @property
    def unit_price(self):
        return Decimal(self.unit_price_cents) / 100

    @property
    def line_total(self):
        return Decimal(self.line_total_cents) / 100


# ===============================================================================
# INVOICE MODELS (IMMUTABLE LEDGER)
# ===============================================================================

class Invoice(models.Model):
    """
    Romanian compliant invoice model with address snapshots.
    Immutable once issued - separate from proforma invoices.
    Updated status choices as requested.
    """

    STATUS_CHOICES = [
        ('draft', _('Draft')),
        ('issued', _('Issued')),        # Changed from 'sent' to 'issued'
        ('paid', _('Paid')),
        ('overdue', _('Overdue')),
        ('void', _('Void')),            # Changed from 'cancelled' to 'void'
        ('refunded', _('Refunded')),
    ]

    # Core identification
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.RESTRICT,  # Cannot delete customer with invoices
        related_name='invoices'
    )
    number = models.CharField(max_length=50, unique=True, default='TMP-000')  # From InvoiceSequence
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Currency and amounts (cents for precision)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    exchange_to_ron = models.DecimalField(
        max_digits=18,
        decimal_places=6,
        null=True,
        blank=True,
        help_text=_('Exchange rate to RON at time of invoice')
    )
    subtotal_cents = models.BigIntegerField(default=0)
    tax_cents = models.BigIntegerField(default=0)
    total_cents = models.BigIntegerField(default=0)

    # Dates
    issued_at = models.DateTimeField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    locked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When invoice became immutable')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    due_at = models.DateTimeField(default=timezone.now)
    sent_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)

    # Billing address snapshot (immutable once issued)
    bill_to_name = models.CharField(max_length=255, default='')
    bill_to_tax_id = models.CharField(max_length=50, blank=True)
    bill_to_email = models.EmailField(blank=True)
    bill_to_address1 = models.CharField(max_length=255, blank=True)
    bill_to_address2 = models.CharField(max_length=255, blank=True)
    bill_to_city = models.CharField(max_length=100, blank=True)
    bill_to_region = models.CharField(max_length=100, blank=True)
    bill_to_postal = models.CharField(max_length=20, blank=True)
    bill_to_country = models.CharField(max_length=2, blank=True)  # ISO 3166-1

    # Romanian e-Factura compliance
    efactura_id = models.CharField(max_length=100, blank=True)
    efactura_sent = models.BooleanField(default=False)
    efactura_sent_date = models.DateTimeField(null=True, blank=True)
    efactura_response = models.JSONField(default=dict, blank=True)

    # File attachments
    pdf_file = models.FileField(upload_to='invoices/pdf/', blank=True, null=True)
    xml_file = models.FileField(upload_to='invoices/xml/', blank=True, null=True)

    # Audit & Relationships
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_invoices'
    )
    converted_from_proforma = models.ForeignKey(
        ProformaInvoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_('Proforma that was converted to this invoice')
    )

    class Meta:
        db_table = 'invoice'
        verbose_name = _('Invoice')
        verbose_name_plural = _('Invoices')
        indexes = [
            models.Index(fields=['customer', '-created_at']),
            models.Index(fields=['customer'], condition=models.Q(status__in=['issued', 'overdue']), name='bill_inv_cust_pending'),
            models.Index(fields=['status', '-due_at']),
            models.Index(fields=['number']),
        ]

    def __str__(self):
        return f"{self.number} - {self.customer}"

    @property
    def subtotal(self):
        """Convert cents to decimal"""
        return Decimal(self.subtotal_cents) / 100

    @property
    def tax_amount(self):
        """Convert cents to decimal"""
        return Decimal(self.tax_cents) / 100

    @property
    def total(self):
        """Convert cents to decimal"""
        return Decimal(self.total_cents) / 100

    def is_overdue(self):
        """Check if invoice is overdue"""
        return (self.due_at and
                timezone.now() > self.due_at and
                self.status in ['issued'])

    def get_remaining_amount(self):
        """Calculate remaining unpaid amount"""
        paid_amount = self.payments.filter(status='succeeded').aggregate(
            total=models.Sum('amount_cents')
        )['total'] or 0
        return max(0, self.total_cents - paid_amount)

    def mark_as_paid(self):
        """Mark invoice as paid"""
        self.status = 'paid'
        self.paid_at = timezone.now()
        self.save()


class InvoiceLine(models.Model):
    """
    Invoice line items with enhanced categorization.
    Replaces old InvoiceItem model with better structure from schema.
    """

    KIND_CHOICES = [
        ('service', _('Service')),
        ('setup', _('Setup Fee')),
        ('credit', _('Credit')),
        ('discount', _('Discount')),
        ('refund', _('Refund')),
        ('misc', _('Miscellaneous')),
    ]

    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='lines')
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    service = models.ForeignKey(
        'provisioning.Service',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_('Related service if applicable')
    )

    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=12, decimal_places=3, default=Decimal('1.000'))
    unit_price_cents = models.BigIntegerField(default=0)
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        default=Decimal('0.0000'),
        help_text=_('Tax rate as decimal (0.19 for 19%)')
    )
    line_total_cents = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'invoice_line'
        verbose_name = _('Invoice Line')
        verbose_name_plural = _('Invoice Lines')
        indexes = [
            models.Index(fields=['service']),
            models.Index(fields=['invoice', 'kind']),
        ]

    @property
    def unit_price(self):
        return Decimal(self.unit_price_cents) / 100

    @property
    def line_total(self):
        return Decimal(self.line_total_cents) / 100

    def save(self, *args, **kwargs):
        # Calculate line total
        subtotal = self.quantity * (Decimal(self.unit_price_cents) / 100)
        tax_amount = subtotal * self.tax_rate
        self.line_total_cents = int((subtotal + tax_amount) * 100)
        super().save(*args, **kwargs)


# ===============================================================================
# PAYMENT & CREDIT MODELS
# ===============================================================================

class Payment(models.Model):
    """
    Enhanced payment tracking aligned with PostgreSQL schema.
    Updated to support multiple payment methods and gateway responses.
    """

    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('succeeded', _('Succeeded')),  # Changed from 'completed'
        ('failed', _('Failed')),
        ('refunded', _('Refunded')),
        ('partially_refunded', _('Partially Refunded')),
    ]

    METHOD_CHOICES = [
        ('stripe', _('Stripe')),
        ('bank', _('Bank Transfer')),
        ('paypal', _('PayPal')),
        ('cash', _('Cash')),
        ('other', _('Other')),
    ]

    # Core relationships
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.RESTRICT,
        related_name='payments'
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payments'
    )

    # Payment details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    method = models.CharField(max_length=20, choices=METHOD_CHOICES, default='stripe')
    amount_cents = models.BigIntegerField(validators=[MinValueValidator(1)], default=0)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)

    # Gateway/external tracking
    gateway_txn_id = models.CharField(max_length=255, blank=True)
    reference_number = models.CharField(max_length=100, blank=True)

    # Dates
    received_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    # Audit
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_payments'
    )

    class Meta:
        db_table = 'payment'
        verbose_name = _('Payment')
        verbose_name_plural = _('Payments')
        indexes = [
            models.Index(fields=['customer', '-received_at']),
            models.Index(fields=['status']),
            models.Index(fields=['method']),
            models.Index(fields=['gateway_txn_id']),
        ]

    def __str__(self):
        return f"Payment {self.amount} {self.currency.code} for {self.customer}"

    @property
    def amount(self):
        return Decimal(self.amount_cents) / 100


class CreditLedger(models.Model):
    """
    Customer credit/balance tracking ledger.
    New model from PostgreSQL schema for prepayments, refunds, adjustments.
    """

    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.CASCADE,
        related_name='credit_entries'
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    payment = models.ForeignKey(
        Payment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Credit change (positive = credit added, negative = credit used)
    delta_cents = models.BigIntegerField()
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    # Audit
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_credit_entries'
    )

    class Meta:
        db_table = 'credit_ledger'
        verbose_name = _('Credit Entry')
        verbose_name_plural = _('Credit Entries')
        indexes = [
            models.Index(fields=['customer', '-created_at']),
        ]

    @property
    def delta(self):
        return Decimal(self.delta_cents) / 100

    def __str__(self):
        return f"{self.customer} - {self.delta} ({self.reason})"


# ===============================================================================
# TAX & VAT COMPLIANCE SYSTEM
# ===============================================================================

class TaxRule(models.Model):
    """
    EU VAT rates by country with temporal validity.
    Critical for Romanian & EU VAT compliance with VIES validation and reverse charge support.
    Handles B2B transactions and cross-border EU sales.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Geographic scope
    country_code = models.CharField(
        max_length=2,
        help_text=_("ISO 3166-1 alpha-2 country code (e.g., 'RO', 'DE')")
    )
    region = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("State/province for countries with regional tax rates")
    )

    # Tax configuration
    tax_type = models.CharField(
        max_length=20,
        choices=[
            ('vat', _('VAT')),
            ('gst', _('GST')),
            ('sales_tax', _('Sales Tax')),
            ('withholding', _('Withholding Tax')),
        ],
        default='vat'
    )
    rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_("Tax rate as decimal (e.g., 0.19 for 19%)")
    )
    reduced_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_("Reduced rate for specific product categories")
    )

    # Validity period
    valid_from = models.DateField(help_text=_("When this tax rate becomes effective"))
    valid_to = models.DateField(
        null=True,
        blank=True,
        help_text=_("When this tax rate expires (null = indefinite)")
    )

    # Business rules
    applies_to_b2b = models.BooleanField(
        default=True,
        help_text=_("Whether tax applies to business-to-business transactions")
    )
    applies_to_b2c = models.BooleanField(
        default=True,
        help_text=_("Whether tax applies to business-to-consumer transactions")
    )
    reverse_charge_eligible = models.BooleanField(
        default=False,
        help_text=_("Whether reverse charge mechanism applies (EU B2B)")
    )

    # Romanian specific
    is_eu_member = models.BooleanField(
        default=False,
        help_text=_("Whether country is EU member for VAT purposes")
    )
    vies_required = models.BooleanField(
        default=False,
        help_text=_("Whether VIES VAT number validation is required")
    )

    # Configuration
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional tax configuration and rules")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tax_rules'
        verbose_name = _('Tax Rule')
        verbose_name_plural = _('Tax Rules')
        unique_together = [['country_code', 'region', 'tax_type', 'valid_from']]
        indexes = [
            models.Index(fields=['country_code', 'tax_type']),
            models.Index(fields=['valid_from', 'valid_to']),
            models.Index(fields=['is_eu_member']),
        ]
        ordering = ['country_code', 'tax_type', '-valid_from']

    def __str__(self):
        rate_display = f"{self.rate * 100:.2f}%"
        if self.valid_to:
            return f"{self.country_code} {self.tax_type.upper()} {rate_display} ({self.valid_from} - {self.valid_to})"
        return f"{self.country_code} {self.tax_type.upper()} {rate_display} (from {self.valid_from})"

    def is_active(self, date=None):
        """Check if tax rule is active on given date"""
        if date is None:
            date = timezone.now().date()

        if date < self.valid_from:
            return False

        return not (self.valid_to and date > self.valid_to)

    @classmethod
    def get_active_rate(cls, country_code, tax_type='vat', date=None):
        """Get active tax rate for country and date"""
        if date is None:
            date = timezone.now().date()

        try:
            rule = cls.objects.filter(
                country_code=country_code.upper(),
                tax_type=tax_type,
                valid_from__lte=date
            ).filter(
                models.Q(valid_to__isnull=True) | models.Q(valid_to__gte=date)
            ).first()

            return rule.rate if rule else Decimal('0.00')
        except cls.DoesNotExist:
            return Decimal('0.00')


class VATValidation(models.Model):
    """
    VIES VAT number validation results cache.
    Stores validation results to avoid repeated API calls and for compliance audit.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # VAT number components
    country_code = models.CharField(max_length=2, help_text=_("Country code (e.g., 'RO')"))
    vat_number = models.CharField(max_length=20, help_text=_("VAT number without country prefix"))
    full_vat_number = models.CharField(
        max_length=25,
        help_text=_("Complete VAT number (e.g., 'RO12345678')")
    )

    # Validation results
    is_valid = models.BooleanField(help_text=_("Whether VAT number is valid"))
    is_active = models.BooleanField(
        default=False,
        help_text=_("Whether company is active for VAT purposes")
    )
    company_name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Company name from VIES (if available)")
    )
    company_address = models.TextField(
        blank=True,
        help_text=_("Company address from VIES (if available)")
    )

    # Validation metadata
    validation_date = models.DateTimeField(auto_now_add=True)
    validation_source = models.CharField(
        max_length=20,
        choices=[
            ('vies', _('VIES API')),
            ('manual', _('Manual Override')),
            ('cached', _('Previous Validation')),
        ],
        default='vies'
    )
    response_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Raw API response for audit purposes")
    )

    # Expiry management
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When validation result expires")
    )

    class Meta:
        db_table = 'vat_validations'
        verbose_name = _('VAT Validation')
        verbose_name_plural = _('VAT Validations')
        unique_together = [['country_code', 'vat_number']]
        indexes = [
            models.Index(fields=['full_vat_number']),
            models.Index(fields=['validation_date']),
            models.Index(fields=['expires_at']),
        ]
        ordering = ['-validation_date']

    def __str__(self):
        status = "✓ Valid" if self.is_valid else "✗ Invalid"
        return f"{self.full_vat_number} - {status}"

    def is_expired(self):
        """Check if validation result has expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at


# ===============================================================================
# PAYMENT COLLECTION & DUNNING SYSTEM
# ===============================================================================

class PaymentRetryPolicy(models.Model):
    """
    Configurable dunning schedules for failed payment recovery.
    Handles automatic retry of failed payments, crucial for revenue recovery.
    Romanian businesses need this for subscription services and recurring billing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Policy identification
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Human-readable policy name (e.g., 'Standard Hosting', 'VIP Customer')")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Description of when this policy applies")
    )

    # Retry configuration
    retry_intervals_days = models.JSONField(
        default=list,
        help_text=_("Days after failure to retry (e.g., [1, 3, 7, 14, 30])")
    )
    max_attempts = models.IntegerField(
        default=4,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text=_("Maximum number of retry attempts")
    )

    # Escalation rules
    suspend_service_after_days = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("Days after final failure to suspend service (null = never)")
    )
    terminate_service_after_days = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("Days after final failure to terminate service (null = never)")
    )

    # Communication settings
    send_dunning_emails = models.BooleanField(
        default=True,
        help_text=_("Whether to send email notifications during dunning")
    )
    email_template_prefix = models.CharField(
        max_length=50,
        default='dunning',
        help_text=_("Template prefix for dunning emails (e.g., 'dunning_vip')")
    )

    # Policy scope
    is_default = models.BooleanField(
        default=False,
        help_text=_("Whether this is the default policy for new customers")
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this policy is currently active")
    )

    # Configuration
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional policy configuration")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payment_retry_policies'
        verbose_name = _('Payment Retry Policy')
        verbose_name_plural = _('Payment Retry Policies')
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({len(self.retry_intervals_days)} attempts)"

    def get_next_retry_date(self, failure_date, attempt_number):
        """Calculate next retry date based on policy"""
        if attempt_number >= len(self.retry_intervals_days):
            return None

        days_to_wait = self.retry_intervals_days[attempt_number]
        return failure_date + timezone.timedelta(days=days_to_wait)


class PaymentRetryAttempt(models.Model):
    """
    Individual retry attempts for failed payments.
    Tracks the complete dunning history for audit and compliance.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Payment reference
    payment = models.ForeignKey(
        'Payment',
        on_delete=models.CASCADE,
        related_name='retry_attempts',
        help_text=_("Original failed payment")
    )
    policy = models.ForeignKey(
        PaymentRetryPolicy,
        on_delete=models.PROTECT,
        help_text=_("Retry policy used for this attempt")
    )

    # Attempt tracking
    attempt_number = models.PositiveIntegerField(
        help_text=_("Sequence number of this retry attempt (1, 2, 3...)")
    )
    scheduled_at = models.DateTimeField(
        help_text=_("When this retry was scheduled to run")
    )
    executed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this retry was actually executed")
    )

    # Results
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', _('Pending')),
            ('processing', _('Processing')),
            ('success', _('Success')),
            ('failed', _('Failed')),
            ('skipped', _('Skipped')),
            ('cancelled', _('Cancelled')),
        ],
        default='pending'
    )

    # Payment gateway response
    gateway_response = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Payment gateway response for audit")
    )
    failure_reason = models.TextField(
        blank=True,
        help_text=_("Reason for failure if retry was unsuccessful")
    )

    # Communication tracking
    dunning_email_sent = models.BooleanField(
        default=False,
        help_text=_("Whether dunning email was sent for this attempt")
    )
    dunning_email_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When dunning email was sent")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payment_retry_attempts'
        verbose_name = _('Payment Retry Attempt')
        verbose_name_plural = _('Payment Retry Attempts')
        unique_together = [['payment', 'attempt_number']]
        indexes = [
            models.Index(fields=['scheduled_at', 'status']),
            models.Index(fields=['payment', '-attempt_number']),
            models.Index(fields=['status', 'executed_at']),
        ]
        ordering = ['payment', 'attempt_number']

    def __str__(self):
        return f"Retry #{self.attempt_number} for Payment {self.payment.id} - {self.status}"


class PaymentCollectionRun(models.Model):
    """
    Batch processing of failed payments for dunning campaigns.
    Tracks execution of collection runs for monitoring and audit.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Run identification
    run_type = models.CharField(
        max_length=20,
        choices=[
            ('automatic', _('Automatic Scheduled')),
            ('manual', _('Manual Trigger')),
            ('test', _('Test Run')),
        ],
        default='automatic'
    )
    triggered_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_("User who triggered manual run")
    )

    # Execution window
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When collection run completed")
    )

    # Execution results
    total_scheduled = models.PositiveIntegerField(
        default=0,
        help_text=_("Total retry attempts scheduled in this run")
    )
    total_processed = models.PositiveIntegerField(
        default=0,
        help_text=_("Total retry attempts processed")
    )
    total_successful = models.PositiveIntegerField(
        default=0,
        help_text=_("Total successful payment recoveries")
    )
    total_failed = models.PositiveIntegerField(
        default=0,
        help_text=_("Total failed retry attempts")
    )

    # Financial impact
    amount_recovered_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total amount recovered in cents")
    )
    fees_charged_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total fees charged by payment processor")
    )

    # Execution status
    status = models.CharField(
        max_length=20,
        choices=[
            ('running', _('Running')),
            ('completed', _('Completed')),
            ('failed', _('Failed')),
            ('cancelled', _('Cancelled')),
        ],
        default='running'
    )
    error_message = models.TextField(
        blank=True,
        help_text=_("Error message if run failed")
    )

    # Configuration snapshot
    config_snapshot = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Configuration used for this run")
    )

    class Meta:
        db_table = 'payment_collection_runs'
        verbose_name = _('Payment Collection Run')
        verbose_name_plural = _('Payment Collection Runs')
        indexes = [
            models.Index(fields=['-started_at']),
            models.Index(fields=['status']),
            models.Index(fields=['run_type', '-started_at']),
        ]
        ordering = ['-started_at']

    def __str__(self):
        duration = ""
        if self.completed_at:
            duration = f" ({(self.completed_at - self.started_at).total_seconds():.0f}s)"
        return f"Collection Run {self.started_at.strftime('%Y-%m-%d %H:%M')} - {self.status}{duration}"

    @property
    def amount_recovered(self):
        """Amount recovered as Decimal"""
        return Decimal(self.amount_recovered_cents) / 100

    @property
    def fees_charged(self):
        """Fees charged as Decimal"""
        return Decimal(self.fees_charged_cents) / 100

    @property
    def net_recovery(self):
        """Net amount recovered after fees"""
        return self.amount_recovered - self.fees_charged

    def mark_completed(self):
        """Mark collection run as completed"""
        self.completed_at = timezone.now()
        self.status = 'completed'
        self.save(update_fields=['completed_at', 'status', 'updated_at'])
