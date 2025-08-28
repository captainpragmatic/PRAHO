"""
Customer models for PRAHO Platform
Romanian hosting provider customer management with PostgreSQL alignment.

Refactored to normalized structure with soft deletes and separated concerns:
- Core Customer model (basic info only)
- CustomerTaxProfile (VAT, CUI, compliance)
- CustomerBillingProfile (payment terms, credit)
- CustomerAddress (versioned addresses)
- CustomerPaymentMethod (Stripe, bank transfers)
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from django.db.models.query import QuerySet

    from apps.users.models import User

from django.core.validators import RegexValidator
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.types import validate_romanian_cui

# ===============================================================================
# SOFT DELETE INFRASTRUCTURE
# ===============================================================================

class SoftDeleteManager(models.Manager[Any]):
    """Manager for soft delete models - only shows non-deleted records by default"""

    def get_queryset(self) -> QuerySet[Any]:
        return super().get_queryset().filter(deleted_at__isnull=True)

    def with_deleted(self) -> QuerySet[Any]:
        """Include soft-deleted records"""
        return super().get_queryset()

    def deleted_only(self) -> QuerySet[Any]:
        """Only show soft-deleted records"""
        return super().get_queryset().filter(deleted_at__isnull=False)


class SoftDeleteModel(models.Model):
    """Abstract model with soft delete capabilities"""

    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name='Șters la')
    deleted_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_%(class)ss',
        verbose_name='Șters de'
    )

    all_objects = models.Manager()  # Shows all records including deleted
    objects = SoftDeleteManager()

    class Meta:
        abstract = True

    def soft_delete(self, user: User | None = None) -> None:
        """Soft delete this record"""
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self.save(update_fields=['deleted_at', 'deleted_by'])

    def restore(self) -> None:
        """Restore soft-deleted record"""
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['deleted_at', 'deleted_by'])

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


# ===============================================================================
# CUSTOMER CORE MODEL (SIMPLIFIED)
# ===============================================================================

class Customer(SoftDeleteModel):
    """
    Core customer model - only essential identifying information.
    All other data is normalized into separate profile models.
    
    🚨 CASCADE Behavior:
    - CustomerTaxProfile: CASCADE (essential for compliance)
    - CustomerBillingProfile: CASCADE (business rules)
    - CustomerAddress: CASCADE (addresses belong to customer)
    - CustomerPaymentMethod: CASCADE (payment methods belong to customer)
    - CustomerMembership: CASCADE (user access removed when customer deleted)
    """

    # Customer Types aligned with PostgreSQL schema
    CUSTOMER_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('individual', _('Individual')),
        ('company', _('Company')),
        ('pfa', _('PFA/SRL')),
        ('ngo', _('NGO/Association')),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('active', _('Active')),
        ('inactive', _('Inactive')),
        ('suspended', _('Suspended')),
        ('prospect', _('Prospect')),
    )

    # Core Identity Fields
    name = models.CharField(max_length=255, verbose_name='Nume')
    customer_type = models.CharField(
        max_length=20,
        choices=CUSTOMER_TYPE_CHOICES,
        default='individual',
        verbose_name='Tip client'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='prospect',
        verbose_name='Status'
    )

    # Company Fields (when customer_type = 'company')
    company_name = models.CharField(
        max_length=255,
        blank=True,
        verbose_name='Nume companie'
    )

    # Primary Contact (from users via CustomerMembership)
    primary_email = models.EmailField(
        verbose_name='Email principal',
        default='contact@example.com'  # Temporary default for migration
    )
    primary_phone = models.CharField(
        max_length=20,
        validators=[RegexValidator(r'^(\+40|0)[0-9]{9,10}$', 'Număr telefon invalid')],
        verbose_name='Telefon principal',
        default='+40712345678'  # Temporary default for migration
    )

    # Business Context
    industry = models.CharField(max_length=100, blank=True, verbose_name='Domeniu')
    website = models.URLField(blank=True, verbose_name='Website')

    # Account Management
    assigned_account_manager = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,  # Keep customer when manager deleted
        null=True,
        blank=True,
        limit_choices_to={'staff_role__in': ['manager', 'support', 'admin']},
        related_name='managed_customers',
        verbose_name='Manager cont'
    )

    # GDPR Compliance (simplified)
    data_processing_consent = models.BooleanField(default=False)
    marketing_consent = models.BooleanField(default=False)
    gdpr_consent_date = models.DateTimeField(null=True, blank=True)

    # Audit Fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_customers'
    )

    class Meta:
        db_table = 'customers'
        verbose_name = _('Customer')
        verbose_name_plural = _('Customers')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['primary_email']),
            models.Index(fields=['status']),
            models.Index(fields=['customer_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['deleted_at']),  # For soft delete queries
        )

    def __str__(self) -> str:
        return self.get_display_name()

    def get_display_name(self) -> str:
        """Get customer display name"""
        if self.customer_type == 'company' and self.company_name:
            return self.company_name
        return self.name

    def get_tax_profile(self) -> CustomerTaxProfile | None:
        """Get customer tax profile"""
        try:
            return CustomerTaxProfile.objects.get(customer=self)
        except CustomerTaxProfile.DoesNotExist:
            return None

    def get_billing_profile(self) -> CustomerBillingProfile | None:
        """Get customer billing profile"""
        try:
            return CustomerBillingProfile.objects.get(customer=self)
        except CustomerBillingProfile.DoesNotExist:
            return None

    def get_primary_address(self) -> CustomerAddress | None:
        """Get primary address"""
        return CustomerAddress.objects.filter(
            customer=self,
            address_type='primary',
            is_current=True
        ).first()

    def get_billing_address(self) -> CustomerAddress | None:
        """Get billing address or fall back to primary"""
        billing = CustomerAddress.objects.filter(
            customer=self,
            address_type='billing',
            is_current=True
        ).first()
        return billing or self.get_primary_address()


# ===============================================================================
# CUSTOMER TAX PROFILE (COMPLIANCE DATA)
# ===============================================================================

class CustomerTaxProfile(SoftDeleteModel):
    """
    Romanian tax compliance information separated from core customer data.
    
    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    customer = models.OneToOneField(
        Customer,
        on_delete=models.CASCADE,  # Delete tax profile when customer deleted
        related_name='tax_profile'
    )

    # Romanian Tax Fields
    cui = models.CharField(
        max_length=20,
        blank=True,
        verbose_name='CUI/CIF',
        validators=[RegexValidator(r'^RO\d{2,10}$', 'CUI invalid')]
    )
    registration_number = models.CharField(
        max_length=50,
        blank=True,
        verbose_name='Nr. registrul comerțului'
    )

    # VAT Information
    is_vat_payer = models.BooleanField(default=True, verbose_name='Plătitor TVA')
    vat_number = models.CharField(max_length=20, blank=True, verbose_name='Nr. TVA')
    vat_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('19.00'),  # Romanian VAT rate
        verbose_name='Cota TVA (%)'
    )

    # Tax Reverse Charge (for B2B EU)
    reverse_charge_eligible = models.BooleanField(default=False)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer_tax_profiles'
        verbose_name = _('Customer Tax Profile')
        verbose_name_plural = _('Customer Tax Profiles')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['cui']),
            models.Index(fields=['vat_number']),
        )

    def validate_cui(self) -> bool:
        """Validate Romanian CUI format"""
        if not self.cui:
            return True
        result = validate_romanian_cui(self.cui)
        return result.is_ok()


# ===============================================================================
# CUSTOMER BILLING PROFILE (FINANCIAL DATA)
# ===============================================================================

class CustomerBillingProfile(SoftDeleteModel):
    """
    Customer billing and financial information.
    
    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    customer = models.OneToOneField(
        Customer,
        on_delete=models.CASCADE,  # Delete billing profile when customer deleted
        related_name='billing_profile'
    )

    # Payment Terms
    payment_terms = models.PositiveIntegerField(
        default=30,
        verbose_name='Termen plată (zile)'
    )

    # Credit Management
    credit_limit = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        verbose_name='Limită credit (RON)'
    )

    # Currency Preferences
    preferred_currency = models.CharField(
        max_length=3,
        choices=[('RON', 'RON'), ('EUR', 'EUR')],
        default='RON',
        verbose_name='Monedă preferată'
    )

    # Billing Preferences
    invoice_delivery_method = models.CharField(
        max_length=20,
        choices=[
            ('email', 'Email'),
            ('postal', 'Poștă'),
            ('both', 'Email și poștă'),
        ],
        default='email',
        verbose_name='Mod livrare facturi'
    )

    # Automatic Payment
    auto_payment_enabled = models.BooleanField(default=False)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer_billing_profiles'
        verbose_name = _('Customer Billing Profile')
        verbose_name_plural = _('Customer Billing Profiles')

    def get_account_balance(self) -> Decimal:
        """Get customer account balance"""
        from apps.billing.models import Invoice  # noqa: PLC0415 # Cross-app import for balance calculation
        invoices = Invoice.objects.filter(customer=self.customer)
        total_due = sum(
            invoice.amount_due for invoice in invoices
            if invoice.status in ['pending', 'overdue']
        )
        return Decimal(str(total_due))


# ===============================================================================
# CUSTOMER ADDRESS (VERSIONED)
# ===============================================================================

class CustomerAddress(SoftDeleteModel):
    """
    Customer addresses with versioning support.
    
    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    ADDRESS_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('primary', 'Adresa principală'),
        ('billing', 'Adresa facturare'),
        ('delivery', 'Adresa livrare'),
        ('legal', 'Sediul social'),
    )

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,  # Delete addresses when customer deleted
        related_name='addresses'
    )

    address_type = models.CharField(
        max_length=20,
        choices=ADDRESS_TYPE_CHOICES,
        verbose_name='Tip adresă'
    )

    # Address Fields
    address_line1 = models.CharField(max_length=200, verbose_name='Adresa 1')
    address_line2 = models.CharField(max_length=200, blank=True, verbose_name='Adresa 2')
    city = models.CharField(max_length=100, verbose_name='Oraș')
    county = models.CharField(max_length=100, verbose_name='Județ')
    postal_code = models.CharField(max_length=10, verbose_name='Cod poștal')
    country = models.CharField(max_length=100, default='România', verbose_name='Țara')

    # Versioning
    is_current = models.BooleanField(default=True, verbose_name='Adresa curentă')
    version = models.PositiveIntegerField(default=1, verbose_name='Versiune')

    # Validation
    is_validated = models.BooleanField(default=False, verbose_name='Validată')
    validated_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer_addresses'
        verbose_name = _('Customer Address')
        verbose_name_plural = _('Customer Addresses')
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (('customer', 'address_type', 'is_current'),)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['customer', 'address_type']),
            models.Index(fields=['customer', 'is_current']),
            models.Index(fields=['postal_code']),
        )

    def __str__(self) -> str:
        return f"{self.customer.name} - {dict(self.ADDRESS_TYPE_CHOICES)[self.address_type]}"

    def get_full_address(self) -> str:
        """Get formatted address"""
        parts = [
            self.address_line1,
            self.address_line2,
            f"{self.city}, {self.county}",
            self.postal_code,
            self.country
        ]
        return ', '.join(part for part in parts if part)


# ===============================================================================
# CUSTOMER PAYMENT METHOD
# ===============================================================================

class CustomerPaymentMethod(SoftDeleteModel):
    """
    Customer payment methods (Stripe, bank transfer, etc.)
    
    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    METHOD_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('stripe_card', 'Card Stripe'),
        ('bank_transfer', 'Transfer bancar'),
        ('cash', 'Numerar'),
        ('other', 'Altele'),
    )

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,  # Delete payment methods when customer deleted
        related_name='payment_methods'
    )

    method_type = models.CharField(
        max_length=20,
        choices=METHOD_TYPE_CHOICES,
        verbose_name='Tip metodă'
    )

    # Stripe Integration
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_payment_method_id = models.CharField(max_length=100, blank=True)

    # Display Information
    display_name = models.CharField(max_length=100, verbose_name='Nume afișaj')
    last_four = models.CharField(max_length=4, blank=True, verbose_name='Ultimele 4 cifre')

    # Status
    is_default = models.BooleanField(default=False, verbose_name='Implicit')
    is_active = models.BooleanField(default=True, verbose_name='Activ')

    # Bank Transfer Details (encrypted)
    bank_details = models.JSONField(blank=True, null=True, verbose_name='Detalii bancare')

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer_payment_methods'
        verbose_name = _('Customer Payment Method')
        verbose_name_plural = _('Customer Payment Methods')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['customer', 'is_default']),
            models.Index(fields=['stripe_customer_id']),
        )

    def __str__(self) -> str:
        return f"{self.customer.name} - {self.display_name}"


# ===============================================================================
# CUSTOMER NOTES (SIMPLIFIED)
# ===============================================================================

class CustomerNote(SoftDeleteModel):
    """Customer interaction notes with soft delete"""

    NOTE_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('general', 'Generală'),
        ('call', 'Apel telefonic'),
        ('email', 'Email'),
        ('meeting', 'Întâlnire'),
        ('complaint', 'Reclamație'),
        ('compliment', 'Compliment'),
    )

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,  # Delete notes when customer deleted
        related_name='notes'
    )

    note_type = models.CharField(
        max_length=20,
        choices=NOTE_TYPE_CHOICES,
        default='general',
        verbose_name='Tip notă'
    )

    title = models.CharField(max_length=200, verbose_name='Titlu')
    content = models.TextField(verbose_name='Conținut')

    is_important = models.BooleanField(default=False, verbose_name='Important')
    is_private = models.BooleanField(default=False, verbose_name='Privat')

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,  # Keep note when user deleted
        null=True,
        verbose_name='Creat de'
    )

    class Meta:
        db_table = 'customer_notes'
        verbose_name = _('Customer Note')
        verbose_name_plural = _('Customer Notes')
        ordering: ClassVar[tuple[str, ...]] = ('-created_at',)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['customer', '-created_at']),
            models.Index(fields=['is_important']),
        )

    def __str__(self) -> str:
        return f"{self.title} - {self.customer.name}"
