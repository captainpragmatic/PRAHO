"""
Customer profile models for PRAHO Platform
Tax compliance and billing profile models for customer business data.
"""

from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

from apps.common.types import validate_romanian_cui

from .customer_models import SoftDeleteModel


class CustomerTaxProfile(SoftDeleteModel):
    """
    Romanian tax compliance information separated from core customer data.

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    customer = models.OneToOneField(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete tax profile when customer deleted
        related_name="tax_profile",
    )

    # Romanian Tax Fields
    cnp = models.CharField(
        max_length=13,
        blank=True,
        verbose_name=_("CNP"),
        help_text=_("Cod Numeric Personal (13 cifre)"),
        validators=[RegexValidator(r"^\d{13}$", _("CNP invalid (trebuie 13 cifre)"))],
    )
    cui = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("CUI/CIF"),
        validators=[RegexValidator(r"^RO\d{2,10}$", _("CUI invalid"))],
    )
    registration_number = models.CharField(max_length=50, blank=True, verbose_name=_("Nr. registrul comerțului"))

    # VAT Information
    is_vat_payer = models.BooleanField(default=True, verbose_name=_("Plătitor TVA"))
    vat_number = models.CharField(max_length=20, blank=True, verbose_name=_("Nr. TVA"))
    vat_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("21.00"),  # Romanian VAT rate (updated Aug 2025)
        verbose_name=_("Cota TVA (%)"),
    )

    # Tax Reverse Charge (for B2B EU)
    reverse_charge_eligible = models.BooleanField(default=False)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_tax_profiles"
        verbose_name = _("Customer Tax Profile")
        verbose_name_plural = _("Customer Tax Profiles")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["cnp"]),
            models.Index(fields=["cui"]),
            models.Index(fields=["vat_number"]),
        )

    def validate_cui(self) -> bool:
        """Validate Romanian CUI format"""
        if not self.cui:
            return True
        result = validate_romanian_cui(self.cui)
        return result.is_ok()


class CustomerBillingProfile(SoftDeleteModel):
    """
    Customer billing and financial information.

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    customer = models.OneToOneField(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete billing profile when customer deleted
        related_name="billing_profile",
    )

    # Payment Terms
    payment_terms = models.PositiveIntegerField(default=30, verbose_name=_("Termen plată (zile)"))

    # Credit Management
    credit_limit = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal("0.00"), verbose_name=_("Limită credit (RON)")
    )

    # Currency Preferences
    preferred_currency = models.CharField(
        max_length=3, choices=[("RON", "RON"), ("EUR", "EUR")], default="RON", verbose_name=_("Monedă preferată")
    )

    # Billing Preferences
    invoice_delivery_method = models.CharField(
        max_length=20,
        choices=[
            ("email", "Email"),
            ("postal", "Poștă"),
            ("both", "Email și poștă"),
        ],
        default="email",
        verbose_name=_("Mod livrare facturi"),
    )

    # Automatic Payment
    auto_payment_enabled = models.BooleanField(default=False)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_billing_profiles"
        verbose_name = _("Customer Billing Profile")
        verbose_name_plural = _("Customer Billing Profiles")

    def get_account_balance(self) -> Decimal:
        """Get customer account balance"""
        from apps.billing.models import Invoice  # Cross-app import for balance calculation  # noqa: PLC0415

        invoices = Invoice.objects.filter(customer=self.customer)
        total_due = sum(invoice.amount_due for invoice in invoices if invoice.status in ["pending", "overdue"])
        return Decimal(str(total_due))
