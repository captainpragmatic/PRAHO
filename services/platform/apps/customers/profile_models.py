"""
Customer profile models for PRAHO Platform
Tax compliance and billing profile models for customer business data.
"""

from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _

from apps.common.cnp_validator import validate_cnp
from apps.common.cui_validator import CUIValidator, validate_cui
from apps.common.types import CurrencyCode

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
        validators=[validate_cnp],
    )
    cui = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("CUI/CIF"),
        validators=[validate_cui],
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

    # VIES Verification (EU cross-border VAT)
    vies_verified_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("VIES verified at"),
        help_text=_("Timestamp of last successful VIES verification"),
    )
    vies_verified_name = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("VIES company name"),
        help_text=_("Company name returned by VIES API"),
    )
    vies_verification_status = models.CharField(
        max_length=25,
        choices=[
            ("pending", _("Pending")),
            ("valid", _("VIES Verified")),
            ("invalid", _("VIES Invalid")),
            ("format_only", _("Format Valid (VIES unavailable)")),
            ("not_applicable", _("Not Applicable")),
        ],
        default="pending",
        verbose_name=_("VIES status"),
    )

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
        """Validate Romanian CUI format (accepts both 'RO12345678' and '12345678')."""
        if not self.cui:
            return True
        return CUIValidator.validate(self.cui).is_valid


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
        max_length=3, choices=CurrencyCode.choices(), default="RON", verbose_name=_("Monedă preferată")
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
        """Get customer outstanding balance in currency units (e.g. RON, not cents).

        Uses global aggregate: max(0, total_invoiced - total_paid) across all issued/overdue
        invoices. Cross-invoice overpayments offset other invoices' debt (intentional).
        """
        from django.db.models import Sum  # noqa: PLC0415  # Deferred: avoids circular import

        from apps.billing.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Invoice,  # Cross-app import for balance calculation  # Circular: cross-app
            Payment,
        )

        # Total invoiced for outstanding invoices (issued or overdue)
        total_invoiced = (
            Invoice.objects.filter(customer=self.customer, status__in=["issued", "overdue"]).aggregate(
                total=Sum("total_cents")
            )["total"]
            or 0
        )
        # Total paid against those invoices
        total_paid = (
            Payment.objects.filter(
                invoice__customer=self.customer,
                invoice__status__in=["issued", "overdue"],
                status__in=["succeeded", "partially_refunded"],
            ).aggregate(total=Sum("amount_cents"))["total"]
            or 0
        )
        balance_cents = max(0, total_invoiced - total_paid)
        return Decimal(balance_cents) / 100
