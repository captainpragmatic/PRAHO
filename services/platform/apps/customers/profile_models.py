"""
Customer profile models for PRAHO Platform
Tax compliance and billing profile models for customer business data.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _

from apps.common.cnp_validator import validate_cnp
from apps.common.cui_validator import CUIValidator, validate_cui
from apps.common.types import CurrencyCode

from .customer_models import SoftDeleteModel

if TYPE_CHECKING:
    from apps.audit.models import AuditEvent


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
        null=True,
        blank=True,
        default=None,
        verbose_name=_("Cota TVA (%)"),
        help_text=_("Optional customer-specific override; leave blank to use TaxService country rules"),
    )

    class VATRateReason(models.TextChoices):
        DIPLOMATIC = "diplomatic", _("Diplomatic exemption")
        EXEMPT_BODY = "exempt_body", _("Exempt body")
        OTHER = "other", _("Other exemption")

    vat_rate_reason = models.CharField(
        max_length=20, choices=VATRateReason.choices, blank=True, verbose_name=_("VAT exemption reason")
    )
    vies_consultation_reference = models.CharField(
        max_length=255, blank=True, verbose_name=_("VIES consultation reference")
    )

    # Tax Reverse Charge (for B2B EU)
    reverse_charge_eligible = models.BooleanField(default=False)

    class VIESVerificationStatus(models.TextChoices):
        PENDING = "pending", _("Pending")
        VALID = "valid", _("VIES Verified")
        INVALID = "invalid", _("VIES Invalid")
        FORMAT_ONLY = "format_only", _("Format Valid (VIES unavailable)")
        NOT_APPLICABLE = "not_applicable", _("Not Applicable")

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
        choices=VIESVerificationStatus.choices,
        default=VIESVerificationStatus.PENDING,
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
            models.Index(fields=["vies_verification_status"], name="customer_tax_vies_status_idx"),
        )

    @property
    def vies_name_mismatch(self) -> bool:
        from apps.billing.config import reverse_charge_requires_name_match  # noqa: PLC0415
        from apps.billing.vies_evidence import vies_name_matches  # noqa: PLC0415

        return reverse_charge_requires_name_match() and not vies_name_matches(
            self.vies_verified_name, self.customer.get_billing_name()
        )

    @property
    def recent_vies_refusals(self) -> models.QuerySet[AuditEvent]:
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        return AuditEvent.objects.filter(
            action="vies_evidence_refused", metadata__customer_id=str(self.customer_id)
        ).order_by("-timestamp")[:10]

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

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_billing_profiles"
        verbose_name = _("Customer Billing Profile")
        verbose_name_plural = _("Customer Billing Profiles")

    def get_account_balances(self) -> dict[str, Decimal]:
        """Outstanding units by recorded currency, net of completed refunds.

        Overpayments offset other issued/overdue invoices within the same currency.
        The current selling policy and the customer's preference do not relabel debt.
        """
        from apps.billing.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Invoice,
            Payment,
            Refund,
        )

        invoices = Invoice.objects.filter(customer=self.customer, status__in=["issued", "overdue"])
        invoiced = {
            row["currency_id"]: row["sum_cents"] or 0
            for row in invoices.values("currency_id").annotate(sum_cents=models.Sum("total_cents"))
        }
        if not invoiced:
            return {}

        payments = Payment.objects.filter(
            customer=self.customer,
            invoice__in=invoices,
            currency_id=models.F("invoice__currency_id"),
            status__in=["succeeded", "partially_refunded", "refunded"],
        )
        collected = {
            row["currency_id"]: row["sum_cents"] or 0
            for row in payments.values("currency_id").annotate(sum_cents=models.Sum("amount_cents"))
        }
        # Payment.amount_cents retains the original amount after a refund. Follow
        # the invoice ledger's direct-invoice or payment-linked refund evidence;
        # a refund matching both relationships is still one row in this query.
        refunds = Refund.objects.filter(customer=self.customer, status="completed").filter(
            models.Q(invoice__in=invoices, currency_id=models.F("invoice__currency_id"))
            | models.Q(payment__in=payments, currency_id=models.F("payment__currency_id"))
        )
        refunded = {
            row["currency_id"]: row["sum_cents"] or 0
            for row in refunds.values("currency_id").annotate(sum_cents=models.Sum("amount_cents"))
        }
        balances = {}
        for code, total in invoiced.items():
            retained = max(0, collected.get(code, 0) - refunded.get(code, 0))
            balances[code] = Decimal(max(0, total - retained)) / 100
        return balances

    def get_account_balance(self, currency_code: str) -> Decimal:
        """Return outstanding units for one explicitly requested currency."""
        from apps.billing.currency_service import normalize_currency_code  # noqa: PLC0415

        code = normalize_currency_code(currency_code)
        return self.get_account_balances().get(code, Decimal("0.00"))
