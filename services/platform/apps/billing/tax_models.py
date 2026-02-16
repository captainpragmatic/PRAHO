"""
Tax models for PRAHO Platform
EU VAT compliance with VIES validation and reverse charge support.
"""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# Date constants for tax rate validation
JANUARY = 1  # First month of year
DECEMBER = 12  # Last month of year
FIRST_DAY_OF_MONTH = 1  # First day of month
LAST_DAY_OF_DECEMBER = 31  # Last day of December


# ===============================================================================
# TAX MODELS
# ===============================================================================


class TaxRule(models.Model):
    """
    EU VAT rates by country with temporal validity.
    Critical for Romanian & EU VAT compliance with VIES validation and reverse charge support.
    Handles B2B transactions and cross-border EU sales.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Geographic scope
    country_code = models.CharField(max_length=2, help_text=_("ISO 3166-1 alpha-2 country code (e.g., 'RO', 'DE')"))
    region = models.CharField(
        max_length=50, blank=True, help_text=_("State/province for countries with regional tax rates")
    )

    # Tax configuration
    tax_type = models.CharField(
        max_length=20,
        choices=[
            ("vat", _("VAT")),
            ("gst", _("GST")),
            ("sales_tax", _("Sales Tax")),
            ("withholding", _("Withholding Tax")),
        ],
        default="vat",
    )
    rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_("Tax rate as decimal (e.g., 0.19 for 19%)"),
    )
    reduced_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_("Reduced rate for specific product categories"),
    )

    # Validity period
    valid_from = models.DateField(help_text=_("When this tax rate becomes effective"))
    valid_to = models.DateField(null=True, blank=True, help_text=_("When this tax rate expires (null = indefinite)"))

    # Business rules
    applies_to_b2b = models.BooleanField(
        default=True, help_text=_("Whether tax applies to business-to-business transactions")
    )
    applies_to_b2c = models.BooleanField(
        default=True, help_text=_("Whether tax applies to business-to-consumer transactions")
    )
    reverse_charge_eligible = models.BooleanField(
        default=False, help_text=_("Whether reverse charge mechanism applies (EU B2B)")
    )

    # Romanian specific
    is_eu_member = models.BooleanField(default=False, help_text=_("Whether country is EU member for VAT purposes"))
    vies_required = models.BooleanField(default=False, help_text=_("Whether VIES VAT number validation is required"))

    # Configuration
    meta = models.JSONField(default=dict, blank=True, help_text=_("Additional tax configuration and rules"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tax_rules"
        verbose_name = _("Tax Rule")
        verbose_name_plural = _("Tax Rules")
        unique_together = (("country_code", "region", "tax_type", "valid_from"),)
        indexes = (
            models.Index(fields=["country_code", "tax_type"]),
            models.Index(fields=["valid_from", "valid_to"]),
            models.Index(fields=["is_eu_member"]),
        )
        ordering = ("country_code", "tax_type", "-valid_from")

    def __str__(self) -> str:
        rate_display = f"{self.rate * 100:.2f}%"
        # Simple format for full year ranges (common case)
        if (
            self.valid_to
            and self.valid_from.month == JANUARY
            and self.valid_from.day == FIRST_DAY_OF_MONTH
            and self.valid_to.month == DECEMBER
            and self.valid_to.day == LAST_DAY_OF_DECEMBER
            and self.valid_from.year == self.valid_to.year
        ):
            return f"{self.country_code} {self.tax_type.upper()} {rate_display}"

        # Detailed format for specific date ranges
        if self.valid_to:
            return f"{self.country_code} {self.tax_type.upper()} {rate_display} ({self.valid_from} - {self.valid_to})"
        return f"{self.country_code} {self.tax_type.upper()} {rate_display} (from {self.valid_from})"

    def is_active(self, date: date | None = None) -> bool:
        """Check if tax rule is active on given date"""
        if date is None:
            date = timezone.now().date()

        if date < self.valid_from:
            return False

        return not (self.valid_to and date > self.valid_to)

    @classmethod
    def get_active_rate(cls, country_code: str, tax_type: str = "vat", date: date | None = None) -> Decimal:
        """Get active tax rate for country and date"""
        if date is None:
            date = timezone.now().date()

        try:
            rule = (
                cls.objects.filter(country_code=country_code.upper(), tax_type=tax_type, valid_from__lte=date)
                .filter(models.Q(valid_to__isnull=True) | models.Q(valid_to__gte=date))
                .order_by("-valid_from", "-created_at")
                .first()
            )

            return rule.rate if rule else Decimal("0.00")
        except cls.DoesNotExist:
            return Decimal("0.00")


def _invalidate_tax_cache(sender: type, instance: object, **kwargs: object) -> None:
    """Invalidate TaxService cache when TaxRule is saved or deleted."""
    try:
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        TaxService.invalidate_cache(instance.country_code)
    except Exception:  # noqa: S110
        pass  # Cache invalidation is best-effort


models.signals.post_save.connect(_invalidate_tax_cache, sender=TaxRule)
models.signals.post_delete.connect(_invalidate_tax_cache, sender=TaxRule)


class VATValidation(models.Model):
    """
    VIES VAT number validation results cache.
    Stores validation results to avoid repeated API calls and for compliance audit.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # VAT number components
    country_code = models.CharField(max_length=2, help_text=_("Country code (e.g., 'RO')"))
    vat_number = models.CharField(max_length=20, help_text=_("VAT number without country prefix"))
    full_vat_number = models.CharField(max_length=25, help_text=_("Complete VAT number (e.g., 'RO12345678')"))

    # Validation results
    is_valid = models.BooleanField(help_text=_("Whether VAT number is valid"))
    is_active = models.BooleanField(default=False, help_text=_("Whether company is active for VAT purposes"))
    company_name = models.CharField(max_length=255, blank=True, help_text=_("Company name from VIES (if available)"))
    company_address = models.TextField(blank=True, help_text=_("Company address from VIES (if available)"))

    # Validation metadata
    validation_date = models.DateTimeField(auto_now_add=True)
    validation_source = models.CharField(
        max_length=20,
        choices=[
            ("vies", _("VIES API")),
            ("manual", _("Manual Override")),
            ("cached", _("Previous Validation")),
        ],
        default="vies",
    )
    response_data = models.JSONField(default=dict, blank=True, help_text=_("Raw API response for audit purposes"))

    # Expiry management
    expires_at = models.DateTimeField(null=True, blank=True, help_text=_("When validation result expires"))

    class Meta:
        db_table = "vat_validations"
        verbose_name = _("VAT Validation")
        verbose_name_plural = _("VAT Validations")
        unique_together = (("country_code", "vat_number"),)
        indexes = (
            models.Index(fields=["full_vat_number"]),
            models.Index(fields=["validation_date"]),
            models.Index(fields=["expires_at"]),
        )
        ordering = ("-validation_date",)

    def __str__(self) -> str:
        status = "Valid" if self.is_valid else "Invalid"
        if self.company_name:
            return f"{self.full_vat_number} ({self.company_name}) - {status}"
        return f"{self.full_vat_number} - {status}"

    def is_expired(self) -> bool:
        """Check if validation result has expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
