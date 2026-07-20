"""
Currency models for PRAHO Platform
Romanian invoice generation with VAT compliance and e-Factura support.
"""

from __future__ import annotations

from decimal import Decimal

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import F, Q
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# CURRENCY & FX MODELS
MAX_FX_RATE = Decimal("9999999999.99999999")

# ===============================================================================


class Currency(models.Model):
    """Currency definitions with decimal precision"""

    code = models.CharField(max_length=3, primary_key=True)  # 'EUR', 'RON'
    name = models.CharField(max_length=50, default="")
    symbol = models.CharField(max_length=10)
    decimals = models.SmallIntegerField(default=2)

    class Meta:
        db_table = "billing_currencies"
        verbose_name = _("Currency")
        verbose_name_plural = _("Currencies")

    def __str__(self) -> str:
        return f"{self.code} ({self.symbol})"

    # Convenience for tests that expect integer PK `.id`
    @property
    def id(self) -> str:
        return self.code


class FXRate(models.Model):
    """Foreign exchange rates for currency conversion"""

    class Source(models.TextChoices):
        LEGACY_UNKNOWN = "legacy_unknown", _("Legacy / unknown")
        BNR = "bnr", _("National Bank of Romania")
        ECB = "ecb", _("European Central Bank")
        BANK = "bank", _("Commercial bank")

    base_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name="base_rates")
    quote_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name="quote_rates")
    rate = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        validators=[MinValueValidator(Decimal("0.00000001")), MaxValueValidator(MAX_FX_RATE)],
    )
    as_of = models.DateField()
    source = models.CharField(max_length=32, choices=Source.choices, default=Source.LEGACY_UNKNOWN)
    source_reference = models.CharField(max_length=500, blank=True)
    fetched_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "billing_fx_rates"
        unique_together = (("base_code", "quote_code", "as_of"),)
        indexes = (models.Index(fields=["base_code", "quote_code", "-as_of"]),)
        constraints = (
            models.CheckConstraint(condition=Q(rate__gt=0, rate__lte=MAX_FX_RATE), name="fxrate_rate_finite_positive"),
            models.CheckConstraint(condition=~Q(base_code=F("quote_code")), name="fxrate_distinct_currency_pair"),
        )

    def __str__(self) -> str:
        return f"{self.base_code.code}/{self.quote_code.code} = {self.rate:.8f} ({self.as_of})"
