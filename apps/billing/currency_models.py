"""
Currency models for PRAHO Platform
Romanian invoice generation with VAT compliance and e-Factura support.
"""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# CURRENCY & FX MODELS
# ===============================================================================


class Currency(models.Model):
    """Currency definitions with decimal precision"""

    code = models.CharField(max_length=3, primary_key=True)  # 'EUR', 'RON'
    name = models.CharField(max_length=50, default="")
    symbol = models.CharField(max_length=10)
    decimals = models.SmallIntegerField(default=2)

    class Meta:
        db_table = "currency"
        verbose_name = _("Currency")
        verbose_name_plural = _("Currencies")

    def __str__(self) -> str:
        return f"{self.code} ({self.symbol})"

    # Convenience for tests that expect integer PK `.id`
    @property
    def id(self) -> str:  # type: ignore[override]
        return self.code


class FXRate(models.Model):
    """Foreign exchange rates for currency conversion"""

    base_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name="base_rates")
    quote_code = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name="quote_rates")
    rate = models.DecimalField(max_digits=18, decimal_places=8)
    as_of = models.DateField()

    class Meta:
        db_table = "fx_rate"
        unique_together = (("base_code", "quote_code", "as_of"),)
        indexes = (models.Index(fields=["base_code", "quote_code", "-as_of"]),)

    def __str__(self) -> str:
        return f"{self.base_code.code}/{self.quote_code.code} = {self.rate:.8f} ({self.as_of})"
