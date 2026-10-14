"""Currency admission + validation helpers (#103).

Two responsibilities, kept deliberately small (not the sprawling CurrencyService
the original issue imagined):

* ``normalize_currency_code`` — normalize a caller-supplied (e.g. POSTed) currency
  code and reject missing/blank/unsupported values with a typed error, so callers
  never crash on ``None`` or silently pass ``"eur"`` into a case-sensitive PK lookup.
* ``assert_currency_issuable`` — the fail-closed admission guard. A billable document
  in a foreign currency may only be created when a provenanced FX rate resolves for
  ``currency -> home currency`` at the tax-point date. This prevents STUCK MONEY: without
  it a paid foreign document converts to an invoice whose ``issue()`` raises for lack of
  a rate, so money is taken but the invoice legally cannot be issued.

The home currency is the operator's national currency (``home_currency()``, RON for a
Romanian operator) and always passes: a same-currency ``FXRate`` is DB-illegal by the
``fxrate_distinct_currency_pair`` CheckConstraint.
"""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING

from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

from apps.common.operator import operator_country
from apps.common.types import CurrencyCode

if TYPE_CHECKING:
    from apps.billing.currency_models import Currency

# The currency each EU member state keeps its accounts in, which VAT amounts on a foreign-currency
# invoice convert into (VAT Directive art. 91): the euro in the 21 euro-area states (Bulgaria from
# 1 January 2026), else the state's own. Its keys equal billing.config.EU_COUNTRY_CODES (tested).
NATIONAL_CURRENCIES: dict[str, str] = {
    **dict.fromkeys(
        (
            "AT",
            "BE",
            "BG",
            "CY",
            "DE",
            "EE",
            "ES",
            "FI",
            "FR",
            "GR",
            "HR",
            "IE",
            "IT",
            "LT",
            "LU",
            "LV",
            "MT",
            "NL",
            "PT",
            "SI",
            "SK",
        ),
        "EUR",
    ),
    "CZ": "CZK",
    "DK": "DKK",
    "HU": "HUF",
    "PL": "PLN",
    "RO": "RON",
    "SE": "SEK",
}


def home_currency() -> str:
    """The currency the operator keeps its accounts in: its country's national currency."""
    country = operator_country()
    try:
        return NATIONAL_CURRENCIES[country]
    except KeyError:
        # Reachable only in DEBUG: outside it the common.E003 check refuses an operator outside the EU.
        raise ImproperlyConfigured(
            f"No accounting currency is known for operator country {country!r}. PRAHO supports operators "
            "established in an EU member state (check common.E003)."
        ) from None


def default_selling_currency() -> str:
    """New sales default to the home currency when PRAHO can sell in it, else to the euro.

    The single-number legacy amounts (review and alert limits, the legacy price columns, the
    legacy bank account, a credit limit) are in this currency too: it is the one the operator
    sells in by default, and it equals the home currency everywhere PRAHO can sell in that.
    """
    home = home_currency()
    return home if CurrencyCode.is_supported(home) else CurrencyCode.EUR.value


def ensure_home_currency_row() -> Currency:
    """The home currency's row: every exchange rate quotes against it, so it must exist first."""
    from apps.billing.currency_models import Currency  # noqa: PLC0415  # Models load after this module

    code = home_currency()
    currency, _created = Currency.objects.get_or_create(code=code, defaults={"symbol": code, "decimals": 2})
    return currency


class CurrencyValidationError(ValueError):
    """A supplied currency code is missing, blank, or unsupported."""


class CurrencyNotIssuableError(ValueError):
    """No provenanced FX rate to the home currency is resolvable at the given date."""


def normalize_currency_code(raw: str | None) -> str:
    """Return the upper-cased ISO code, or raise ``CurrencyValidationError``.

    Guards ``None``/blank (``CurrencyCode.is_supported`` raises ``AttributeError`` on
    ``None``) and rejects unsupported codes before any case-sensitive DB lookup.
    """
    if raw is None or not raw.strip():
        raise CurrencyValidationError(_("Currency is required."))
    code = raw.strip().upper()
    if not CurrencyCode.is_supported(code):
        raise CurrencyValidationError(_("Unsupported currency: %(code)s") % {"code": raw})
    return code


def assert_currency_issuable(currency_code: str, effective_date: date) -> None:
    """Fail-closed guard: refuse a foreign-currency billable document unless an FX rate resolves.

    The home currency returns immediately. For any other currency, resolve
    ``currency -> home`` at ``effective_date`` via the authoritative resolver; a
    ``ExchangeRateError`` (missing / unprovenanced) becomes ``CurrencyNotIssuableError``
    so the caller can reject at admission instead of stranding money at ``issue()``.
    """
    code = currency_code.strip().upper()
    home = home_currency()
    if code == home:
        return
    # Function-level import breaks the app-level import cycle (ADR-0007).
    from apps.billing.exchange_rate_service import ExchangeRateError, ExchangeRateService  # noqa: PLC0415

    try:
        ExchangeRateService.resolve(code, home, effective_date)
    except ExchangeRateError as exc:
        raise CurrencyNotIssuableError(
            _("No exchange rate available for %(code)s on %(date)s — provision one before issuing in this currency.")
            % {"code": code, "date": effective_date}
        ) from exc
