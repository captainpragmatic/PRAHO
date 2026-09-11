"""Currency admission + validation helpers (#103).

Two responsibilities, kept deliberately small (not the sprawling CurrencyService
the original issue imagined):

* ``normalize_currency_code`` — normalize a caller-supplied (e.g. POSTed) currency
  code and reject missing/blank/unsupported values with a typed error, so callers
  never crash on ``None`` or silently pass ``"eur"`` into a case-sensitive PK lookup.
* ``assert_currency_issuable`` — the fail-closed admission guard. A non-RON billable
  document may only be created when a provenanced FX rate resolves for
  ``currency -> RON`` at the tax-point date. This prevents STUCK MONEY: without it a
  paid EUR document converts to an invoice whose ``issue()`` raises for lack of a
  rate, so money is taken but the invoice legally cannot be issued.

RON is the home currency and always passes (a RON/RON ``FXRate`` is DB-illegal by the
``fxrate_distinct_currency_pair`` CheckConstraint).
"""

from __future__ import annotations

from datetime import date

from django.utils.translation import gettext_lazy as _

from apps.common.types import CurrencyCode

HOME_CURRENCY = "RON"


class CurrencyValidationError(ValueError):
    """A supplied currency code is missing, blank, or unsupported."""


class CurrencyNotIssuableError(ValueError):
    """No provenanced FX rate is resolvable for a non-RON currency at the given date."""


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
    """Fail-closed guard: refuse a non-RON billable document unless an FX rate resolves.

    RON returns immediately (home currency). For any other currency, resolve
    ``currency -> RON`` at ``effective_date`` via the authoritative resolver; a
    ``ExchangeRateError`` (missing / unprovenanced) becomes ``CurrencyNotIssuableError``
    so the caller can reject at admission instead of stranding money at ``issue()``.
    """
    code = currency_code.strip().upper()
    if code == HOME_CURRENCY:
        return
    # Function-level import breaks the app-level import cycle (ADR-0007).
    from apps.billing.exchange_rate_service import ExchangeRateError, ExchangeRateService  # noqa: PLC0415

    try:
        ExchangeRateService.resolve(code, HOME_CURRENCY, effective_date)
    except ExchangeRateError as exc:
        raise CurrencyNotIssuableError(
            _("No exchange rate available for %(code)s on %(date)s — provision one before issuing in this currency.")
            % {"code": code, "date": effective_date}
        ) from exc
