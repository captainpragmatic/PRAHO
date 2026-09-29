"""Configured public voucher denominations and usable original funding methods."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from apps.settings.services import SettingsService

DEFAULT_GIFT_DENOMINATIONS = {
    "RON": [5000, 10000, 25000],
    "EUR": [1000, 2500, 5000],
    "USD": [1000, 2500, 5000],
}


def gift_purchase_options(currency_code: str) -> dict[str, Any]:
    from apps.billing.bank_transfer import bank_transfer_instructions  # noqa: PLC0415  # ADR-0007

    from .gift_cards import MAX_PURCHASE_CENTS, MIN_PURCHASE_CENTS  # noqa: PLC0415  # Runtime avoids a cycle

    enabled = SettingsService.get_boolean_setting("promotions.gift_card_sales_enabled", False)
    configured = SettingsService.get_setting("promotions.gift_card_denominations", DEFAULT_GIFT_DENOMINATIONS)
    amounts = configured.get(currency_code, []) if isinstance(configured, dict) else []
    denominations = (
        sorted(set(amounts))
        if (
            isinstance(amounts, list)
            and all(type(amount) is int and MIN_PURCHASE_CENTS <= amount <= MAX_PURCHASE_CENTS for amount in amounts)
        )
        else []
    )
    allowed = SettingsService.get_setting("promotions.gift_card_payment_methods", ["stripe", "bank"])
    if not isinstance(allowed, list) or any(
        not isinstance(method, str) or method not in {"stripe", "bank"} for method in allowed
    ):
        allowed = []
    methods = []
    if (
        "stripe" in allowed
        and SettingsService.get_boolean_setting("integrations.stripe_enabled", False)
        and SettingsService.get_setting("integrations.stripe_secret_key")
        and SettingsService.get_setting("integrations.stripe_publishable_key")
        and SettingsService.get_setting("integrations.stripe_webhook_secret")
    ):
        methods.append("stripe")
    if "bank" in allowed and bank_transfer_instructions(currency_code):
        methods.append("bank")
    return {
        "sales_enabled": enabled,
        "currency": currency_code,
        "denominations_cents": denominations,
        "payment_methods": methods,
    }


def gift_purchase_currency_blockers(currency_code: str) -> list[str]:
    options = gift_purchase_options(currency_code)
    if not options["sales_enabled"]:
        return []
    blockers = []
    if not options["denominations_cents"]:
        blockers.append(_("Gift-card sales need valid denominations in %(currency)s.") % {"currency": currency_code})
    if not options["payment_methods"]:
        blockers.append(
            _("Gift-card sales need a configured payment method in %(currency)s.") % {"currency": currency_code}
        )
    return blockers
