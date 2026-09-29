"""Pure rendering and timing rules for a currency-change offer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

NOTICE_DAYS = 30


def terms_fingerprint(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def notice_allows_preparation(accepted_at: datetime | None, preparation_at: datetime) -> bool:
    return accepted_at is not None and preparation_at >= accepted_at + timedelta(days=NOTICE_DAYS)


def _money(cents: int, currency: str) -> str:
    return f"{Decimal(cents) / 100:.2f} {currency}"


def _term_lines(snapshot: dict[str, Any]) -> list[str]:
    currency = snapshot["currency"]
    quantity = snapshot["quantity"]
    unit = snapshot["unit_price_cents"]
    period = snapshot.get("billing_cycle", "billing period").replace("_", " ")
    if period == "custom":
        period = f"{snapshot['custom_cycle_days']} days"
    lines = [f"{quantity} x {_money(unit, currency)} = {_money(quantity * unit, currency)} per {period}, before tax."]
    for meter in snapshot.get("meters", {}).values():
        if not meter.get("is_billable") or meter.get("hold_reason"):
            continue
        lines.append(
            f"Usage {meter['name']}: allowance {meter['included_allowance']}; "
            f"rounding {meter['rounding_mode']} to {meter['rounding_increment']}."
        )
        if meter.get("unit_price_cents") is not None:
            lines.append(f"Usage price: {_money(meter['unit_price_cents'], currency)} per unit above the allowance.")
        lines.extend(
            f"Usage range {bracket['from_quantity']} to {bracket['to_quantity'] or 'unlimited'}: "
            f"{_money(bracket['unit_price_cents'], currency)} per unit, "
            f"{_money(bracket['flat_fee_cents'], currency)} fixed fee."
            for bracket in meter.get("brackets", [])
        )
        if meter.get("minimum_charge_cents"):
            lines.append(f"Minimum usage charge: {_money(meter['minimum_charge_cents'], currency)}.")
    return lines


def render_notice(
    subscription_number: str,
    product_name: str,
    old: dict[str, Any],
    target: dict[str, Any],
) -> tuple[str, str]:
    subject = f"Renewal currency and price notice for {subscription_number}"
    body = "\n".join(
        [
            f"Your {product_name} subscription ({subscription_number}) has proposed renewal terms.",
            "Current terms:",
            *_term_lines(old),
            "Future terms:",
            *_term_lines(target),
            "",
            "The first renewal document using these terms will be prepared at least 30 days after this notice is sent.",
            "The new terms take effect at the start of that renewal period, including if you pay early.",
            "Existing invoices, orders, payments, gift cards and credit balances keep their original amounts and currency.",
            "Any protected price or remaining renewal benefit continues under its original terms until its protection ends.",
            "An existing automatic-payment authorization continues to apply. You can review or cancel renewal in your portal.",
        ]
    )
    return subject, body
