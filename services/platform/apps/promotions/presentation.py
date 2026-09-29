"""Presentation data shared by staff promotion screens."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from django.urls import reverse
from django.utils.translation import gettext as _

from .models import GiftCard, Referral

SECTIONS = (
    ("dashboard", _("Promotions")),
    ("campaign_list", _("Campaigns")),
    ("coupon_list", _("Coupons")),
    ("rule_list", _("Automatic offers")),
    ("gift_card_list", _("Gift cards")),
    ("referral_list", _("Referrals")),
    ("loyalty_dashboard", _("Loyalty")),
)


def _value(record: Any, path: str) -> Any:
    value = record
    for part in path.split("."):
        value = getattr(value, part, None)
        if callable(value):
            value = value()
        if value is None:
            return "—"
    return value


def record_table(records: Any, fields: tuple[tuple[str, str], ...], route: str = "") -> dict[str, Any]:
    rows = []
    for record in records:
        row = {"cells": [{"text": _value(record, path)} for _, path in fields], "actions": []}
        if route:
            row["actions"] = [
                {
                    "component": "button",
                    "text": _("Open"),
                    "variant": "secondary",
                    "size": "sm",
                    "href": reverse(f"promotions:{route}", kwargs={"pk": record.pk}),
                }
            ]
        rows.append(row)
    return {"columns": [{"label": _(label)} for label, path in fields], "rows": rows}


LISTS = {
    "campaign_list": (
        "Campaigns",
        "campaigns",
        (("Name", "name"), ("Status", "get_status_display"), ("Starts", "start_date"), ("Ends", "end_date")),
        "campaign_detail",
        "campaign_create",
    ),
    "coupon_list": (
        "Coupons",
        "coupons",
        (
            ("Code", "code"),
            ("Name", "name"),
            ("Discount", "get_discount_type_display"),
            ("Status", "get_status_display"),
            ("Uses", "total_uses"),
        ),
        "coupon_detail",
        "coupon_create",
    ),
    "rule_list": (
        "Automatic offers",
        "rules",
        (
            ("Name", "name"),
            ("Type", "get_rule_type_display"),
            ("Discount", "get_discount_type_display"),
            ("Priority", "priority"),
            ("Active", "is_active"),
        ),
        "rule_update",
        "rule_create",
    ),
    "gift_card_list": (
        "Gift cards",
        "gift_cards",
        (
            ("Code", "code"),
            ("Status", "get_status_display"),
            ("Balance (cents)", "current_balance_cents"),
            ("Currency", "currency.code"),
        ),
        "gift_card_detail",
        "gift_card_create",
    ),
    "referral_list": (
        "Referrals",
        "referrals",
        (
            ("Code", "referral_code.code"),
            ("Customer", "referred_customer"),
            ("Status", "get_status_display"),
            ("Created", "created_at"),
        ),
        "",
        "",
    ),
}


def staff_context(request: HttpRequest, context: dict[str, Any]) -> dict[str, Any]:
    route = request.resolver_match.url_name if request.resolver_match else ""
    context["promotion_navigation"] = [
        {"label": _(label), "url": reverse(f"promotions:{name}"), "active": name == route} for name, label in SECTIONS
    ]
    parameters = request.GET.copy()
    parameters.pop("page", None)
    context["extra_params"] = "&" + parameters.urlencode() if parameters else ""
    if route == "gift_card_list":
        context["statuses"] = [{"value": value, "label": label} for value, label in GiftCard.STATUS_CHOICES]
    if route == "referral_list":
        context["statuses"] = [{"value": value, "label": label} for value, label in Referral.STATUS_CHOICES]
    if route == "coupon_list":
        context["campaign_options"] = [
            {"value": str(campaign.pk), "label": campaign.name} for campaign in context.get("campaigns", [])
        ]
    if route in LISTS:
        title, key, fields, detail, create = LISTS[route]
        context.update(record_table(context.get(key, []), fields, detail))
        context["page_title"] = _(title)
        context["create_url"] = reverse(f"promotions:{create}") if create else ""
    return context
