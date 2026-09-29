"""Validate offer configuration before publication or financial evaluation."""

from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from .offer_currency import validate_offer_currency
from .pricing import PERIOD_MONTHS

MAX_TIERS = 50
MAX_PERCENT = 100
MAX_DISCOUNT_CENTS = 100_000_000
MAX_RESTRICTED_PRODUCTS = 1000
MAX_FREE_MONTHS = 36

CONDITION_KEYS = {
    "min_order_cents",
    "max_order_cents",
    "min_items",
    "customer_types",
    "required_product_types",
    "required_product_ids",
    "customer_ids",
    "first_order_only",
}
RESTRICTION_KEYS = {"product_ids", "excluded_product_ids", "product_types", "excluded_product_types", "billing_periods"}


def validate_tiers(tiers: Any, kind: str) -> None:  # noqa: C901  # Each tier schema rejection remains explicit
    if kind not in {"tiered", "tiered_percent", "tiered_fixed"}:
        return
    if not isinstance(tiers, list) or not tiers or len(tiers) > MAX_TIERS:
        raise ValidationError(_("Add between one and fifty discount tiers."))
    thresholds = set()
    metrics = set()
    for tier in tiers:
        if not isinstance(tier, dict) or set(tier) - {"threshold", "threshold_type", "percent", "amount_cents"}:
            raise ValidationError(_("A tier contains unsupported fields."))
        threshold = tier.get("threshold")
        if type(threshold) is not int or threshold < 0 or threshold in thresholds:
            raise ValidationError(_("Tier thresholds must be unique nonnegative integers."))
        thresholds.add(threshold)
        metrics.add(tier.get("threshold_type"))
        if ("percent" in tier) == ("amount_cents" in tier):
            raise ValidationError(_("Each tier needs either a percentage or an amount."))
        if (kind == "tiered_fixed" and "percent" in tier) or (kind == "tiered_percent" and "amount_cents" in tier):
            raise ValidationError(_("Tier values must match the discount type."))
        if "percent" in tier:
            try:
                value = Decimal(str(tier["percent"]))
                valid = value.is_finite() and 0 <= value <= MAX_PERCENT
            except InvalidOperation:
                valid = False
            if not valid:
                raise ValidationError(_("Tier percentages must be between zero and one hundred."))
        elif type(tier["amount_cents"]) is not int or not 0 <= tier["amount_cents"] <= MAX_DISCOUNT_CENTS:
            raise ValidationError(_("Tier amounts must be nonnegative cents, up to 100,000,000."))
    if len(metrics) != 1 or not metrics <= {"amount", "quantity"}:
        raise ValidationError(_("All tiers must use the same threshold: amount or quantity."))


def validate_conditions(conditions: Any) -> None:
    if not isinstance(conditions, dict) or set(conditions) - CONDITION_KEYS:
        raise ValidationError(_("This offer has unsupported conditions. Review its configuration."))
    for key in ("min_order_cents", "max_order_cents", "min_items"):
        if key in conditions and (type(conditions[key]) is not int or conditions[key] < 0):
            raise ValidationError(_("Condition thresholds must be nonnegative integers."))
    for key in ("customer_types", "required_product_types", "required_product_ids", "customer_ids"):
        if key in conditions and (
            not isinstance(conditions[key], list) or any(not isinstance(value, str) for value in conditions[key])
        ):
            raise ValidationError(_("Condition selections must be lists of identifiers."))
    if "first_order_only" in conditions and type(conditions["first_order_only"]) is not bool:
        raise ValidationError(_("First-order eligibility must be true or false."))
    if conditions.get("max_order_cents", 0) and conditions.get("min_order_cents", 0) > conditions["max_order_cents"]:
        raise ValidationError(_("The maximum order amount must be at least the minimum."))


def validate_restrictions(restrictions: Any) -> None:
    if not isinstance(restrictions, dict) or set(restrictions) - RESTRICTION_KEYS:
        raise ValidationError(_("This offer has unsupported product restrictions."))
    for key, values in restrictions.items():
        if (
            not isinstance(values, list)
            or len(values) > MAX_RESTRICTED_PRODUCTS
            or any(not isinstance(value, str) for value in values)
        ):
            raise ValidationError(_("Product restrictions must contain lists of identifiers."))
        if key in {"product_ids", "excluded_product_ids"}:
            try:
                for value in values:
                    UUID(value)
            except ValueError as exc:
                raise ValidationError(_("Select valid products.")) from exc
        if key == "billing_periods" and set(values) - {*PERIOD_MONTHS, "once"}:
            raise ValidationError(_("Select valid billing periods."))


def validate_offer(offer: Any) -> None:
    validate_tiers(offer.tiers, offer.discount_type)
    validate_restrictions(offer.product_restrictions)
    if hasattr(offer, "conditions"):
        validate_conditions(offer.conditions)
    if offer.discount_type == "free_shipping":
        raise ValidationError(_("Shipping discounts are unavailable for hosting services."))
    validate_offer_currency(offer)
    if offer.discount_type == "percent" and (
        offer.discount_percent is None or not 0 <= offer.discount_percent <= MAX_PERCENT
    ):
        raise ValidationError(_("Enter a percentage between zero and one hundred."))
    if offer.discount_type == "fixed" and (offer.discount_amount_cents is None or offer.discount_amount_cents < 0):
        raise ValidationError(_("Enter a nonnegative discount amount."))
    if offer.discount_type == "free_months" and not 1 <= (offer.free_months or 0) <= MAX_FREE_MONTHS:
        raise ValidationError(_("Enter between one and thirty-six free months."))
