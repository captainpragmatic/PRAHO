"""Keep promotion amounts in explicit units; never infer historical currency.

Before rollout, staff must review the original currency of existing offers with
money bounds and no currency. Until reviewed, they cannot discount new orders.
Frozen order quotes, documents, and redemptions retain their recorded amounts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

if TYPE_CHECKING:
    from .models import Coupon, PromotionRule


def has_monetary_terms(offer: Coupon | PromotionRule) -> bool:
    """Whether evaluating this offer reads configured money, rather than a ratio."""
    if offer.discount_type in {"fixed", "tiered_fixed"} or offer.max_discount_cents is not None:
        return True
    if getattr(offer, "min_order_cents", None):
        return True
    conditions = getattr(offer, "conditions", {}) or {}
    if isinstance(conditions, dict) and (conditions.get("min_order_cents") or conditions.get("max_order_cents")):
        return True
    if offer.discount_type in {"tiered", "tiered_percent"} and isinstance(offer.tiers, list):
        return any(
            isinstance(tier, dict) and (tier.get("threshold_type", "amount") == "amount" or "amount_cents" in tier)
            for tier in offer.tiers
        )
    return False


def validate_offer_currency(offer: Coupon | PromotionRule) -> None:
    """Reject ambiguous configured amounts without rewriting old records."""
    if has_monetary_terms(offer) and not offer.currency_id:
        raise ValidationError(
            {
                "currency": _(
                    "Choose a currency for monetary limits, caps, and amount tiers. "
                    "For an existing offer, verify its original currency before saving."
                )
            }
        )
    campaign = offer.campaign
    if campaign and campaign.budget_cents is not None and not campaign.budget_currency_id:
        raise ValidationError({"campaign": _("Choose the campaign budget currency before using this offer.")})


def validate_order_currency(offer: Coupon | PromotionRule, currency_id: str) -> None:
    """Check all offer and campaign money against the order's recorded currency."""
    validate_offer_currency(offer)
    if offer.currency_id and offer.currency_id != currency_id:
        raise ValidationError(_("This offer uses a different currency."))
    if offer.campaign and offer.campaign.budget_currency_id not in {None, currency_id}:
        raise ValidationError(_("This campaign budget uses a different currency."))
