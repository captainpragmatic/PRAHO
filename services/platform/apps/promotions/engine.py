"""Authoritative quotes, reservations and settlement of version-two promotions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from decimal import Decimal
from typing import Any

from django.core import signing
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.audit.services import AuditService
from apps.common.financial_arithmetic import calculate_line_totals
from apps.settings.services import SettingsService

from .models import Coupon, GiftCard, PromotionApplication, PromotionCampaign, PromotionRule, RenewalBenefit
from .pricing import Offer, PriceLine, evaluate_offers
from .validation import validate_offer

QUOTE_SALT = "promotions.checkout.v2"
QUOTE_MAX_AGE = 900
MAX_COUPON_CODES = 5


def preview_cart(  # noqa: PLR0913  # Quote inputs include explicit customer, currency, tax and tender
    customer: Any,
    currency: Any,
    items: list[dict[str, Any]],
    codes: list[str],
    tax_rate: Decimal,
    *,
    gift_code: str = "",
) -> dict[str, Any]:
    from apps.orders.models import Order, OrderItem  # noqa: PLC0415

    preview_items = [
        OrderItem(
            product_id=item["product_id"],
            product_type=item["product_type"],
            quantity=item["quantity"],
            unit_price_cents=item["unit_price_cents"],
            setup_cents=item["setup_cents"],
            config={"billing_period": item["billing_period"]},
            domain_name=item.get("domain_name", ""),
            tax_rate=tax_rate,
        )
        for item in items
    ]
    order = Order(
        customer=customer,
        currency=currency,
        subtotal_cents=sum(item.quantity * item.unit_price_cents + item.setup_cents for item in preview_items),
    )
    order.tax_cents = sum(
        calculate_line_totals(item.quantity * item.unit_price_cents + item.setup_cents, tax_rate).tax_cents
        for item in preview_items
    )
    return quote_order(order, preview_items, codes, gift_code=gift_code)


def _line_key(item: Any) -> str:
    """Independent of temporary ORM UUIDs; identical configurations can be grouped."""
    identity = [str(item.product_id), item.billing_period, item.domain_name, item.unit_price_cents, item.setup_cents]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def _keyed_items(items: list[Any]) -> list[tuple[str, Any]]:
    counts: dict[str, int] = {}
    result = []
    for item in items:
        base = _line_key(item)
        occurrence = counts.get(base, 0)
        counts[base] = occurrence + 1
        result.append((f"{base}:{occurrence}", item))
    return sorted(result, key=lambda entry: entry[0])


def _eligible(offer: Any, item: Any) -> bool:
    if offer.applies_to_all_products:
        return True
    rules = offer.product_restrictions or {}
    product_id = str(item.product_id)
    return (
        (not rules.get("product_ids") or product_id in rules["product_ids"])
        and product_id not in rules.get("excluded_product_ids", [])
        and (not rules.get("product_types") or item.product_type in rules["product_types"])
        and item.product_type not in rules.get("excluded_product_types", [])
        and (not rules.get("billing_periods") or item.billing_period in rules["billing_periods"])
    )


def _has_prior_order(order: Any) -> bool:
    return (
        order.customer.orders.exclude(pk=order.pk).exclude(status__in=["draft", "cancelled", "failed"]).exists()
        or PromotionApplication.objects.filter(order__customer=order.customer, status__in=["reserved", "settled"])
        .exclude(order=order)
        .exists()
    )


def _rule_matches(rule: PromotionRule, order: Any, items: list[Any]) -> bool:  # noqa: PLR0911  # Independent eligibility gates
    conditions = rule.conditions or {}
    if conditions.get("min_order_cents", 0) > order.subtotal_cents:
        return False
    if conditions.get("max_order_cents") and conditions["max_order_cents"] < order.subtotal_cents:
        return False
    if conditions.get("min_items", 0) > sum(item.quantity for item in items if _eligible(rule, item)):
        return False
    if conditions.get("customer_types") and order.customer.customer_type not in conditions["customer_types"]:
        return False
    if conditions.get("customer_ids") and str(order.customer_id) not in conditions["customer_ids"]:
        return False
    if conditions.get("first_order_only") and _has_prior_order(order):
        return False
    return set(conditions.get("required_product_types", [])).issubset({item.product_type for item in items}) and set(
        conditions.get("required_product_ids", [])
    ).issubset({str(item.product_id) for item in items})


def _validate_coupon_customer(candidate: Coupon, order: Any, items: list[Any]) -> None:
    valid, reason = candidate.can_customer_use(order.customer)
    if not valid:
        raise ValidationError(reason)
    if (candidate.first_order_only or candidate.customer_target == "new") and _has_prior_order(order):
        raise ValidationError(_("This coupon is for a customer's first order."))
    if candidate.customer_target == "segment":
        raise ValidationError(_("This coupon needs an explicit eligible customer selection."))
    if (candidate.min_order_cents or 0) > order.subtotal_cents or (candidate.min_order_items or 0) > sum(
        item.quantity for item in items
    ):
        raise ValidationError(_("The order does not meet the coupon minimum."))


def _validate_offer_state(candidate: Coupon | PromotionRule, order: Any) -> None:
    validate_offer(candidate)
    if candidate.currency_id and candidate.currency_id != order.currency_id:
        raise ValidationError(_("This offer uses a different currency."))
    if candidate.campaign and (
        not candidate.campaign.can_apply() or candidate.campaign.budget_currency_id not in {None, order.currency_id}
    ):
        raise ValidationError(_("This campaign is unavailable."))


def _candidate_offers(order: Any, items: list[Any], codes: list[str]) -> list[Coupon | PromotionRule]:
    now = timezone.now()
    if not SettingsService.get_boolean_setting("promotions.new_offers_enabled", False):
        if codes:
            raise ValidationError(_("New promotions are temporarily unavailable."))
        return []
    normalized = list(dict.fromkeys(code.strip().upper() for code in codes if code.strip()))
    if len(normalized) > MAX_COUPON_CODES:
        raise ValidationError(_("Use at most five coupon codes."))
    coupons = list(Coupon.objects.filter(code__in=normalized).select_related("campaign", "currency"))
    if len(coupons) != len(normalized):
        raise ValidationError(_("A coupon code is invalid or unavailable."))
    rules = list(
        PromotionRule.objects.filter(is_active=True, published_at__isnull=False, valid_from__lte=now)
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gte=now))
        .select_related("campaign", "currency")
    )
    available: list[Coupon | PromotionRule] = []
    candidates: list[Coupon | PromotionRule] = [*coupons, *rules]
    for candidate in candidates:
        entered = isinstance(candidate, Coupon)
        try:
            _validate_offer_state(candidate, order)
            if isinstance(candidate, Coupon):
                _validate_coupon_customer(candidate, order, items)
            elif not _rule_matches(candidate, order, items):
                continue
            if not any(_eligible(candidate, item) for item in items):
                raise ValidationError(_("No items qualify for this offer."))
        except ValidationError:
            if entered:
                raise
            continue
        available.append(candidate)
    if len(coupons) > 1 and any(coupon.is_exclusive or not coupon.is_stackable for coupon in coupons):
        raise ValidationError(_("These coupon codes cannot be combined."))
    return available


def quote_order(order: Any, items: list[Any], codes: list[str], *, gift_code: str = "") -> dict[str, Any]:
    keyed = _keyed_items(items)
    models = _candidate_offers(order, items, codes)
    sources = {str(source.pk): source for source in models}
    offers = []
    for source in models:
        campaign = source.campaign
        offers.append(
            Offer(
                str(source.pk),
                source.discount_type,
                percent=source.discount_percent or Decimal(0),
                amount_cents=source.discount_amount_cents or 0,
                months=getattr(source, "free_months", 0) or 0,
                tiers=tuple(source.tiers or []),
                eligible_ids=frozenset(key for key, item in keyed if _eligible(source, item)),
                stackable=source.is_stackable,
                exclusive=getattr(source, "is_exclusive", False),
                priority=getattr(source, "stacking_priority", getattr(source, "priority", 100)),
                entered=isinstance(source, Coupon),
                max_cents=source.max_discount_cents,
                budget_key=str(campaign.pk) if campaign else "",
                budget_available_cents=max(0, campaign.budget_cents - campaign.spent_cents - campaign.reserved_cents)
                if campaign and campaign.budget_cents is not None
                else None,
            )
        )
    lines = [
        PriceLine(key, item.quantity, item.unit_price_cents, item.setup_cents, item.billing_period)
        for key, item in keyed
    ]
    result = evaluate_offers(lines, offers)
    if any(str(coupon.pk) in result.unavailable for coupon in models if isinstance(coupon, Coupon)):
        raise ValidationError(_("The coupon budget has been exhausted. Review your order total."))
    rates = {Decimal(str(item.tax_rate)) for item in items}
    if result.discount_cents and len(rates) != 1:
        raise ValidationError(_("This order needs separate quotes for its tax categories."))
    tax = (
        calculate_line_totals(order.subtotal_cents - result.discount_cents, rates.pop()).tax_cents
        if result.discount_cents
        else order.tax_cents
    )
    payload = {
        "version": 2,
        "customer": str(order.customer_id),
        "currency": order.currency.code,
        "lines": [asdict(line) for line in lines],
        "codes": sorted(code.strip().upper() for code in codes),
        "subtotal_cents": order.subtotal_cents,
        "discount_cents": result.discount_cents,
        "tax_cents": tax,
        "total_cents": order.subtotal_cents - result.discount_cents + tax,
        "offers": [
            {
                **asdict(applied),
                "source": "coupon" if isinstance(sources[applied.key], Coupon) else "rule",
                "label": sources[applied.key].name
                if isinstance(sources[applied.key], Coupon)
                else getattr(sources[applied.key], "display_name", "") or _("Automatic discount"),
                "kind": sources[applied.key].discount_type,
                "campaign": str(sources[applied.key].campaign_id or ""),
            }
            for applied in result.offers
        ],
    }
    from .gift_cards import preview_value  # noqa: PLC0415

    gift = preview_value(gift_code, order.currency_id, payload["total_cents"])
    payload.update(gift=gift, cash_due_cents=payload["total_cents"] - gift["amount_cents"])
    return {**payload, "quote_token": signing.dumps(payload, salt=QUOTE_SALT, compress=True)}


def _confirm_quote(fresh: dict[str, Any], quote_token: str, *, required: bool) -> None:
    unsigned = {key: value for key, value in fresh.items() if key != "quote_token"}
    if quote_token:
        try:
            previous = signing.loads(quote_token, salt=QUOTE_SALT, max_age=QUOTE_MAX_AGE)
        except signing.BadSignature as exc:
            raise ValidationError("PROMOTION_QUOTE_CHANGED: " + _("Review the current checkout total.")) from exc
        if previous != unsigned:
            raise ValidationError("PROMOTION_QUOTE_CHANGED: " + _("Review the current checkout total."))
    elif required:
        raise ValidationError("PROMOTION_QUOTE_CHANGED: " + _("Confirm the promotion quote before placing the order."))


@transaction.atomic
def freeze_order(
    order: Any, codes: list[str], quote_token: str = "", *, require_quote: bool = True, gift_code: str = ""
) -> dict[str, Any]:
    """Reserve all limits and freeze a confirmed quote before issuing its proforma."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.orders.models import Order  # noqa: PLC0415

    order.refresh_from_db(from_queryset=Order.objects.select_for_update())
    if order.status != "draft" or order.discount_cents or order.promotion_applications.exists():
        raise ValidationError(_("This order's promotion quote is already frozen."))
    Customer.objects.select_for_update().get(pk=order.customer_id)
    items = list(order.items.select_related("product"))
    candidates = _candidate_offers(order, items, codes)
    list(
        PromotionCampaign.objects.select_for_update()
        .filter(pk__in={source.campaign_id for source in candidates if source.campaign_id})
        .order_by("pk")
    )
    list(
        Coupon.objects.select_for_update()
        .filter(pk__in=[source.pk for source in candidates if isinstance(source, Coupon)])
        .order_by("pk")
    )
    list(
        PromotionRule.objects.select_for_update()
        .filter(pk__in=[source.pk for source in candidates if isinstance(source, PromotionRule)])
        .order_by("pk")
    )
    if gift_code:
        list(GiftCard.objects.select_for_update().filter(code=gift_code.strip().upper()))
    fresh = quote_order(order, items, codes, gift_code=gift_code)
    unsigned = {key: value for key, value in fresh.items() if key != "quote_token"}
    _confirm_quote(fresh, quote_token, required=require_quote and bool(fresh["offers"] or codes or gift_code))

    keyed = dict(_keyed_items(items))
    for applied in fresh["offers"]:
        future_cents = sum(value["remaining_cents"] for value in applied["renewals"].values())
        discount = sum(applied["allocations"].values())
        application = PromotionApplication.objects.create(
            order=order,
            coupon_id=applied["key"] if applied["source"] == "coupon" else None,
            rule_id=applied["key"] if applied["source"] == "rule" else None,
            campaign_id=applied["campaign"] or None,
            discount_cents=discount,
            future_cents=future_cents,
            allocations={str(keyed[key].pk): value for key, value in applied["allocations"].items()},
            snapshot=applied,
        )
        if application.campaign_id:
            PromotionCampaign.objects.filter(pk=application.campaign_id).update(
                reserved_cents=F("reserved_cents") + discount + future_cents
            )
        if application.coupon_id:
            Coupon.objects.filter(pk=application.coupon_id).update(
                total_uses=F("total_uses") + 1, total_discount_cents=F("total_discount_cents") + discount
            )
        for key, benefit in applied["renewals"].items():
            RenewalBenefit.objects.create(
                application=application,
                order_item=keyed[key],
                remaining_cents=benefit["remaining_cents"],
                remaining_months=benefit["months"],
                monthly_cents=Decimal(benefit["monthly_cents"]),
            )
    order.discount_cents = fresh["discount_cents"]
    order.meta = {**order.meta, "promotion_version": 2, "promotion_quote": unsigned}
    order.save(update_fields=["discount_cents", "meta"])
    order.calculate_totals()
    if fresh["gift"]["amount_cents"]:
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        from .gift_cards import reserve_value  # noqa: PLC0415

        result = ProformaService.create_from_order(order)
        if result.is_err():
            raise ValidationError(result.unwrap_err())
        reserve_value(gift_code, result.unwrap(), order.customer, f"checkout:{order.pk}", fresh["gift"]["amount_cents"])
    if fresh["offers"]:
        AuditService.log_simple_event(
            "promotion_rule_applied",
            content_object=order,
            description="Reserved confirmed promotions",
            metadata={
                "version": 2,
                "offer_ids": [applied["key"] for applied in fresh["offers"]],
                "discount_cents": order.discount_cents,
            },
        )
    return fresh


@transaction.atomic
def settle_order(order: Any) -> None:
    applications = list(order.promotion_applications.filter(status="reserved").order_by("campaign_id", "pk"))
    list(
        PromotionCampaign.objects.select_for_update()
        .filter(pk__in={application.campaign_id for application in applications if application.campaign_id})
        .order_by("pk")
    )
    from .audit import audit_ledger_transition  # noqa: PLC0415

    for application in applications:
        if not PromotionApplication.objects.filter(pk=application.pk, status="reserved").update(
            status="settled"
        ):  # fsm-bypass: Locked ledger CharField; no protected FSM field
            continue
        audit_ledger_transition(application, "reserved", "settled")
        if application.campaign_id:
            PromotionCampaign.objects.filter(pk=application.campaign_id).update(
                reserved_cents=F("reserved_cents") - application.discount_cents,
                spent_cents=F("spent_cents") + application.discount_cents,
            )


@transaction.atomic
def release_order(order: Any, *, full_refund: bool = False) -> None:
    from .audit import audit_ledger_transition  # noqa: PLC0415

    applications = list(order.promotion_applications.exclude(status="released").order_by("campaign_id", "pk"))
    list(
        PromotionCampaign.objects.select_for_update()
        .filter(pk__in={application.campaign_id for application in applications if application.campaign_id})
        .order_by("pk")
    )
    list(
        Coupon.objects.select_for_update()
        .filter(pk__in={application.coupon_id for application in applications if application.coupon_id})
        .order_by("pk")
    )
    for application in applications:
        old_status = application.status
        if old_status == "settled" and not full_refund:
            continue
        if not PromotionApplication.objects.filter(pk=application.pk, status=old_status).update(
            status="released"
        ):  # fsm-bypass: Locked ledger CharField; no protected FSM field
            continue
        audit_ledger_transition(application, old_status, "released")
        benefits = list(application.benefits.select_for_update().filter(ended_at__isnull=True))
        from .renewals import end_locked_benefit  # noqa: PLC0415

        for benefit in benefits:
            end_locked_benefit(benefit)
        if application.campaign_id:
            updates = {
                "reserved_cents": F("reserved_cents") - (application.discount_cents if old_status == "reserved" else 0)
            }
            if old_status == "settled":
                updates["spent_cents"] = F("spent_cents") - application.discount_cents
            PromotionCampaign.objects.filter(pk=application.campaign_id).update(**updates)
        if application.coupon_id:
            Coupon.objects.filter(pk=application.coupon_id).update(
                total_uses=F("total_uses") - 1,
                total_discount_cents=F("total_discount_cents") - application.discount_cents,
            )
