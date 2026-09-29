"""Read promotion history in its recorded currencies without changing ledgers."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal, TypedDict

from django.core.exceptions import ValidationError
from django.db.models import Q, QuerySet, Sum
from django.utils.translation import gettext as _

from .models import Coupon, CouponRedemption, PromotionApplication, PromotionCampaign, RenewalBenefit, RenewalBenefitUse


class CurrencyTotals(TypedDict):
    currency_code: str | None
    spent_cents: int
    reserved_cents: int


def history_sources(
    subject: Coupon | PromotionCampaign,
) -> tuple[QuerySet[CouponRedemption], QuerySet[PromotionApplication]]:
    if isinstance(subject, PromotionCampaign):
        return (
            CouponRedemption.objects.filter(charged_campaign_id=subject.pk),
            PromotionApplication.objects.filter(campaign=subject),
        )
    return CouponRedemption.objects.filter(coupon=subject), PromotionApplication.objects.filter(coupon=subject)


def money_totals(subject: Coupon | PromotionCampaign) -> list[CurrencyTotals]:
    legacy, applications = history_sources(subject)
    totals: dict[str | None, CurrencyTotals] = {}

    def add(code: str | None, field: Literal["spent_cents", "reserved_cents"], amount: int) -> None:
        if amount:
            row = totals.setdefault(code, {"currency_code": code, "spent_cents": 0, "reserved_cents": 0})
            row[field] += amount

    for row in legacy.filter(status="applied").values("currency_code").annotate(total=Sum("discount_cents")):
        add(row["currency_code"] or None, "spent_cents", row["total"])
    for row in (
        applications.filter(status__in=["reserved", "settled"])
        .values("order__currency_id", "status")
        .annotate(total=Sum("discount_cents"))
    ):
        add(row["order__currency_id"], "spent_cents" if row["status"] == "settled" else "reserved_cents", row["total"])

    # A benefit's remaining value already includes any prepared renewal reservation.
    # Adding reserved RenewalBenefitUse rows too would count those promises twice.
    benefits = RenewalBenefit.objects.filter(application__in=applications)
    for row in benefits.values("currency_id").annotate(total=Sum("remaining_cents")):
        add(row["currency_id"], "reserved_cents", row["total"])
    for row in (
        RenewalBenefitUse.objects.filter(benefit__in=benefits, status="settled")
        .values("benefit__currency_id")
        .annotate(total=Sum("amount_cents"))
    ):
        add(row["benefit__currency_id"], "spent_cents", row["total"])
    return sorted(totals.values(), key=lambda row: row["currency_code"] or "")


def campaign_history_is_complete(campaign: PromotionCampaign, totals: list[CurrencyTotals]) -> bool:
    return (
        all(row["currency_code"] for row in totals)
        and sum(row["spent_cents"] for row in totals) == campaign.spent_cents
        and sum(row["reserved_cents"] for row in totals) == campaign.reserved_cents
    )


def format_money_totals(subject: Coupon | PromotionCampaign, field: Literal["spent_cents", "reserved_cents"]) -> str:
    return (
        "; ".join(
            f"{Decimal(row[field]) / 100:.2f} {row['currency_code'] or _('Unresolved currency')}"
            for row in money_totals(subject)
            if row[field]
        )
        or "—"
    )


def validate_campaign_currency_change(campaign: PromotionCampaign, original: PromotionCampaign | None = None) -> None:
    if campaign._state.adding:
        return
    original = original or PromotionCampaign.objects.filter(pk=campaign.pk).first()
    if original is None:
        return
    if original.budget_currency_id != campaign.budget_currency_id:
        legacy, applications = history_sources(original)
        used = (
            original.spent_cents
            or original.reserved_cents
            or legacy.filter(applied_at__isnull=False, discount_cents__gt=0).exists()
            or applications.filter(Q(discount_cents__gt=0) | Q(future_cents__gt=0)).exists()
        )
        if used:
            raise ValidationError(
                {
                    "budget_currency": _(
                        "A campaign with monetary history cannot change or acquire a currency. "
                        "Review its original currency and use a separate campaign for a new budget currency."
                    )
                }
            )
    if original.budget_cents is None and campaign.budget_cents is not None:
        totals = money_totals(original)
        if not campaign_history_is_complete(original, totals) or any(
            row["currency_code"] != campaign.budget_currency_id for row in totals
        ):
            raise ValidationError(
                {
                    "budget_currency": _(
                        "Review the original currency of this campaign's history before adding a budget."
                    )
                }
            )
