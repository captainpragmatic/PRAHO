"""Reserve original-value credits at invoicing and consume only on settlement."""

from __future__ import annotations

from decimal import ROUND_CEILING, Decimal
from typing import Any

from django.db import transaction
from django.db.models import F, Sum
from django.utils import timezone

from .audit import audit_ledger_transition
from .models import PromotionCampaign, RenewalBenefit, RenewalBenefitUse
from .pricing import cents

CYCLE_MONTHS = {"monthly": 1, "quarterly": 3, "semi_annual": 6, "yearly": 12}


def _lock_campaigns(benefits: list[RenewalBenefit]) -> None:
    list(
        PromotionCampaign.objects.select_for_update()
        .filter(pk__in={benefit.application.campaign_id for benefit in benefits if benefit.application.campaign_id})
        .order_by("pk")
    )


@transaction.atomic
def reserve_cycle(subscription: Any, cycle: Any, charge_cents: int) -> int:
    if subscription.status not in {"active", "trialing", "past_due"} or subscription.cancel_at_period_end:
        return 0
    existing = list(RenewalBenefitUse.objects.filter(cycle=cycle, status__in=["reserved", "settled"]))
    if existing:
        return sum(use.amount_cents for use in existing)
    benefits = list(
        subscription.promotion_benefits.filter(ended_at__isnull=True, remaining_cents__gt=0)
        .select_related("application")
        .order_by("application__campaign_id", "pk")
    )
    _lock_campaigns(benefits)
    locked = list(
        RenewalBenefit.objects.select_for_update().filter(pk__in=[benefit.pk for benefit in benefits]).order_by("pk")
    )
    applied = 0
    for benefit in locked:
        held = benefit.uses.filter(status="reserved").aggregate(total=Sum("amount_cents"))["total"] or 0
        months = CYCLE_MONTHS.get(subscription.billing_cycle)
        if months is None:
            # A custom term keeps the monthly value, prorated over actual calendar days.
            days = Decimal(str((cycle.period_end - cycle.period_start).total_seconds())) / 86400
            period_value = cents(benefit.monthly_cents * days / Decimal("30.4375"))
            months = max(1, int((days / Decimal("30.4375")).to_integral_value(rounding=ROUND_CEILING)))
        else:
            period_value = cents(benefit.monthly_cents * months)
        amount = max(0, min(benefit.remaining_cents - held, period_value, charge_cents - applied))
        if amount:
            RenewalBenefitUse.objects.create(benefit=benefit, cycle=cycle, amount_cents=amount, months=months)
            applied += amount
    return applied


@transaction.atomic
def settle_cycle(cycle: Any) -> None:
    uses = list(
        cycle.promotion_uses.filter(status="reserved")
        .select_related("benefit__application")
        .order_by("benefit__application__campaign_id", "benefit_id")
    )
    _lock_campaigns([use.benefit for use in uses])
    for use in uses:
        benefit = RenewalBenefit.objects.select_for_update().get(pk=use.benefit_id)
        if not RenewalBenefitUse.objects.filter(pk=use.pk, status="reserved").update(
            status="settled"
        ):  # fsm-bypass: Locked ledger CharField; no protected FSM field
            continue
        audit_ledger_transition(use, "reserved", "settled")
        if use.amount_cents > benefit.remaining_cents:
            raise ValueError("Renewal promotion changed before settlement; review the billing document")
        benefit.remaining_cents -= use.amount_cents
        benefit.remaining_months = (
            int((Decimal(benefit.remaining_cents) / benefit.monthly_cents).to_integral_value(rounding=ROUND_CEILING))
            if benefit.monthly_cents
            else 0
        )
        if not benefit.remaining_cents:
            benefit.ended_at = timezone.now()
        benefit.save(update_fields=["remaining_cents", "remaining_months", "ended_at"])
        campaign_id = use.benefit.application.campaign_id
        if campaign_id:
            PromotionCampaign.objects.filter(pk=campaign_id).update(
                reserved_cents=F("reserved_cents") - use.amount_cents, spent_cents=F("spent_cents") + use.amount_cents
            )


@transaction.atomic
def end_benefits(subscription: Any) -> None:
    benefits = list(
        subscription.promotion_benefits.filter(ended_at__isnull=True)
        .select_related("application")
        .order_by("application__campaign_id", "pk")
    )
    _lock_campaigns(benefits)
    for original in benefits:
        benefit = RenewalBenefit.objects.select_for_update().get(pk=original.pk)
        if benefit.ended_at:
            continue
        end_locked_benefit(benefit)


def end_locked_benefit(benefit: RenewalBenefit) -> int:
    """End future value while retaining the credit backing an existing document."""
    held = benefit.uses.filter(status="reserved").aggregate(total=Sum("amount_cents"))["total"] or 0
    released = benefit.remaining_cents - held
    if benefit.application.campaign_id and released:
        PromotionCampaign.objects.filter(pk=benefit.application.campaign_id).update(
            reserved_cents=F("reserved_cents") - released
        )
    benefit.remaining_cents = held
    benefit.remaining_months = 0
    benefit.ended_at = benefit.ended_at or timezone.now()
    benefit.save(update_fields=["remaining_cents", "remaining_months", "ended_at"])
    return released


def reconcile_expired_credits() -> int:
    """Release unpaid expired-document holds under document-before-subscription locks."""
    from django.db.models import Q  # noqa: PLC0415

    from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415

    document_ids = (
        ProformaInvoice.objects.filter(Q(valid_until__lt=timezone.now()) | Q(status="expired"))
        .exclude(status="converted")
        .filter(billing_cycles__promotion_uses__status="reserved")
        .values_list("pk", flat=True)
        .distinct()
    )
    released = 0
    for document_id in document_ids:
        with transaction.atomic():
            document = ProformaInvoice.objects.select_for_update().get(pk=document_id)
            if document.status == "converted" or not document.is_expired:
                continue
            # An unresolved gateway attempt may already have moved money.
            if document.payments.filter(payment_method="stripe", status__in=["pending", "succeeded"]).exists():
                continue
            uses = list(
                RenewalBenefitUse.objects.filter(cycle__proforma=document, status="reserved").select_related(
                    "benefit__application"
                )
            )
            list(
                Subscription.objects.select_for_update()
                .filter(pk__in={use.benefit.subscription_id for use in uses})
                .order_by("pk")
            )
            _lock_campaigns([use.benefit for use in uses])
            for use in sorted(uses, key=lambda use: str(use.benefit_id)):
                benefit = RenewalBenefit.objects.select_for_update().get(pk=use.benefit_id)
                if not RenewalBenefitUse.objects.filter(pk=use.pk, status="reserved").update(
                    status="released"
                ):  # fsm-bypass: Locked ledger CharField; no protected FSM field
                    continue
                audit_ledger_transition(use, "reserved", "released")
                if benefit.ended_at:
                    benefit.remaining_cents -= use.amount_cents
                    benefit.save(update_fields=["remaining_cents"])
                    if benefit.application.campaign_id:
                        PromotionCampaign.objects.filter(pk=benefit.application.campaign_id).update(
                            reserved_cents=F("reserved_cents") - use.amount_cents
                        )
                released += 1
    return released
