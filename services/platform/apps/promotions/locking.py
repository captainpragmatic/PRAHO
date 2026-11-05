"""Shared document-before-benefit-before-tender lock ordering for settlement."""

from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils.translation import gettext as _

from .models import (
    Coupon,
    GiftCard,
    GiftCardReservation,
    PromotionApplication,
    PromotionCampaign,
    RenewalBenefit,
    RenewalBenefitUse,
)


def lock_document_context(document: Any, *, gift_code: str = "") -> None:
    """Caller holds the document; acquire business locks before any payment row."""
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.metering_models import BillingCycle  # noqa: PLC0415
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.orders.models import Order  # noqa: PLC0415
    from apps.provisioning.models import Service  # noqa: PLC0415

    relation = {"invoice_id" if isinstance(document, Invoice) else "proforma_id": document.pk}
    orders = list(Order.objects.select_for_update().filter(**relation).order_by("pk"))
    # Payment signals also lock Customer before changing recurring failure state.
    # Acquire it before Subscription so a refund and a later decline cannot invert them.
    Customer.objects.select_for_update(of=("self",), no_key=True).get(pk=document.customer_id)
    cycles = BillingCycle.objects.filter(**relation)
    scope = Q(proforma_id=document.pk)
    if isinstance(document, Invoice):
        scope = Q(invoice_id=document.pk)
        if document.converted_from_proforma_id:
            scope |= Q(proforma_id=document.converted_from_proforma_id)
    changes = list(PlanChange.objects.filter(scope).values("pk", "subscription_id", "service_id", "customer_id"))
    if any(change["customer_id"] != document.customer_id for change in changes):
        raise ValidationError(_("The plan-change document belongs to another customer."))
    subscriptions = list(
        Subscription.objects.select_for_update(of=("self",), no_key=True)
        .filter(
            Q(pk__in=cycles.values("subscription_id")) | Q(pk__in=[change["subscription_id"] for change in changes])
        )
        .order_by("pk")
    )
    service_ids = {row.service_id for row in subscriptions if row.service_id is not None}
    service_ids.update(change["service_id"] for change in changes)
    list(Service.objects.select_for_update(of=("self",), no_key=True).filter(pk__in=service_ids).order_by("pk"))
    list(PlanChange.objects.select_for_update(of=("self",), no_key=True).filter(scope).order_by("pk"))
    applications = PromotionApplication.objects.filter(
        Q(order__in=orders)
        | Q(benefits__uses__in=RenewalBenefitUse.objects.filter(cycle__in=cycles))
        | Q(benefits__subscription_id__in=[change["subscription_id"] for change in changes])
    )
    list(PromotionCampaign.objects.select_for_update().filter(pk__in=applications.values("campaign_id")).order_by("pk"))
    list(Coupon.objects.select_for_update().filter(pk__in=applications.values("coupon_id")).order_by("pk"))
    list(
        RenewalBenefit.objects.select_for_update(of=("self",))
        .filter(subscription_id__in=[change["subscription_id"] for change in changes])
        .order_by("pk")
    )
    list(
        GiftCard.objects.select_for_update()
        .filter(
            Q(pk__in=GiftCardReservation.objects.filter(**relation).values("gift_card_id"))
            | Q(code=gift_code.strip().upper())
        )
        .order_by("pk")
    )
