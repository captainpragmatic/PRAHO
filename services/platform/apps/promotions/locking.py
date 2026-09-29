"""Shared document-before-benefit-before-tender lock ordering for settlement."""

from typing import Any

from django.db.models import Q

from .models import Coupon, GiftCard, GiftCardReservation, PromotionApplication, PromotionCampaign, RenewalBenefitUse


def lock_document_context(document: Any, *, gift_code: str = "") -> None:
    """Caller holds the document; acquire business locks before any payment row."""
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.metering_models import BillingCycle  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.orders.models import Order  # noqa: PLC0415

    relation = {"invoice_id" if isinstance(document, Invoice) else "proforma_id": document.pk}
    orders = list(Order.objects.select_for_update().filter(**relation).order_by("pk"))
    # Payment signals also lock Customer before changing recurring failure state.
    # Acquire it before Subscription so a refund and a later decline cannot invert them.
    Customer.objects.select_for_update().get(pk=document.customer_id)
    cycles = BillingCycle.objects.filter(**relation)
    list(Subscription.objects.select_for_update().filter(pk__in=cycles.values("subscription_id")).order_by("pk"))
    applications = PromotionApplication.objects.filter(
        Q(order__in=orders) | Q(benefits__uses__in=RenewalBenefitUse.objects.filter(cycle__in=cycles))
    )
    list(PromotionCampaign.objects.select_for_update().filter(pk__in=applications.values("campaign_id")).order_by("pk"))
    list(Coupon.objects.select_for_update().filter(pk__in=applications.values("coupon_id")).order_by("pk"))
    list(
        GiftCard.objects.select_for_update()
        .filter(
            Q(pk__in=GiftCardReservation.objects.filter(**relation).values("gift_card_id"))
            | Q(code=gift_code.strip().upper())
        )
        .order_by("pk")
    )
