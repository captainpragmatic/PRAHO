"""Short financial holds; expired application authority never freezes renewals forever."""

from __future__ import annotations

from datetime import datetime

from django.utils import timezone
from django.utils.translation import gettext as _

from .plan_change_payment_models import PlanChangePaymentAttempt
from .subscription_models import Subscription


def unsettled_plan_change_reason(subscription: Subscription, *, at: datetime | None = None) -> str | None:
    """Final charge callers serialize this read with first claims through Customer."""
    now = timezone.now() if at is None else at
    if PlanChangePaymentAttempt.objects.filter(
        change__subscription_id=subscription.pk,
        change__status__in=("awaiting_payment", "payment_in_flight"),
        change__authority_expires_at__gt=now,
        payment__status__in=("pending", "succeeded"),
    ).exists():
        return _("Resolve the unsettled plan-change payment before preparing or collecting this renewal")
    return None
