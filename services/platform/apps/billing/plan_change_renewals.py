"""Accepted per-service terms precede historical prepared-period fallback."""

from __future__ import annotations

from copy import copy
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils.translation import gettext as _

from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms

from .cycle_terms import build_terms_snapshot
from .plan_change_models import PlanChange
from .subscription_models import Subscription


def accepted_plan_change(subscription: Subscription, period_start: datetime) -> PlanChange | None:
    return (
        PlanChange.objects.filter(
            Q(committed_at__isnull=False) | Q(status="scheduled"),
            subscription_id=subscription.pk,
            confirmed_at__isnull=False,
            effective_at__lte=period_start,
        )
        .select_related("to_product__default_service_plan", "service", "currency")
        .order_by("-effective_at", "-committed_at", "-created_at", "-pk")
        .first()
    )


def accepted_plan_terms(subscription: Subscription, period_start: datetime) -> dict[str, Any] | None:
    """Only new periods use this selector; already-frozen periods retain their evidence."""
    change = accepted_plan_change(subscription, period_start)
    if change is None:
        return None
    # A later independently accepted currency transition retains its existing
    # immutable preparation and activation protocol. An old plan quote must not
    # force that service back into its earlier currency.
    if subscription.currency_transitions.filter(
        status="committed",
        effective_period_start__gt=change.effective_at,
        effective_period_start__lte=period_start,
        committed_cycle__isnull=False,
    ).exists():
        return None
    expected_product = change.from_product_id if change.status == "scheduled" else change.to_product_id
    if (
        change.customer_id != subscription.customer_id
        or change.service_id != subscription.service_id
        or change.service.customer_id != subscription.customer_id
        or subscription.product_id != expected_product
        or subscription.currency_id != change.currency_id
        or subscription.quantity != 1
        or subscription.billing_cycle != change.quote_snapshot.get("billing_cycle")
    ):
        raise ValidationError(
            _("The accepted plan's renewal terms require review before another document is prepared.")
        )
    staged = copy(subscription)
    staged.product = change.to_product
    accepted = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    snapshot = build_terms_snapshot(
        staged,
        effective_at=period_start,
        currency_code=change.currency_id,
        unit_price_cents=change.target_period_price_cents,
        # Preserve the existing ServicePlan fallback's GB tariff units, using
        # the accepted allowance. Explicit subscription-item terms still win.
        resource_allowances={
            "storage": Decimal(accepted.disk_allowance_mib) / 1024,
            "bandwidth": Decimal(accepted.bandwidth_allowance_mib) / 1024,
        },
    )
    snapshot["plan_change"] = {
        "version": 1,
        "id": str(change.pk),
        "product_id": str(change.to_product_id),
        "plan_id": change.to_plan_id,
        "accepted_limits": change.quote_snapshot["accepted_limits"],
    }
    return snapshot
