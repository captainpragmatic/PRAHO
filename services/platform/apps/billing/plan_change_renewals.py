"""Accepted per-service terms precede historical prepared-period fallback."""

from __future__ import annotations

from copy import copy
from datetime import datetime
from decimal import Decimal
from typing import Any, cast

from django.core.exceptions import ValidationError
from django.db.models import Prefetch, Q, QuerySet
from django.utils.translation import gettext as _

from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms

from .cycle_terms import CycleTerms, build_terms_snapshot
from .plan_change_models import PlanChange
from .subscription_currency_models import SubscriptionCurrencyTransition
from .subscription_models import Subscription


def with_plan_change_renewal_data(queryset: QuerySet[Subscription]) -> QuerySet[Subscription]:
    """Batch commercial facts for one locked preparation operation.

    The caller holds Customer and Subscription through preparation. These
    per-instance prefetches never outlive or replace a new locked queryset;
    standalone selectors continue to read current committed data normally.
    """
    changes = (
        PlanChange.objects.filter(
            Q(committed_at__isnull=False) | Q(status__in=("scheduled", "awaiting_payment", "payment_in_flight"))
        )
        .select_related("to_product__default_service_plan", "service", "currency", "payment_attempt__payment")
        .order_by("-effective_at", "-committed_at", "-created_at", "-pk")
    )
    return queryset.prefetch_related(
        Prefetch("plan_changes", queryset=changes, to_attr="_renewal_plan_changes"),
        Prefetch(
            "currency_transitions",
            queryset=SubscriptionCurrencyTransition.objects.filter(status="committed", committed_cycle__isnull=False),
            to_attr="_renewal_committed_currency_changes",
        ),
    )


def primed_plan_changes(subscription: Subscription) -> list[PlanChange] | None:
    return cast("list[PlanChange] | None", getattr(subscription, "_renewal_plan_changes", None))


def accepted_plan_change(subscription: Subscription, period_start: datetime) -> PlanChange | None:
    if (changes := primed_plan_changes(subscription)) is not None:
        return next(
            (
                change
                for change in changes
                if change.confirmed_at is not None
                and (change.committed_at is not None or change.status == "scheduled")
                and change.effective_at <= period_start
            ),
            None,
        )
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
    transitions = cast(
        "list[SubscriptionCurrencyTransition] | None",
        getattr(subscription, "_renewal_committed_currency_changes", None),
    )
    newer_currency_terms = (
        any(
            transition.effective_period_start is not None
            and change.effective_at < transition.effective_period_start <= period_start
            for transition in transitions
        )
        if transitions is not None
        else subscription.currency_transitions.filter(
            status="committed",
            effective_period_start__gt=change.effective_at,
            effective_period_start__lte=period_start,
            committed_cycle__isnull=False,
        ).exists()
    )
    if newer_currency_terms:
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
    labels = change.quote_snapshot.get("labels")
    if not isinstance(labels, dict) or any(
        not isinstance(labels.get(field), str) or not labels[field] for field in ("to", "to_sku")
    ):
        raise ValidationError(_("The accepted plan's document identity requires review."))
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
        "product_name": labels["to"],
        "seller_item_id": labels["to_sku"],
    }
    return snapshot


def renewal_product_identity(terms: CycleTerms, subscription: Subscription) -> tuple[str, str]:
    """A scheduled plan is the future document's identity before live activation."""
    accepted = terms.snapshot.get("plan_change")
    if accepted is None:
        return subscription.product.name, subscription.product.slug
    if not isinstance(accepted, dict) or any(
        not isinstance(accepted.get(field), str) or not accepted[field] for field in ("product_name", "seller_item_id")
    ):
        raise ValidationError(_("The frozen renewal's accepted document identity requires review."))
    return accepted["product_name"], accepted["seller_item_id"]
