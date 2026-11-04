"""Curated standard-price targets compared with the service's assigned allowances."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from django.db.models import Q

from apps.provisioning.hosting_limit_assignments import assignment_terms_for_plans
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms

from .subscription_models import Subscription


@dataclass(frozen=True)
class PlanTarget:
    product_id: UUID
    name: str
    direction: str
    period_price_cents: int
    limits: HostingAssignmentTerms


def eligible_plan_targets(subscription: Subscription) -> list[PlanTarget]:
    """Database-only catalog selection; charge admission separately requires native proof."""

    from apps.products.models import (  # noqa: PLC0415  # ADR-0007: runtime model.
        Product,
        ProductPrice,
        ProductRelationship,
    )

    current = Subscription.objects.select_related("product", "service__service_plan", "service__hosting_limits").get(
        pk=subscription.pk
    )
    if current.service_id is None or current.quantity != 1 or current.status != "active":
        return []
    service = current.service
    if service is None or service.status != "active" or service.customer_id != current.customer_id:
        return []
    assigned = getattr(service, "hosting_limits", None)
    if assigned is None or assigned.disk_allowance_mib is None or assigned.bandwidth_allowance_mib is None:
        return []
    directions: dict[UUID, set[str]] = {}
    for source, target in ProductRelationship.objects.filter(
        Q(source_product_id=current.product_id) | Q(target_product_id=current.product_id),
        relationship_type="upgrades_to",
        is_active=True,
    ).values_list("source_product_id", "target_product_id"):
        direction = "upgrade" if source == current.product_id else "downgrade"
        identifier = target if direction == "upgrade" else source
        directions.setdefault(identifier, set()).add(direction)
    products = list(
        Product.objects.filter(
            pk__in=directions,
            is_active=True,
            is_public=True,
            default_service_plan__isnull=False,
        )
        .select_related("default_service_plan")
        .order_by("sort_order", "pk")
    )
    prices = {
        price.product_id: price
        for price in ProductPrice.objects.filter(
            product_id__in=directions,
            currency_id=current.currency_id,
            is_active=True,
        )
    }
    plans = [product.default_service_plan for product in products if product.default_service_plan is not None]
    terms = assignment_terms_for_plans(plans)
    profile = ("plan_type", "features", "email_accounts", "databases", "domains", "cpu_cores", "ram_gb")
    result = []
    for product in products:
        plan, tariff = product.default_service_plan, prices.get(product.pk)
        if (
            len(directions[product.pk]) != 1
            or plan is None
            or not plan.is_active
            or tariff is None
            or tariff.setup_cents != 0
            or tariff.minimum_quantity > 1
            or product.module != current.product.module
            or product.module_config != current.product.module_config
            or plan.plan_type not in service.VIRTUALMIN_HOSTING_PLAN_TYPES
            or any(getattr(plan, field) != getattr(service.service_plan, field) for field in profile)
        ):
            continue
        try:
            price = tariff.get_price_cents_for_period(
                current.billing_cycle,
                custom_cycle_days=current.custom_cycle_days,
                include_promotions=False,
            )
        except ValueError:
            continue
        accepted = terms[plan.pk]
        # An unbounded disk target cannot reserve a finite shared-node delta.
        if price <= 0 or (assigned.disk_allowance_mib and accepted.disk_allowance_mib == 0):
            continue
        direction = next(iter(directions[product.pk]))
        old = (assigned.disk_allowance_mib, assigned.bandwidth_allowance_mib)
        new = (accepted.disk_allowance_mib, accepted.bandwidth_allowance_mib)
        at_least = all(a == 0 or (b != 0 and a >= b) for a, b in zip(new, old, strict=True))
        at_most = all(b == 0 or (a != 0 and a <= b) for a, b in zip(new, old, strict=True))
        if (direction == "upgrade" and price > current.effective_price_cents and at_least) or (
            direction == "downgrade" and price < current.effective_price_cents and at_most
        ):
            result.append(PlanTarget(product.pk, product.name, direction, price, accepted))
    return result
