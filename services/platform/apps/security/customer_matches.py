"""Indexed customer-address intersections never alter independent host decisions."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.db.models import BooleanField, Case, Exists, OuterRef, QuerySet, Value, When

from .models import CustomerIPObservation, SecurityDecision


def with_customer_matches(rows: QuerySet[SecurityDecision], now: datetime) -> QuerySet[SecurityDecision]:
    from apps.users.models import CustomerMembership  # noqa: PLC0415 -- ADR-0007: runtime membership boundary

    memberships = CustomerMembership.objects.filter(
        user_id=OuterRef("user_id"), customer_id=OuterRef("customer_id"), is_active=True
    )
    recent = (
        CustomerIPObservation.objects.filter(
            user__is_active=True,
            last_seen_at__gte=now - timedelta(days=7),
            address_family=OuterRef("address_family"),
            address__gte=OuterRef("network_start"),
            address__lte=OuterRef("network_end"),
        )
        .annotate(active_membership=Exists(memberships))
        .filter(active_membership=True)
    )
    return rows.annotate(
        recent_customer_match=Case(
            When(type="ban", simulated=False, ended_at__isnull=True, expires_at__gt=now, then=Exists(recent)),
            default=Value(False),
            output_field=BooleanField(),
        )
    )
