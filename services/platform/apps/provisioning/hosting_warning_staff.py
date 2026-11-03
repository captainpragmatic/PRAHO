"""Bounded staff-only projections of canonical usage and current-owner warning history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _

from .hosting_warning_models import HostingWarningDeliveryPart, HostingWarningIntent
from .service_models import Service
from .virtualmin_usage_models import AccountUsageState
from .virtualmin_usage_service import public_usage, usage_history

MAX_WARNINGS = 50
MAX_ATTEMPTS = 200


@dataclass(frozen=True)
class StaffUsageReading:
    resource: str
    gib: Decimal | None
    observed_at: datetime | None
    age_hours: int | None
    availability: str


@dataclass(frozen=True)
class StaffUsagePoint:
    taken_at: datetime
    gib: Decimal


@dataclass(frozen=True)
class StaffWarningAttempt:
    phase: str
    refusal: str
    certainty: str
    created_at: datetime
    accepted_at: datetime | None


@dataclass(frozen=True)
class StaffWarningHistory:
    resource: str
    threshold: int
    phase: str
    refusal: str
    created_at: datetime
    observed_at: datetime | None
    attempts: tuple[StaffWarningAttempt, ...]


@dataclass(frozen=True)
class StaffHostingHistory:
    usage: tuple[StaffUsageReading, ...]
    disk_trend: tuple[StaffUsagePoint, ...]
    disk_sparkline: str
    warnings: tuple[StaffWarningHistory, ...]


def _phase(value: str) -> str:
    return {
        "pending": _("Awaiting delivery"),
        "linked": _("Queued"),
        "dispatching": _("Dispatch started; outcome unconfirmed"),
        "accepted": _("Accepted by email provider"),
        "delivered": _("Accepted by email provider"),
        "refused": _("Refused"),
        "cancelled": _("Cancelled"),
    }.get(value, _("Unknown status"))


def _refusal(value: str) -> str:
    if not value:
        return ""
    return {
        "warning_recipient_suppressed": _("Recipient suppressed"),
        "warning_optional_opt_out": _("Optional warnings disabled"),
        "warning_recipient_changed": _("Recipient changed"),
        "warning_ownership_changed": _("Ownership changed"),
        "warning_customer_unavailable": _("Customer unavailable"),
        "warning_service_inactive": _("Service inactive"),
        "warning_native_mail_not_handed_over": _("Platform notification handover pending"),
        "warning_period_changed": _("Usage month changed"),
        "warning_usage_unavailable": _("Fresh usage unavailable"),
        "warning_allowance_changed": _("Operational allowance changed"),
        "warning_raise_changed": _("Temporary relief changed"),
        "warning_condition_changed": _("Usage condition changed"),
        "warning_episode_superseded": _("Warning episode superseded"),
        "warning_pipeline_disabled": _("Warning delivery disabled"),
    }.get(value, _("Delivery refused; review notification status."))


def _decimal(value: object) -> Decimal | None:
    return Decimal(str(value)) if isinstance(value, int | float | Decimal) and not isinstance(value, bool) else None


def _instant(value: object) -> datetime | None:
    return parse_datetime(value) if isinstance(value, str) else None


def _usage_rows(service: Service) -> tuple[StaffUsageReading, ...]:
    current = public_usage(service)
    labels = {
        "fresh": _("Fresh reading"),
        "partial": _("Incomplete monthly coverage"),
        "stale": _("Stale reading"),
        "unknown": _("Usage unknown"),
    }
    rows = []
    for resource, label in (("disk", _("Disk")), ("bandwidth", _("Monthly bandwidth"))):
        disk = resource == "disk"
        age = current.get("usage_age_hours" if disk else "bandwidth_age_hours")
        rows.append(
            StaffUsageReading(
                resource=label,
                gib=_decimal(current.get(f"{resource}_usage_gb")),
                observed_at=_instant(current.get("usage_as_of" if disk else "bandwidth_as_of")),
                age_hours=age if isinstance(age, int) else None,
                availability=labels.get(
                    str(current.get("usage_state" if disk else "bandwidth_state")), labels["unknown"]
                ),
            )
        )
    return tuple(rows)


def staff_hosting_history(service: Service) -> StaffHostingHistory:
    """Call after prime_service_usage; never load EmailLog bodies, recipient hashes or native payloads."""
    canonical = usage_history(service)
    points = []
    raw_points = canonical.get("disk_usage_trend")
    if isinstance(raw_points, list):
        for item in raw_points:
            if isinstance(item, dict):
                taken_at, gib = _instant(item.get("taken_at")), _decimal(item.get("value"))
                if taken_at is not None and gib is not None:
                    points.append(StaffUsagePoint(taken_at, gib))
    current_scope = (
        AccountUsageState.objects.filter(
            account__service_id=service.pk,
            account__service__customer_id=service.customer_id,
            service_id_snapshot=service.pk,
            customer_id_snapshot=service.customer_id,
        )
        .values_list("owner_scope", flat=True)
        .first()
    )
    sparkline = canonical.get("disk_sparkline")
    usage = _usage_rows(service)
    if current_scope is None:
        return StaffHostingHistory(usage, tuple(points), "", ())
    intents = list(
        HostingWarningIntent.objects.filter(
            service_id_snapshot=service.pk,
            customer_id_snapshot=service.customer_id,
            owner_scope=current_scope,
        )
        .select_related("reading")
        .only("resource", "threshold", "phase", "refusal_reason", "created_at", "reading__taken_at")
        .order_by("-created_at", "-pk")[:MAX_WARNINGS]
    )
    attempts: dict[UUID, list[StaffWarningAttempt]] = {intent.pk: [] for intent in intents}
    parts = (
        HostingWarningDeliveryPart.objects.filter(
            intent_id__in=attempts,
            intent__service_id_snapshot=service.pk,
            intent__customer_id_snapshot=service.customer_id,
            intent__owner_scope=current_scope,
            delivery__customer_id_snapshot=service.customer_id,
        )
        .select_related("delivery")
        .only(
            "intent_id",
            "delivery__phase",
            "delivery__refusal_reason",
            "delivery__certainty",
            "delivery__created_at",
            "delivery__accepted_at",
        )
        .order_by("-delivery__created_at", "-pk")[:MAX_ATTEMPTS]
    )
    for part in parts:
        delivery = part.delivery
        attempts[part.intent_id].append(
            StaffWarningAttempt(
                _phase(delivery.phase),
                _refusal(delivery.refusal_reason),
                {
                    "never_dispatched": _("Not dispatched"),
                    "uncertain": _("Delivery outcome uncertain"),
                    "accepted": _("Provider acceptance recorded"),
                }.get(delivery.certainty, _("Unknown status")),
                delivery.created_at,
                delivery.accepted_at,
            )
        )
    warnings = tuple(
        StaffWarningHistory(
            _("Disk") if intent.resource == "disk" else _("Monthly bandwidth"),
            intent.threshold,
            _phase(intent.phase),
            _refusal(intent.refusal_reason),
            intent.created_at,
            intent.reading.taken_at if intent.reading else None,
            tuple(attempts[intent.pk]),
        )
        for intent in intents
    )
    return StaffHostingHistory(usage, tuple(points), sparkline if isinstance(sparkline, str) else "", warnings)
