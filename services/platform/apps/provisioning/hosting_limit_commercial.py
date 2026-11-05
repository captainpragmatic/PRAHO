"""Resolve purchased base authority before granting composed native permissions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.utils.translation import gettext as _

from .hosting_limit_models import HostingLimitApplication


@dataclass(frozen=True)
class CommercialOrigin:
    application: HostingLimitApplication | None = None
    refusal: str | None = None


def commercial_origin(application: HostingLimitApplication) -> CommercialOrigin:
    """The actual PlanChange FK owns the base; overlay labels confer no exemption.

    Historical parents select their own base revision. Current catalog, desired
    revision and billing currency cannot substitute for that accepted source.
    """
    from apps.billing.plan_change_financial import COMMERCIAL_LIMIT_AUTHORITIES  # noqa: PLC0415
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415

    reason = _("The composed hosting allowance has no matching original financial authority.")
    changes = list(
        PlanChange.objects.select_related("limit_application")
        .filter(service_id=application.service_id, limit_application__revision=application.revision)
        .order_by("pk")[:2]
    )
    if not changes:
        claimed = HostingLimitApplication.objects.filter(
            service_id=application.service_id,
            revision=application.revision,
            authority__kind__in=COMMERCIAL_LIMIT_AUTHORITIES,
        ).exists()
        return CommercialOrigin(refusal=reason if claimed else None)
    if len(changes) != 1:
        return CommercialOrigin(refusal=reason)
    source = changes[0].limit_application
    if source is None or any(
        getattr(source, field) != getattr(application, field)
        for field in (
            "service_id",
            "revision",
            "target_plan_id",
            "disk_allowance_mib",
            "bandwidth_allowance_mib",
            "policy_version",
        )
    ):
        return CommercialOrigin(refusal=reason)
    if str(source.authority.get("customer_id")) != str(
        application.authority.get("customer_id")
    ) or application.expected_plan_id not in {source.expected_plan_id, source.target_plan_id}:
        return CommercialOrigin(refusal=reason)
    return CommercialOrigin(application=source)


def _source_refusal(application: HostingLimitApplication) -> str | None:
    from apps.billing.plan_change_financial import commercial_source_refusal  # noqa: PLC0415

    origin = commercial_origin(application)
    if origin.refusal:
        return origin.refusal
    return commercial_source_refusal(origin.application) if origin.application is not None else None


def parent_dispatch_refusal(application: HostingLimitApplication, parent: dict[str, Any]) -> str | None:
    """Starting an archive/create requires coverage or this exact issued claim."""
    from .hosting_limit_review import issued_reviewed_parent  # noqa: PLC0415

    refusal = _source_refusal(application)
    return None if refusal and issued_reviewed_parent(application, parent) else refusal


def quota_dispatch_refusal(application: HostingLimitApplication, parent: dict[str, Any]) -> str | None:
    """Expiry may remove only an operational R, without authorizing parent I/O.

    The quota worker additionally proves both hard caps decrease from a fresh
    native observation, and sends the private monotonic-reduction protocol flag.
    """
    from .hosting_raise_expiry import operational_expiry_authorized  # noqa: PLC0415
    from .service_models import Service  # noqa: PLC0415

    refusal = parent_dispatch_refusal(application, parent)
    if refusal and operational_expiry_authorized(application, Service.objects.get(pk=application.service_id)):
        return None
    return refusal
