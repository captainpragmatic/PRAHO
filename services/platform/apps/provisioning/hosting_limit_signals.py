"""Audit accepted allowances and verified transitions, never periodic usage polls."""

from __future__ import annotations

from typing import Any

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits


def _limits_state(instance: ServiceHostingLimits) -> dict[str, object]:
    return {
        "service_id": instance.service_id,
        "revision": instance.revision,
        "policy_version": instance.policy_version,
        "assigned_plan_id": instance.assigned_plan_id,
        "disk_allowance_mib": instance.disk_allowance_mib,
        "bandwidth_allowance_mib": instance.bandwidth_allowance_mib,
        "disk_source": instance.disk_source,
        "bandwidth_source": instance.bandwidth_source,
        "applied_revision": instance.applied_revision,
        "operational_revision": instance.operational_revision,
        "operational_disk_allowance_mib": instance.operational_disk_allowance_mib,
        "operational_bandwidth_allowance_mib": instance.operational_bandwidth_allowance_mib,
    }


def audit_initial_limits(records: list[ServiceHostingLimits]) -> None:
    """One bounded batch event preserves the INSERT path without per-row reads or writes."""
    if records and not audit_signals_disabled():
        AuditService.log_simple_event(
            "create",
            content_object=records[0],
            description="Initial hosting allowance assignments",
            new_values={"assignments": [_limits_state(record) for record in records]},
        )


@receiver(post_save, sender=ServiceHostingLimits)
def audit_hosting_limits(
    sender: type[ServiceHostingLimits],
    instance: ServiceHostingLimits,
    created: bool,
    **kwargs: Any,
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Hosting allowance or verified application changed",
            new_values=_limits_state(instance),
        )


@receiver(post_save, sender=HostingLimitApplication)
def audit_hosting_assignment(
    sender: type[HostingLimitApplication],
    instance: HostingLimitApplication,
    created: bool,
    **kwargs: Any,
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Hosting resource assignment accepted",
            old_values={"revision": instance.revision - 1, "service_plan_id": instance.expected_plan_id},
            new_values={
                "service_id": instance.service_id,
                "revision": instance.revision,
                "policy_version": instance.policy_version,
                "service_plan_id": instance.target_plan_id,
                "disk_allowance_mib": instance.disk_allowance_mib,
                "bandwidth_allowance_mib": instance.bandwidth_allowance_mib,
                "submission_id": str(instance.submission_id),
                "reason": instance.reason,
                "authority": instance.authority,
            },
        )


@receiver(post_save, sender=HostingLimitApplication)
def queue_hosting_assignment(
    sender: type[HostingLimitApplication], instance: HostingLimitApplication, created: bool, **kwargs: Any
) -> None:
    if created:
        from .hosting_limit_tasks import enqueue_application  # noqa: PLC0415 -- Enqueue only after commit.

        transaction.on_commit(lambda: enqueue_application(instance.pk), using=kwargs.get("using"), robust=True)
