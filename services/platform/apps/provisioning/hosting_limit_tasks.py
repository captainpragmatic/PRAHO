"""Best-effort enqueue backed by immutable applications and a periodic DB sweep."""

from __future__ import annotations

import logging
from uuid import NAMESPACE_URL, UUID, uuid5

from django.db import transaction
from django.db.models import F, Q
from django_q.tasks import async_task

from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .service_models import Service

logger = logging.getLogger(__name__)


def enqueue_application(application_id: UUID | str) -> None:
    try:
        async_task(
            "apps.provisioning.hosting_limit_execution.apply_hosting_limits",
            str(application_id),
            q_options={"cluster": "praho-cluster", "timeout": 960, "ack_failure": True},
        )
    except (OSError, RuntimeError, ConnectionError):
        # The immutable application is the queue; a broker outage loses no authority.
        logger.exception("Quota application enqueue deferred to durable sweep: %s", application_id)


def current_application(service_id: int) -> HostingLimitApplication:
    """Materialize initial/import-adopted policy without rereading mutable catalog defaults."""
    with transaction.atomic():
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service_id)
        limits = ServiceHostingLimits.objects.get(service_id=service_id)
        existing = HostingLimitApplication.objects.filter(service_id=service_id, revision=limits.revision).first()
        if existing is not None:
            return existing
        return HostingLimitApplication.objects.create(
            service_id=service_id,
            revision=limits.revision,
            submission_id=uuid5(NAMESPACE_URL, f"praho:initial-quota:{service_id}:{limits.revision}"),
            expected_plan_id=limits.assigned_plan_id,
            target_plan_id=limits.assigned_plan_id,
            disk_allowance_mib=limits.disk_allowance_mib,
            bandwidth_allowance_mib=limits.bandwidth_allowance_mib,
            policy_version=limits.policy_version,
            reason="Apply pinned hosting allowance after explicit node adoption",
            authority={"kind": "native_policy_reconciliation", "customer_id": service.customer_id},
        )


def dispatch_hosting_limits() -> dict[str, int]:
    from .hosting_limit_execution import recover_quota_executions  # noqa: PLC0415 -- Task entrypoint.

    recovered = recover_quota_executions()
    # A bounded batch; no polling write or customer lock, and no per-row catalog read.
    pending = (
        ServiceHostingLimits.objects.filter(
            service__virtualmin_account__server__hosting_policy__quota_adopted=True,
            service__virtualmin_account__status__in=("active", "suspended"),
            service__status__in=("active", "suspended"),
        )
        .filter(
            Q(service__virtualmin_account__quota_managed=True)
            | Q(
                service__limit_applications__revision=F("revision"),
                service__limit_applications__authority__adopt_existing_native_limits="acknowledged",
            )
        )
        .filter(Q(applied_revision__isnull=True) | ~Q(applied_revision=F("revision")) | Q(verified_at__isnull=True))
        .order_by("updated_at")
        .values_list("service_id", flat=True)[:100]
    )
    queued = 0
    for service_id in pending:
        application = current_application(service_id)
        enqueue_application(application.pk)
        queued += 1
    return {"queued": queued, "recovered": recovered}
