"""Best-effort enqueue backed by immutable applications and a periodic DB sweep."""

from __future__ import annotations

import logging
from uuid import NAMESPACE_URL, UUID, uuid5

from django.db import transaction
from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone
from django_q.tasks import async_task

from .hosting_limit_execution_models import HostingLimitExecution
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
    from .hosting_raise_service import (  # noqa: PLC0415 -- Expiry materialization before native selection.
        expire_hosting_raise,
    )

    expire_hosting_raise(service_id)
    from .hosting_raise_expiry import (  # noqa: PLC0415 -- Recover pinned cleanup before a pending desire.
        pending_expiry_cleanup,
    )

    if cleanup := pending_expiry_cleanup(service_id):
        return cleanup
    with transaction.atomic():
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service_id)
        limits = ServiceHostingLimits.objects.get(service_id=service_id)
        from .hosting_raise_service import current_raise_terms  # noqa: PLC0415 -- Service owns composed outbox.

        overlay = current_raise_terms(service.pk, service.customer_id)
        existing = HostingLimitApplication.objects.filter(
            service_id=service_id, revision=limits.revision, overlay_revision=overlay.revision
        ).first()
        if existing is not None:
            return existing
        return HostingLimitApplication.objects.create(
            service_id=service_id,
            revision=limits.revision,
            submission_id=uuid5(
                NAMESPACE_URL, f"praho:initial-quota:{service_id}:{limits.revision}:{overlay.revision}"
            ),
            expected_plan_id=limits.assigned_plan_id,
            target_plan_id=limits.assigned_plan_id,
            disk_allowance_mib=limits.disk_allowance_mib,
            bandwidth_allowance_mib=limits.bandwidth_allowance_mib,
            policy_version=limits.policy_version,
            reason="Apply pinned hosting allowance after explicit node adoption",
            authority={"kind": "native_policy_reconciliation", "customer_id": service.customer_id},
            **overlay.application_fields(),
        )


def dispatch_hosting_limits() -> dict[str, int]:
    from .hosting_limit_execution import recover_quota_executions  # noqa: PLC0415 -- Task entrypoint.
    from .hosting_raise_service import expire_hosting_raises  # noqa: PLC0415

    expire_hosting_raises()
    recovered = recover_quota_executions()
    reviewed_adoption = HostingLimitApplication.objects.filter(
        service_id=OuterRef("service_id"),
        revision=OuterRef("revision"),
        authority__adopt_existing_native_limits="acknowledged",
    )
    held_execution = HostingLimitExecution.objects.filter(
        job__account__service_id=OuterRef("service_id"), phase__in=("prepared", "issued", "attention")
    ).exclude(
        phase="prepared",
        job__status="running",
        job__parameters__quota_parent__isnull=False,
        job__parameters__quota_parent={},
    )
    candidates = (
        ServiceHostingLimits.objects.filter(
            service__virtualmin_account__server__hosting_policy__quota_adopted=True,
            service__virtualmin_account__status__in=("active", "suspended"),
            service__virtualmin_account__restore_hold="",
            service__status__in=("active", "suspended"),
        )
        .alias(reviewed_adoption=Exists(reviewed_adoption), held_execution=Exists(held_execution))
        .filter(Q(service__virtualmin_account__quota_managed=True) | Q(reviewed_adoption=True), held_execution=False)
        .filter(Q(applied_revision__isnull=True) | ~Q(applied_revision=F("revision")) | Q(verified_at__isnull=True))
    )
    # Record scheduling progress even when the worker later refuses admission or
    # the broker is down. Only this bounded Limits batch is locked; release it
    # before current_application takes any Service lock or enqueue performs I/O.
    with transaction.atomic():
        pending = list(
            candidates.select_for_update(of=("self",), skip_locked=True)
            .order_by("updated_at", "pk")
            .values_list("pk", "service_id")[:100]
        )
        if pending:
            ServiceHostingLimits.objects.filter(pk__in=[pk for pk, _service_id in pending]).update(
                updated_at=timezone.now()
            )
    queued = 0
    for _limits_id, service_id in pending:
        application = current_application(service_id)
        enqueue_application(application.pk)
        queued += 1
    return {"queued": queued, "recovered": recovered}
