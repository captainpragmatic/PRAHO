"""Shared server-row admission boundary for node-wide and account mutations.

Callers lock their Account first when needed, then server rows in primary-key order.
The predicate and durable operation publication belong to that same transaction.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution, NodeMaintenanceWindow

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
    from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

ACTIVE_EXECUTIONS = ("claimed", "issued", "awaiting_recovery", "uncertain")
ACTIVE_ACCOUNT_JOBS = ("pending", "running", "attention")
TERMINAL_MIGRATIONS = ("completed", "failed", "rolled_back")


class _DeploymentBindingChangedError(Exception):
    """Retry outside the savepoint so the old binding's row locks are released."""


@contextmanager
def locked_deployment_gate(deployment_id: int) -> Iterator[NodeDeployment | None]:
    """Take Server→Deployment locks, with a bounded optimistic binding recheck."""
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Model registration
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Shared node gate

    for _attempt in range(3):
        try:
            with transaction.atomic():
                hint = (
                    NodeDeployment.objects.filter(pk=deployment_id)
                    .values_list("virtualmin_server_id", flat=True)
                    .first()
                )
                if hint is not None:
                    VirtualminServer.objects.select_for_update(of=("self",)).filter(pk=hint).first()
                row = NodeDeployment.objects.select_for_update(of=("self",)).filter(pk=deployment_id).first()
                if row is not None and row.virtualmin_server_id != hint:
                    raise _DeploymentBindingChangedError
                yield row
                return
        except _DeploymentBindingChangedError:
            continue
    raise ValidationError(_("The deployment's server binding keeps changing; reload before retrying."))


def begin_account_job(account: VirtualminAccount, job: VirtualminProvisioningJob) -> str | None:
    """Publish/recheck the existing domain job under Account→sortedServers, before native I/O."""
    from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer  # noqa: PLC0415

    with transaction.atomic():
        locked = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=account.pk)
        nodes = list(
            VirtualminServer.objects.select_for_update(of=("self",))
            .filter(pk__in=(locked.server_id, job.server_id))
            .order_by("pk")
        )
        if job.operation != "create_domain" and locked.server_id != job.server_id:
            return "The account moved to another server; review the operation before retrying."
        for node in nodes:
            if refusal := maintenance_refusal(node.pk):
                return refusal
        if job._state.adding:
            job.save()
        job.mark_started()
    return None


def maintenance_refusal(node_id: UUID, *, execution_token: UUID | None = None) -> str | None:
    """Future schedules do not reserve the server; a live attempt does."""
    from apps.provisioning.virtualmin_models import (  # noqa: PLC0415  # Deferred optional reviewed-hardening owner
        VirtualminServer,  # Optional reviewed-hardening owner
    )

    node = VirtualminServer.objects.filter(pk=node_id).first()
    # A later hardening schema adds this durable owner. Reuse it when present;
    # older installations have no such field and retain their current behavior.
    if node is not None and getattr(node, "security_operation", None) is not None:
        return str(_("A reviewed hardening operation owns this server. Reconcile its outcome before other work."))
    executions = NodeMaintenanceExecution.objects.filter(node_id=node_id, phase__in=ACTIVE_EXECUTIONS)
    if execution_token is not None:
        executions = executions.exclude(token=execution_token)
    if executions.exists():
        return str(_("Maintenance currently owns this server. Wait for its verified completion."))
    windows = NodeMaintenanceWindow.objects.filter(node_id=node_id, status__in=("running", "overran"))
    if execution_token is not None:
        windows = windows.exclude(current_execution__token=execution_token)
    if windows.exists():
        return str(_("Maintenance is in progress on this server."))
    return None


def deployment_maintenance_refusal(deployment: NodeDeployment) -> str | None:
    """The deployment gate also covers native ownership before a server exists."""
    if NodeMaintenanceExecution.objects.filter(deployment=deployment, phase__in=ACTIVE_EXECUTIONS).exists():
        return str(_("Maintenance currently owns this deployment. Verify its outcome before another operation."))
    return maintenance_refusal(deployment.virtualmin_server_id) if deployment.virtualmin_server_id else None


def teardown_maintenance_refusal(
    node_id: UUID, *, execution_token: UUID | None = None, preserve_scheduled: bool = False
) -> str | None:
    if refusal := maintenance_refusal(node_id, execution_token=execution_token):
        return refusal
    if not preserve_scheduled and NodeMaintenanceWindow.objects.filter(node_id=node_id, status="scheduled").exists():
        return str(_("Cancel the scheduled maintenance window and its announcements before removing this server."))
    return None


def competing_operation_refusal(node_id: UUID, *, owned_drift_request_id: int | None = None) -> str | None:
    """Inventory actual durable owners, including incoming work on an empty target."""
    from apps.provisioning.component_maintenance_ownership import terminal_component_refusal  # noqa: PLC0415
    from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415

    refusal = maintenance_refusal(node_id) or terminal_component_refusal(node_id)
    if refusal:
        return refusal
    if VirtualminProvisioningJob.objects.filter(server_id=node_id, status__in=ACTIVE_ACCOUNT_JOBS).exists():
        return str(_("A hosting-account operation is pending, running, or requires reconciliation."))
    if (
        VirtualminMigration.objects.filter(Q(source_server_id=node_id) | Q(target_server_id=node_id))
        .exclude(status__in=TERMINAL_MIGRATIONS)
        .exists()
        or MigrationBridge.objects.filter(Q(source_server_id=node_id) | Q(target_server_id=node_id))
        .exclude(status="torn_down")
        .exists()
    ):
        return str(_("A migration, retained bridge or recovery operation owns this server."))
    from apps.infrastructure.models import (  # noqa: PLC0415  # Model registration
        DriftRemediationRequest,
        NodeDeployment,
    )

    deployments = NodeDeployment.objects.filter(virtualmin_server_id=node_id)
    if (
        deployments.filter(Q(needs_reconciliation=True) | Q(operation_reserved_at__isnull=False)).exists()
        or deployments.exclude(status__in=("completed", "stopped", "failed", "destroyed")).exists()
    ):
        return str(_("A deployment operation is active or requires reconciliation."))
    drift = DriftRemediationRequest.objects.filter(
        deployment__virtualmin_server_id=node_id, status__in=("approved", "in_progress")
    )
    if owned_drift_request_id is not None:
        drift = drift.exclude(pk=owned_drift_request_id)
    if drift.exists():
        return str(_("A drift operation currently owns this server."))
    return None
