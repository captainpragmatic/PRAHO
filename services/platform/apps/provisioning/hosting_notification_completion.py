"""Read-only customer-mail evidence under the existing native lifecycle claim."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import connection
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result, Retriability

from .hosting_node_policy import POLICY_VERSION, evidence_digest, verify_notification_evidence
from .hosting_node_policy_models import NodeHostingPolicy
from .virtualmin_create_retry_binding import create_binding_snapshot, create_origin_allowed
from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)


def _claim_current(
    account: VirtualminAccount,
    server: VirtualminServer,
    parent_job: VirtualminProvisioningJob | None,
    migration: VirtualminMigration | None,
) -> bool:
    if parent_job is not None and migration is None:
        if parent_job.operation == "create_domain":
            if parent_job.status != "running" or parent_job.started_at is None:
                return False
            current_account = VirtualminAccount.objects.filter(pk=account.pk).first()
            current_job = VirtualminProvisioningJob.objects.filter(pk=parent_job.pk).first()
            if current_account is None or current_job is None or current_job.server_id != server.pk:
                return False
            frozen = create_binding_snapshot(account, parent_job, origin_server_id=current_account.server_id)
            return create_origin_allowed(frozen, current_job) and frozen.owns(current_account, current_job)
        return bool(
            parent_job.execution_token
            and VirtualminProvisioningJob.objects.filter(
                pk=parent_job.pk,
                account_id=account.pk,
                server_id=server.pk,
                operation="restore_domain",
                status="running",
                execution_token=parent_job.execution_token,
                execution_deadline__gt=timezone.now(),
            ).exists()
        )
    if migration is not None and parent_job is None:
        return bool(
            migration.lease_token
            and migration.status in {"restoring", "activating"}
            and VirtualminMigration.objects.filter(
                pk=migration.pk,
                account_id=account.pk,
                source_server_id=migration.source_server_id,
                target_server_id=server.pk,
                status=migration.status,
                lease_token=migration.lease_token,
                worker_lease_expires_at__gt=timezone.now(),
            ).exists()
        )
    return False


def _binding(account: VirtualminAccount, server_id: UUID) -> tuple[Mapping[str, object], str, str, tuple[object, ...]]:
    current = VirtualminServer.objects.get(pk=server_id)
    policy = NodeHostingPolicy.objects.get(server_id=server_id)
    identity = connection_identity(current)
    if (
        policy.notification_owner != "platform"
        or policy.notifications_verified_at is None
        or policy.operation is not None
        or policy.policy_version != POLICY_VERSION
        or policy.connection_identity != identity
    ):
        raise ValidationError(_("Accepted native notification ownership changed"))
    proof = verify_notification_evidence(policy.notification_evidence, identity)
    scope = (
        VirtualminAccount.objects.filter(pk=account.pk)
        .values("service_id", "service__customer_id", "server_id", "domain", "virtualmin_username")
        .get()
    )
    if scope["service_id"] != account.service_id or scope["domain"] != account.domain:
        raise ValidationError(_("Native notification account scope changed"))
    return (
        scope,
        identity,
        proof["installation"],
        (policy.pk, policy.revision, policy.notifications_verified_at, evidence_digest(policy.notification_evidence)),
    )


def verify_lifecycle_notification_policy(
    account: VirtualminAccount,
    *,
    native_server: VirtualminServer,
    parent_job: VirtualminProvisioningJob | None = None,
    migration: VirtualminMigration | None = None,
) -> Result[None, str]:
    """Never adopt quotas or mutate native policy; uncertainty retains the caller's hold.

    Persisted Platform ownership remains authoritative during a delivery outage.
    Pipeline readiness is required for handover, not for keeping native mail suppressed.
    The native inspection proves actual emitter safety, including its guarded sources;
    a historical per-domain flag alone does not decide whether an old archive is safe.
    """
    from .hosting_node_transport import run_node_operation  # noqa: PLC0415 -- Existing enrolled read-only boundary.

    owner = (
        NodeHostingPolicy.objects.filter(server_id=native_server.pk)
        .values_list("notification_owner", flat=True)
        .first()
    )
    if owner != "platform":
        return Ok(None)
    stage = "lifecycle_claim"
    try:
        if connection.in_atomic_block or not _claim_current(account, native_server, parent_job, migration):
            raise ValidationError(_("Native notification inspection has no current lifecycle claim"))
        stage = "accepted_binding"
        before = _binding(account, native_server.pk)
        stage = "caller_identity"
        if connection_identity(native_server) != before[1]:
            raise ValidationError(_("The supplied native notification endpoint is stale"))
        stage = "native_inspection"
        evidence = run_node_operation(native_server, "inspect", {"identity": before[1]})
        stage = "native_evidence"
        proof = verify_notification_evidence(evidence.get("notifications", {}), before[1])
        stage = "completion_binding"
        if (
            evidence.get("identity") != before[1]
            or proof["installation"] != before[2]
            or _binding(account, native_server.pk) != before
            or not _claim_current(account, native_server, parent_job, migration)
        ):
            raise ValidationError(_("Native notification inspection lost its accepted scope or claim"))
    except (ObjectDoesNotExist, ValidationError, ValueError, KeyError, TypeError, RuntimeError, OSError) as error:
        logger.warning(
            "Native notification verification refused: account=%s server=%s stage=%s error_type=%s",
            account.pk,
            native_server.pk,
            stage,
            type(error).__name__,
        )
        return Err(
            _("Native customer notification policy could not be verified; review the node before continuing."),
            retriability=Retriability.UNKNOWN,
        )
    return Ok(None)
