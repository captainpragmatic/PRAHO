"""Current hosting policy on a committed target, separate from one-time restore evidence."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from time import perf_counter
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from .domain_veto import blocking_domain_status
from .service_models import Service
from .virtualmin_gateway import listing_attribute
from .virtualmin_migration_models import ACTIVE_JOB_STATUSES, VirtualminMigration
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

if TYPE_CHECKING:
    from .virtualmin_migration_service import VirtualminMigrationService

_READY_PHASES = frozenset({"bridging", "repointing"})
_IDENTITY_READ_SECONDS = 90
# Native policy action (300s), two bounded identity reads (180s), plus queue/DB margin.
_MIN_POLICY_TASK_SECONDS = 600


@dataclass(frozen=True)
class EnabledPolicy:
    enabled: bool
    service_status: str
    domain_hold: str | None
    service_reason: str = ""

    @property
    def reason(self) -> str:
        return (
            f"domain_{self.domain_hold}"
            if self.domain_hold
            else self.service_reason or f"service_{self.service_status}"
        )


def current_policy(account: VirtualminAccount) -> EnabledPolicy:
    """ADR-0051's live predicate; the original migration snapshot is never edited."""
    service = Service.objects.filter(pk=account.service_id).values("status", "suspension_reason").first()
    status = str(service["status"]) if service else "missing"
    hold = blocking_domain_status(account)
    return EnabledPolicy(
        status == "active" and hold is None, status, hold, str(service["suspension_reason"] or "") if service else ""
    )


@contextmanager
def activation_guard(migration: VirtualminMigration, token: UUID) -> Iterator[VirtualminAccount]:
    """Use the existing Migration→Account order while activating only committed ownership."""
    with transaction.atomic():
        current = VirtualminMigration.objects.select_for_update().get(pk=migration.pk)
        account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=current.account_id)
        if (
            current.cutover_committed_at is None
            or current.status != "activating"
            or current.lease_token != token
            or current.worker_lease_expires_at is None
            or current.worker_lease_expires_at <= timezone.now()
            or account.server_id != current.target_server_id
            or account.restore_hold
        ):
            raise ValueError("Target activation no longer owns a committed, unrestored account")
        migration.account = account
        yield account


def _target(migration: VirtualminMigration) -> dict[str, Any]:
    from .virtualmin_migration_service import (  # noqa: PLC0415  # Same-app orchestration.
        VirtualminMigrationService,
        list_migration_domains,
    )

    result = list_migration_domains(
        VirtualminMigrationService()._gateway(migration.target_server), deadline=perf_counter() + _IDENTITY_READ_SECONDS
    )
    if result.is_err():
        raise ValueError("The committed target's identity could not be read within its policy budget")
    matches = [row for row in result.unwrap() if row["domain"] == migration.account.domain]
    if len(matches) != 1:
        raise ValueError("The committed target's domain identity is absent or ambiguous")
    remote = matches[0]
    expected = str(migration.barrier_state.get("target_domain_id", ""))
    actual = str(listing_attribute(remote["attributes"], "ID") or "")
    if (
        not expected.isdigit()
        or actual != expected
        or remote["username"] != migration.account.virtualmin_username
        or remote["enabled"] not in (True, False)
    ):
        raise ValueError("The committed target's domain identity or enabled state changed")
    return remote


def apply_target_policy(migration: VirtualminMigration, policy: EnabledPolicy) -> dict[str, Any]:
    """Native policy callbacks preserve current credentials/cron; they never replay a backup."""
    _target(migration)
    if migration.contract == VirtualminMigration.Contract.RECOVERY:
        from .migration_target_hold import run_held_target_node  # noqa: PLC0415  # Native transport seam

        run_held_target_node(migration, "reconcile_policy", enabled=policy.enabled)
    else:
        from .migration_bridge_service import enforce_target_policy  # noqa: PLC0415  # Native transport seam

        result = enforce_target_policy(migration, policy.enabled)
        if result.is_err():
            raise RuntimeError("The committed target's current hosting policy could not be applied")
    remote = _target(migration)
    if remote["enabled"] is not policy.enabled:
        raise ValueError("The committed target did not converge to the current hosting policy")
    return remote


def converge_before_release(
    service: VirtualminMigrationService, migration: VirtualminMigration, token: UUID, account: VirtualminAccount
) -> EnabledPolicy:
    """Re-read after native I/O; rapidly changing policy defers instead of exposing stale intent."""
    for _attempt in range(2):
        policy = current_policy(account)
        service._move(migration, token, "activating")
        apply_target_policy(migration, policy)
        if current_policy(account) == policy:
            return policy
    from .virtualmin_migration_service import MigrationDeferredError  # noqa: PLC0415  # Same-app orchestration

    raise MigrationDeferredError(timezone.now() + timedelta(seconds=1), "Hosting policy changed during activation")


def _record_account_policy(account: VirtualminAccount, policy: EnabledPolicy) -> bool:
    desired = "active" if policy.enabled else "suspended"
    reason = "" if policy.enabled else policy.reason
    if (account.status, account.status_message) == (desired, reason):
        return False
    account.status = desired  # fsm-bypass: VirtualminAccount status is a CharField; reconciled native state.
    account.status_message = reason
    account.save(update_fields=["status", "status_message", "updated_at"])
    return True


def record_activation(
    service: VirtualminMigrationService, migration: VirtualminMigration, token: UUID, policy: EnabledPolicy, phase: str
) -> None:
    """Grant only enabled-policy convergence after all one-time native work and hold release."""
    account = migration.account
    _record_account_policy(account, policy)
    proof = {
        "complete": True,
        "server_id": str(migration.target_server_id),
        "domain_id": str(migration.barrier_state["target_domain_id"]),
        "owner": account.virtualmin_username,
        "service_id": str(account.service_id),
        "enabled": policy.enabled,
        "completed_at": timezone.now().isoformat(),
    }
    service._move(migration, token, phase, barrier_state={**migration.barrier_state, "target_activation": proof})
    from .virtualmin_migration_service import _reconcile_after_migration  # noqa: PLC0415  # Post-commit seam

    transaction.on_commit(lambda: _reconcile_after_migration(str(account.service_id)), robust=True)


def _eligible(migration: VirtualminMigration, account: VirtualminAccount) -> bool:
    phase = migration.parked_phase if migration.status == "needs_review" else migration.status
    proof = migration.barrier_state.get("target_activation") or {}
    return bool(
        migration.cutover_committed_at is not None
        and phase in _READY_PHASES
        and (migration.status in _READY_PHASES or migration.status == "needs_review")
        and migration.contract in {VirtualminMigration.Contract.CUTOVER, VirtualminMigration.Contract.RECOVERY}
        and account.server_id == migration.target_server_id
        and proof.get("complete") is True
        and proof.get("server_id") == str(account.server_id)
        and proof.get("domain_id") == str(migration.barrier_state.get("target_domain_id"))
        and proof.get("owner") == account.virtualmin_username
    )


def _other_operation(account: VirtualminAccount) -> bool:
    return bool(
        account.restore_hold
        or VirtualminProvisioningJob.objects.filter(
            account=account, status__in=ACTIVE_JOB_STATUSES, operation__in=("restore_domain", "delete_domain")
        ).exists()
        or VirtualminProvisioningJob.objects.filter(account=account, status="running").exists()
    )


def reconcile_committed_target(service_id: str, *, task_budget_seconds: int) -> dict[str, Any] | None:
    """A dedicated reconciler branch; no general lifecycle writer gains migration permission."""
    identifier = (
        VirtualminMigration.objects.filter(account__service_id=service_id)
        .exclude(status__in=("completed", "failed", "rolled_back"))
        .values_list("pk", flat=True)
        .first()
    )
    if identifier is None:
        return None
    with transaction.atomic():
        migration = VirtualminMigration.objects.select_for_update().get(pk=identifier)
        account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=migration.account_id)
        if str(account.service_id) != service_id or not _eligible(migration, account):
            return None
        if _other_operation(account):
            return {"success": True, "action": "operation_active"}
        if task_budget_seconds < _MIN_POLICY_TASK_SECONDS:
            return {
                "success": False,
                "action": "migration_policy",
                "error": f"Current target policy requires a task budget of at least {_MIN_POLICY_TASK_SECONDS} seconds",
            }
        migration.account = account
        policy = current_policy(account)
        try:
            apply_target_policy(migration, policy)
            _record_account_policy(account, policy)
        except (ValueError, RuntimeError) as error:
            return {"success": False, "action": "migration_policy", "error": str(error)}
        from .virtualmin_migration_service import _reconcile_after_migration  # noqa: PLC0415  # Race follow-up

        if current_policy(account) != policy:
            transaction.on_commit(lambda: _reconcile_after_migration(str(account.service_id)), robust=True)
        return {"success": True, "action": "migration_policy", "enabled": policy.enabled}
