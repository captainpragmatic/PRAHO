"""Token-fenced single-domain migration, automatic cutover and resumable compensation."""

from __future__ import annotations

import logging
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict
from uuid import UUID, uuid4

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from . import account_hostname_service
from .account_hostname_lifecycle import ensure_on_recreated_node
from .account_hostname_models import AccountHostname
from .migration_barrier import BarrierRecord, BarrierStep, barrier_variables, run_barrier
from .placement import order_placement_candidates
from .virtualmin_backup_service import (
    CHAIN_ROLE_STANDALONE,
    REMOTE_ARCHIVE_DIR,
    differential_flags,
    restore_domain_params,
)
from .virtualmin_chain import invalidate_chain
from .virtualmin_domain_state import DOMAIN_STATE_PROGRAMS, domain_state_params
from .virtualmin_gateway import (
    VirtualminConfig,
    VirtualminGateway,
    get_virtualmin_timeouts,
    is_customer_domain_row,
    listing_attribute,
    listing_enabled,
)
from .virtualmin_gateway import explicit_rejection as _explicit_rejection
from .virtualmin_migration_models import (
    _TERMINAL_STATUSES,
    PRE_COMMIT_STATUSES,
    MigrationBridge,
    NodeDrain,
    VirtualminMigration,
    account_has_active_operation,
)
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleService as AnsibleRunner
    from apps.users.models import User

logger = logging.getLogger(__name__)

# How long a lowered TTL may take to appear on every authoritative answer before the move is
# compensated instead of proceeding on routing that still carries the old TTL (ADR-0061 P2.3).
TTL_POLL_SECONDS = 60


def _reconcile_after_migration(service_id: str) -> None:
    """Post-commit: converge the account's enabled state once a migration releases it."""
    from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415  # Circular: same-app

    reconcile_virtualmin_service_state_async(service_id)


def _wake_drain(drain_id: UUID) -> None:
    from .virtualmin_drain_service import NodeDrainService  # noqa: PLC0415  # Circular

    NodeDrainService.wake(drain_id)


def migration_backup_params(archive_name: str) -> dict[str, str]:
    """The source node's backup-domain parameters for one migration archive.

    Standalone (`no-differential`): a migration backup must not replace the
    source domain's differential base. `mkdir` lets Virtualmin create the
    private staging directory (0700) on a node that does not have it yet.
    """
    return {
        "dest": f"{REMOTE_ARCHIVE_DIR}/{archive_name}",
        "all-features": "",
        "mkdir": "",
        **differential_flags(CHAIN_ROLE_STANDALONE),
    }


# Recovery policy concerns an INTERRUPTED phase, before invoking execute().
RESUME_POLICY = {
    "pending": "continue",  # Preflight evidence exists; no remote mutation issued.
    "lowering_ttl": "continue",  # Republishing the lower TTL and re-reading it is idempotent.
    "quiescing": "continue",  # Read state first; disable is verifiable and repeatable.
    "backing_up": "review",  # Never infer that a remote backup stopped.
    "fetching": "continue",  # Deterministic local filename; checksum-checked fetch.
    "pushing": "continue",  # Deterministic remote filename; checksum-checked copy.
    "restoring": "review",  # No replay, listing inference, or deletion.
    "verifying": "continue",  # Synchronous restore success was already persisted.
    "activating": "review",  # Committed cutovers replay forward; legacy ambiguous enables need review.
    "bridging": "continue",
    "repointing": "continue",  # Repeat the fenced local transaction only.
    "compensating": "continue",  # Durable undo steps are replayed without restarting the forward path.
    "fencing": "review",  # Reserved historical state; no remote replay without operator evidence.
    "completed": "stop",
    "failed": "stop",
    "rolled_back": "stop",
    "needs_review": "stop",
}


class MigrationResumeOutcome(TypedDict):
    action: str
    migration_id: str
    lease_acquired: bool


class MigrationLeaseLostError(RuntimeError):
    pass


class MigrationCancelledBeforeCommitError(ValueError):
    """A cancellation won the row lock before the ownership commit."""


def source_is_fenced(migration: VirtualminMigration) -> bool:
    """Only an audited staff attestation may replace source RPCs after a cutover commits."""
    control = migration.barrier_state.get("source_fenced_control")
    return bool(
        migration.contract == VirtualminMigration.Contract.CUTOVER
        and migration.cutover_committed_at is not None
        and isinstance(control, dict)
        and control.get("source_server_id") == str(migration.source_server_id)
        and control.get("confirmed_by")
        and control.get("confirmed_at")
        and str(control.get("attestation", "")).strip()
    )


class DefiniteMigrationFailureError(RuntimeError):
    pass


class MigrationDeferredError(Exception):
    """A step that must wait (ADR-0061 P2.1): the row keeps its state and is woken at `until`.

    Raised by a handler only once everything it did is persisted, so the wait is a clean checkpoint:
    the step runs again from its state when it is due, whatever an interruption there would mean.
    """

    def __init__(self, until: datetime, reason: str) -> None:
        super().__init__(reason)
        self.until = until
        self.reason = reason


def AnsibleService() -> AnsibleRunner:  # noqa: N802  # Lazy constructor preserves the requested mock seam.
    from apps.infrastructure.ansible_service import AnsibleService as Runner  # noqa: PLC0415

    return Runner()


# The listing attributes a row keeps, in text-label form; the 8.x snake_case
# form of each is kept too. These are what migration verification compares
# and what listing_enabled() reads. A full 8.x row also carries
# `hashed_password`, `password_for_mysql` and other secrets, and rows end up
# in the persisted pre-migration snapshot, so nothing else is kept.
SNAPSHOT_ATTRIBUTES = ("Username", "ID", "Status", "Disabled", "Server byte quota", "Bandwidth limit", "Features")
_SNAPSHOT_KEYS = frozenset(key for label in SNAPSHOT_ATTRIBUTES for key in (label, label.lower().replace(" ", "_")))


def snapshot_attributes(values: dict[str, Any]) -> dict[str, Any]:
    """Only the allowlisted attributes of one listing row."""
    return {key: value for key, value in values.items() if key in _SNAPSHOT_KEYS}


def list_migration_domains(
    gateway: VirtualminGateway, *, strict: bool = True, deadline: float | None = None
) -> Result[list[dict[str, Any]], str]:
    """Reuse call()'s VirtualminResponseParser output, retaining multiline attributes.

    strict=True (migration admission) treats any malformed row as fatal — a
    listing that cannot be fully trusted must not gate a collision check.
    strict=False (account sync) skips malformed rows so one odd header or
    separator row cannot abort a whole server's sync.
    """
    result = (
        gateway.call("list-domains", {"multiline": ""}, deadline=deadline)
        if deadline is not None
        else gateway.call("list-domains", {"multiline": ""})
    )
    if result.is_err():
        return Err(str(result.unwrap_err()))
    response = result.unwrap()
    items = response.data.get("data")
    if not response.success or not isinstance(items, list):
        return Err("Unrecognized or failed Virtualmin domain listing")
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("name") or not isinstance(item.get("values"), dict):
            if strict:
                return Err("Incomplete Virtualmin multiline domain listing")
            logger.warning("⚠️ [VirtualminMigration] Skipping malformed listing row: %r", item)
            continue
        values = item["values"]
        rows.append(
            {
                "domain": str(item["name"]),
                "username": listing_attribute(values, "Username"),
                "enabled": listing_enabled(values),
                # Read from the raw row: the snapshot allowlist below drops the type and parent.
                "type": listing_attribute(values, "Type"),
                "parent_domain": listing_attribute(values, "Parent domain"),
                "attributes": snapshot_attributes(values),
            }
        )
    if len({row["domain"] for row in rows}) != len(rows):
        return Err("Duplicate domains in Virtualmin listing")
    return Ok(rows)


def account_name_children(hostname: AccountHostname | None) -> set[str]:
    """The account-name sub-server a live hostname puts under its customer domain, if any."""
    if hostname is None or hostname.retired_at is not None:
        return set()
    return {f"{hostname.label}.{hostname.zone}"}


def owned_customer_rows(
    rows: list[dict[str, Any]], account: VirtualminAccount, account_names: set[str]
) -> list[dict[str, Any]]:
    """The source owner's rows a migration moves, refusing any it cannot (ADR-0061 P1.6).

    A migration archives the customer domain alone, so every other row the owner has would be lost
    on the target. The one exception is the account's own account name: a sub-server of the
    account's domain, owned by the same user, named by its live hostname. PRAHO recreates it from
    that record on the target. Any other sub-server, alias or extra domain refuses the migration.
    """
    owned = [row for row in rows if row["username"] == account.virtualmin_username]
    kept = [
        row
        for row in owned
        if not (
            row.get("type") == "Sub-server"
            and row.get("parent_domain") == account.domain
            and row["domain"] in account_names
        )
    ]
    if len(kept) != 1 or kept[0]["domain"] != account.domain or not is_customer_domain_row(kept[0]):
        raise ValueError("Source owner must have exactly one domain: the account's own domain")
    return kept


def migration_task_timeout() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    backup = SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", 1800)
    transfer = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
    if min(backup, transfer) <= 0:
        raise ValueError("Migration timeouts must be positive")
    # A held pair restores data and TLS separately for each archive. Bridge preparation
    # and activation also have explicit RPC budgets, even when operators shorten transfer.
    return max(2 * backup + 2 * transfer + 600, 4 * backup + 2400, 10800)


class VirtualminMigrationService:
    def __init__(self) -> None:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        self.enabled = SettingsService.get_boolean_setting("provisioning.migration_enabled", False)
        self.backup_timeout = SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", 1800)
        self.transfer_timeout = SettingsService.get_integer_setting(
            "provisioning.migration_transfer_timeout_seconds", 3600
        )
        self.spool = Path(
            str(SettingsService.get_setting("provisioning.migration_spool_dir", "/var/lib/praho/migration-spool"))
        )
        self.task_timeout = migration_task_timeout()
        self.lease_ttl = timedelta(seconds=self.task_timeout + 60)

    @staticmethod
    def eligible_targets(account: VirtualminAccount, preferred_region: str | None = None) -> list[VirtualminServer]:
        candidates = [
            server
            for server in VirtualminServer.objects.filter(status="active", is_draining=False)
            .exclude(pk=account.server_id)
            .select_related("node_deployment")
            if hasattr(server, "node_deployment")
            and server.node_deployment is not None
            and server.can_host_domain()
            and server.current_domains + VirtualminMigration.active_reservations(server) < server.max_domains
        ]
        return order_placement_candidates(candidates, preferred_region)

    @staticmethod
    def _gateway(server: VirtualminServer) -> VirtualminGateway:
        return VirtualminGateway(VirtualminConfig(server=server))

    @staticmethod
    def _listing(gateway: VirtualminGateway) -> list[dict[str, Any]]:
        result = list_migration_domains(gateway)
        if result.is_err():
            raise ValueError(result.unwrap_err())
        return result.unwrap()

    def _domain(self, server: VirtualminServer, domain: str) -> dict[str, Any]:
        rows = self._listing(self._gateway(server))
        matches = [row for row in rows if row["domain"] == domain]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one remote domain: {domain}")
        return matches[0]

    def _move(self, migration: VirtualminMigration, token: UUID, status: str, **fields: object) -> None:
        if not migration.renew_lease(token, self.lease_ttl):
            raise MigrationLeaseLostError("Migration lease expired or ownership changed")
        if not migration.transition(token, migration.status, status, **fields):
            raise MigrationLeaseLostError(f"Migration transition rejected: {migration.status} -> {status}")
        migration.refresh_from_db()
        logger.info("✅ [VirtualminMigration] migration=%s phase=%s", migration.pk, status)

    @staticmethod
    def _audit(
        migration: VirtualminMigration, action: str, *, compensation_failure: bool = False, actor: User | None = None
    ) -> None:
        from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

        user = actor or migration.initiated_by
        AuditService.log_event(
            AuditEventData(
                event_type=f"virtualmin_migration_{action}",
                content_object=migration,
                description=f"Migration {migration.pk}: {migration.status}",
                new_values={"status": migration.status, "error_detail": migration.error_detail},
            ),
            AuditContext(
                user=user,
                actor_type="user" if user else "system",
                metadata={
                    "source_app": "provisioning",
                    "compensation_failure": compensation_failure,
                    **(
                        {
                            "source_fenced": migration.barrier_state.get("source_fenced", ""),
                            "source_server_id": str(migration.source_server_id),
                        }
                        if migration.contract == VirtualminMigration.Contract.RECOVERY
                        else {}
                    ),
                    **(
                        {"source_fenced_control": migration.barrier_state["source_fenced_control"]}
                        if source_is_fenced(migration)
                        else {}
                    ),
                },
            ),
        )

    def _finish(  # noqa: PLR0913  # Terminal transition carries its full audit context
        self,
        migration: VirtualminMigration,
        token: UUID,
        status: str,
        error: str = "",
        *,
        compensation_failure: bool = False,
        actor: User | None = None,
    ) -> None:
        with transaction.atomic():
            self._move(migration, token, status, error_detail=error)
            self._audit(migration, status, compensation_failure=compensation_failure, actor=actor)
            if status in _TERMINAL_STATUSES and migration.contract != VirtualminMigration.Contract.RECOVERY:
                from .migration_artifact_cleanup import schedule_artifact_cleanup  # noqa: PLC0415

                transaction.on_commit(lambda: schedule_artifact_cleanup(migration.pk), robust=True)
            # While the migration held the account the reconciler skipped it (migration_locked),
            # and the migration restores its own pre-migration snapshot. Any Service or domain
            # change made meanwhile is applied now, not left for the divergence sweep (ADR-0051).
            service_id = (
                VirtualminAccount.objects.filter(pk=migration.account_id).values_list("service_id", flat=True).first()
            )
            if service_id is not None:
                transaction.on_commit(lambda: _reconcile_after_migration(str(service_id)), robust=True)
            if migration.drain_id is not None:
                # The one place a drain's migration is counted, however it ran (inline, or woken
                # after a deferral); a drain that checkpointed to wait for it is woken.
                if status == "completed":
                    NodeDrain.objects.filter(pk=migration.drain_id).update(
                        accounts_migrated=F("accounts_migrated") + 1, updated_at=timezone.now()
                    )
                drain_id = migration.drain_id
                transaction.on_commit(lambda: _wake_drain(drain_id), robust=True)

    def _local_preflight(self, account: VirtualminAccount, target: VirtualminServer) -> None:
        if not self.enabled:
            raise ValueError("Virtualmin migration is disabled")
        if account_has_active_operation(account):
            raise ValueError("Account already has an active migration or backup/restore operation")
        if (
            MigrationBridge.objects.filter(migration__account_id=account.pk)
            .exclude(status=MigrationBridge.Status.TORN_DOWN)
            .exists()
        ):
            raise ValueError("An earlier move's bridge is still standing for this account")
        if account.server_id == target.pk:
            raise ValueError("Source and target must differ")
        if account.status not in {"active", "suspended"}:
            raise ValueError("Only active or suspended accounts can migrate")
        if account.domains not in ([], [account.domain]):
            raise ValueError("Migration requires exactly one domain: the account's own domain")
        for server in (account.server, target):
            if server.status != "active":
                raise ValueError("Both migration servers must be active")
            if not (hasattr(server, "node_deployment") and server.node_deployment is not None):
                raise ValueError(f"Server {server.name}: manual registration has no managed node_deployment")
        self._admission_preflight(target)

    def _admission_preflight(self, target: VirtualminServer) -> None:
        """Target-capacity and operator-configuration admission checks."""
        if not target.can_host_domain():
            raise ValueError("Target is unhealthy or full")
        # Tags are hard filters everywhere — an explicit target must not
        # bypass the placement tag policy that placement/eligible_targets apply.
        if not order_placement_candidates([target]):
            raise ValueError("Target server violates the placement tag policy")
        if target.current_domains + VirtualminMigration.active_reservations(target) >= target.max_domains:
            raise ValueError("Target capacity is reserved or full")
        if not self.spool.is_absolute():
            raise ValueError("Migration spool directory must be absolute")
        if self.task_timeout + 60 >= int(str(settings.Q_CLUSTER.get("retry", 0))):
            raise ValueError("Migration budget must fit below the Django-Q broker visibility timeout")

    @staticmethod
    def _contract(account: VirtualminAccount) -> str:
        """A cutover when the account has a live published name; nothing to carry otherwise."""
        hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
        if hostname is not None and hostname.records and hostname.target_server_id is not None:
            return VirtualminMigration.Contract.CUTOVER
        return VirtualminMigration.Contract.LEGACY

    def start_migration(  # noqa: PLR0913  # Admission carries its whole context, the drain included
        self,
        account: VirtualminAccount,
        target_server: VirtualminServer,
        *,
        initiated_by: User | None,
        reason: str = "manual",
        enqueue: bool = True,
        drain: NodeDrain | None = None,
    ) -> Result[VirtualminMigration, str]:
        try:
            with transaction.atomic():
                # Lock ONLY the account row here — a select_related join would also
                # lock the source server out of pk order (PostgreSQL locks joined
                # rows), deadlocking concurrent A→B / B→A admissions against the
                # ordered server locks below.
                account = VirtualminAccount.objects.select_for_update().get(pk=account.pk)
                servers = {
                    server.pk: server
                    for server in VirtualminServer.objects.select_for_update()
                    .filter(pk__in=(account.server_id, target_server.pk))
                    .order_by("pk")
                }
                account.server = servers[account.server_id]
                target = servers[target_server.pk]
                self._local_preflight(account, target)
                if reason not in VirtualminMigration.Reason.values:
                    raise ValueError("Invalid migration reason")
                invalidate_chain(account)  # the retained source copy keeps a snapshot the account no longer owns
                migration = VirtualminMigration.objects.create(
                    account=account,
                    source_server=account.server,
                    target_server=target,
                    initiated_by=initiated_by,
                    reason=reason,
                    drain=drain,
                    contract=self._contract(account),
                )
                token = uuid4()
                if not migration.acquire_lease(token, self.lease_ttl):
                    raise MigrationLeaseLostError("Could not acquire the new migration lease")
                self._audit(migration, "started")
                try:
                    target_rows = self._listing(self._gateway(target))
                    if any(row["domain"] == account.domain for row in target_rows):
                        raise ValueError("Domain already exists on target")
                    source_rows = self._listing(self._gateway(account.server))
                    names = account_name_children(AccountHostname.objects.filter(account=account).first())
                    remote = owned_customer_rows(source_rows, account, names)[0]
                    if "mail" in str(listing_attribute(remote["attributes"], "Features") or "").split():
                        raise ValueError("Mail-enabled domains need the verified mail bridge before they can migrate")
                    if remote["enabled"] is not (account.status == "active"):
                        raise ValueError("Source enabled state disagrees with the account snapshot")
                    self._move(
                        migration,
                        token,
                        "pending",
                        pre_migration_snapshot={
                            "domain": account.domain,
                            "status": account.status,
                            "remote": remote,
                        },
                    )
                except Exception as error:
                    self._finish(migration, token, "failed", str(error))
                    return Err(str(error))
                self._move(migration, token, "pending", lease_token=None, worker_lease_expires_at=None)
                if enqueue:
                    transaction.on_commit(lambda: self._enqueue(migration.pk))
            return Ok(migration)
        except (ValueError, IntegrityError, MigrationLeaseLostError) as error:
            return Err(str(error))

    def _enqueue(self, migration_id: UUID) -> None:
        from .virtualmin_tasks import enqueue_virtualmin_migration  # noqa: PLC0415

        try:
            enqueue_virtualmin_migration(str(migration_id), self.task_timeout)
        except Exception as error:
            migration = VirtualminMigration.objects.get(pk=migration_id)
            token = uuid4()
            if migration.acquire_lease(token, self.lease_ttl):
                migration.refresh_from_db()
                if migration.status == "pending":
                    self._finish(migration, token, "failed", f"Enqueue failed: {error}")
                else:
                    migration.transition(
                        token, migration.status, migration.status, lease_token=None, worker_lease_expires_at=None
                    )
            logger.exception("🔥 [VirtualminMigration] Enqueue failed: migration=%s", migration_id)

    def _command(
        self,
        migration: VirtualminMigration,
        server: VirtualminServer,
        program: str,
        **params: object,
    ) -> None:
        if program in {"backup-domain", "restore-domain"}:
            timeout = self.backup_timeout
        elif program == "create-domain":
            timeout = get_virtualmin_timeouts()["PROVISIONING_TIMEOUT"]
        else:
            timeout = 30
        domain = migration.account.domain
        base = domain_state_params(domain) if program in DOMAIN_STATE_PROGRAMS else {"domain": domain}
        result = self._gateway(server).call(program, {**base, **params}, timeout_seconds=timeout)
        if result.is_err():
            if retriability_of(result) is not Retriability.UNKNOWN:
                raise DefiniteMigrationFailureError(str(result.unwrap_err()))
            raise RuntimeError(f"Ambiguous {program}: {result.unwrap_err()}")
        response = result.unwrap()
        if not response.success:
            # Only a well-formed JSON envelope that ITSELF reports failure is
            # rejection evidence. Blank bodies, truncated JSON, proxy HTML, or
            # heuristic text/XML error guesses prove nothing about execution —
            # that ambiguity must never authorize compensation (delete/enable).
            rejection = _explicit_rejection(response.raw_response)
            if rejection is None:
                raise RuntimeError(f"Ambiguous {program}: response could not be interpreted as a rejection")
            raise DefiniteMigrationFailureError(f"{program} rejected: {rejection}")
        if response.data.get("status") != "success" and response.data.get("success") is not True:
            raise RuntimeError(f"{program} lacked an explicit synchronous success response")

    def _abort(
        self,
        migration: VirtualminMigration,
        token: UUID,
        error: Exception,
        *,
        target_delete_allowed: bool = False,
    ) -> None:
        self._move(migration, token, migration.status, error_detail=str(error))
        self._rollback(migration, token, target_delete_allowed=target_delete_allowed)

    def _rollback(self, migration: VirtualminMigration, token: UUID, *, target_delete_allowed: bool) -> None:
        """Resume the undo workflow; target cleanup is derived from durable restore-issued evidence."""
        del target_delete_allowed  # Kept for callers from older worker checkpoints.
        logger.warning("⚠️ [VirtualminMigration] Rollback: migration=%s", migration.pk)
        try:
            if migration.status != "compensating":
                self._move(migration, token, "compensating")
            self._compensate(migration, token)
        except (MigrationLeaseLostError, MigrationDeferredError):
            raise
        except Exception as error:
            self._park_compensation(migration, token, str(error))

    def _compensate(self, migration: VirtualminMigration, token: UUID) -> None:
        """Remove the target copy, release the original fence, then restore the TTL, checkpointing each step.

        Raw Virtualmin API requests do not hold the barrier's lock. Ambiguous backup/restore calls
        therefore remain needs_review until staff retries this workflow after checking the node.
        """
        state = migration.barrier_state or {}
        if state.get("source_idle_required"):
            idle = self._barrier(migration, "idle", token=str(uuid4()))
            self._defer_if_node_busy(idle)
            if idle.is_err() or not idle.unwrap().ok:
                reason = idle.unwrap_err() if idle.is_err() else idle.unwrap().reason
                raise ValueError(f"The source is not proven idle: {reason}")
        if migration.restore_issued and not state.get("target_removed"):
            self._remove_target_copy(migration, token)
            self._store_barrier_state(migration, token, {**migration.barrier_state, "target_removed": True})
        if state.get("bridge_prepared"):
            from .migration_bridge_service import remove_bridge  # noqa: PLC0415

            removed = remove_bridge(migration)
            if removed.is_err():
                raise ValueError(f"Prepared bridge resources were not removed: {removed.unwrap_err()}")
            self._store_barrier_state(migration, token, {**migration.barrier_state, "bridge_prepared": False})
        if state.get("record"):
            self._release_barrier(migration, token)
        elif migration.source_disabled_at and migration.pre_migration_snapshot["status"] != "suspended":
            # Legacy rows have no persisted node fence. Their synchronous disable is undone once.
            if self._domain(migration.source_server, migration.account.domain)["enabled"] is not True:
                self._command(migration, migration.source_server, "enable-domain")
            if self._domain(migration.source_server, migration.account.domain)["enabled"] is not True:
                raise ValueError("Source re-enable could not be verified")
        self._restore_ttl(migration)
        self._finish(migration, token, "rolled_back", migration.error_detail)

    def _remove_target_copy(self, migration: VirtualminMigration, token: UUID) -> None:
        """Delete only this account's restored copy after a bounded node-idle proof; verify its absence."""
        idle = self._barrier(
            migration,
            "idle",
            token=str(uuid4()),
            previous_token=str(migration.barrier_state.get("token") or ""),
            server=migration.target_server,
        )
        self._defer_if_node_busy(idle)
        if idle.is_err() or not idle.unwrap().ok:
            reason = idle.unwrap_err() if idle.is_err() else idle.unwrap().reason
            raise ValueError(f"The target is not proven idle: {reason}")
        rows = self._listing(self._gateway(migration.target_server))
        matches = [row for row in rows if row["domain"] == migration.account.domain]
        if matches and matches[0]["username"] != migration.pre_migration_snapshot["remote"]["username"]:
            raise ValueError("The target domain belongs to another owner; it was left in place")
        target_id = migration.barrier_state.get("target_domain_id")
        if target_id:
            if matches and str(listing_attribute(matches[0]["attributes"], "ID")) != str(target_id):
                raise ValueError("The held target identity changed; it was left in place")
            self._release_target_hold(migration)
        if not matches:
            return
        if not migration.renew_lease(token, self.lease_ttl):
            raise MigrationLeaseLostError("Target cleanup lost the migration lease")
        self._command(migration, migration.target_server, "delete-domain")
        rows = self._listing(self._gateway(migration.target_server))
        if any(row["domain"] == migration.account.domain for row in rows):
            raise ValueError("Target deletion could not be verified")

    def _park_compensation(self, migration: VirtualminMigration, token: UUID, reason: str) -> None:
        """Keep the account exclusion while staff resolves an unproven undo step."""
        self._move(migration, token, "compensating", parked_phase="compensating", error_detail=reason)
        self._audit(migration, "compensation_parked", compensation_failure=True)
        if migration.drain_id:
            drain_id = migration.drain_id
            transaction.on_commit(lambda: _wake_drain(drain_id), robust=True)

    @staticmethod
    def _defer_if_node_busy(step: Result[BarrierStep, str]) -> None:
        if step.is_ok() and step.unwrap().outcome == "busy":
            raise MigrationDeferredError(
                timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), "Waiting for node operations"
            )

    def _lower_ttl(self, migration: VirtualminMigration, token: UUID) -> None:
        """Contract step 1: lower the published name's TTL and wait until every record confirms it."""
        hostname = AccountHostname.objects.filter(account_id=migration.account_id, retired_at__isnull=True).first()
        if hostname is None:
            self._move(migration, token, "quiescing")
            return
        if migration.cancel_requested:
            self._abort(migration, token, ValueError("Migration cancelled while lowering the TTL"))
            return
        outcome = account_hostname_service.lower_account_hostname_ttl(hostname)
        if outcome.is_err():
            self._abort(migration, token, DefiniteMigrationFailureError(outcome.unwrap_err()))
            return
        state = outcome.unwrap()
        if state == "waiting":
            # Published, not confirmed: keep the state and come back, bounded by the service's deadline.
            hostname.refresh_from_db()
            until = timezone.now() + timedelta(seconds=TTL_POLL_SECONDS)
            if hostname.ttl_confirmed_at is not None and hostname.previous_ttl:
                until = max(until, hostname.ttl_confirmed_at + timedelta(seconds=hostname.previous_ttl))
            raise MigrationDeferredError(until, "waiting for the lower TTL and old cached answers")
        if state not in {"converged", "skipped:not_published"}:
            self._abort(migration, token, DefiniteMigrationFailureError(f"Account name TTL was not lowered: {state}"))
            return
        self._move(migration, token, "quiescing")

    def _restore_ttl(self, migration: VirtualminMigration) -> None:
        """Undo the cutover's TTL change; a legacy migration or an unlowered name is a no-op."""
        hostname = AccountHostname.objects.filter(
            account_id=migration.account_id, retired_at__isnull=True, previous_ttl__isnull=False
        ).first()
        if hostname is None:
            return
        restored = account_hostname_service.restore_account_hostname_ttl(hostname)
        if restored.is_err():
            raise ValueError(f"TTL restore failed: {restored.unwrap_err()}")
        state = restored.unwrap()
        if state not in {"restored", "noop"}:
            raise ValueError(f"TTL restore refused: {state}")

    def _barrier(  # noqa: PLR0913  # Every barrier input is explicit; the node validates each
        self,
        migration: VirtualminMigration,
        action: str,
        *,
        token: str,
        previous_token: str = "",
        saved_token: str = "",
        record: BarrierRecord | None = None,
        server: VirtualminServer | None = None,
        killed_at: int = 0,
    ) -> Result[BarrierStep, str]:
        """Run one barrier action on the source node; the variables refuse what the node would."""
        remote = migration.pre_migration_snapshot["remote"]
        domain_id = str(listing_attribute(remote["attributes"], "ID") or "")
        variables = barrier_variables(
            action,
            domain=migration.account.domain,
            domain_id=domain_id,
            token=token,
            previous_token=previous_token,
            saved_token=saved_token,
            record=record,
            killed_at=killed_at,
        )
        if variables.is_err():
            return Err(variables.unwrap_err(), retriability=retriability_of(variables))
        return run_barrier(server or migration.source_server, variables.unwrap())

    def _barrier_quiesce(self, migration: VirtualminMigration, token: UUID) -> None:
        """Contract step 2 on a cutover: persist the record, apply the fence, verify it holds."""
        state = migration.barrier_state or {}
        barrier_token = str(state.get("token") or migration.pk)
        if "record" in state:
            record = BarrierRecord.from_state(state["record"])
        else:
            recorded = self._barrier(migration, "record", token=barrier_token)
            if recorded.is_err():
                self._abort(migration, token, DefiniteMigrationFailureError(recorded.unwrap_err()))
                return
            step = recorded.unwrap()
            if not step.ok:
                self._abort(migration, token, DefiniteMigrationFailureError(f"Barrier record refused: {step.reason}"))
                return
            record = BarrierRecord.from_state(step.payload)
            if record.is_ok():
                state = {"record": record.unwrap().as_state(), "token": barrier_token, "recorded": step.payload}
                self._store_barrier_state(migration, token, state)
        if record.is_err():
            raise ValueError(f"The original barrier record is unusable: {record.unwrap_err()}")
        for action in ("apply", "verify"):
            result = self._barrier(
                migration,
                action,
                token=barrier_token,
                record=record.unwrap(),
                killed_at=int(state.get("killed_at") or 0),
            )
            if result.is_err():
                self._abort(migration, token, DefiniteMigrationFailureError(result.unwrap_err()))
                return
            step = result.unwrap()
            if not step.ok:
                self._abort(migration, token, DefiniteMigrationFailureError(f"Barrier {action} failed: {step.reason}"))
                return
            if action == "apply":
                state = {**state, "killed_at": int(step.payload.get("killed_at") or 0)}
                self._store_barrier_state(migration, token, state)
        self._move(
            migration,
            token,
            "backing_up",
            source_disabled_at=migration.source_disabled_at or timezone.now(),
        )

    def _store_barrier_state(self, migration: VirtualminMigration, token: UUID, state: dict[str, Any]) -> None:
        """Persist barrier evidence only while this worker still owns an unexpired lease."""
        updated = VirtualminMigration.objects.filter(
            pk=migration.pk, lease_token=token, worker_lease_expires_at__gt=timezone.now()
        ).update(  # fsm-bypass: evidence only; the status moves through _move
            barrier_state=state, updated_at=timezone.now()
        )
        if not updated:
            raise MigrationLeaseLostError("Barrier evidence write lost the migration lease")
        migration.barrier_state = state

    def _release_barrier(self, migration: VirtualminMigration, token: UUID) -> None:
        """Undo the fence from the persisted record; a migration that never fenced is a no-op."""
        state = migration.barrier_state or {}
        if not state.get("record") or "release" in state:
            return
        record = BarrierRecord.from_state(state["record"])
        if record.is_err():
            raise ValueError(f"Barrier record unusable: {record.unwrap_err()}")
        step = self._barrier(
            migration,
            "release",
            token=str(uuid4()),
            previous_token=str(state.get("token") or ""),
            saved_token=str(state.get("token") or ""),
            record=record.unwrap(),
        )
        if step.is_err():
            raise ValueError(step.unwrap_err())
        result = step.unwrap()
        if not result.ok:
            raise ValueError(f"Barrier release not confirmed: {result.reason}")
        self._store_barrier_state(migration, token, {**state, "release": result.payload})

    def _quiesce(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            self._barrier_quiesce(migration, token)
            return
        source = self._domain(migration.source_server, migration.account.domain)
        if migration.pre_migration_snapshot["status"] == "suspended":
            if source["enabled"] is not False:
                raise ValueError("Previously suspended source is no longer quiesced")
            self._move(migration, token, "backing_up")
            return
        if source["enabled"] is True:
            try:
                self._command(migration, migration.source_server, "disable-domain")
            except DefiniteMigrationFailureError as error:
                self._abort(migration, token, error)
                return
            source = self._domain(migration.source_server, migration.account.domain)
        if source["enabled"] is not False:
            if source["enabled"] is True:
                self._abort(migration, token, ValueError("Source disable was a no-op"))
                return
            raise ValueError("Source disable could not be verified")
        self._move(
            migration,
            token,
            "backing_up",
            source_disabled_at=migration.source_disabled_at or timezone.now(),
        )

    def _backup(self, migration: VirtualminMigration, token: UUID) -> None:
        from .migration_target_hold import capture_backup_owner_shadow  # noqa: PLC0415

        try:
            self._move(migration, token, "backing_up")
            source = self._domain(migration.source_server, migration.account.domain)
            self._move(migration, token, "backing_up")
            capture_backup_owner_shadow(
                migration.source_server,
                domain=migration.account.domain,
                owner=migration.account.virtualmin_username,
                domain_id=str(listing_attribute(source["attributes"], "ID")),
                archive_name=migration.archive_name,
                operation_id=migration.pk,
                require_fenced=migration.contract == VirtualminMigration.Contract.CUTOVER,
            )
            self._move(migration, token, "backing_up")
            self._command(
                migration,
                migration.source_server,
                "backup-domain",
                **migration_backup_params(migration.archive_name),
            )
        except DefiniteMigrationFailureError as error:
            self._abort(migration, token, error)
            return
        self._move(migration, token, "fetching")

    def _transfer(self, migration: VirtualminMigration, token: UUID) -> None:
        fetching = migration.status == "fetching"
        reservation_name = migration.archive_name if fetching else ""
        try:
            self.spool.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.spool.is_symlink() or self.spool.stat().st_mode & 0o077:
                raise ValueError("Migration spool must be a private directory")
            if fetching:
                from .spool import acquire_spool_reservation, estimated_transfer_bytes  # noqa: PLC0415

                reserved = acquire_spool_reservation(
                    self.spool,
                    reservation_name,
                    estimated_transfer_bytes(migration.account.current_disk_usage_mb or 0),
                    f"migration:{migration.pk}",
                    self.transfer_timeout + 300,
                )
                if reserved.is_err():
                    raise ValueError(reserved.unwrap_err())
            variables: dict[str, Any] = {
                "archive_name": migration.archive_name,
                "spool_dir": str(self.spool),
                "spool_free_bytes": shutil.disk_usage(self.spool).free,
                "expected_sha256": migration.archive_sha256,
            }
            server = migration.source_server if fetching else migration.target_server
            playbook = "virtualmin_migrate_fetch.yml" if fetching else "virtualmin_migrate_push.yml"
            result = AnsibleService().run_playbook(
                server.node_deployment, playbook, variables, timeout_seconds=self.transfer_timeout
            )
            if result.is_err() or not result.unwrap().success:
                raise ValueError(f"Migration {playbook} failed")
            checksums = set(re.findall(r"MIGRATE_SHA256=([0-9a-f]{64})(?![0-9a-f])", result.unwrap().stdout))
            if fetching and len(checksums) != 1:
                raise ValueError("Fetch did not return exactly one SHA-256")
        except Exception as error:
            self._abort(migration, token, error)
            return
        finally:
            if fetching:
                from .spool import release_spool_reservation  # noqa: PLC0415

                release_spool_reservation(reservation_name)
        fields: dict[str, object] = {"archive_sha256": checksums.pop()} if fetching else {}
        self._move(migration, token, "pushing" if fetching else "restoring", **fields)

    def _restore(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            from .migration_target_hold import restore_held_target  # noqa: PLC0415

            restore_held_target(
                self,
                migration,
                token,
                [{"archive_name": migration.archive_name, "checksum_sha256": migration.archive_sha256}],
            )
            return
        self._move(migration, token, "restoring", restore_issued=True)
        try:
            self._command(
                migration,
                migration.target_server,
                "restore-domain",
                **restore_domain_params(
                    domain=migration.account.domain, source=f"{REMOTE_ARCHIVE_DIR}/{migration.archive_name}"
                ),
            )
        except DefiniteMigrationFailureError as error:
            self._abort(migration, token, error, target_delete_allowed=True)
            return
        self._move(migration, token, "verifying")

    def _verify(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.contract == VirtualminMigration.Contract.CUTOVER and not migration.barrier_state.get(
            "held_restore_complete"
        ):
            raise ValueError("The cutover has no verified target write hold; staff must review the restored copy")
        target = self._domain(migration.target_server, migration.account.domain)
        source = migration.pre_migration_snapshot["remote"]
        if target["username"] != source["username"] or target["enabled"] is not False:
            raise ValueError("Restored domain owner or disabled state differs from snapshot")
        for key in ("Server byte quota", "Bandwidth limit", "Features"):
            # Either key form: text label or the 8.x JSON snake_case key.
            expected = listing_attribute(source["attributes"], key)
            if not expected:
                continue
            actual = listing_attribute(target["attributes"], key)
            if key == "Features":
                expected, actual = " ".join(sorted(expected.split())), " ".join(sorted(actual.split()))
            if actual != expected:
                raise ValueError(f"Restored domain differs from snapshot: {key}")
        # The archive carries the customer domain only: put the account name back on the target,
        # disabled. The activation's cascading enable turns it on with the account (ADR-0061 P1.7).
        named = ensure_on_recreated_node(migration.account, migration.target_server, enabled=False)
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            from .account_hostname_config import account_zone_psl_shipped  # noqa: PLC0415

            outcome = named.unwrap() if named.is_ok() else None
            if (
                outcome is None
                or outcome.enabled
                or not outcome.certificate_installed
                or (account_zone_psl_shipped() and not outcome.linked)
            ):
                self._abort(migration, token, ValueError("The target account name and certificate are not ready"))
                return
            from .migration_bridge_service import prepare_bridge  # noqa: PLC0415

            self._store_barrier_state(migration, token, {**migration.barrier_state, "bridge_prepared": True})
            prepared = prepare_bridge(migration)
            if prepared.is_err():
                self._abort(migration, token, ValueError(f"Bridge preparation failed: {prepared.unwrap_err()}"))
                return
            from .migration_routing import prepare_frontend_snapshot  # noqa: PLC0415

            try:
                frontend_state = prepare_frontend_snapshot(migration, prepared.unwrap())
            except ValueError as error:
                self._abort(migration, token, error)
                return
            self._store_barrier_state(
                migration,
                token,
                {
                    **migration.barrier_state,
                    **frontend_state,
                },
            )
            self._commit_cutover(migration, token)
            return
        if named.is_err():
            logger.warning("⚠️ [VirtualminMigration] Account name not ensured on the target: %s", named.unwrap_err())
        self._move(migration, token, "activating")

    def _commit_cutover(self, migration: VirtualminMigration, token: UUID) -> None:
        try:
            self._commit_cutover_transaction(migration, token)
        except MigrationCancelledBeforeCommitError as error:
            self._abort(migration, token, error)

    def _commit_cutover_transaction(self, migration: VirtualminMigration, token: UUID) -> None:
        """The sole point of no return, before target activation or any routing publication."""
        if self._domain(migration.source_server, migration.account.domain)["enabled"] is not False:
            raise ValueError("The source is not fenced before the ownership commit")
        with transaction.atomic():
            locked = VirtualminMigration.objects.select_for_update().get(pk=migration.pk)
            if locked.cancel_requested:
                raise MigrationCancelledBeforeCommitError("Migration cancelled before the ownership commit")
            account = VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
            hostname_id = (
                AccountHostname.objects.filter(account=account, retired_at__isnull=True)
                .values_list("pk", flat=True)
                .first()
            )
            hostname = account_hostname_service.lock_for_publication(hostname_id) if hostname_id else None
            if hostname is None:
                raise ValueError("The cutover lost its account hostname before the commit")
            if (
                account.server_id != migration.source_server_id
                or hostname.target_server_id != migration.source_server_id
            ):
                raise ValueError("Account or hostname ownership changed before the commit")
            self._move(migration, token, "activating", cutover_committed_at=timezone.now())
            account.server = migration.target_server
            account.save(update_fields=["server", "updated_at"])
            hostname.target_server = migration.target_server
            hostname.save(update_fields=["target_server", "updated_at"])
            MigrationBridge.objects.create(
                migration=migration,
                source_server=migration.source_server,
                target_server=migration.target_server,
                domain=account.domain,
                evidence={
                    key: migration.barrier_state[key]
                    for key in ("certificate_not_after", "dns_names", "frontend_dns_before")
                },
            )
            VirtualminServer.objects.filter(pk=migration.target_server_id).update(
                current_domains=F("current_domains") + 1, updated_at=timezone.now()
            )

    def _activate(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            if migration.cutover_committed_at is None:
                raise ValueError("The ownership commit must precede target activation")
            from .migration_bridge_service import activate_target  # noqa: PLC0415
            from .migration_enabled_state import (  # noqa: PLC0415  # Same-app activation policy seam.
                activation_guard,
                converge_before_release,
                current_policy,
                record_activation,
            )
            from .migration_target_hold import run_held_target_node  # noqa: PLC0415

            with activation_guard(migration, token) as account:
                enabled = current_policy(account).enabled
                run_held_target_node(migration, "activate", enabled=enabled)
                self._move(migration, token, "activating")
                activated = activate_target(migration, enabled=enabled)
                if activated.is_err():
                    if retriability_of(activated) is not Retriability.NOT_RETRIABLE:
                        raise MigrationDeferredError(
                            timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), activated.unwrap_err()
                        )
                    raise ValueError(f"Target activation failed: {activated.unwrap_err()}")
                policy = converge_before_release(self, migration, token, account)
                self._release_target_hold(migration)
                record_activation(self, migration, token, policy, "bridging")
            return
        if migration.pre_migration_snapshot["status"] != "suspended":
            self._command(migration, migration.target_server, "enable-domain")
            if self._domain(migration.target_server, migration.account.domain)["enabled"] is not True:
                raise ValueError("Target enable could not be verified")
        elif self._domain(migration.target_server, migration.account.domain)["enabled"] is not False:
            raise ValueError("Target did not preserve suspension")
        self._move(migration, token, "repointing")

    @staticmethod
    def _release_target_hold(migration: VirtualminMigration) -> None:
        from .migration_target_hold import held_pair_variables  # noqa: PLC0415
        from .virtualmin_pair_restore import run_pair_step  # noqa: PLC0415

        result = run_pair_step(
            migration.target_server,
            {**held_pair_variables(migration), "pair_action": "release"},
            token=str(migration.pk),
            domain_id=str(migration.barrier_state["target_domain_id"]),
            timeout_seconds=180,
        )
        if result.is_err() or result.unwrap().outcome != "released":
            raise MigrationDeferredError(
                timezone.now() + timedelta(seconds=TTL_POLL_SECONDS),
                "Waiting for the target maintenance hold to release",
            )

    def _bridge(self, migration: VirtualminMigration, token: UUID) -> None:
        from .migration_bridge_service import install_bridge, verify_bridge  # noqa: PLC0415

        if migration.cutover_committed_at is None:
            raise ValueError("A bridge requires the ownership commit")
        if source_is_fenced(migration):
            self._move(migration, token, "repointing")
            return
        installed = install_bridge(migration)
        verified = verify_bridge(migration) if installed.is_ok() else installed
        if verified.is_err():
            if retriability_of(verified) is not Retriability.NOT_RETRIABLE:
                raise MigrationDeferredError(
                    timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), verified.unwrap_err()
                )
            raise ValueError(f"The source bridge was not verified: {verified.unwrap_err()}")
        with transaction.atomic():
            self._move(migration, token, "repointing")
            bridge = MigrationBridge.objects.select_for_update().get(migration=migration)
            if bridge.status == MigrationBridge.Status.PENDING:
                bridge.activate()
                bridge.save()

    def _converge_cutover(self, migration: VirtualminMigration, token: UUID) -> None:
        from dataclasses import asdict  # noqa: PLC0415

        from apps.infrastructure.dns_agreement import authoritative_agreement, record_progress  # noqa: PLC0415

        hostname = AccountHostname.objects.get(account_id=migration.account_id, retired_at__isnull=True)
        if migration.cutover_committed_at is None or hostname.target_server_id != migration.target_server_id:
            raise ValueError("DNS convergence requires committed target ownership")
        if (
            migration.contract != VirtualminMigration.Contract.RECOVERY
            and not MigrationBridge.objects.filter(migration=migration, status="active").exists()
            and not source_is_fenced(migration)
        ):
            raise ValueError("DNS convergence requires a verified active bridge")
        published = account_hostname_service.sync_account_hostname(hostname)
        if published.is_err():
            hostname.refresh_from_db()
            self._store_barrier_state(
                migration,
                token,
                {
                    **migration.barrier_state,
                    "dns": {
                        "checked_at": timezone.now().isoformat(),
                        "detail": published.unwrap_err(),
                        "records": {
                            family: {"agreed": False, "provider": entry} for family, entry in hostname.records.items()
                        },
                    },
                },
            )
            raise MigrationDeferredError(timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), published.unwrap_err())
        target = migration.target_server
        ipv4 = target.ipv4_address
        if not ipv4:
            raise ValueError("The committed target has no IPv4 address")
        agreement = authoritative_agreement(hostname.fqdn, ipv4, target.ipv6_address or None)
        self._store_barrier_state(
            migration,
            token,
            {
                **migration.barrier_state,
                "dns": {
                    "checked_at": timezone.now().isoformat(),
                    **asdict(agreement),
                    "records": record_progress(agreement, ipv4, target.ipv6_address or None),
                },
            },
        )
        if not agreement.agreed:
            raise MigrationDeferredError(
                timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), agreement.detail or "Waiting for DNS convergence"
            )
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            from .migration_routing import observe_frontends  # noqa: PLC0415

            bridge = MigrationBridge.objects.get(migration=migration)
            routing, _waiting = observe_frontends(bridge)
            with transaction.atomic():
                self._store_barrier_state(migration, token, {**migration.barrier_state, "frontend_dns": routing})
                bridge = MigrationBridge.objects.select_for_update().get(pk=bridge.pk)
                bridge.evidence = {**bridge.evidence, "routing": routing}
                bridge.save(update_fields=["evidence", "updated_at"])
        self._prepare_completion(migration, token)
        with transaction.atomic():
            self._move(migration, token, "repointing", dns_converged_at=timezone.now())
            self._finish(migration, token, "completed")
            from .migration_bridge_cleanup import schedule_bridge_cleanup  # noqa: PLC0415

            if migration.contract != VirtualminMigration.Contract.RECOVERY:
                transaction.on_commit(lambda: schedule_bridge_cleanup(migration.pk), robust=True)

    def _prepare_completion(self, migration: VirtualminMigration, token: UUID) -> None:
        """An operation may finish its private staging cleanup before releasing account exclusion."""

    def _repoint(self, migration: VirtualminMigration, token: UUID) -> None:
        # Final write-barrier check: an external writer (drift enforcement, an
        # operator) re-enabling the quiesced source after backup would create a
        # split-brain retained copy — park for review instead of completing.
        # Require an AFFIRMATIVE disabled state: an unknown Status (None) is
        # not proof the source stayed quiesced.
        if (
            not source_is_fenced(migration)
            and self._domain(migration.source_server, migration.account.domain)["enabled"] is not False
        ):
            raise ValueError("Source domain is no longer verifiably quiesced (re-enabled by an external writer?)")
        if migration.contract == VirtualminMigration.Contract.CUTOVER:
            self._converge_cutover(migration, token)
            return
        with transaction.atomic():
            self._move(migration, token, "repointing")
            account = VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
            if account.server_id not in {migration.source_server_id, migration.target_server_id}:
                raise ValueError("Account ownership changed during migration")
            account.server = migration.target_server
            account.save(update_fields=["server", "updated_at"])
            # The restored domain occupies target capacity now; the reservation
            # row dies with this completion, so account for it immediately. Any
            # double count against the 6-hourly stats snapshot over-counts (the
            # safe direction) and self-heals on the next snapshot.
            VirtualminServer.objects.filter(pk=migration.target_server_id).update(
                current_domains=F("current_domains") + 1, updated_at=timezone.now()
            )
            self._finish(migration, token, "completed")

    def _begin(self, migration: VirtualminMigration, token: UUID) -> None:
        self._move(
            migration,
            token,
            "lowering_ttl" if migration.contract == VirtualminMigration.Contract.CUTOVER else "quiescing",
        )

    def execute(self, migration: VirtualminMigration, lease_token: UUID) -> Result[VirtualminMigration, str]:
        handlers = {
            "pending": self._begin,
            "lowering_ttl": self._lower_ttl,
            "quiescing": self._quiesce,
            "backing_up": self._backup,
            "fetching": self._transfer,
            "pushing": self._transfer,
            "restoring": self._restore,
            "verifying": self._verify,
            "activating": self._activate,
            "bridging": self._bridge,
            "repointing": self._repoint,
            "compensating": self._compensate,
        }
        try:
            if migration.resume_after is not None:
                self._move(migration, lease_token, migration.status, resume_after=None)
            while migration.status in handlers and not migration.parked_phase:
                if not migration.renew_lease(lease_token, self.lease_ttl):
                    raise MigrationLeaseLostError("Migration lease expired or ownership changed")
                migration.refresh_from_db()
                if migration.cancel_requested and migration.status in PRE_COMMIT_STATUSES:
                    self._abort(migration, lease_token, ValueError("Migration cancelled"))
                    break
                logger.info("🚀 [VirtualminMigration] migration=%s phase=%s", migration.pk, migration.status)
                phase = migration.status
                handlers[phase](migration, lease_token)
                if (
                    migration.contract in {VirtualminMigration.Contract.CUTOVER, VirtualminMigration.Contract.RECOVERY}
                    and phase in {"quiescing", "backing_up", "fetching", "pushing", "restoring", "verifying"}
                    and migration.status != phase
                    and migration.status not in _TERMINAL_STATUSES
                    and not migration.parked_phase
                ):
                    raise MigrationDeferredError(
                        timezone.now() + timedelta(seconds=1), "Continue at the next migration checkpoint"
                    )
        except MigrationDeferredError as deferral:
            self._defer(migration, lease_token, deferral)
        except Exception as error:
            logger.exception("🔥 [VirtualminMigration] Migration interrupted: %s", migration.pk)
            migration.refresh_from_db()
            if not migration.renew_lease(lease_token, self.lease_ttl):
                return Err("Migration lease lost; current owner must resolve the phase")
            if migration.status == "compensating":
                self._park_compensation(migration, lease_token, str(error))
            else:
                if migration.cutover_committed_at is not None:
                    self._move(migration, lease_token, migration.status, parked_phase=migration.status)
                self._finish(migration, lease_token, "needs_review", str(error))
        return Ok(migration)

    def _defer(self, migration: VirtualminMigration, token: UUID, deferral: MigrationDeferredError) -> None:
        from .virtualmin_tasks import schedule_migration_wake  # noqa: PLC0415  # Circular

        migration.refresh_from_db()
        self._move(migration, token, migration.status, resume_after=deferral.until)
        logger.info(
            "🐢 [VirtualminMigration] migration=%s waits in %s until %s: %s",
            migration.pk,
            migration.status,
            deferral.until.isoformat(),
            deferral.reason,
        )
        schedule_migration_wake(migration.pk, deferral.until)

    def run(self, migration_id: UUID) -> Result[MigrationResumeOutcome, str]:
        try:
            migration = VirtualminMigration.objects.select_related(
                "account", "source_server", "target_server", "initiated_by"
            ).get(pk=migration_id)
        except VirtualminMigration.DoesNotExist:
            return Err("migration not found")
        if migration.contract == VirtualminMigration.Contract.RECOVERY and type(self) is VirtualminMigrationService:
            from .virtualmin_recovery_service import VirtualminRecoveryService  # noqa: PLC0415

            return VirtualminRecoveryService().run(migration_id)
        token = uuid4()
        acquired = migration.acquire_lease(token, self.lease_ttl)
        if not acquired:
            logger.info("✅ [VirtualminMigration] BUSY: migration=%s", migration_id)
            return Ok({"action": "busy", "migration_id": str(migration_id), "lease_acquired": False})
        try:
            migration.refresh_from_db()
            policy = RESUME_POLICY.get(migration.status, "review")
            if migration.cutover_committed_at is not None and migration.status in {
                "activating",
                "bridging",
                "repointing",
            }:
                policy = "continue"
            if (
                migration.resume_after is not None
                and migration.status not in _TERMINAL_STATUSES
                and not migration.cancel_requested
            ):
                if migration.resume_after > timezone.now():
                    return Ok({"action": "waiting", "migration_id": str(migration_id), "lease_acquired": True})
                policy = "continue"  # A deferral is a checkpoint, not an interruption
            if migration.parked_phase:
                policy = "stop"
            if policy == "review":
                self._finish(migration, token, "needs_review", f"Interrupted phase: {migration.status}")
            elif policy == "continue":
                result = self.execute(migration, token)
                if result.is_err():
                    return Err(result.unwrap_err())
            return Ok({"action": migration.status, "migration_id": str(migration_id), "lease_acquired": True})
        finally:
            migration.refresh_from_db()
            migration.transition(
                token,
                migration.status,
                migration.status,
                lease_token=None,
                worker_lease_expires_at=None,
            )


def resolve_migration(
    migration: VirtualminMigration, *, resolved_by: User | None, note: str, source_fenced: str = ""
) -> Result[VirtualminMigration, str]:
    """Retry target recovery after commit, compensate before commit, or resolve a legacy operation."""
    service = VirtualminMigrationService()
    invalid_fencing = bool(source_fenced.strip()) and (
        migration.contract != VirtualminMigration.Contract.CUTOVER
        or migration.cutover_committed_at is None
        or migration.status != "needs_review"
        or resolved_by is None
        or not resolved_by.is_staff_user
    )
    token = uuid4()
    if invalid_fencing or not migration.acquire_lease(token, service.lease_ttl):
        return Err(
            "Only staff may attest a fenced source after a cutover has committed"
            if invalid_fencing
            else "Migration is currently owned by a worker; try again shortly"
        )
    migration.refresh_from_db()
    if migration.cutover_committed_at is not None and migration.status == "needs_review":
        with transaction.atomic():
            if source_fenced.strip():
                _record_fenced_source(service, migration, token, source_fenced, resolved_by)
            phase = (
                migration.parked_phase
                if migration.parked_phase in {"activating", "bridging", "repointing"}
                else "activating"
            )
            service._move(migration, token, phase, parked_phase="", error_detail=f"Keep target: {note}")
            service._audit(migration, "keep_target", actor=resolved_by)
            migration.transition(token, phase, phase, lease_token=None, worker_lease_expires_at=None)
            transaction.on_commit(lambda: service._enqueue(migration.pk))
        return Ok(migration)
    if (
        migration.cutover_committed_at is None
        and migration.status in {"needs_review", "compensating"}
        and (migration.contract == VirtualminMigration.Contract.CUTOVER or migration.status == "compensating")
    ):
        state = migration.barrier_state or {}
        if migration.status == "needs_review":
            state = {**state, "source_idle_required": True}
        actor = resolved_by.email if resolved_by else "system"
        service._move(
            migration,
            token,
            "compensating",
            parked_phase="",
            barrier_state=state,
            error_detail=f"Keep source requested by {actor}: {note or 'operator checked remote state'}",
        )
        service._audit(migration, "keep_source", actor=resolved_by)
        migration.transition(token, "compensating", "compensating", lease_token=None, worker_lease_expires_at=None)
        transaction.on_commit(lambda: service._enqueue(migration.pk))
        return Ok(migration)
    if migration.status != "needs_review":
        migration.transition(token, migration.status, migration.status, lease_token=None, worker_lease_expires_at=None)
        return Err("Only a needs_review migration can be resolved manually")
    if migration.contract == VirtualminMigration.Contract.RECOVERY:
        from .virtualmin_recovery_service import VirtualminRecoveryService  # noqa: PLC0415

        try:
            return VirtualminRecoveryService().abandon_precommit(migration, token, actor=resolved_by, note=note)
        finally:
            migration.refresh_from_db()
            migration.transition(
                token, migration.status, migration.status, lease_token=None, worker_lease_expires_at=None
            )
    actor = resolved_by.email if resolved_by else "system"
    detail = f"Manually resolved by {actor}: {note or 'operator confirmed remote state'}"
    service._finish(migration, token, "failed", detail)
    return Ok(migration)


def _record_fenced_source(
    service: VirtualminMigrationService,
    migration: VirtualminMigration,
    token: UUID,
    attestation: str,
    actor: User | None,
) -> None:
    """Keep failed transport visible while routing recovers on the sole writable target."""
    control = {
        "attestation": attestation.strip()[:1000],
        "source_server_id": str(migration.source_server_id),
        "confirmed_by": str(actor.pk) if actor else "",
        "confirmed_at": timezone.now().isoformat(),
    }
    with transaction.atomic():
        service._store_barrier_state(migration, token, {**migration.barrier_state, "source_fenced_control": control})
        bridge = MigrationBridge.objects.select_for_update().get(migration=migration)
        if bridge.status not in {MigrationBridge.Status.FAILED, MigrationBridge.Status.TORN_DOWN}:
            bridge.fail()
        bridge.evidence = {
            **bridge.evidence,
            "source_fenced_control": control,
            "last_error": "Source is fenced and unavailable; retained source and transport still require separate cleanup",
        }
        bridge.save()
        # fsm-bypass: VirtualminServer.status is a CharField; exclude the attested fenced source from placement.
        VirtualminServer.objects.filter(pk=migration.source_server_id).update(
            status="disabled", updated_at=timezone.now()
        )


def resume_migration(job: VirtualminProvisioningJob) -> Result[MigrationResumeOutcome, str]:
    """Acquire a lease, then apply RESUME_POLICY; contention retains the BUSY contract."""
    try:
        migration_id = UUID(str(job.parameters["migration_id"]))
    except (KeyError, TypeError, ValueError):
        return Err("migration not found")
    return VirtualminMigrationService().run(migration_id)
