"""Token-fenced single-domain migration; routing and retained-copy removal are manual."""

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
    is_customer_domain_row,
    listing_attribute,
    listing_enabled,
)
from .virtualmin_gateway import explicit_rejection as _explicit_rejection
from .virtualmin_migration_models import (
    _TERMINAL_STATUSES,
    PRE_COMMIT_STATUSES,
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
    "activating": "review",  # Enable may have succeeded; no automatic compensation.
    "repointing": "continue",  # Repeat the fenced local transaction only.
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


def list_migration_domains(gateway: VirtualminGateway, *, strict: bool = True) -> Result[list[dict[str, Any]], str]:
    """Reuse call()'s VirtualminResponseParser output, retaining multiline attributes.

    strict=True (migration admission) treats any malformed row as fatal — a
    listing that cannot be fully trusted must not gate a collision check.
    strict=False (account sync) skips malformed rows so one odd header or
    separator row cannot abort a whole server's sync.
    """
    result = gateway.call("list-domains", {"multiline": ""})
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
    return 2 * backup + 2 * transfer + 600


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
        timeout = self.backup_timeout if program in {"backup-domain", "restore-domain"} else 30
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
        logger.warning("⚠️ [VirtualminMigration] Rollback: migration=%s", migration.pk)
        try:
            if migration.status != "compensating":
                self._move(migration, token, "compensating")
            self._release_barrier(migration)
            self._restore_ttl(migration)
            if target_delete_allowed:
                if not migration.restore_issued:
                    raise ValueError("Target deletion lacks restore-issued evidence")
                self._command(migration, migration.target_server, "delete-domain")
            if migration.source_disabled_at and migration.pre_migration_snapshot["status"] != "suspended":
                self._command(migration, migration.source_server, "enable-domain")
                if self._domain(migration.source_server, migration.account.domain)["enabled"] is not True:
                    raise ValueError("Source re-enable could not be verified")
        except Exception as error:
            self._finish(migration, token, "needs_review", f"Compensation failed: {error}", compensation_failure=True)
            return
        self._finish(migration, token, "rolled_back", migration.error_detail)

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
            raise MigrationDeferredError(
                timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), "waiting for the lower TTL"
            )
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

    def _barrier(
        self,
        migration: VirtualminMigration,
        action: str,
        *,
        token: str,
        previous_token: str = "",
        record: BarrierRecord | None = None,
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
            record=record,
        )
        if variables.is_err():
            return Err(variables.unwrap_err(), retriability=retriability_of(variables))
        return run_barrier(migration.source_server, variables.unwrap())

    def _barrier_quiesce(self, migration: VirtualminMigration, token: UUID) -> None:
        """Contract step 2 on a cutover: persist the record, apply the fence, verify it holds."""
        barrier_token = str(migration.pk)
        recorded = self._barrier(migration, "record", token=barrier_token)
        if recorded.is_err():
            self._abort(migration, token, DefiniteMigrationFailureError(recorded.unwrap_err()))
            return
        step = recorded.unwrap()
        if not step.ok:
            self._abort(migration, token, DefiniteMigrationFailureError(f"Barrier record refused: {step.reason}"))
            return
        record = BarrierRecord.from_state(step.payload)
        if record.is_err():
            self._abort(migration, token, DefiniteMigrationFailureError(record.unwrap_err()))
            return
        state = {"record": record.unwrap().as_state(), "token": barrier_token, "recorded": step.payload}
        # fsm-bypass: barrier evidence, not a state move; the lease token fences this writer.
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=state, updated_at=timezone.now())
        migration.refresh_from_db()
        for action in ("apply", "verify"):
            result = self._barrier(migration, action, token=barrier_token, record=record.unwrap())
            if result.is_err():
                self._abort(migration, token, DefiniteMigrationFailureError(result.unwrap_err()))
                return
            step = result.unwrap()
            if not step.ok:
                self._abort(migration, token, DefiniteMigrationFailureError(f"Barrier {action} failed: {step.reason}"))
                return
        self._move(
            migration,
            token,
            "backing_up",
            source_disabled_at=migration.source_disabled_at or timezone.now(),
        )

    def _release_barrier(self, migration: VirtualminMigration) -> None:
        """Undo the fence from the persisted record; a migration that never fenced is a no-op."""
        state = migration.barrier_state or {}
        if not state.get("record"):
            return
        record = BarrierRecord.from_state(state["record"])
        if record.is_err():
            raise ValueError(f"Barrier record unusable: {record.unwrap_err()}")
        step = self._barrier(
            migration,
            "release",
            token=str(uuid4()),
            previous_token=str(state.get("token") or ""),
            record=record.unwrap(),
        )
        if step.is_err():
            raise ValueError(step.unwrap_err())
        result = step.unwrap()
        if not result.ok:
            raise ValueError(f"Barrier release not confirmed: {result.reason}")
        state = {**state, "release": result.payload}
        # fsm-bypass: release evidence, not a state move; the row's own transition records the outcome.
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=state, updated_at=timezone.now())
        migration.barrier_state = state

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
        try:
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
        if named.is_err():
            logger.warning("⚠️ [VirtualminMigration] Account name not ensured on the target: %s", named.unwrap_err())
        self._move(migration, token, "activating")

    def _activate(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.pre_migration_snapshot["status"] != "suspended":
            self._command(migration, migration.target_server, "enable-domain")
            if self._domain(migration.target_server, migration.account.domain)["enabled"] is not True:
                raise ValueError("Target enable could not be verified")
        elif self._domain(migration.target_server, migration.account.domain)["enabled"] is not False:
            raise ValueError("Target did not preserve suspension")
        self._move(migration, token, "repointing")

    def _repoint(self, migration: VirtualminMigration, token: UUID) -> None:
        # Final write-barrier check: an external writer (drift enforcement, an
        # operator) re-enabling the quiesced source after backup would create a
        # split-brain retained copy — park for review instead of completing.
        # Require an AFFIRMATIVE disabled state: an unknown Status (None) is
        # not proof the source stayed quiesced.
        if self._domain(migration.source_server, migration.account.domain)["enabled"] is not False:
            raise ValueError("Source domain is no longer verifiably quiesced (re-enabled by an external writer?)")
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

    def execute(self, migration: VirtualminMigration, lease_token: UUID) -> Result[VirtualminMigration, str]:
        handlers = {
            "pending": lambda row, token: self._move(
                row, token, "lowering_ttl" if row.contract == VirtualminMigration.Contract.CUTOVER else "quiescing"
            ),
            "lowering_ttl": self._lower_ttl,
            "quiescing": self._quiesce,
            "backing_up": self._backup,
            "fetching": self._transfer,
            "pushing": self._transfer,
            "restoring": self._restore,
            "verifying": self._verify,
            "activating": self._activate,
            "repointing": self._repoint,
        }
        try:
            if migration.resume_after is not None:
                self._move(migration, lease_token, migration.status, resume_after=None)
            while migration.status in handlers:
                if not migration.renew_lease(lease_token, self.lease_ttl):
                    raise MigrationLeaseLostError("Migration lease expired or ownership changed")
                migration.refresh_from_db()
                if migration.cancel_requested and migration.status in PRE_COMMIT_STATUSES:
                    self._abort(migration, lease_token, ValueError("Migration cancelled"))
                    break
                logger.info("🚀 [VirtualminMigration] migration=%s phase=%s", migration.pk, migration.status)
                handlers[migration.status](migration, lease_token)
        except MigrationDeferredError as deferral:
            self._defer(migration, lease_token, deferral)
        except Exception as error:
            logger.exception("🔥 [VirtualminMigration] Migration interrupted: %s", migration.pk)
            migration.refresh_from_db()
            if not migration.renew_lease(lease_token, self.lease_ttl):
                return Err("Migration lease lost; current owner must resolve the phase")
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
        token = uuid4()
        acquired = migration.acquire_lease(token, self.lease_ttl)
        if not acquired:
            logger.info("✅ [VirtualminMigration] BUSY: migration=%s", migration_id)
            return Ok({"action": "busy", "migration_id": str(migration_id), "lease_acquired": False})
        try:
            migration.refresh_from_db()
            policy = RESUME_POLICY.get(migration.status, "review")
            if migration.resume_after is not None and migration.status not in _TERMINAL_STATUSES:
                if migration.resume_after > timezone.now():
                    return Ok({"action": "waiting", "migration_id": str(migration_id), "lease_acquired": True})
                policy = "continue"  # A deferral is a checkpoint, not an interruption
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
    migration: VirtualminMigration, *, resolved_by: User | None, note: str
) -> Result[VirtualminMigration, str]:
    """Operator terminal resolution for a needs_review migration.

    The operator repairs remote state by hand (re-enable the source, remove a
    partial target, ...) and then releases the ownership lock, the capacity
    reservation, and the one-active-migration constraint by failing the row.
    """
    service = VirtualminMigrationService()
    token = uuid4()
    if not migration.acquire_lease(token, service.lease_ttl):
        return Err("Migration is currently owned by a worker; try again shortly")
    migration.refresh_from_db()
    if migration.status != "needs_review":
        migration.transition(token, migration.status, migration.status, lease_token=None, worker_lease_expires_at=None)
        return Err("Only a needs_review migration can be resolved manually")
    actor = resolved_by.email if resolved_by else "system"
    detail = f"Manually resolved by {actor}: {note or 'operator confirmed remote state'}"
    service._finish(migration, token, "failed", detail)
    return Ok(migration)


def resume_migration(job: VirtualminProvisioningJob) -> Result[MigrationResumeOutcome, str]:
    """Acquire a lease, then apply RESUME_POLICY; contention retains the BUSY contract."""
    try:
        migration_id = UUID(str(job.parameters["migration_id"]))
    except (KeyError, TypeError, ValueError):
        return Err("migration not found")
    return VirtualminMigrationService().run(migration_id)
