"""Token-fenced single-domain migration; routing and retained-copy removal are manual."""

from __future__ import annotations

import logging
import re
import shutil
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict
from uuid import UUID, uuid4

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .placement import order_placement_candidates
from .virtualmin_gateway import VirtualminConfig, VirtualminGateway
from .virtualmin_migration_models import VirtualminMigration, account_has_active_migration
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleService as AnsibleRunner
    from apps.users.models import User

logger = logging.getLogger(__name__)

# Archive staging path ON THE REMOTE VIRTUALMIN NODE (sent as an API parameter),
# not a local temporary file — S108's local-tempfile race does not apply.
_REMOTE_ARCHIVE_DIR = "/tmp"  # noqa: S108

# Recovery policy concerns an INTERRUPTED phase, before invoking execute().
RESUME_POLICY = {
    "pending": "continue",  # Preflight evidence exists; no remote mutation issued.
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


def AnsibleService() -> AnsibleRunner:  # noqa: N802  # Lazy constructor preserves the requested mock seam.
    from apps.infrastructure.ansible_service import AnsibleService as Runner  # noqa: PLC0415

    return Runner()


def _scalar(value: object) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value).strip()
    return str(value).strip()


def list_migration_domains(gateway: VirtualminGateway) -> Result[list[dict[str, Any]], str]:
    """Reuse call()'s VirtualminResponseParser output, retaining multiline attributes."""
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
            return Err("Incomplete Virtualmin multiline domain listing")
        values = item["values"]
        state = _scalar(values.get("Status", "")).lower()
        rows.append(
            {
                "domain": str(item["name"]),
                "username": _scalar(values.get("Username", "")),
                "enabled": True if state.startswith("enable") else False if state.startswith("disable") else None,
                "attributes": values,
            }
        )
    if len({row["domain"] for row in rows}) != len(rows):
        return Err("Duplicate domains in Virtualmin listing")
    return Ok(rows)


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
    def _audit(migration: VirtualminMigration, action: str, *, compensation_failure: bool = False) -> None:
        from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

        AuditService.log_event(
            AuditEventData(
                event_type=f"virtualmin_migration_{action}",
                content_object=migration,
                description=f"Migration {migration.pk}: {migration.status}",
                new_values={"status": migration.status, "error_detail": migration.error_detail},
            ),
            AuditContext(
                user=migration.initiated_by,
                actor_type="user" if migration.initiated_by_id else "system",
                metadata={
                    "source_app": "provisioning",
                    "compensation_failure": compensation_failure,
                    "requires_review": action == "needs_review",
                },
            ),
        )

    def _finish(
        self,
        migration: VirtualminMigration,
        token: UUID,
        status: str,
        error: str = "",
        *,
        compensation_failure: bool = False,
    ) -> None:
        with transaction.atomic():
            self._move(migration, token, status, error_detail=error)
            self._audit(migration, status, compensation_failure=compensation_failure)

    def _local_preflight(self, account: VirtualminAccount, target: VirtualminServer) -> None:
        if not self.enabled:
            raise ValueError("Virtualmin migration is disabled")
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
        if account_has_active_migration(account):
            raise ValueError("Account already has an active migration")
        self._admission_preflight(target)

    def _admission_preflight(self, target: VirtualminServer) -> None:
        """Target-capacity and operator-configuration admission checks."""
        if not target.can_host_domain():
            raise ValueError("Target is unhealthy or full")
        if target.current_domains + VirtualminMigration.active_reservations(target) >= target.max_domains:
            raise ValueError("Target capacity is reserved or full")
        if not self.spool.is_absolute():
            raise ValueError("Migration spool directory must be absolute")
        if self.task_timeout + 60 >= int(str(settings.Q_CLUSTER.get("retry", 0))):
            raise ValueError("Migration budget must fit below the Django-Q broker visibility timeout")

    def start_migration(
        self,
        account: VirtualminAccount,
        target_server: VirtualminServer,
        *,
        initiated_by: User | None,
        reason: str = "manual",
        enqueue: bool = True,
    ) -> Result[VirtualminMigration, str]:
        try:
            with transaction.atomic():
                account = VirtualminAccount.objects.select_for_update().select_related("server").get(pk=account.pk)
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
                migration = VirtualminMigration.objects.create(
                    account=account,
                    source_server=account.server,
                    target_server=target,
                    initiated_by=initiated_by,
                    reason=reason,
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
                    owned = [row for row in source_rows if row["username"] == account.virtualmin_username]
                    if len(owned) != 1 or owned[0]["domain"] != account.domain:
                        raise ValueError("Source owner must have exactly one domain: the account's own domain")
                    remote = owned[0]
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
            logger.exception("🔥 [VirtualminMigration] Enqueue failed: migration=%s", migration_id)

    def _command(
        self,
        migration: VirtualminMigration,
        server: VirtualminServer,
        program: str,
        **params: object,
    ) -> None:
        timeout = self.backup_timeout if program in {"backup-domain", "restore-domain"} else 30
        result = self._gateway(server).call(
            program, {"domain": migration.account.domain, **params}, timeout_seconds=timeout
        )
        if result.is_err():
            if retriability_of(result) is not Retriability.UNKNOWN:
                raise DefiniteMigrationFailureError(str(result.unwrap_err()))
            raise RuntimeError(f"Ambiguous {program}: {result.unwrap_err()}")
        response = result.unwrap()
        if not response.success:
            raise DefiniteMigrationFailureError(f"{program} rejected: {response.data.get('error', response.data)}")
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

    def _quiesce(self, migration: VirtualminMigration, token: UUID) -> None:
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
                dest=f"{_REMOTE_ARCHIVE_DIR}/{migration.archive_name}",
                **{"all-features": ""},
            )
        except DefiniteMigrationFailureError as error:
            self._abort(migration, token, error)
            return
        self._move(migration, token, "fetching")

    def _transfer(self, migration: VirtualminMigration, token: UUID) -> None:
        fetching = migration.status == "fetching"
        try:
            self.spool.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.spool.is_symlink() or self.spool.stat().st_mode & 0o077:
                raise ValueError("Migration spool must be a private directory")
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
        fields: dict[str, object] = {"archive_sha256": checksums.pop()} if fetching else {}
        self._move(migration, token, "pushing" if fetching else "restoring", **fields)

    def _restore(self, migration: VirtualminMigration, token: UUID) -> None:
        self._move(migration, token, "restoring", restore_issued=True)
        try:
            self._command(
                migration,
                migration.target_server,
                "restore-domain",
                source=f"{_REMOTE_ARCHIVE_DIR}/{migration.archive_name}",
                **{"all-features": ""},
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
            if key not in source["attributes"]:
                continue
            expected = _scalar(source["attributes"][key])
            actual = _scalar(target["attributes"].get(key, ""))
            if key == "Features":
                expected, actual = " ".join(sorted(expected.split())), " ".join(sorted(actual.split()))
            if actual != expected:
                raise ValueError(f"Restored domain differs from snapshot: {key}")
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
        with transaction.atomic():
            self._move(migration, token, "repointing")
            account = VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
            if account.server_id not in {migration.source_server_id, migration.target_server_id}:
                raise ValueError("Account ownership changed during migration")
            account.server = migration.target_server
            account.save(update_fields=["server", "updated_at"])
            self._finish(migration, token, "completed")

    def execute(self, migration: VirtualminMigration, lease_token: UUID) -> Result[VirtualminMigration, str]:
        handlers = {
            "pending": lambda row, token: self._move(row, token, "quiescing"),
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
            while migration.status in handlers:
                if not migration.renew_lease(lease_token, self.lease_ttl):
                    raise MigrationLeaseLostError("Migration lease expired or ownership changed")
                logger.info("🚀 [VirtualminMigration] migration=%s phase=%s", migration.pk, migration.status)
                handlers[migration.status](migration, lease_token)
        except Exception as error:
            logger.exception("🔥 [VirtualminMigration] Migration interrupted: %s", migration.pk)
            migration.refresh_from_db()
            if not migration.renew_lease(lease_token, self.lease_ttl):
                return Err("Migration lease lost; current owner must resolve the phase")
            self._finish(migration, lease_token, "needs_review", str(error))
        return Ok(migration)

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


def resume_migration(job: VirtualminProvisioningJob) -> Result[MigrationResumeOutcome, str]:
    """Acquire a lease, then apply RESUME_POLICY; contention retains the BUSY contract."""
    try:
        migration_id = UUID(str(job.parameters["migration_id"]))
    except (KeyError, TypeError, ValueError):
        return Err("migration not found")
    return VirtualminMigrationService().run(migration_id)
