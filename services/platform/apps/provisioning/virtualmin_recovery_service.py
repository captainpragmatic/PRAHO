"""Backup-based recovery to a fenced replacement node, without contacting the source."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from . import account_hostname_service
from .account_hostname_config import account_zone_psl_shipped
from .account_hostname_lifecycle import ensure_on_recreated_node
from .account_hostname_models import AccountHostname
from .migration_barrier import barrier_variables, run_barrier
from .migration_target_hold import cleanup_held_target, held_pair_variables, restore_held_target, run_held_target_node
from .spool import release_spool_reservation
from .virtualmin_backup_service import VirtualminBackupService, manifest_restore_refusal
from .virtualmin_chain import invalidate_chain
from .virtualmin_gateway import listing_attribute
from .virtualmin_migration_models import MigrationBridge, VirtualminMigration, account_has_active_operation
from .virtualmin_migration_service import MigrationDeferredError, VirtualminMigrationService
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_pair_restore import pair_lineage_refusal, run_pair_step
from .virtualmin_units import modify_quota_parameters

if TYPE_CHECKING:
    from apps.users.models import User

_BACKUP_ID = re.compile(r"^[0-9a-f]{32}$")
_COMPONENTS = ("include_files", "include_databases", "include_email", "include_ssl")
PAIR_ARCHIVES = 2
_MANIFEST_KEYS = frozenset(
    {
        "backup_id",
        "archive_name",
        "checksum_sha256",
        "praho_service_id",
        "domain",
        "status",
        "chain_role",
        "manifest_version",
        "base_backup_id",
        "chain_epoch",
        "node_id",
        "virtualmin_domain_id",
        "fp_before",
        "fp_after",
        "domain_features",
        *_COMPONENTS,
    }
)


def _complete_archive(account: VirtualminAccount, archive: dict[str, Any]) -> str | None:
    if str(archive.get("praho_service_id")) != str(account.service_id) or archive.get("domain") != account.domain:
        return "The backup belongs to another account or domain"
    if archive.get("status") != "completed" or any(archive.get(flag) is not True for flag in _COMPONENTS):
        return "Recovery requires a completed backup of every component"
    if not _BACKUP_ID.fullmatch(str(archive.get("backup_id", ""))):
        return "The backup has an invalid identity"
    return None


def select_recovery_backups(account: VirtualminAccount, archives: list[dict[str, Any]]) -> Result[list[str], str]:
    """Select the latest complete point in time; refuse broken lineage rather than silently losing newer data."""
    if not archives:
        return Err("No retained backup exists for this account")
    try:
        ordered = sorted(archives, key=lambda item: datetime.fromisoformat(item["created_at"]), reverse=True)
    except (KeyError, TypeError, ValueError):
        return Err("Backup inventory contains an invalid creation time")
    latest = ordered[0]
    refusal = _complete_archive(account, latest)
    if refusal:
        return Err(refusal)
    if latest.get("chain_role") == "differential":
        base = next((item for item in ordered if item.get("backup_id") == latest.get("base_backup_id")), None)
        if base is None:
            return Err("The latest differential has no retained base")
        refusal = pair_lineage_refusal(base, latest, service_id=account.service_id, domain=account.domain)
        return Err(refusal) if refusal else Ok([str(base["backup_id"]), str(latest["backup_id"])])
    refusal = manifest_restore_refusal(latest)
    return Err(refusal) if refusal else Ok([str(latest["backup_id"])])


class VirtualminRecoveryService(VirtualminMigrationService):
    """Uses migration leases/exclusion and the same atomic point of no return; no source operations."""

    def start_recovery(  # noqa: PLR0913  # Explicit archive identities and source-fencing attestation
        self,
        account: VirtualminAccount,
        target: VirtualminServer,
        *,
        backup_ids: list[str],
        source_fenced: str,
        initiated_by: User | None = None,
        enqueue: bool = True,
    ) -> Result[VirtualminMigration, str]:
        try:
            if not self.enabled:
                raise ValueError("Virtualmin migration and recovery are disabled")
            if not source_fenced.strip():
                raise ValueError("Confirm the old node is powered off or otherwise fenced before applying recovery")
            if not 1 <= len(backup_ids) <= PAIR_ARCHIVES or any(
                not _BACKUP_ID.fullmatch(value) for value in backup_ids
            ):
                raise ValueError("Recovery needs one full archive or an exact base/differential pair")
            with transaction.atomic():
                locked = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=account.pk)
                servers = {
                    server.pk: server
                    for server in VirtualminServer.objects.select_for_update(no_key=True)
                    .filter(pk__in=(locked.server_id, target.pk))
                    .order_by("pk")
                }
                source, target = servers[locked.server_id], servers[target.pk]
                if locked.server_id == target.pk or locked.status not in {"active", "suspended"}:
                    raise ValueError("Recover an active or suspended account onto a different node")
                if not AccountHostname.objects.filter(
                    account=locked, retired_at__isnull=True, target_server_id=locked.server_id
                ).exists():
                    raise ValueError("Recovery requires the account's existing live name on its original node")
                if account_has_active_operation(locked) or locked.restore_hold:
                    raise ValueError("Resolve the account's existing operation or restore hold before recovery")
                from .managed_dns_service import assert_move_ready  # noqa: PLC0415  # Customer zone integration

                assert_move_ready(locked)
                if MigrationBridge.objects.filter(migration__account=locked).exclude(status="torn_down").exists():
                    raise ValueError("Resolve the account's retained bridge before recovery")
                if target.status != "active" or getattr(target, "node_deployment", None) is None:
                    raise ValueError("Recovery needs an active managed target")
                self._admission_preflight(target)
                rows = self._listing(self._gateway(target))
                if any(row["domain"] == locked.domain or row["username"] == locked.virtualmin_username for row in rows):
                    raise ValueError("The recovery target already holds the domain or its owner")
                invalidate_chain(locked)
                source.status = "disabled"  # fsm-bypass: the fenced node is unavailable for placement
                source.save(update_fields=["status", "updated_at"])
                migration = VirtualminMigration.objects.create(
                    account=locked,
                    source_server=source,
                    target_server=target,
                    contract=VirtualminMigration.Contract.RECOVERY,
                    reason=VirtualminMigration.Reason.RECOVERY,
                    initiated_by=initiated_by,
                    pre_migration_snapshot={
                        "domain": locked.domain,
                        "status": locked.status,
                        "remote": {"username": locked.virtualmin_username, "attributes": {}},
                    },
                    barrier_state={"recovery_backups": backup_ids, "source_fenced": source_fenced.strip()[:1000]},
                )
                self._audit(migration, "started")
                if enqueue:
                    transaction.on_commit(lambda: self._enqueue(migration.pk))
            return Ok(migration)
        except (ValueError, IntegrityError) as error:
            return Err(str(error))

    def _begin(self, migration: VirtualminMigration, token: UUID) -> None:
        if not migration.barrier_state.get("source_fenced"):
            raise ValueError("Recovery has no source-fencing attestation")
        self._move(migration, token, "fetching")

    def _transfer(self, migration: VirtualminMigration, token: UUID) -> None:
        store = VirtualminBackupService(migration.target_server)
        store._progress_key = str(migration.pk)
        manifests: list[dict[str, Any]] = list(migration.barrier_state.get("recovery_manifests", []))
        backup_ids = migration.barrier_state["recovery_backups"]
        local_path: Path | None = None
        archive_name = ""
        try:
            # A pair's four network stages do not fit one migration worker's budget. Transfer
            # one archive per invocation, with a durable checkpoint and no controller spool
            # file held between workers. Both manifests are verified before domain mutation.
            if len(manifests) < len(backup_ids):
                backup_id = backup_ids[len(manifests)]
                downloaded = store._download_backup_to_spool(backup_id)
                if downloaded.is_err():
                    raise ValueError(downloaded.unwrap_err())
                _path, manifest = downloaded.unwrap()
                local_path = Path(_path)
                archive_name = str(manifest["archive_name"])
                if str(manifest.get("backup_id")) != backup_id:
                    raise ValueError("The downloaded backup manifest names a different archive")
                refusal = _complete_archive(migration.account, manifest)
                if refusal:
                    raise ValueError(refusal)
                self._move(migration, token, migration.status)
                safe_manifest = {key: value for key, value in manifest.items() if key in _MANIFEST_KEYS}
                self._store_barrier_state(
                    migration, token, {**migration.barrier_state, "recovery_transfer_intent": safe_manifest}
                )
                pushed = store._push_archive_to_target(
                    migration.target_server, archive_name, str(manifest["checksum_sha256"])
                )
                if pushed.is_err():
                    raise ValueError(pushed.unwrap_err())
                manifests.append({key: value for key, value in manifest.items() if key in _MANIFEST_KEYS})
                self._store_barrier_state(
                    migration,
                    token,
                    {**migration.barrier_state, "recovery_manifests": manifests, "recovery_transfer_intent": None},
                )
            if len(manifests) < len(backup_ids):
                raise MigrationDeferredError(
                    timezone.now() + timedelta(seconds=1), "Transfer the next recovery archive"
                )
            refusal = (
                pair_lineage_refusal(
                    manifests[0], manifests[1], service_id=migration.account.service_id, domain=migration.account.domain
                )
                if len(manifests) == PAIR_ARCHIVES
                else manifest_restore_refusal(manifests[0])
            )
            if refusal:
                raise ValueError(refusal)
            # Keep only non-secret verification inputs; full manifests may hold unrelated metadata.
            archives = [
                {key: item[key] for key in ("backup_id", "archive_name", "checksum_sha256")} for item in manifests
            ]
            state = {
                **migration.barrier_state,
                "recovery_archives": archives,
                "features": manifests[-1].get("domain_features"),
            }
            if migration.status == "fetching":
                self._move(migration, token, "pushing", barrier_state=state)
            self._move(migration, token, "restoring", barrier_state=state)
        finally:
            if local_path is not None:
                try:
                    local_path.unlink(missing_ok=True)
                finally:
                    release_spool_reservation(archive_name)

    def _restore(self, migration: VirtualminMigration, token: UUID) -> None:
        restore_held_target(self, migration, token, migration.barrier_state["recovery_archives"])

    @staticmethod
    def _pair_variables(migration: VirtualminMigration) -> dict[str, Any]:
        return held_pair_variables(migration)

    @staticmethod
    def _node(migration: VirtualminMigration, action: str) -> None:
        run_held_target_node(migration, action)

    def _verify(self, migration: VirtualminMigration, token: UUID) -> None:
        target = self._domain(migration.target_server, migration.account.domain)
        if target["username"] != migration.account.virtualmin_username or target["enabled"] is not False:
            raise ValueError("The recovered domain is not verifiably owned and disabled")
        features = migration.barrier_state.get("features")
        if isinstance(features, list) and set(
            str(listing_attribute(target["attributes"], "Features") or "").split()
        ) != set(features):
            raise ValueError("The recovered features differ from the selected backup")
        # Native restore replaces the placeholder's limits with those in the older archive.
        # Billing's current limits take effect before this replacement can be activated.
        quotas = modify_quota_parameters(migration.account.disk_quota_mb, migration.account.bandwidth_quota_mb)
        if quotas:
            self._move(migration, token, migration.status)
            self._command(migration, migration.target_server, "modify-domain", **quotas)
        named = ensure_on_recreated_node(migration.account, migration.target_server, enabled=False)
        if named.is_err():
            raise ValueError(named.unwrap_err())
        ready = named.unwrap()
        if (
            ready is None
            or ready.enabled
            or not ready.certificate_installed
            or (account_zone_psl_shipped() and not ready.linked)
        ):
            raise ValueError("The recovered account name and certificate are not ready")
        with transaction.atomic():
            account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=migration.account_id)
            name_id = (
                AccountHostname.objects.filter(account=account, retired_at__isnull=True)
                .values_list("pk", flat=True)
                .first()
            )
            name = account_hostname_service.lock_for_publication(name_id) if name_id else None
            if (
                account.server_id != migration.source_server_id
                or name is None
                or name.target_server_id not in {None, migration.source_server_id}
            ):
                raise ValueError("Recovery ownership changed before the commit")
            self._move(migration, token, "activating", cutover_committed_at=timezone.now())
            account.server = migration.target_server
            account.save(update_fields=["server", "updated_at"])
            name.target_server = migration.target_server
            name.save(update_fields=["target_server", "updated_at"])
            from .managed_dns_service import advance_target_locked  # noqa: PLC0415  # Customer-zone ownership commit

            advance_target_locked(name)
            VirtualminServer.objects.filter(pk=migration.target_server_id).update(
                current_domains=F("current_domains") + 1
            )

    def _activate(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.cutover_committed_at is None:
            raise ValueError("Recovery activation requires the ownership commit")
        self._move(migration, token, "activating")
        self._node(migration, "activate")
        variables = {**self._pair_variables(migration), "pair_action": "release"}
        released = run_pair_step(
            migration.target_server,
            variables,
            token=str(migration.pk),
            domain_id=str(migration.barrier_state["target_domain_id"]),
            timeout_seconds=180,
        )
        if released.is_err() or released.unwrap().outcome != "released":
            raise RuntimeError("The recovery maintenance barrier could not be released")
        intended = migration.pre_migration_snapshot["status"] == "active"
        current = self._domain(migration.target_server, migration.account.domain)["enabled"]
        if current is None:
            raise ValueError("The recovered domain's enabled state cannot be read")
        if intended and not current:
            self._command(migration, migration.target_server, "enable-domain")
        if self._domain(migration.target_server, migration.account.domain)["enabled"] is not intended:
            raise ValueError("Recovery did not preserve the account's intended state")
        self._move(migration, token, "repointing")

    def _repoint(self, migration: VirtualminMigration, token: UUID) -> None:
        self._converge_cutover(migration, token)

    def _prepare_completion(self, migration: VirtualminMigration, token: UUID) -> None:
        # These normal-backup names can be used by a future restore. Delete them while this
        # recovery still holds the account exclusion, rather than scheduling a late deletion.
        store = VirtualminBackupService(migration.target_server)
        removed = list(migration.barrier_state.get("recovery_archives_removed", []))
        artifacts = list(
            migration.barrier_state.get("recovery_archives") or migration.barrier_state.get("recovery_manifests", [])
        )
        intent = migration.barrier_state.get("recovery_transfer_intent")
        if intent:
            artifacts.append(intent)
        for artifact in artifacts:
            name = artifact["archive_name"]
            if name in removed:
                continue
            self._move(migration, token, migration.status)
            cleanup = store.remove_staged_archive(name)
            if cleanup.is_err():
                raise MigrationDeferredError(timezone.now() + timedelta(seconds=60), cleanup.unwrap_err())
            removed.append(name)
            self._store_barrier_state(
                migration, token, {**migration.barrier_state, "recovery_archives_removed": removed}
            )
        if migration.barrier_state.get("target_domain_id"):
            cleanup_held_target(migration)

    def abandon_precommit(
        self, migration: VirtualminMigration, token: UUID, *, actor: User | None, note: str
    ) -> Result[VirtualminMigration, str]:
        """Keep exclusion until the target is idle, absent and its reusable staging removed."""
        try:
            if migration.cutover_committed_at is not None:
                raise ValueError("A committed recovery can only continue on its target")
            # idle never reads or changes a domain; id 0 is its lock namespace when a
            # failed create returned no id. Every mutation below uses a verified live id.
            variables = barrier_variables(
                "idle",
                domain=migration.account.domain,
                domain_id=str(migration.barrier_state.get("target_domain_id") or "0"),
                token=str(uuid4()),
            ).unwrap()
            idle = run_barrier(migration.target_server, variables)
            if idle.is_err() or not idle.unwrap().ok:
                return Err("The recovery target is not proven idle; keep the account held for review")
            rows = self._listing(self._gateway(migration.target_server))
            target = next((row for row in rows if row["domain"] == migration.account.domain), None)
            domain_id = str(migration.barrier_state.get("target_domain_id") or "")
            if target is not None:
                if target["username"] != migration.account.virtualmin_username or target["enabled"] is not False:
                    raise ValueError("The partial recovery target is not verifiably owned and disabled")
                live_id = str(listing_attribute(target["attributes"], "ID") or "")
                if not live_id.isdigit() or (domain_id and live_id != domain_id):
                    raise ValueError("The partial recovery target identity changed or cannot be read")
                domain_id = live_id
            if domain_id:
                self._store_barrier_state(migration, token, {**migration.barrier_state, "target_domain_id": domain_id})
                released = run_pair_step(
                    migration.target_server,
                    {**self._pair_variables(migration), "pair_action": "release"},
                    token=str(migration.pk),
                    domain_id=domain_id,
                    timeout_seconds=180,
                )
                if released.is_err() or released.unwrap().outcome != "released":
                    return Err("The recovery node runner is not cancelled; keep the account held for review")
            if target is not None:
                self._move(migration, token, migration.status)
                self._command(migration, migration.target_server, "delete-domain")
                if any(
                    row["domain"] == migration.account.domain
                    for row in self._listing(self._gateway(migration.target_server))
                ):
                    return Err("The partial recovery target could not be verified absent")
            self._prepare_completion(migration, token)
            self._finish(
                migration, token, "failed", f"Recovery abandoned after target verification: {note}", actor=actor
            )
            return Ok(migration)
        except (ValueError, RuntimeError, MigrationDeferredError) as error:
            return Err(f"Recovery abandonment still needs target review: {error}")

    def _abort(
        self, migration: VirtualminMigration, token: UUID, error: Exception, *, target_delete_allowed: bool = False
    ) -> None:
        # Source is unavailable. Neither cancellation nor a failed restore can enable it.
        self._finish(migration, token, "needs_review", f"Recovery target requires review: {error}")
