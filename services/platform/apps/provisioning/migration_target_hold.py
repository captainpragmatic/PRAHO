"""Restore onto a disabled replacement without exposing Unix credentials, cron or applications."""

from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING, Any

from .virtualmin_gateway import listing_attribute
from .virtualmin_pair_restore import run_pair_step
from .virtualmin_service import create_domain_params

if TYPE_CHECKING:
    from uuid import UUID

    from .virtualmin_migration_models import VirtualminMigration
    from .virtualmin_migration_service import VirtualminMigrationService

MAX_ARCHIVES = 2
_BACKUP_NAME = re.compile(r"virtualmin_backup_[0-9a-f]{32}\.tar\.gz")


def held_pair_variables(migration: VirtualminMigration) -> dict[str, Any]:
    return {
        "chain_domain": migration.account.domain,
        "chain_domain_id": migration.barrier_state["target_domain_id"],
        "chain_token": str(migration.pk),
    }


def run_held_target_node(migration: VirtualminMigration, action: str) -> None:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

    if action not in {"stage", "verify-held", "activate", "cleanup"}:
        raise ValueError("Unknown held-target node action")
    state = migration.barrier_state
    archives = state.get("held_archives") or state.get("recovery_archives") or []
    if not archives and action != "cleanup":
        raise ValueError("The held target has no verified archive")
    latest = archives[-1] if archives else {"archive_name": "", "checksum_sha256": ""}
    variables = {
        "recovery_action": action,
        "recovery_id": str(migration.pk),
        "recovery_domain": migration.account.domain,
        "recovery_username": migration.account.virtualmin_username,
        "recovery_domain_id": state["target_domain_id"],
        "recovery_archive": latest["archive_name"],
        "recovery_sha256": latest["checksum_sha256"],
        "recovery_enabled": migration.pre_migration_snapshot["status"] == "active",
    }
    result = AnsibleService().run_playbook(
        migration.target_server.node_deployment, "virtualmin_recovery.yml", variables, timeout_seconds=600
    )
    if result.is_err() or not result.unwrap().success:
        raise RuntimeError("The held-target node step is uncertain; the target requires review")


def cleanup_held_target(migration: VirtualminMigration) -> None:
    """Call only after conclusive completion/abandonment and stopping the pair runner."""
    run_held_target_node(migration, "cleanup")


def _checked_archives(migration: VirtualminMigration, archives: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not 1 <= len(archives) <= MAX_ARCHIVES:
        raise ValueError("Held restore requires one full archive or a base/differential pair")
    for archive in archives:
        name = str(archive.get("archive_name", ""))
        if not _BACKUP_NAME.fullmatch(name) and not (len(archives) == 1 and name == f"migration_{migration.pk}.tar.gz"):
            raise ValueError("The held archive has an invalid identity")
        if re.fullmatch(r"[0-9a-f]{64}", str(archive.get("checksum_sha256", ""))) is None:
            raise ValueError("The held archive has an invalid checksum")
    if migration.barrier_state.get("held_archives") not in (None, archives):
        raise ValueError("The held archive identity changed")
    return [dict(archive) for archive in archives]


def restore_held_target(
    service: VirtualminMigrationService, migration: VirtualminMigration, token: UUID, archives: list[dict[str, Any]]
) -> None:
    """Create an empty disabled domain, restore under maintenance, and prove Unix stays locked."""
    archives = _checked_archives(migration, archives)
    service._move(
        migration,
        token,
        "restoring",
        restore_issued=True,
        barrier_state={**migration.barrier_state, "held_archives": archives},
    )
    recorded_id = migration.barrier_state.get("target_domain_id")
    if not recorded_id:
        params = create_domain_params(
            domain=migration.account.domain,
            username=migration.account.virtualmin_username,
            password=secrets.token_urlsafe(48),
            template=migration.account.template_name,
            recovery_seed=migration.account.get_recovery_seed(),
            disk_quota_mb=migration.account.disk_quota_mb,
            bandwidth_quota_mb=migration.account.bandwidth_quota_mb,
        )
        service._command(migration, migration.target_server, "create-domain", **params)
        service._move(migration, token, "restoring")
        service._command(migration, migration.target_server, "disable-domain")
    target = service._domain(migration.target_server, migration.account.domain)
    domain_id = str(listing_attribute(target["attributes"], "ID"))
    if (
        target["username"] != migration.account.virtualmin_username
        or target["enabled"] is not False
        or not domain_id.isdigit()
        or (recorded_id and domain_id != recorded_id)
    ):
        raise ValueError("The held target identity is not verifiably owned and disabled")
    service._store_barrier_state(migration, token, {**migration.barrier_state, "target_domain_id": domain_id})
    if not migration.barrier_state.get("held_restore_complete"):
        run_held_target_node(migration, "stage")
        service._move(migration, token, "restoring")
        variables = {
            **held_pair_variables(migration),
            "pair_action": "restore",
            "pair_recovery": True,
            "pair_base_archive": archives[0]["archive_name"],
            "pair_base_sha": archives[0]["checksum_sha256"],
            "pair_diff_archive": archives[1]["archive_name"] if len(archives) == MAX_ARCHIVES else "",
            "pair_diff_sha": archives[1]["checksum_sha256"] if len(archives) == MAX_ARCHIVES else "",
        }
        result = run_pair_step(
            migration.target_server,
            variables,
            token=str(migration.pk),
            domain_id=domain_id,
            timeout_seconds=2 * len(archives) * service.backup_timeout + 180,
        )
        if result.is_err() or result.unwrap().outcome != "ok" or result.unwrap().barrier_broken():
            detail = result.unwrap_err() if result.is_err() else result.unwrap().reason
            raise RuntimeError(f"Held restore needs target review; maintenance stays up: {detail}")
    run_held_target_node(migration, "verify-held")
    service._store_barrier_state(migration, token, {**migration.barrier_state, "held_restore_complete": True})
    service._move(migration, token, "verifying")
