"""Transfer only a published selected archive through the enrolled source and destination."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from typing import TYPE_CHECKING, Any

from .component_migration_transport import run_source_operation, source_operation_refusal, source_operation_variables
from .spool import acquire_spool_reservation, release_spool_reservation

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from .virtualmin_migration_models import VirtualminMigration
    from .virtualmin_migration_service import VirtualminMigrationService


def _export(migration: VirtualminMigration) -> dict[str, Any]:
    exported = migration.barrier_state.get("component_export")
    if (
        not isinstance(exported, dict)
        or migration.archive_name != f"migration_{migration.pk}.tar.gz"
        or set(exported) != {"path", "sha256", "bytes", "files", "databases"}
        or exported["path"] != f"/var/lib/praho-transfer/components/{migration.pk}/{migration.archive_name}"
        or exported["sha256"] != migration.archive_sha256
        or re.fullmatch(r"[0-9a-f]{64}", migration.archive_sha256) is None
        or type(exported["bytes"]) is not int
        or not 0 < exported["bytes"] <= 2**63 - 1
    ):
        raise ValueError("The component migration has no exact published selected archive receipt")
    return exported


def _authority(migration: VirtualminMigration, token: UUID) -> None:
    values = source_operation_variables(migration, token, "source_verify")
    if refusal := source_operation_refusal(migration.source_server, values):
        raise ValueError(refusal)


def _archive(path: Path, checksum: str, size: int, *, incoming: bool = False) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size != size
            or info.st_mode & (0o022 if incoming else 0o077)
            or hashlib.file_digest(stream, "sha256").hexdigest() != checksum
        ):
            raise ValueError("The private selected archive is unsafe or differs from its source receipt")
        if incoming:
            os.fchmod(stream.fileno(), 0o600)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("The selected archive identity changed during verification")


def transfer_selected_archive(engine: VirtualminMigrationService, migration: VirtualminMigration, token: UUID) -> None:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- app transport boundary

    if migration.status not in {"fetching", "pushing"}:
        raise ValueError("Selected archive transfer needs its exact migration phase")
    _authority(migration, token)
    exported = _export(migration)
    # Publish intent before a push can leave an archive with an unrecorded reply.
    engine._move(
        migration,
        token,
        migration.status,
        barrier_state={
            **migration.barrier_state,
            "component_target_archive_issued": migration.barrier_state.get("component_target_archive_issued") is True
            or migration.status == "pushing",
        },
    )
    run_source_operation(migration, token, "source_verify")
    if not engine.spool.is_absolute() or engine.spool.resolve() != engine.spool:
        raise ValueError("Selected migration spool must be an absolute directory without symlinked ancestors")
    engine.spool.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = engine.spool.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Selected migration spool must be a private owned directory")
    archive = engine.spool / migration.archive_name
    fetching = migration.status == "fetching"
    existing = archive.exists() or archive.is_symlink()
    if existing:
        _archive(archive, migration.archive_sha256, exported["bytes"])
    elif not fetching:
        raise ValueError("The exact private selected archive is absent before target push")
    if fetching and not existing:
        reserved = acquire_spool_reservation(
            engine.spool,
            migration.archive_name,
            exported["bytes"],
            f"component-migration:{migration.pk}",
            engine.transfer_timeout + 300,
        )
        if reserved.is_err():
            raise ValueError(reserved.unwrap_err())
    try:
        if not fetching or not existing:
            values = {
                "archive_name": migration.archive_name,
                "spool_dir": str(engine.spool),
                "spool_free_bytes": shutil.disk_usage(engine.spool).free,
                "expected_sha256": migration.archive_sha256,
                "remote_archive_dir": f"/var/lib/praho-transfer/components/{migration.pk}"
                if fetching
                else "/var/lib/praho-transfer",
            }
            server = migration.source_server if fetching else migration.target_server
            playbook = "virtualmin_migrate_fetch.yml" if fetching else "virtualmin_migrate_push.yml"
            result = AnsibleService().run_server_playbook(
                server, playbook, values, timeout_seconds=engine.transfer_timeout
            )
            if result.is_err() or not result.unwrap().success:
                raise RuntimeError(
                    "Selected component transfer is uncertain; preserve its published source and local receipts"
                )
            if fetching and set(re.findall(r"MIGRATE_SHA256=([0-9a-f]{64})(?![0-9a-f])", result.unwrap().stdout)) != {
                migration.archive_sha256
            }:
                raise ValueError("The fetched selected archive checksum differs from its published source receipt")
            _archive(archive, migration.archive_sha256, exported["bytes"], incoming=fetching)
        _authority(migration, token)
        run_source_operation(migration, token, "source_verify")
        engine._move(migration, token, "pushing" if fetching else "restoring")
    finally:
        if fetching and not existing:
            release_spool_reservation(migration.archive_name)
