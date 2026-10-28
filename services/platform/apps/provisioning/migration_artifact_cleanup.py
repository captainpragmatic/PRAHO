"""Retire UUID-owned temporary archives after determinate migration exits.

Recovery deliberately stays synchronous: its backup archive name can be reused by another restore.
Normal migration UUIDs are never reused, so this work may run after account exclusion is released.
"""

from __future__ import annotations

import logging
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone
from django_q.tasks import async_task

from apps.infrastructure.ansible_service import AnsibleService
from apps.settings.services import SettingsService

from .spool import release_spool_reservation
from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_models import VirtualminServer

logger = logging.getLogger(__name__)
TASK = "apps.provisioning.migration_artifact_cleanup.cleanup_migration_artifacts"
TASK_TIMEOUT = 2700
REMOTE_TIMEOUT = 180
# Each node can first wait up to 180 seconds for SSH before the playbook's own timeout.
LEASE_TTL = timedelta(seconds=TASK_TIMEOUT + 60)
RETRY_DELAY = timedelta(minutes=5)
TERMINAL = ("completed", "failed", "rolled_back")


class ArtifactLeaseLostError(ValueError):
    """A different worker or operation state owns the migration evidence."""


def _eligible() -> QuerySet[VirtualminMigration]:
    return (
        VirtualminMigration.objects.filter(status__in=TERMINAL).exclude(contract="recovery").exclude(reason="recovery")
    )


def _progress(migration: VirtualminMigration) -> dict[str, Any]:
    saved = migration.barrier_state.get("artifact_cleanup", {})
    return saved if isinstance(saved, dict) else {}


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def schedule_artifact_cleanup(migration_id: UUID | str) -> bool:
    """Dispatch after commit; terminal rows remain discoverable if dispatch or a worker fails."""
    migration = _eligible().filter(pk=UUID(str(migration_id))).first()
    if migration is None or _progress(migration).get("done"):
        return False
    try:
        async_task(TASK, str(migration.pk), timeout=TASK_TIMEOUT)
    except (ValueError, RuntimeError, OSError):
        logger.exception("🔥 [MigrationArtifacts] Dispatch failed; reclaim will retry %s", migration_id)
        return False
    return True


def _claim(migration_id: str, token: UUID) -> tuple[VirtualminMigration | None, str]:
    with transaction.atomic():
        migration = (
            _eligible()
            .select_for_update()
            .select_related("source_server", "target_server")
            .filter(pk=UUID(migration_id))
            .first()
        )
        if migration is None:
            return None, "excluded"
        progress = _progress(migration)
        if progress.get("done"):
            return None, "cleaned"
        due = _date(progress.get("next_run"))
        if due is not None and due > timezone.now():
            return None, "waiting"
        if not migration.acquire_lease(token, LEASE_TTL):
            return None, "busy"
        migration.refresh_from_db()
        return migration, "claimed"


def _checkpoint(migration: VirtualminMigration, token: UUID, fields: dict[str, Any]) -> None:
    """Merge only under this worker's live lease and the original terminal status CAS."""
    with transaction.atomic():
        current = _eligible().select_for_update().filter(pk=migration.pk, status=migration.status).first()
        if current is None or not current.renew_lease(token, LEASE_TTL):
            raise ArtifactLeaseLostError("Migration artifact cleanup lease lost")
        state = {**current.barrier_state, "artifact_cleanup": {**_progress(current), **fields}}
        if not current.transition(token, migration.status, migration.status, barrier_state=state):
            raise ArtifactLeaseLostError("Migration artifact cleanup status changed")
        migration.barrier_state = state


def _release(migration: VirtualminMigration, token: UUID) -> None:
    with transaction.atomic():
        current = (
            _eligible().select_for_update().filter(pk=migration.pk, status=migration.status, lease_token=token).first()
        )
        if current is not None:
            current.transition(token, current.status, current.status, lease_token=None, worker_lease_expires_at=None)


def _remove_spool(archive: str) -> None:
    spool = Path(str(SettingsService.get_setting("provisioning.migration_spool_dir", "/var/lib/praho/migration-spool")))
    if not spool.is_absolute() or spool.is_symlink():
        raise ValueError("Migration spool must be an absolute private directory")
    if spool.exists():
        info = spool.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Migration spool must be a private directory")
        paths = [spool / (archive + suffix) for suffix in ("", ".dom", ".info")]
        for path in paths:
            try:
                file_info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.geteuid():
                raise ValueError("A migration spool artifact is not an owned regular file")
        for path in paths:
            path.unlink(missing_ok=True)
    release_spool_reservation(archive)


def _remove_remote(server: VirtualminServer, archive: str) -> None:
    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        raise ValueError("The migration node has no managed deployment available for cleanup")
    result = AnsibleService().run_playbook(
        deployment,
        "virtualmin_remote_cleanup.yml",
        {"archive_name": archive},
        timeout_seconds=REMOTE_TIMEOUT,
    )
    if result.is_err():
        raise ValueError(f"Remote migration archive cleanup could not run: {result.unwrap_err()}")
    if not result.unwrap().success:
        raise ValueError("Remote migration archive cleanup was not confirmed")


def _retire_target_data(migration: VirtualminMigration, token: UUID) -> None:
    """Remove private UUID staging while retaining node markers that prevent late replay."""
    from .migration_bridge_service import retire_target_activation_data  # noqa: PLC0415
    from .migration_target_hold import cleanup_held_target  # noqa: PLC0415

    if not migration.barrier_state.get("target_domain_id") or not migration.barrier_state.get("held_archives"):
        return
    if not _progress(migration).get("target_hold"):
        _checkpoint(migration, token, {})
        cleanup_held_target(migration)
        _checkpoint(migration, token, {"target_hold": True})
    if not _progress(migration).get("target_activation"):
        _checkpoint(migration, token, {})
        retired = retire_target_activation_data(migration)
        if retired.is_err():
            raise ValueError(retired.unwrap_err())
        _checkpoint(migration, token, {"target_activation": True})


def _clean_locations(migration: VirtualminMigration, token: UUID, archive: str) -> list[str]:
    failures = []
    for location, server in (("spool", None), ("source", migration.source_server), ("target", migration.target_server)):
        if _progress(migration).get(location):
            continue
        _checkpoint(migration, token, {})
        try:
            if server is None:
                _remove_spool(archive)
            else:
                _remove_remote(server, archive)
        except (ValueError, RuntimeError, OSError) as error:
            failures.append(f"{location}: {error}")
            continue
        _checkpoint(migration, token, {location: True})
    try:
        _retire_target_data(migration, token)
    except ArtifactLeaseLostError:
        raise
    except (ValueError, RuntimeError, OSError) as error:
        failures.append(f"target staging: {error}")
    return failures


def cleanup_migration_artifacts(migration_id: str) -> dict[str, str]:
    """Checkpoint each location independently; unavailable nodes never retain other nodes' files."""
    token = uuid4()
    migration, action = _claim(migration_id, token)
    if migration is None:
        return {"action": action}
    try:
        archive = f"migration_{migration.pk}.tar.gz"
        if migration.archive_name != archive:
            raise ValueError("The archive name does not belong to this migration UUID")
        failures = _clean_locations(migration, token, archive)
        if failures:
            raise ValueError("; ".join(failures))
        _checkpoint(migration, token, {"done": True, "last_error": "", "next_run": None})
        return {"action": "cleaned"}
    except ArtifactLeaseLostError:
        return {"action": "busy"}
    except (ValueError, RuntimeError, OSError) as error:
        try:
            _checkpoint(
                migration, token, {"last_error": str(error), "next_run": (timezone.now() + RETRY_DELAY).isoformat()}
            )
        except ArtifactLeaseLostError:
            return {"action": "busy"}
        return {"action": "retrying"}
    finally:
        _release(migration, token)


def reclaim_migration_artifacts() -> int:
    """Redeliver at most five due terminal rows, including jobs whose first dispatch failed."""
    now = timezone.now()
    candidates = (
        _eligible()
        .filter(Q(lease_token__isnull=True) | Q(worker_lease_expires_at__lte=now))
        .filter(Q(barrier_state__artifact_cleanup__done=False) | Q(barrier_state__artifact_cleanup__done__isnull=True))
        .filter(
            Q(barrier_state__artifact_cleanup__next_run__lte=now.isoformat())
            | Q(barrier_state__artifact_cleanup__next_run__isnull=True)
        )
        .order_by("updated_at")[:5]
    )
    return sum(schedule_artifact_cleanup(migration.pk) for migration in candidates)
