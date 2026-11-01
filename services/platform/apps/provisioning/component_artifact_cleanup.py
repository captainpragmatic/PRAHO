"""Retire selected migration staging after a determinate native compensation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .component_migration_transport import run_source_operation
from .component_target_transport import run_target_operation

if TYPE_CHECKING:
    from uuid import UUID

    from .virtualmin_migration_models import VirtualminMigration


def cleanup_component_artifacts(migration: VirtualminMigration, token: UUID, archive: str) -> list[str]:
    """Shared caller owns the current terminal cleanup lease and final release."""
    from .migration_artifact_cleanup import (  # noqa: PLC0415 -- shared lease/progress owner
        ArtifactLeaseLostError,
        _checkpoint,
        _progress,
        _remove_spool,
    )

    intent = (
        "component_source_hold_issued",
        "component_source_released",
        "component_target_archive_issued",
        "component_target_removed",
        "component_source_seal_intent",
        "component_source_sealed",
        "component_target_sealed",
    )
    if any(type(migration.barrier_state[key]) is not bool for key in intent if key in migration.barrier_state):
        raise ValueError("Native component cleanup intent is malformed; preserve its private ownership evidence")
    if (
        migration.contract != "imported_web"
        or migration.status not in {"failed", "rolled_back"}
        or migration.cutover_committed_at is not None
        or migration.component_approval_id is None
        or migration.component_source_obligation_id is None
        or any(
            migration.barrier_state.get(key) is True
            for key in ("component_source_seal_intent", "component_source_sealed", "component_target_sealed")
        )
    ):
        raise ValueError("Selected staging retirement requires an admitted unsealed terminal compensation")
    failures = []
    for location in ("spool", "source", "target"):
        if _progress(migration).get(location):
            continue
        _checkpoint(migration, token, {})
        try:
            if location == "spool":
                _remove_spool(archive)
            elif location == "source":
                _retire_source(migration, token)
            else:
                _retire_target(migration, token)
        except ArtifactLeaseLostError:
            raise
        except (ValueError, RuntimeError, OSError) as error:
            failures.append(f"{location}: {error}")
            continue
        _checkpoint(migration, token, {location: True})
    return failures


def _retire_source(migration: VirtualminMigration, token: UUID) -> None:
    state = migration.barrier_state
    if state.get("component_source_hold_issued") is not True:
        return
    if state.get("component_source_released") is not True:
        raise ValueError("The selected source holds have no confirmed native release")
    # An export response may have been lost before the controller saved its receipt.
    # The released native parent journal owns the exact allowlisted staging files.
    run_source_operation(migration, token, "source_retire_artifacts")


def _retire_target(migration: VirtualminMigration, token: UUID) -> None:
    if migration.restore_issued:
        if migration.barrier_state.get("component_target_removed") is not True:
            raise ValueError("The prepared selected target has no confirmed native removal")
        run_target_operation(migration, token, "target_retire_artifacts")
    elif migration.barrier_state.get("component_target_archive_issued") is True:
        run_target_operation(migration, token, "target_retire_unprepared_archive")
