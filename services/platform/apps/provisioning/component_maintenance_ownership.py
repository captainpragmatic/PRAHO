"""Native component ownership can outlive a terminal controller status."""

from uuid import UUID

from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from .virtualmin_migration_models import VirtualminMigration


def _unreleased_receipts(state: object, *, restored: bool) -> bool:
    if not isinstance(state, dict):
        return True
    seals = ("component_source_seal_intent", "component_source_sealed", "component_target_sealed")
    if any(key in state and state[key] is not False for key in seals):
        return True
    pairs = {
        "component_source_hold_issued": "component_source_released",
        "component_bridge_source_prepare_issued": "component_bridge_source_removed",
        "component_bridge_origin_issued": "component_bridge_origin_removed",
    }
    for issued, released in pairs.items():
        value = state.get(issued, False)
        if type(value) is not bool or (value and state.get(released) is not True):
            return True
    if state.get("component_source_hold_issued") is not True and any(
        key in state for key in ("component_source_held", "component_export", "component_source_released")
    ):
        return True
    return restored and state.get("component_target_removed") is not True


def terminal_component_refusal(node_id: UUID) -> str | None:
    """Caller holds Server; private archives and retained service duties alone are not native holds."""
    migrations = VirtualminMigration.objects.filter(
        Q(source_server_id=node_id) | Q(target_server_id=node_id),
        contract="imported_web",
        status__in=("completed", "failed", "rolled_back"),
    ).select_related("bridge")
    now = timezone.now()
    for migration in migrations:
        if migration.lease_token is not None and (
            migration.worker_lease_expires_at is None or migration.worker_lease_expires_at > now
        ):
            return str(_("A component cleanup worker owns this server; wait for its recorded release."))
        if migration.status == "completed":
            bridge = getattr(migration, "bridge", None)
            evidence = bridge.evidence if bridge is not None else None
            if (
                bridge is None
                or bridge.status != "torn_down"
                or not isinstance(evidence, dict)
                or any(
                    evidence.get(key) is not True
                    for key in (
                        "bridge_removed",
                        "source_components_removed",
                        "origin_removed",
                        "target_artifacts_retired",
                    )
                )
                or evidence.get("lease_token") is not None
            ):
                return str(_("A completed component migration still needs verified native retirement on this server."))
        elif migration.cutover_committed_at is not None or _unreleased_receipts(
            migration.barrier_state,
            restored=migration.restore_issued,
        ):
            return str(_("A terminal component migration still has unresolved native holds on this server."))
    return None
