"""Live hosting dependencies and frozen maintenance outcome membership."""

from uuid import UUID

from django.utils import timezone

from apps.infrastructure.node_maintenance_models import NodeMaintenanceAudience, NodeMaintenanceWindow


def live_node_services(service_ids: set[int]) -> dict[UUID, set[int]]:
    """Current placement plus unreleased source duties, with no historical owner snapshots."""
    from apps.provisioning.component_migration_models import SourceServiceObligation  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    result: dict[UUID, set[int]] = {}
    for node_id, service_id in VirtualminAccount.objects.filter(service_id__in=service_ids).values_list(
        "server_id", "service_id"
    ):
        result.setdefault(node_id, set()).add(service_id)
    for node_id, service_id in SourceServiceObligation.objects.filter(
        release__isnull=True, migration__account__service_id__in=service_ids
    ).values_list("source_server_id", "migration__account__service_id"):
        result.setdefault(node_id, set()).add(service_id)
    return result


def live_service_ids_for_node(node_id: UUID | None) -> set[int]:
    """A retained mail/DNS responsibility is independent of the website's current node."""
    if node_id is None:
        return set()
    from apps.provisioning.component_migration_models import SourceServiceObligation  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    return set(VirtualminAccount.objects.filter(server_id=node_id).values_list("service_id", flat=True)) | set(
        SourceServiceObligation.objects.filter(source_server_id=node_id, release__isnull=True).values_list(
            "migration__account__service_id", flat=True
        )
    )


def is_unstarted_not_run(window: NodeMaintenanceWindow) -> bool:
    return window.status == "failed" and window.started_at is None and window.current_execution_id is None


def freeze_not_run_audience(window: NodeMaintenanceWindow) -> None:
    """Snapshot placement and possibly announced services at the unstarted terminal transition."""
    if not is_unstarted_not_run(window):
        return
    identities = live_service_ids_for_node(window.node_id)
    for selected in window.deliveries.filter(first_dispatch_claimed_at__isnull=False).values_list(
        "selected_service_ids", flat=True
    ):
        identities.update(selected)
    for service_id in identities:
        row, created = NodeMaintenanceAudience.objects.get_or_create(
            window=window,
            service_id_snapshot=service_id,
            defaults={"service_id": service_id, "provenance": "not_run"},
        )
        if not created:
            row.provenance = "not_run"
            row.captured_at = timezone.now()
            row.save(update_fields=["provenance", "captured_at", "updated_at"])


def not_run_service_ids(window: NodeMaintenanceWindow) -> set[int]:
    """A terminal receipt never expands to services arriving after the outcome."""
    if not is_unstarted_not_run(window):
        return set()
    return set(window.audience.filter(provenance="not_run").values_list("service_id_snapshot", flat=True))
