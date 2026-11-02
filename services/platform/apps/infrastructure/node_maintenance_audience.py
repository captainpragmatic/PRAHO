"""Planned not-run receipts never pretend that scheduled work actually executed."""

from django.utils import timezone

from apps.infrastructure.node_maintenance_models import NodeMaintenanceAudience, NodeMaintenanceWindow


def is_unstarted_not_run(window: NodeMaintenanceWindow) -> bool:
    return window.status == "failed" and window.started_at is None and window.current_execution_id is None


def freeze_not_run_audience(window: NodeMaintenanceWindow) -> None:
    """Snapshot placement and possibly announced services at the unstarted terminal transition."""
    if not is_unstarted_not_run(window):
        return
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # Current tracked placement

    identities = set(VirtualminAccount.objects.filter(server_id=window.node_id).values_list("service_id", flat=True))
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
