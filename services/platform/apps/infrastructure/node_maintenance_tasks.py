"""Small queue leaves for maintenance lifecycle and normal notice dispatch."""

from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.infrastructure.node_maintenance_audience import freeze_not_run_audience
from apps.infrastructure.node_maintenance_delivery import dispatch_due_notices, publish_window_notices
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import (
    _begin_operator_window,
    audit_window,
    locked_window,
    queue_window_execution,
)


def setup_node_maintenance_schedule() -> dict[str, str]:
    from django_q.models import Schedule  # noqa: PLC0415  # Schedule setup runs after migrations.

    _schedule, created = Schedule.objects.update_or_create(
        name="infra_node_maintenance",
        defaults={
            "func": "apps.infrastructure.node_maintenance_tasks.tick_node_maintenance",
            "schedule_type": Schedule.MINUTES,
            "minutes": 1,
            "repeats": -1,
        },
    )
    return {"node_maintenance": "created" if created else "already_exists"}


def tick_node_maintenance(window_ids: list[str] | None = None) -> dict[str, int]:
    """Reconcile due windows; an explicit lab scope never expands to unrelated rows."""
    result = {"overran": 0, "not_run": 0, "queued": 0}
    from apps.infrastructure.node_maintenance_execution import recover_unissued_executions  # noqa: PLC0415

    result["not_run"] += recover_unissued_executions(window_ids)
    windows = NodeMaintenanceWindow.objects.filter(status__in=("scheduled", "running", "overran"))
    if window_ids is not None:
        windows = windows.filter(pk__in=window_ids)
    for window_id in windows.values_list("pk", flat=True):
        with transaction.atomic():
            window = locked_window(window_id)
            if window.status == "scheduled" and (
                timezone.now() > window.start_by or window.execution_mode not in {"manual", "reboot"}
            ):
                window.fail()
                window.public_outcome = _("The planned work did not run. An operator will review the next steps.")
                window.completion_source = "job"
                freeze_not_run_audience(window)
                window.save()
                audit_window(window, None, "finish", "The latest start passed without an execution")
                publish_window_notices(window, "completed")
                result["not_run"] += 1
            elif (
                window.status == "scheduled"
                and window.execution_mode != "manual"
                and timezone.now() >= window.starts_at
            ):
                try:
                    _begin_operator_window(window)
                except ValidationError:
                    continue  # Busy admitted work may defer only until the original start_by.
                window.save()
                queue_window_execution(window)
                audit_window(window, None, "start", "The scheduler claimed a supported automatic window")
                result["queued"] += 1
            if window.status == "running" and timezone.now() > window.ends_at:
                window.mark_overrun()
                window.save()
                audit_window(window, None, "overran", "The planned end passed while maintenance still owned the server")
                result["overran"] += 1
    dispatch_due_notices(window_ids=window_ids)
    return result


def execute_window(window_id: str, revision: int, execution_token: str) -> dict[str, object]:
    from apps.infrastructure.node_maintenance_execution import execute_window_claim  # noqa: PLC0415

    result = execute_window_claim(UUID(window_id), revision, UUID(execution_token))
    return {"success": result.is_ok(), "error": result.unwrap_err() if result.is_err() else ""}
