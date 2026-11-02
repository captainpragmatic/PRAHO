"""Customer-owned maintenance reads through the established signed POST boundary."""

from datetime import datetime, timedelta
from typing import TypedDict

from django.db.models import Q
from django.http import HttpRequest
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.secure_auth import require_customer_authentication
from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_audience import is_unstarted_not_run, live_node_services, not_run_service_ids
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.provisioning.service_models import Service


class PublicWindow(TypedDict):
    id: str
    kind: str
    status: str
    starts_at: str
    ends_at: str
    started_at: str | None
    finished_at: str | None
    expects_downtime: bool
    expected_downtime_minutes: int | None
    customer_note: str
    public_outcome: str
    completion_source: str
    was_overrun: bool
    service_ids: list[int]


class PublicMaintenance(TypedDict):
    windows: list[PublicWindow]
    last_completed: PublicWindow | None


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _public_window(window: NodeMaintenanceWindow, service_ids: list[int]) -> PublicWindow:
    return {
        "id": str(window.pk),
        "kind": window.kind,
        "status": window.status,
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "started_at": _stamp(window.started_at),
        "finished_at": _stamp(window.finished_at),
        "expects_downtime": window.expects_downtime,
        "expected_downtime_minutes": window.expected_downtime_minutes,
        "customer_note": window.customer_note,
        "public_outcome": window.public_outcome,
        "completion_source": window.completion_source,
        "was_overrun": window.was_overrun,
        "service_ids": service_ids,
    }


def maintenance_for_customer(customer: Customer, service_id: int | None = None) -> PublicMaintenance:
    services = Service.objects.filter(customer=customer)
    if service_id is not None:
        services = services.filter(pk=service_id)
    owned_ids = set(services.values_list("pk", flat=True))
    dependencies = live_node_services(owned_ids)
    now = timezone.now()
    windows = (
        NodeMaintenanceWindow.objects.filter(
            Q(node_id__in=dependencies)
            | Q(audience__service_id_snapshot__in=owned_ids, audience__provenance="execution")
            | Q(
                status="failed",
                started_at__isnull=True,
                current_execution__isnull=True,
                audience__service_id_snapshot__in=owned_ids,
            )
        )
        .filter(
            Q(status__in=("scheduled", "running", "overran"))
            | Q(status__in=("completed", "failed"), finished_at__gt=now - timedelta(hours=24), finished_at__lte=now)
        )
        .distinct()
        .prefetch_related("audience")
        .order_by("starts_at", "pk")
    )
    result: PublicMaintenance = {"windows": [], "last_completed": None}
    latest_finish: datetime | None = None
    for window in windows:
        captured_ids = {row.service_id_snapshot for row in window.audience.all() if row.provenance == "execution"}
        placed_ids = dependencies.get(window.node_id, set()) if window.node_id is not None else set()
        affected_ids = captured_ids if window.status in {"completed", "failed"} else captured_ids | placed_ids
        if is_unstarted_not_run(window):
            affected_ids = not_run_service_ids(window)
        selected_ids = sorted(owned_ids & affected_ids)
        if not selected_ids:
            continue
        public = _public_window(window, selected_ids)
        if window.status in {"scheduled", "running", "overran"}:
            result["windows"].append(public)
        elif window.finished_at and (latest_finish is None or window.finished_at > latest_finish):
            result["last_completed"] = public
            latest_finish = window.finished_at
    # Stable sort retains the query's start/UUID order within each urgency class.
    urgency = {"overran": 0, "running": 1, "scheduled": 2}
    result["windows"].sort(key=lambda item: urgency[item["status"]])
    return result


def _response(customer: Customer, service_id: int | None = None) -> Response:
    if service_id is not None and not Service.objects.filter(pk=service_id, customer=customer).exists():
        response = Response({"error": "Service not found"}, status=404)
    else:
        response = Response({"success": True, "data": {"maintenance": maintenance_for_customer(customer, service_id)}})
    response["Cache-Control"] = "private, no-store"
    return response


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # Portal HMAC and current membership are enforced by the inner decorator.
@require_customer_authentication
def summary(request: HttpRequest, customer: Customer) -> Response:
    return _response(customer)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # Same signed, current-customer boundary as summary.
@require_customer_authentication
def service(request: HttpRequest, customer: Customer, service_id: int) -> Response:
    return _response(customer, service_id)
