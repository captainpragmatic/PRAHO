"""Staff-only node-window controls; no remote operation occurs during a preview."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods, require_POST

from apps.common.decorators import staff_required
from apps.common.localisation_services import get_request_localisation
from apps.infrastructure.node_maintenance_audience import live_service_ids_for_node
from apps.infrastructure.node_maintenance_execution import reconcile_direct_execution
from apps.infrastructure.node_maintenance_forms import (
    NodeMaintenancePolicyForm,
    NodeMaintenanceWindowForm,
    maintenance_action_form,
    maintenance_reconcile_form,
)
from apps.infrastructure.node_maintenance_gate import ACTIVE_EXECUTIONS
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_policy import parse_staff_datetime
from apps.infrastructure.node_maintenance_policy_service import PolicyValues, save_maintenance_policy
from apps.infrastructure.node_maintenance_service import change_window, create_window, require_maintenance_operator

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminServer
    from apps.users.models import User


def _can_change(actor: User) -> bool:
    try:
        require_maintenance_operator(actor)
    except PermissionDenied:
        return False
    return True


def direct_maintenance_context(
    request: HttpRequest, *, node_id: UUID | None = None, deployment_id: int | None = None
) -> dict[str, object]:
    """Show only the active unwindowed owner of the explicit node or deployment."""
    owners = NodeMaintenanceExecution.objects.filter(window__isnull=True, phase__in=ACTIVE_EXECUTIONS)
    if node_id is not None:
        owners = owners.filter(node_id=node_id)
    elif deployment_id is not None:
        owners = owners.filter(deployment_id=deployment_id)
    else:
        owners = owners.none()
    action_labels = {
        "reboot": _("Restart"),
        "start": _("Power on"),
        "stop": _("Power off"),
        "resize": _("Resize node"),
        "security": _("Security maintenance"),
    }
    phase_labels = {
        "claimed": _("Not issued"),
        "issued": _("Command issued"),
        "awaiting_recovery": _("Awaiting outcome verification"),
        "uncertain": _("Uncertain result"),
    }
    return {
        "maintenance_direct_rows": [
            {
                "execution": execution,
                "action_label": action_labels.get(execution.action, execution.action),
                "phase_label": phase_labels[execution.phase],
                "form": maintenance_reconcile_form(execution),
                "recorded_address": execution.internal_result.get("ipv4_address", ""),
                "recorded_port": execution.internal_result.get("ssh_port", ""),
            }
            for execution in owners.select_related("deployment").order_by("-created_at")
        ],
        "maintenance_can_reconcile": _can_change(cast("User", request.user)),
        "maintenance_viewer_zone": get_request_localisation(request).timezone,
    }


def node_maintenance_context(node: VirtualminServer, request: HttpRequest) -> dict[str, object]:
    """Tracked ownership preview only: no native inspection or remote mutation."""
    from apps.provisioning.component_migration_models import SourceServiceObligation  # noqa: PLC0415
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # Cross-app ownership seam.

    actor = cast("User", request.user)
    can_change = _can_change(actor)
    accounts = VirtualminAccount.objects.filter(server=node)
    retained = SourceServiceObligation.objects.filter(source_server=node, release__isnull=True)
    service_labels = {
        "mail": _("Mail"),
        "dns": _("DNS"),
        "mysql": _("Databases"),
        "authentication": _("Authentication"),
    }
    policy = NodeMaintenancePolicy.objects.filter(node=node).first()
    windows = list(
        NodeMaintenanceWindow.objects.filter(node_uuid=node.pk)
        .select_related("current_execution")
        .order_by("-created_at")[:10]
    )
    applicable = any(window.status in {"scheduled", "running", "overran"} for window in windows)
    # History is bounded for rendering; the exclusion query covers every row.
    applicable = (
        applicable
        or NodeMaintenanceWindow.objects.filter(node=node, status__in=("scheduled", "running", "overran")).exists()
    )
    rows = []
    labels = {
        "start": _("Start maintenance"),
        "finish": _("Record actual outcome"),
        "move": _("Move window"),
        "cancel": _("Cancel window"),
    }
    for window in windows:
        actions: list[str] = []
        if can_change and window.status == "scheduled" and window.current_execution_id is None:
            if window.starts_at <= timezone.now() <= window.start_by:
                actions.append("start")
            actions.extend(("move", "cancel"))
        elif can_change and window.status in {"running", "overran"}:
            actions.append("finish")
        rows.append(
            {
                "window": window,
                "manual_target": window.current_execution.internal_result.get("manual_target")
                if window.current_execution
                else None,
                "actions": [
                    {"name": action, "label": labels[action], "form": maintenance_action_form(window, action)}
                    for action in actions
                ],
            }
        )
    return {
        **direct_maintenance_context(request, node_id=node.pk),
        "maintenance_node": node,
        "maintenance_policy": policy,
        "maintenance_rows": rows,
        "maintenance_account_count": accounts.count(),
        "maintenance_customer_count": Service.objects.filter(pk__in=live_service_ids_for_node(node.pk))
        .values("customer_id")
        .distinct()
        .count(),
        "maintenance_accounts": list(accounts.select_related("service__customer").order_by("domain")[:25]),
        "maintenance_retained_count": retained.count(),
        "maintenance_retained": [
            {
                "domain": duty.domain,
                "customer": duty.migration.account.service.customer,
                "services": [service_labels[name] for name in duty.retained_services],
            }
            for duty in retained.select_related("migration__account__service__customer").order_by("domain")[:25]
        ],
        "maintenance_can_change": can_change,
        "maintenance_can_edit_policy": can_change and not applicable,
        "maintenance_can_schedule": can_change and policy is not None and not applicable,
        "maintenance_applicable": applicable,
        "maintenance_viewer_zone": get_request_localisation(request).timezone,
        "maintenance_policy_weekdays": [
            day["label"] for day in NodeMaintenancePolicyForm(instance=policy).weekday_options if day["selected"]
        ]
        if policy
        else [],
    }


@staff_required
@require_http_methods(["GET", "POST"])
def policy_edit(request: HttpRequest, node_id: UUID) -> HttpResponse:
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Cross-app ownership seam.

    node = get_object_or_404(VirtualminServer, pk=node_id)
    policy = NodeMaintenancePolicy.objects.filter(node=node).first()
    form = NodeMaintenancePolicyForm(
        request.POST if request.method == "POST" else None,
        instance=policy,
        initial={"revision": policy.revision if policy else 0},
    )
    if request.method == "POST":
        actor = cast("User", request.user)
        require_maintenance_operator(actor)
        if form.is_valid():
            try:
                save_maintenance_policy(
                    node.pk,
                    actor=actor,
                    values=cast(PolicyValues, form.cleaned_data),
                    expected_revision=form.cleaned_data["revision"],
                )
                return redirect("infrastructure:maintenance_policy", node_id=node.pk)
            except (ValidationError, IntegrityError) as exc:
                form.add_error(None, str(exc))
    return render(
        request,
        "infrastructure/maintenance_window_form.html",
        {"form": form, "node": node, "policy_form": True, **node_maintenance_context(node, request)},
    )


@staff_required
@require_http_methods(["GET", "POST"])
def window_create(request: HttpRequest, node_id: UUID) -> HttpResponse:
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Cross-app ownership seam.

    node = get_object_or_404(VirtualminServer, pk=node_id)
    policy = NodeMaintenancePolicy.objects.filter(node=node).first()
    form = NodeMaintenanceWindowForm(
        request.POST if request.method == "POST" else None,
        initial={"policy_revision": policy.revision if policy else None},
    )
    if request.method == "POST":
        actor = cast("User", request.user)
        require_maintenance_operator(actor)
        if form.is_valid():
            try:
                with transaction.atomic():
                    VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node.pk)
                    policy = NodeMaintenancePolicy.objects.get(node=node)
                    values = form.cleaned_data
                    if values["policy_revision"] is not None and values["policy_revision"] != policy.revision:
                        raise ValidationError(
                            _("The scheduling policy changed. Reload the current policy and preview.")
                        )
                    create_window(
                        node.pk,
                        actor=actor,
                        kind=values["kind"],
                        execution_mode=values["execution_mode"],
                        starts_at=parse_staff_datetime(values["starts_at"], policy.timezone),
                        ends_at=parse_staff_datetime(values["ends_at"], policy.timezone),
                        expects_downtime=values["expects_downtime"],
                        expected_downtime_minutes=values["expected_downtime_minutes"],
                        customer_note=values["customer_note"],
                    )
                return redirect("infrastructure:maintenance_policy", node_id=node.pk)
            except (ValidationError, IntegrityError, NodeMaintenancePolicy.DoesNotExist) as exc:
                form.add_error(None, str(exc))
    return render(
        request,
        "infrastructure/maintenance_window_form.html",
        {"form": form, "node": node, **node_maintenance_context(node, request)},
    )


@staff_required
@require_POST
def window_action(request: HttpRequest, window_id: UUID, action: str) -> HttpResponse:
    window = get_object_or_404(NodeMaintenanceWindow, pk=window_id)
    actor = cast("User", request.user)
    require_maintenance_operator(actor)
    if request.POST.get("confirmation") != "on":
        return HttpResponseBadRequest(
            _("Review and confirm the maintenance impact before continuing."), content_type="text/plain; charset=utf-8"
        )
    if action not in {"start", "finish", "cancel", "move"}:
        return HttpResponseBadRequest(
            _("Choose a supported maintenance action."), content_type="text/plain; charset=utf-8"
        )
    form = maintenance_action_form(window, action, request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(form.errors.as_text(), content_type="text/plain")
    try:
        values = form.cleaned_data
        change_window(
            window.pk,
            actor=actor,
            revision=values["revision"],
            action=action,
            reason=values["reason"],
            outcome=values.get("outcome", ""),
            public_outcome=values.get("public_outcome", ""),
            attestation=request.POST.get("attestation") == "on",
            starts_at=parse_staff_datetime(values["starts_at"], window.policy_timezone) if action == "move" else None,
            ends_at=parse_staff_datetime(values["ends_at"], window.policy_timezone) if action == "move" else None,
            customer_note=values.get("customer_note", ""),
        )
    except (ValidationError, ValueError, KeyError) as exc:
        return HttpResponseBadRequest(str(exc), content_type="text/plain; charset=utf-8")
    return redirect("infrastructure:maintenance_policy", node_id=window.node_uuid)


@staff_required
@require_POST
def execution_reconcile(request: HttpRequest, execution_id: UUID) -> HttpResponse:
    actor = cast("User", request.user)
    require_maintenance_operator(actor)
    execution = get_object_or_404(NodeMaintenanceExecution, pk=execution_id)
    form = maintenance_reconcile_form(execution, request.POST)
    if not form.is_valid() or any(
        request.POST.get(name) != "on" for name in ("commands_stopped", "resource_confirmed")
    ):
        return HttpResponseBadRequest(
            form.errors.as_text() or _("Confirm both independent operation checks."), content_type="text/plain"
        )
    try:
        values = form.cleaned_data
        execution = reconcile_direct_execution(
            execution.pk,
            actor=actor,
            expected_phase=values["expected_phase"],
            outcome=values["outcome"],
            reason=values["reason"],
            commands_stopped=True,
            resource_confirmed=True,
        )
    except ValidationError as exc:
        return HttpResponseBadRequest(str(exc), content_type="text/plain; charset=utf-8")
    if execution.deployment_id is not None:
        return redirect("infrastructure:deployment_detail", pk=execution.deployment_id)
    if execution.node_id is not None:
        return redirect("infrastructure:maintenance_policy", node_id=execution.node_id)
    return redirect("infrastructure:dashboard")
