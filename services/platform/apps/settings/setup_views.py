"""Read-only setup and health pages; existing writers remain authoritative."""

from datetime import timedelta
from uuid import UUID

from django.contrib import messages
from django.core.cache import cache
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from apps.common.decorators import admin_required
from apps.common.rate_limiting import rate_limit
from apps.common.status_observations import display_level
from apps.common.system_status import node_input_identities, runtime_input_identity

from .setup_checklist import get_setup_report
from .views import _sidebar_context


@admin_required
def setup_checklist(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "settings/setup_checklist.html",
        {
            **_sidebar_context(None, request.user),
            "is_admin": True,
            "setup_report": get_setup_report(),
            "setup_active": True,
        },
    )


@admin_required
def system_status_page(request: HttpRequest) -> HttpResponse:
    from apps.common.status_models import (  # noqa: PLC0415
        INTERNAL_CHECK_KEYS,
        NodeResourceHourlySummary,
        SystemCheckState,
    )
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415
    from apps.provisioning.virtualmin_usage_service import node_usage_status  # noqa: PLC0415

    states = (
        SystemCheckState.objects.exclude(check_key__in=INTERNAL_CHECK_KEYS)
        .select_related("node")
        .order_by("node__name", "check_key")
    )
    summaries = (
        NodeResourceHourlySummary.objects.select_related("node")
        .filter(hour__gte=timezone.now() - timedelta(hours=48))
        .order_by("-hour", "node__name")
    )
    node = None
    if selected := request.GET.get("node"):
        try:
            node_id = UUID(selected)
        except ValueError:
            return HttpResponseBadRequest(_("Invalid node selection"))
        node = get_object_or_404(VirtualminServer, pk=node_id)
        states, summaries = states.filter(node=node), summaries.filter(node=node)
    labels = {
        "green": _("Healthy"),
        "amber": _("Needs attention"),
        "red": _("Unhealthy"),
        "grey": _("Not applicable"),
        "unknown": _("Unknown"),
    }
    reasons = {
        "connected": _("Connection verified"),
        "connection_failed": _("Connection check failed"),
        "configuration_changed": _("Configuration changed; run a fresh check"),
        "check_failed": _("Check could not complete"),
    }
    state_rows = list(states)
    identities = node_input_identities(state.node for state in state_rows if state.node is not None)
    global_identity = runtime_input_identity()
    rows = []
    for state in state_rows:
        level = display_level(state, current_identity=identities[state.node_id] if state.node_id else global_identity)
        rows.append(
            {
                "state": state,
                "level": level,
                "label": labels[level],
                "message": state.details.get("message") or reasons.get(state.reason, _("Awaiting a fresh check")),
            }
        )
    return render(
        request,
        "settings/system_status.html",
        {
            "rows": rows,
            "summaries": Paginator(summaries, 48).get_page(request.GET.get("page")),
            "selected_node": node,
            "usage_rows": node_usage_status(node.pk if node else None),
        },
    )


@admin_required
@require_POST
@rate_limit(key="user", rate="1/m", method="POST", block=False)
def node_status_refresh(request: HttpRequest, node_id: UUID) -> HttpResponse:
    from django_q.tasks import async_task  # noqa: PLC0415

    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    node = get_object_or_404(VirtualminServer, pk=node_id)
    if not getattr(request, "limited", False) and cache.add(f"status:node-request:{node.pk}", True, timeout=60):
        try:
            async_task("apps.provisioning.virtualmin_tasks.refresh_virtualmin_node_status", str(node.pk))
            messages.info(request, _("Node check queued. Refresh this page shortly for results."))
        except Exception:
            cache.delete(f"status:node-request:{node.pk}")
            messages.error(request, _("The node check could not be queued. Check the worker and database."))
    else:
        messages.info(request, _("A check was recently requested. Please wait one minute."))
    return redirect(f"{reverse('system_status')}?node={node.pk}")
