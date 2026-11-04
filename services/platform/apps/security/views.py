"""Staff security requests query Platform only; host work belongs to background tasks."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET

from .addresses import address_bounds
from .customer_matches import with_customer_matches
from .forms import SecurityFilterForm
from .models import SecurityAlert, SecurityDecision, SecuritySource
from .permissions import can_manage_security, can_revoke_security, can_view_security
from .presentation import source_status

if TYPE_CHECKING:
    from apps.users.models import User


def _decision_rows(form: SecurityFilterForm) -> QuerySet[SecurityDecision]:
    rows = SecurityDecision.objects.select_related("source")
    if not form.is_valid():
        return rows.none()
    now = timezone.now()
    state = form.cleaned_data.get("state") or "active"
    if state == "active":
        rows = rows.filter(ended_at__isnull=True, expires_at__gt=now)
    elif state == "ended":
        rows = rows.filter(Q(ended_at__isnull=False) | Q(expires_at__lte=now))
    if source := form.cleaned_data.get("source"):
        rows = rows.filter(source=source)
    if scenario := form.cleaned_data.get("scenario"):
        rows = rows.filter(scenario__icontains=scenario)
    if origin := form.cleaned_data.get("origin"):
        rows = rows.filter(origin=origin)
    if scope := form.cleaned_data.get("scope"):
        rows = rows.filter(scope=scope)
    if address := form.cleaned_data.get("address"):
        bounds = address_bounds("range" if "/" in address else "ip", address)
        rows = rows.filter(
            address_family=bounds.address_family,
            network_start__lte=bounds.network_end,
            network_end__gte=bounds.network_start,
        )
    return with_customer_matches(rows, now).order_by(
        "-recent_customer_match", "expires_at", "source__hostname", "remote_id"
    )


def _alert_rows(form: SecurityFilterForm) -> QuerySet[SecurityAlert]:
    rows = SecurityAlert.objects.select_related("source")
    if not form.is_valid():
        return rows.none()
    if source := form.cleaned_data.get("source"):
        rows = rows.filter(source=source)
    if scenario := form.cleaned_data.get("scenario"):
        rows = rows.filter(scenario__icontains=scenario)
    if scope := form.cleaned_data.get("scope"):
        rows = rows.filter(scope=scope)
    if simulated := form.cleaned_data.get("simulated"):
        rows = rows.filter(simulated=simulated == "yes")
    if address := form.cleaned_data.get("address"):
        bounds = address_bounds("range" if "/" in address else "ip", address)
        rows = rows.filter(
            address_family=bounds.address_family,
            network_start__lte=bounds.network_end,
            network_end__gte=bounds.network_start,
        )
    return rows.order_by("-source_created_at", "source__hostname", "-remote_id")


@login_required
@require_GET
def dashboard(request: HttpRequest) -> HttpResponse:
    user = cast("User", request.user)
    if not can_view_security(user):
        raise PermissionDenied
    parameters = request.GET.copy()
    if "state" not in parameters:
        parameters["state"] = "active"
    form = SecurityFilterForm(parameters)
    kind = "alerts" if request.GET.get("kind") == "alerts" else "decisions"
    form.fields.pop("state" if kind == "alerts" else "simulated")
    if kind == "alerts":
        form.fields.pop("origin")
    rows = _alert_rows(form) if kind == "alerts" else _decision_rows(form)
    page = Paginator(rows, 25).get_page(request.GET.get("page"))
    parameters.pop("page", None)
    parameters.pop("kind", None)
    query = parameters.urlencode()
    now = timezone.now()
    sources = SecuritySource.objects.select_related("sync_state").order_by("hostname", "created_at")
    return render(
        request,
        "security/dashboard.html",
        {
            "page_title": _("Security"),
            "filters": form,
            "security_page": page,
            "kind": kind,
            "query": query,
            "source_statuses": [source_status(source, now) for source in sources],
            "can_manage_security": can_manage_security(user),
            "can_revoke_security": can_revoke_security(user),
        },
        status=200 if form.is_valid() else 400,
    )
