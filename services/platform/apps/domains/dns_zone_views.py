"""Staff DNS diagnostics display recorded state; mutations persist background intent."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from apps.common.decorators import staff_required_strict

from .dns_zone_models import HostedZone
from .dns_zone_services import cached_zone_status, request_crosscheck, request_operation_retry

if TYPE_CHECKING:
    from apps.users.models import User


@staff_required_strict
@never_cache
def zone_list(request: HttpRequest) -> HttpResponse:
    rows = HostedZone.objects.select_related("customer").order_by("name")
    state = request.GET.get("state", "all")
    if state in {"pending_import", "awaiting_ns", "active", "deleting", "deleted", "failed"}:
        rows = rows.filter(status=state)
    page = Paginator(rows, 25).get_page(request.GET.get("page"))
    return render(request, "domains/staff/zone_list.html", {"zone_page": page})


@staff_required_strict
@never_cache
def zone_detail(request: HttpRequest, zone_id: UUID) -> HttpResponse:
    zone = get_object_or_404(HostedZone.objects.select_related("customer", "account", "service"), pk=zone_id)
    try:
        page = max(1, int(request.GET.get("page", "1")))
    except ValueError:
        page = 1
    operations = [
        {"operation": row, "evidence": json.dumps(row.evidence, ensure_ascii=False, indent=2)[:12000]}
        for row in zone.operations.select_related("revision", "registrar_operation").order_by("-created_at")[:10]
    ]
    return render(
        request,
        "domains/staff/zone_detail.html",
        {
            "zone": zone,
            "dns": cached_zone_status(zone, page=page),
            "operations": operations,
            "readiness_evidence": json.dumps(zone.readiness, ensure_ascii=False, indent=2)[:12000],
            "retry_available": zone.operations.filter(status="parked", revision__number=zone.current_revision)
            .exclude(phase="create_zone_inflight")
            .exists(),
        },
    )


@staff_required_strict
@require_POST
@never_cache
def zone_crosscheck(request: HttpRequest, zone_id: UUID) -> HttpResponse:
    zone = get_object_or_404(HostedZone, pk=zone_id)
    try:
        revision = int(request.POST.get("expected_revision", ""))
    except ValueError:
        revision = 0
    result = request_crosscheck(zone, revision, actor=cast("User", request.user))
    if result.is_ok():
        messages.success(request, _("A background DNS inventory check was requested."))
    else:
        messages.warning(request, _("This DNS inventory cannot be checked in its current state."))
    return redirect("domains:zone_detail", zone_id=zone.pk)


@staff_required_strict
@require_POST
@never_cache
def zone_retry(request: HttpRequest, zone_id: UUID) -> HttpResponse:
    zone = get_object_or_404(HostedZone, pk=zone_id)
    result = request_operation_retry(zone, actor=cast("User", request.user))
    if result.is_ok():
        messages.success(request, _("The recorded DNS operation is waiting for a background retry."))
    else:
        messages.warning(request, _("This operation requires review before it can be retried."))
    return redirect("domains:zone_detail", zone_id=zone.pk)
