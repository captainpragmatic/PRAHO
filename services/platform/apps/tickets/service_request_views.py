"""Staff-only service-request decisions from the ticket page."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from apps.common.decorators import staff_required_strict
from apps.provisioning.service_request_service import ServiceRequestError, review_service_request

from .models import Ticket

if TYPE_CHECKING:
    from apps.users.models import User


@staff_required_strict
@require_POST
def service_request_decision(request: HttpRequest, pk: int) -> HttpResponse:
    from apps.provisioning.service_request_models import ServiceRequest  # noqa: PLC0415 -- cross-app model

    from .views import ticket_detail  # noqa: PLC0415 -- reuse the complete error page

    ticket = get_object_or_404(Ticket, pk=pk)
    get_object_or_404(ServiceRequest, ticket=ticket)
    try:
        review_service_request(
            ticket_id=ticket.pk,
            staff=cast("User", request.user),
            decision=request.POST.get("decision", ""),
            note=request.POST.get("note", ""),
            expected_status=request.POST.get("expected_status", ""),
        )
    except ServiceRequestError as exc:
        messages.error(request, str(exc))
        response = ticket_detail(request, pk)
        response.status_code = exc.status_code
        return response
    messages.success(request, _("Internal service-request decision recorded."))
    return redirect("tickets:detail", pk=ticket.pk)
