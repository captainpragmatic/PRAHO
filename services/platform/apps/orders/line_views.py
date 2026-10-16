"""Staff finish an order's service line by hand."""

from __future__ import annotations

from uuid import UUID

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from apps.common.decorators import staff_required_strict

from .hosting_fulfilment import complete_line_for_staff
from .models import OrderItem

# Who may finish a line by hand: it can put a service live and completes what the customer paid for.
LINE_FULFILMENT_ROLES = frozenset({"admin", "manager"})


def can_fulfil_lines(user: object) -> bool:
    from apps.users.models import User  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    return isinstance(user, User) and (user.is_superuser or user.staff_role in LINE_FULFILMENT_ROLES)


@staff_required_strict
@require_POST
def order_item_fulfil(request: HttpRequest, pk: UUID, item_pk: UUID) -> HttpResponse:
    from apps.users.models import User  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    if not can_fulfil_lines(request.user) or not isinstance(request.user, User):
        return HttpResponseForbidden(_("Only admin or manager staff can mark a line fulfilled."))
    line = get_object_or_404(OrderItem, pk=item_pk, order_id=pk)
    if not request.user.can_access_customer(line.order.customer):
        raise Http404
    result = complete_line_for_staff(
        line.pk, actor=request.user, activate_service=bool(request.POST.get("activate_service"))
    )
    if result.is_ok():
        messages.success(request, _("The line is marked fulfilled."))
    else:
        messages.error(request, result.unwrap_err())
    destination = reverse("orders:order_detail", kwargs={"pk": pk})
    if request.headers.get("HX-Request") == "true":
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)
