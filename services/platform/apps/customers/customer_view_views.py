"""Staff side of customer view (ADR-0065): the reason page and the handoff to the portal.

The member card links here; this page names the member, explains anything that stops the view, and
asks for a reason. Submitting it issues a one-time code and answers a page that posts the code to the
portal's redeem URL in the request body, so the code never appears in a URL, a log or history.
"""

from __future__ import annotations

import logging
from typing import cast
from urllib.parse import urlsplit

from django.conf import settings
from django.db import DatabaseError, InterfaceError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from apps.common.decorators import staff_required
from apps.customers.user_management_views import _get_accessible_customer
from apps.users import customer_view

logger = logging.getLogger(__name__)

REDEEM_PATH = "/customer-view/redeem/"


def valid_origin(origin: str) -> bool:
    """An exact origin: https (http only while DEBUG), a host, and nothing else."""
    parts = urlsplit(origin)
    secure = parts.scheme == "https" or (parts.scheme == "http" and settings.DEBUG)
    return (
        secure
        and bool(parts.hostname)
        and parts.path in {"", "/"}
        and not (parts.query or parts.fragment or parts.username or parts.password)
    )


@staff_required
@never_cache
@require_http_methods(["GET", "POST"])
def customer_view_start(request: HttpRequest, customer_id: int, user_id: int) -> HttpResponse:
    from apps.users.models import CustomerViewGrant, User  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    customer = _get_accessible_customer(request, customer_id)
    target = get_object_or_404(User, pk=user_id)
    staff = cast(User, request.user)
    context = {
        "customer": customer,
        "target": target,
        "blockers": customer_view.staff_blockers(staff, str(request.session.session_key or "")),
        "target_refusal": customer_view.target_refusal(target, customer),
        "reason_options": [{"value": value, "label": label} for value, label in CustomerViewGrant.REASON_CHOICES],
        "values": {"reason_category": "", "reason": "", "ticket_reference": ""},
        "error": "",
    }
    if request.method == "GET":
        return render(request, "customers/customer_view_start.html", context)

    origin = str(settings.PORTAL_PUBLIC_ORIGIN).rstrip("/")
    values = {key: str(request.POST.get(key, "")) for key in ("reason_category", "reason", "ticket_reference")}
    context["values"] = values
    if not valid_origin(origin):
        context["error"] = _("The portal address is not configured. Set PORTAL_PUBLIC_ORIGIN and restart Platform.")
        return render(request, "customers/customer_view_start.html", context, status=503)
    try:
        grant = customer_view.issue(
            request,
            target_id=target.pk,
            customer_id=customer.pk,
            reason=values["reason"],
            reason_category=values["reason_category"],
            ticket_reference=values["ticket_reference"],
        )
    except customer_view.CustomerViewBlocked as exc:
        context["error"] = exc.message
        return render(request, "customers/customer_view_start.html", context, status=403)
    except (DatabaseError, InterfaceError):
        logger.exception("🔥 [CustomerView] Grant not issued: database or audit unavailable")
        context["error"] = _("Nothing was issued: the database or the audit trail is unavailable. Try again shortly.")
        return render(request, "customers/customer_view_start.html", context, status=503)
    response = render(
        request,
        "customers/customer_view_handoff.html",
        {"code": grant.code, "redeem_url": origin + REDEEM_PATH, "customer": customer, "target": target},
    )
    response["Cache-Control"] = "no-store"
    # This page alone may post a form to the portal; SecurityHeadersMiddleware widens form-action for it.
    vars(response)["csp_form_action"] = origin
    return response
