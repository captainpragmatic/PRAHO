"""What a customer view may open in the portal (ADR-0065): reading pages only, deny by default.

Applied by the auth middleware before every view, public routes included, whenever the browser
session is a customer view. Platform enforces the same rule on every API call; this gate keeps a
staff member from even reaching a form whose submission Platform would refuse.
"""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import Resolver404, resolve

from apps.common.store_unavailable import wants_json

_GET = frozenset({"GET", "HEAD"})
_POST = frozenset({"POST"})

READS: frozenset[str] = frozenset(
    {
        "root",
        "dashboard:dashboard",
        "dashboard:account_overview",
        "users:profile",
        "users:company_profile",
        "users:consent_history",
        "billing:invoices_list",
        "billing:invoices_search_api",
        "billing:invoice_detail",
        "billing:invoice_pdf_export",
        "billing:proforma_detail",
        "billing:proforma_pdf_export",
        "billing:dashboard_widget",
        "billing:recurring_payments",
        "tickets:list",
        "tickets:detail",
        "tickets:attachment_download",
        "tickets:search_api",
        "tickets:dashboard_widget",
        "services:list",
        "services:search_api",
        "services:detail",
        "services:usage",
        "services:dashboard_widget",
        "customers:team",
        "customers:addresses",
        "cookie_policy",
        "terms_of_service",
        "privacy_policy",
        "legal_document",
        "robots_txt",
        "portal_status",
    }
)
# Leaving the view, and opening another one: the only writes a customer view may make.
CONTROLS: dict[str, frozenset[str]] = {
    "users:logout": _GET | _POST,
    "users:customer_view_leave": _POST,
    "users:customer_view_redeem": _POST,
}


def route_name(request: HttpRequest) -> str:
    try:
        return resolve(request.path_info).view_name
    except Resolver404:
        return ""


def allowed(request: HttpRequest) -> bool:
    name = route_name(request)
    method = request.method or ""
    if method in CONTROLS.get(name, frozenset()):
        return True
    if name not in READS or method not in _GET:
        return False
    # No query may name another person or customer than the one being viewed.
    for key, expected in (
        ("user_id", request.session.get("user_id")),
        ("customer_id", request.session.get("customer_view_customer_id")),
    ):
        if any(value != str(expected) for value in request.GET.getlist(key)):
            return False
    return True


def refused(request: HttpRequest) -> HttpResponse:
    if wants_json(request):
        return JsonResponse({"error": "customer_view_forbidden"}, status=403)
    context: dict[str, Any] = {"customer_view_denied_path": request.path}
    return render(request, "users/customer_view_denied.html", context, status=403)
