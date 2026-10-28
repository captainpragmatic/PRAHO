"""What a customer view may call on Platform (ADR-0065): reads only, deny by default.

Applied in ``PortalServiceHMACMiddleware`` to every verified request bound to a ``customer_view``
session, decorated view or not. A route is allowed only by its URL name and method. The endpoints in
v1 are reads that choose nothing from a body ``action``; the profile view reads on POST and writes on
PUT, so only its POST is listed. Any customer id the request names must be the viewed customer's.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import Resolver404, resolve

if TYPE_CHECKING:
    from apps.users.models import PortalSession

logger = logging.getLogger(__name__)

_POST = frozenset({"POST"})
_GET = frozenset({"GET", "HEAD"})

READS: dict[str, frozenset[str]] = {
    "api:localisation": _POST,
    "api:legal_document": _POST,
    "api:user_info": _GET,
    "api:customer_profile": _POST,
    "api:user_customers": _POST,
    "api:verify_customer_access": _POST,
    "api:customers:customer-detail": _POST,
    "api:customers:customer-users-list": _POST,
    "api:customers:customer-addresses-list": _POST,
    "api:api_billing:currencies": _GET,
    "api:api_billing:customer_billing_documents": _POST,
    "api:api_billing:customer_invoices": _POST,
    "api:api_billing:customer_invoice_detail": _POST,
    "api:api_billing:invoice_pdf_export": _POST,
    "api:api_billing:customer_invoice_summary": _POST,
    "api:api_billing:customer_proformas": _POST,
    "api:api_billing:customer_proforma_detail": _POST,
    "api:api_billing:proforma_pdf_export": _POST,
    "api:api_billing:recurring_payments_overview": _POST,
    "api:tickets:customer_tickets_list": _POST,
    "api:tickets:customer_tickets_summary": _POST,
    "api:tickets:support_categories": _GET,
    "api:tickets:customer_ticket_detail": _POST,
    "api:tickets:ticket_attachment_download": _POST,
    "api:services:customer_services_list": _POST,
    "api:services:customer_services_summary": _POST,
    "api:services:customer_service_detail": _POST,
    "api:services:customer_service_domains": _POST,
    "api:services:service_usage_stats": _POST,
    "api:gdpr_consent_history": _POST,
}
# The session's own lifecycle: allowed, and not recorded as a data access.
CONTROLS: dict[str, frozenset[str]] = {
    "api:validate_session_secure": _POST,
    "api:portal_session_end": _POST,
}


def _route(request: HttpRequest) -> str:
    try:
        return resolve(request.path_info).view_name
    except Resolver404:
        return ""


def _names_another_customer(request: HttpRequest, data: dict[str, object], customer_id: int) -> bool:
    """Any customer id in the body or query that is not exactly the viewed customer's."""
    named = [data["customer_id"]] if "customer_id" in data else []
    named += request.GET.getlist("customer_id")
    for value in named:
        if isinstance(value, bool) or not isinstance(value, int | str) or str(value) != str(customer_id):
            return True
    return False


def forbidden() -> JsonResponse:
    response = JsonResponse({"error": "customer_view_forbidden"}, status=403)
    response["Cache-Control"] = "no-store"
    return response


def check(request: HttpRequest, data: dict[str, object], row: PortalSession) -> HttpResponse | None:
    """Refuse what a customer view may not do; record every data access and every refusal."""
    from apps.users.customer_view import _audit  # noqa: PLC0415  # one audit vocabulary for the feature

    route = _route(request)
    method = request.method or ""
    if method in CONTROLS.get(route, frozenset()):
        return None
    allowed = method in READS.get(route, frozenset()) and not _names_another_customer(
        request, data, int(row.customer_view_customer_id or 0)
    )
    metadata = {
        "customer_id": str(row.customer_view_customer_id),
        "grant_id": str(row.customer_view_grant_id),
        "route": route or "unresolved",
        "method": method,
    }
    try:
        with transaction.atomic():
            _audit(
                "customer_view_accessed" if allowed else "customer_view_denied",
                staff=row.viewed_as_customer_by,
                target=row.user,
                metadata=metadata,
            )
    except Exception:
        # Accountability first: a read that cannot be recorded is not served; a refusal stays refused.
        logger.exception("🔥 [CustomerView] Access record unavailable for %s %s", method, route)
        if allowed:
            return JsonResponse({"error": "Customer view unavailable"}, status=503)
    return None if allowed else forbidden()
