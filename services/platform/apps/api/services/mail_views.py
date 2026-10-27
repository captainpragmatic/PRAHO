"""Signed customer reads of PRAHO mail enrollment; no execution or enrollment endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.views.decorators.cache import never_cache
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import require_customer_authentication

if TYPE_CHECKING:
    from apps.customers.models import Customer


@never_cache
@api_view(["GET"])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@authentication_classes([])  # type: ignore[untyped-decorator]  # The existing middleware verifies signed JSON requests.
@permission_classes([AllowAny])  # type: ignore[untyped-decorator]  # Customer authentication follows HMAC verification.
@require_customer_authentication
def service_mail_status_api(request: Request, customer: Customer, service_id: int) -> Response:
    """Current active membership authorizes only the database projection for this customer's service."""
    from apps.provisioning.virtualmin_mail_status import cached_mail_status  # noqa: PLC0415  # ADR-0007: service seam.
    from apps.users.models import User  # noqa: PLC0415  # ADR-0007: canonical authenticated principal.

    actor = getattr(request, "_customer_user", None)
    if not isinstance(actor, User):
        return Response({"success": False, "error": "Access denied"}, status=403, headers={"Cache-Control": "no-store"})
    result = cached_mail_status(service_id, customer_id=customer.pk, actor=actor)
    if result.is_err():
        missing = result.unwrap_err() == "mail_status_not_found"
        return Response(
            {"success": False, "error": "Service not found" if missing else "Access denied"},
            status=404 if missing else 403,
            headers={"Cache-Control": "no-store"},
        )
    return Response({"success": True, "data": {"mail_status": result.unwrap()}}, headers={"Cache-Control": "no-store"})
