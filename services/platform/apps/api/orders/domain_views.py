"""Signed, customer-scoped operations on paid domain lines."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.http import Http404
from django.utils.translation import gettext as _
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import (
    BILLING_ROLES,
    get_authenticated_customer,
    require_customer_role_in,
    require_portal_authentication,
)
from apps.common.performance.rate_limiting import (
    PortalHMACBurstThrottle,
    PortalHMACRateThrottle,
    PublicLookupClientIPThrottle,
)
from apps.domains.availability import DomainAvailabilityService
from apps.domains.transfer_codes import receive_transfer_code

if TYPE_CHECKING:
    from apps.customers.models import Customer


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle])
@require_customer_role_in(*BILLING_ROLES)
def transfer_code(request: Request, customer: Customer, order_id: UUID, item_id: UUID) -> Response:
    """The role decorator authenticates the signed request and its active membership."""
    from apps.orders.models import Order, OrderItem  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).
    from apps.users.models import User  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    actor = getattr(request, "_customer_user", None)
    if not isinstance(actor, User):
        return Response({"error": _("Access denied")}, status=403)
    try:
        receive_transfer_code(
            order_id, item_id, customer=customer, actor=actor, value=request.data.get("transfer_code")
        )
    except (Order.DoesNotExist, OrderItem.DoesNotExist):
        raise Http404 from None
    except ValueError as error:
        return Response({"error": str(error)}, status=400)
    return Response({"success": True}, headers={"Cache-Control": "no-store"})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, PublicLookupClientIPThrottle])
@require_portal_authentication
def availability(request: Request) -> Response:
    """Public browsing is signed; customer-specific requirements need active membership."""
    customer = None
    if "customer_id" in request.data:
        customer, error = get_authenticated_customer(request)
        if error is not None:
            return error
    result = DomainAvailabilityService.check(
        str(request.data.get("domain_name", "")),
        customer=customer,
        action=str(request.data.get("domain_mode", "register")),
    )
    data = (
        result.unwrap()
        if result.is_ok()
        else {"success": False, "available": False, "orderable": False, "error": result.unwrap_err()}
    )
    return Response(data, headers={"Cache-Control": "no-store"})
