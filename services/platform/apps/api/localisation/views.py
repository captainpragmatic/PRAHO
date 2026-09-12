"""Allowlisted display defaults for the HMAC-authenticated customer portal."""

from typing import Any

from django.http import HttpRequest
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.secure_auth import require_portal_service_authentication
from apps.common.localisation_services import get_localisation_defaults
from apps.common.performance.rate_limiting import PortalHMACBurstThrottle, PortalHMACRateThrottle


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # HMAC authentication is required by the service decorator.
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle])
@require_portal_service_authentication
def localisation_defaults(request: HttpRequest, request_data: dict[str, Any]) -> Response:
    return Response({"success": True, "localisation": get_localisation_defaults().customer_payload()})
