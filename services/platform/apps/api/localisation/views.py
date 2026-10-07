"""Allowlisted display defaults for the HMAC-authenticated customer portal."""

from django.http import HttpRequest
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.secure_auth import require_portal_service_authentication
from apps.common.localisation_services import get_localisation_defaults
from apps.common.performance.rate_limiting import (
    BurstRateThrottle,
    CustomerRateThrottle,
    PortalHMACBurstThrottle,
    PortalHMACRateThrottle,
)
from apps.settings.services import SettingsService


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # HMAC authentication is required by the service decorator.
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, CustomerRateThrottle, BurstRateThrottle])
@require_portal_service_authentication
def localisation_defaults(request: HttpRequest, request_data: dict[str, object]) -> Response:
    company = {
        field: str(SettingsService.get_setting(f"company.{field}") or "")
        for field in ("legal_name", "email_support", "email_privacy", "email_finance", "phone")
    }
    return Response(
        {
            "success": True,
            "localisation": get_localisation_defaults().customer_payload(),
            "company": company,
        }
    )
