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
from apps.settings.services import SettingsService, get_brand_name, get_company_legal_name


def _text(value: object) -> str:
    return str(value or "")


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # HMAC authentication is required by the service decorator.
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, CustomerRateThrottle, BurstRateThrottle])
@require_portal_service_authentication
def localisation_defaults(request: HttpRequest, request_data: dict[str, object]) -> Response:
    # What the portal shows customers. The legal pages state the operator's identity, the privacy
    # contact and the DPO's (GDPR Art. 13(1)(b)), so these are public; the no-reply sender is not.
    company = {
        "legal_name": get_company_legal_name(),
        "brand_name": get_brand_name(),
        "email_support": _text(SettingsService.get_setting("company.email_support")),
        "email_privacy": _text(SettingsService.get_setting("company.email_privacy")),
        "email_finance": _text(SettingsService.get_setting("company.email_finance")),
        "phone": _text(SettingsService.get_setting("company.phone")),
        "email_dpo": _text(SettingsService.get_setting("company.email_dpo")),
        "email_contact": _text(SettingsService.get_setting("company.email_contact")),
        "address": _text(SettingsService.get_setting("company.address")),
        "registration_number": _text(SettingsService.get_setting("company.registration_number")),
    }
    from apps.customers.anaf_verification import lookups_enabled  # noqa: PLC0415  # Deferred: loaded on use

    return Response(
        {
            "success": True,
            "localisation": get_localisation_defaults().customer_payload(),
            "company": company,
            # Features the portal shows only when Platform offers them; it never learns why.
            "features": {"company_lookup": lookups_enabled()},
        }
    )
