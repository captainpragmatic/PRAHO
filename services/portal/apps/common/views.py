"""
Common views for Portal service.
Cookie consent proxy, cookie policy page.
"""

import json
import logging
import uuid
from datetime import date

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common.legal import TERMS_OF_SERVICE_VERSION
from apps.common.localisation_services import get_company_identity
from apps.common.request_ip import get_safe_client_ip

logger = logging.getLogger(__name__)

api_client = PlatformAPIClient()


@require_POST
@csrf_protect
def cookie_consent_view(request: HttpRequest) -> HttpResponse:
    """
    Proxy cookie consent to Platform GDPR API.
    Accepts JSON body with consent preferences from the banner.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON"}, status=400)

    # Read or generate cookie_id for anonymous visitors
    cookie_id = request.COOKIES.get("cookie_consent_id", "")
    if not cookie_id:
        cookie_id = str(uuid.uuid4())

    # Build payload for Platform GDPR API
    consent_data = {
        "cookie_id": cookie_id,
        "status": data.get("status", "customized"),
        "functional": bool(data.get("functional", False)),
        "analytics": bool(data.get("analytics", False)),
        "marketing": bool(data.get("marketing", False)),
        "ip_address": get_safe_client_ip(request),
        "user_agent": request.META.get("HTTP_USER_AGENT", "")[:500],
    }

    # Include user_id from session if authenticated
    user_id = request.session.get("user_id")
    if user_id:
        consent_data["user_id"] = user_id

    try:
        result = api_client.submit_cookie_consent(consent_data)
        success = result.get("success", False)
    except PlatformAPIError:  # fire-and-forget: rate-limit-aware, consent saved client-side as fallback
        logger.warning("⚠️ [Portal Cookie] Platform API unavailable, consent saved client-side only")
        success = False

    response = JsonResponse({"success": success})

    # Set cookie_consent_id for anonymous tracking across sessions
    if not request.COOKIES.get("cookie_consent_id"):
        response.set_cookie(
            "cookie_consent_id",
            cookie_id,
            max_age=365 * 24 * 60 * 60,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure(),
        )

    return response


def terms_of_service_view(request: HttpRequest) -> HttpResponse:
    """Terms of Service - public. The text is shared with Platform's page, and the version is the one Platform records."""
    company = get_company_identity()
    effective_date = date.fromisoformat(TERMS_OF_SERVICE_VERSION)  # A calendar date, in every timezone
    context = {
        "terms_version": TERMS_OF_SERVICE_VERSION,
        "last_updated": effective_date,
        "effective_date": effective_date,
        "legal_name": company["legal_name"],
        "company_phone": company["phone"],
        "company_support_email": company["email_support"],
        "privacy_policy_url": reverse("privacy_policy"),
    }
    return render(request, "legal/terms_of_service.html", context)


# A calendar date, as Platform's page states it.
PRIVACY_POLICY_DATE = date(2024, 12, 27)


def privacy_policy_view(request: HttpRequest) -> HttpResponse:
    """Privacy Policy - public. The text is shared with Platform's page."""
    company = get_company_identity()
    context = {
        "last_updated": PRIVACY_POLICY_DATE,
        "effective_date": PRIVACY_POLICY_DATE,
        "legal_name": company["legal_name"],
        "company_email": company["email_support"],
        "company_phone": company["phone"],
        "company_privacy_email": company["email_privacy"],
        # The customer's own privacy dashboard; signing in leads there.
        "rights_url": reverse("users:privacy_dashboard"),
        "rights_label": _("Go to your Privacy Dashboard"),
    }
    return render(request, "legal/privacy_policy.html", context)


def cookie_policy_view(request: HttpRequest) -> HttpResponse:
    """
    Cookie policy page - public, no auth required.
    Lists all cookie categories with name, purpose, duration, provider.
    """
    return render(request, "legal/cookie_policy.html")
