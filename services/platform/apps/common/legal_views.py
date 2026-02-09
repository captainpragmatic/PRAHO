"""
Legal pages views for GDPR compliance.
Privacy Policy, Terms of Service, Cookie Policy, and Data Processors.
"""

import json
import logging
import uuid

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.audit.models import CookieConsent
from apps.common.request_ip import get_safe_client_ip

logger = logging.getLogger(__name__)


def privacy_policy(request: HttpRequest) -> HttpResponse:
    """GDPR-compliant Privacy Policy page."""
    context = {
        "last_updated": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
        "effective_date": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
    }
    return render(request, "legal/privacy_policy.html", context)


def terms_of_service(request: HttpRequest) -> HttpResponse:
    """Terms of Service page."""
    context = {
        "last_updated": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
        "effective_date": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
    }
    return render(request, "legal/terms_of_service.html", context)


def cookie_policy(request: HttpRequest) -> HttpResponse:
    """Cookie Policy page with detailed cookie descriptions."""
    context = {
        "last_updated": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
    }
    return render(request, "legal/cookie_policy.html", context)


def data_processors(request: HttpRequest) -> HttpResponse:
    """Third-party data processors disclosure page."""
    context = {
        "last_updated": timezone.datetime(2024, 12, 27, tzinfo=timezone.utc),
    }
    return render(request, "legal/data_processors.html", context)


@require_POST
@csrf_protect
def cookie_consent_update(request: HttpRequest) -> HttpResponse:
    """
    Handle cookie consent updates from the banner.
    Creates or updates the CookieConsent record.
    """
    try:
        data = json.loads(request.body)

        # Get or create cookie ID for anonymous users
        cookie_id = request.COOKIES.get("cookie_consent_id", "")
        if not cookie_id:
            cookie_id = str(uuid.uuid4())

        # Map status string to model choice
        status_map = {
            "accepted_all": "accepted_all",
            "accepted_essential": "accepted_essential",
            "customized": "customized",
        }
        status = status_map.get(data.get("status", ""), "customized")

        # Get or create consent record
        if request.user.is_authenticated:
            consent, created = CookieConsent.objects.update_or_create(
                user=request.user,
                defaults={
                    "status": status,
                    "essential_cookies": True,  # Always true
                    "functional_cookies": data.get("functional", False),
                    "analytics_cookies": data.get("analytics", False),
                    "marketing_cookies": data.get("marketing", False),
                    "ip_address": get_safe_client_ip(request),
                    "user_agent": request.META.get("HTTP_USER_AGENT", "")[:500],
                    "consent_version": "1.0",
                },
            )
        else:
            consent, created = CookieConsent.objects.update_or_create(
                cookie_id=cookie_id,
                user__isnull=True,
                defaults={
                    "status": status,
                    "essential_cookies": True,
                    "functional_cookies": data.get("functional", False),
                    "analytics_cookies": data.get("analytics", False),
                    "marketing_cookies": data.get("marketing", False),
                    "ip_address": get_safe_client_ip(request),
                    "user_agent": request.META.get("HTTP_USER_AGENT", "")[:500],
                    "consent_version": "1.0",
                },
            )

        logger.info(
            f"Cookie consent {'created' if created else 'updated'}: "
            f"user={request.user.id if request.user.is_authenticated else 'anonymous'}, "
            f"status={status}"
        )

        response = JsonResponse({"success": True, "consent_id": str(consent.id)})

        # Set cookie ID for anonymous users
        if not request.user.is_authenticated:
            response.set_cookie(
                "cookie_consent_id",
                cookie_id,
                max_age=365 * 24 * 60 * 60,  # 1 year
                httponly=True,
                samesite="Lax",
            )

        return response

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.error(f"Cookie consent update error: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)
