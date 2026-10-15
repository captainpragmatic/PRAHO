"""
Common views for Portal service.
Cookie consent proxy and the operator's legal pages.
"""

import json
import logging
import uuid
from collections.abc import Callable
from functools import partial

from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.translation import get_language, ngettext
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common import altcha, counters
from apps.common.legal_documents import (
    TITLES,
    LegalDocument,
    LegalDocumentsUnavailableError,
    current_legal_document,
    legal_document_release,
)
from apps.common.request_ip import get_safe_client_ip

logger = logging.getLogger(__name__)

api_client = PlatformAPIClient()

# Kept as long as the consent cookie the banner sets: the two are read together.
COOKIE_CONSENT_ID_MAX_AGE = 365 * 24 * 60 * 60


# Per client IP: each verification fetches one, so a page refused a few times stays far below it.
ALTCHA_CHALLENGES_PER_MINUTE = 30


@never_cache
@require_GET
def altcha_challenge_view(request: HttpRequest) -> HttpResponse:
    """A signed proof-of-work challenge for the public forms' widget; 404 while the feature is off."""
    if not altcha.enabled():
        raise Http404
    from apps.common.rate_limiting import _client_ip_is_distinguishable  # noqa: PLC0415  # Shared IP policy

    if getattr(settings, "RATE_LIMITING_ENABLED", True) and _client_ip_is_distinguishable():
        key = f"altcha_challenge_ip_{get_safe_client_ip(request)}"
        try:
            spent = counters.increment(key, 60) > ALTCHA_CHALLENGES_PER_MINUTE
        except Exception:
            logger.exception("🔥 [Altcha] Challenge limiter unavailable")
            return JsonResponse({"error": "unavailable"}, status=503)
        if spent:
            return JsonResponse({"error": "rate_limited"}, status=429, headers={"Retry-After": "60"})
    return JsonResponse(altcha.new_challenge())


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
        # Platform records the Cookie Policy release in force in this language with the choice.
        "language": get_language(),
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
            max_age=COOKIE_CONSENT_ID_MAX_AGE,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure(),
        )

    return response


def _days(seconds: int) -> str:
    count = seconds // (24 * 60 * 60)
    return ngettext("%(count)d day", "%(count)d days", count) % {"count": count}


def _praho_cookies() -> list[tuple[str, str, str]]:
    """What the portal itself stores in the browser: the name, its purpose, and how long it is kept."""
    session = _("%(default)s, or %(remember)s if you choose to stay signed in") % {
        "default": _days(settings.SESSION_COOKIE_AGE_DEFAULT),
        "remember": _days(settings.SESSION_COOKIE_AGE_REMEMBER_ME),
    }
    year = _days(365 * 24 * 60 * 60)  # The consent banner's cookie and the language cookie
    return [
        (settings.SESSION_COOKIE_NAME, _("Keeps you signed in"), session),
        (
            settings.CSRF_COOKIE_NAME,
            _("Protects forms against cross-site request forgery"),
            _days(settings.CSRF_COOKIE_AGE),
        ),
        ("cookie_consent", _("Your cookie choices"), year),
        ("cookie_consent_id", _("Links your cookie choices to the record of them"), _days(COOKIE_CONSENT_ID_MAX_AGE)),
        (settings.LANGUAGE_COOKIE_NAME, _("The language you chose"), year),
        (
            "pendingCookieConsent",
            _("Your cookie choices, kept in local storage until they are recorded"),
            _("Until recorded"),
        ),
        (
            "htmx-history-cache",
            _("Pages opened in this tab, for the Back button, kept in session storage"),
            _("Until the tab is closed"),
        ),
        (
            "Stripe",
            _("On payment pages only, Stripe sets its own cookies to process the payment and prevent fraud"),
            _("As Stripe sets them"),
        ),
    ]


def _legal_page(request: HttpRequest, load: Callable[[], LegalDocument | None], kind: str = "") -> HttpResponse:
    """A legal page: the release load() returns, a notice while none is published, a 503 while Platform is away."""
    try:
        document = load()
    except LegalDocumentsUnavailableError:
        title = TITLES.get(kind, _("Legal document"))
        notice = _("This page cannot be shown right now. Please try again in a few minutes.")
        return render(request, "legal/document.html", {"title": title, "notice": notice}, status=503)
    if document is not None:
        kind = document["kind"]
    elif not kind:
        raise Http404  # No release has this id
    context: dict[str, object] = {"title": TITLES[kind], "kind": kind, "document": document}
    if kind == "cookies":
        context["cookies"] = _praho_cookies()  # Listed under the operator's own policy
    return render(request, "legal/document.html", context)


def terms_of_service_view(request: HttpRequest) -> HttpResponse:
    return _legal_page(request, partial(current_legal_document, "terms", get_language()), "terms")


def privacy_policy_view(request: HttpRequest) -> HttpResponse:
    return _legal_page(request, partial(current_legal_document, "privacy", get_language()), "privacy")


def cookie_policy_view(request: HttpRequest) -> HttpResponse:
    return _legal_page(request, partial(current_legal_document, "cookies", get_language()), "cookies")


def legal_document_view(request: HttpRequest, document_id: uuid.UUID) -> HttpResponse:
    """One release, as an acceptance names it, whether or not it is still in force."""
    return _legal_page(request, partial(legal_document_release, str(document_id)))
