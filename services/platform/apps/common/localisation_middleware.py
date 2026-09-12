"""Apply language to web pages while keeping display timezone explicit."""

from collections.abc import Callable
from dataclasses import replace

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils import translation
from django.utils.cache import patch_vary_headers

# Django 5.2's public request helper hardcodes settings.LANGUAGE_CODE on fallback.
# Its bounded parser lets unsupported browser languages inherit the runtime default
# without changing process-wide settings or maintaining a second HTTP parser.
# Django is pinned to 5.2; mirrored negotiation tests guard upgrades of this import.
from django.utils.translation.trans_real import parse_accept_lang_header

from apps.common.localisation import LANGUAGES
from apps.common.localisation_services import get_request_localisation


def sync_language_selection(request: HttpRequest, response: HttpResponse, language: str) -> None:
    """Replace old explicit choices after a successful profile save."""
    request.session["localisation_preferences_saved"] = True
    for key in ("_language", "django_language"):
        request.session.pop(key, None)
    cookie_name = settings.LANGUAGE_COOKIE_NAME
    if language in LANGUAGES:
        request.session["_language"] = language
        response.set_cookie(
            cookie_name,
            language,
            max_age=31536000,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure(),
            path=settings.LANGUAGE_COOKIE_PATH,
            domain=settings.LANGUAGE_COOKIE_DOMAIN,
        )
    else:
        response.delete_cookie(cookie_name, path=settings.LANGUAGE_COOKIE_PATH, domain=settings.LANGUAGE_COOKIE_DOMAIN)


class LocalisationMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Document/API endpoints retain the pre-existing Django locale policy.
        if (
            "/api/" in request.path_info
            or request.path_info.startswith(("/api/", "/admin/", "/i18n/", "/static/", "/media/", "/status/"))
            or request.path_info.rstrip("/").endswith("/pdf")
        ):
            return self.get_response(request)
        policy = get_request_localisation(request)
        authenticated = bool(getattr(getattr(request, "user", None), "is_authenticated", False))
        if not authenticated:
            selected = next(
                (
                    value
                    for value in (
                        request.session.get("_language"),
                        request.session.get("django_language"),
                        request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME),
                    )
                    if isinstance(value, str) and value in LANGUAGES
                ),
                None,
            )
            if selected is None:
                # Django's normal browser negotiation, only when a header is present.
                selected = None
                for code, _quality in parse_accept_lang_header(request.META.get("HTTP_ACCEPT_LANGUAGE", "")):
                    try:
                        candidate = translation.get_supported_language_variant(code)
                    except LookupError:
                        continue
                    if candidate in LANGUAGES:
                        selected = candidate
                        break
            if selected in LANGUAGES:
                policy = replace(policy, language=selected)
        request.localisation = policy  # type: ignore[attr-defined]  # Request-scoped display policy attached by this middleware
        request.LANGUAGE_CODE = policy.language
        with translation.override(policy.language):
            response = self.get_response(request)
            response.setdefault("Content-Language", policy.language)
            patch_vary_headers(response, ("Accept-Language", "Cookie"))
            return response
