"""
Helpers for user-facing rate-limit feedback in Portal views/templates.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError
from apps.common.retry_after import coerce_retry_after_seconds

_RATE_LIMIT_MESSAGE_ADDED_ATTR = "_rate_limit_message_added"


def get_retry_after_from_error(error: Exception) -> int | None:
    if isinstance(error, PlatformAPIError):
        return coerce_retry_after_seconds(error.retry_after)
    return None


def is_rate_limited_error(error: Exception) -> bool:
    return isinstance(error, PlatformAPIError) and bool(error.is_rate_limited)


def is_maintenance_error(error: Exception) -> bool:
    """Only a 503 the platform's own gate MARKED as maintenance. See `PlatformAPIError`."""
    return isinstance(error, PlatformAPIError) and bool(error.is_maintenance)


def is_unavailable_error(error: Exception) -> bool:
    """Any 502/503/504 — the platform is not answering, planned or otherwise."""
    return isinstance(error, PlatformAPIError) and bool(error.is_unavailable)


def get_maintenance_message(retry_after: int | None) -> str:
    if retry_after:
        return _(
            "We're carrying out scheduled maintenance. Your data is safe - please try again in %(seconds)s seconds."
        ) % {"seconds": retry_after}
    return _("We're carrying out scheduled maintenance. Your data is safe - please try again shortly.")


def get_unavailable_message(retry_after: int | None) -> str:
    """For an outage the platform did not declare as maintenance.

    Deliberately says nothing about the data being safe. That reassurance is true of a planned window
    and unknowable during an unexplained failure, and telling a customer their data is safe when
    nobody knows why the request failed is the kind of promise that is remembered.
    """
    if retry_after:
        return _("This information is temporarily unavailable. Please try again in %(seconds)s seconds.") % {
            "seconds": retry_after
        }
    return _("This information is temporarily unavailable. Please try again shortly.")


def get_degraded_message(error: Exception) -> str:
    """The customer-facing sentence for a degraded platform, whichever kind it is.

    One place makes the maintenance-vs-outage choice so a JSON endpoint and a rendered template cannot
    drift into telling the same customer two different things about the same 503.
    """
    retry_after = get_retry_after_from_error(error)
    if is_maintenance_error(error):
        return get_maintenance_message(retry_after)
    if is_rate_limited_error(error):
        return get_rate_limit_message(retry_after)
    return get_unavailable_message(retry_after)


def build_maintenance_context(request: HttpRequest, error: Exception) -> dict[str, str | bool | int | None]:
    """The shape `build_rate_limited_context` established, for the other degraded state.

    "Your data is safe" is the load-bearing half of the message. The failure this replaces did not
    merely fail to explain itself - it showed a customer an empty invoice list, which reads as
    their records having gone missing.
    """
    retry_after = get_retry_after_from_error(error)
    declared_maintenance = is_maintenance_error(error)
    return {
        "maintenance": True,
        "maintenance_retry_after": retry_after,
        # The heading was hardcoded "Scheduled maintenance" in the template, so an undeclared 503 -
        # a real failure the platform happened to answer with 503 - announced itself as planned work.
        "maintenance_heading": _("Scheduled maintenance") if declared_maintenance else _("Temporarily unavailable"),
        "maintenance_message": (
            get_maintenance_message(retry_after) if declared_maintenance else get_unavailable_message(retry_after)
        ),
        "maintenance_retry_url": request.get_full_path(),
    }


def get_rate_limit_message(retry_after: int | None) -> str:
    if retry_after:
        return _("We're receiving many requests right now. Please try again in %(seconds)s seconds.") % {
            "seconds": retry_after
        }
    return _("We're receiving many requests right now. Please try again shortly.")


def record_rate_limit_banner(request: HttpRequest, retry_after: int | None) -> None:
    """
    Queue a warning message for the next rendered response.

    Uses Django's messages framework instead of session-managed banner state
    to keep feedback behavior simple and avoid custom expiration bookkeeping.
    """
    if getattr(request, _RATE_LIMIT_MESSAGE_ADDED_ATTR, False):
        return
    setattr(request, _RATE_LIMIT_MESSAGE_ADDED_ATTR, True)
    messages.warning(request, get_rate_limit_message(coerce_retry_after_seconds(retry_after)), extra_tags="rate-limit")


def build_rate_limited_context(request: HttpRequest, error: Exception) -> dict[str, str | bool | int | None]:
    retry_after = get_retry_after_from_error(error)
    return {
        "rate_limited": True,
        "rate_limit_retry_after": retry_after,
        "rate_limit_message": get_rate_limit_message(retry_after),
        "rate_limit_retry_url": request.get_full_path(),
    }


def handle_platform_error(
    request: HttpRequest,
    error: Exception,
    error_logger: logging.Logger,
    *,
    fallback_message: str = "",
) -> dict[str, Any]:
    """
    Centralized error handler for platform API errors in views.

    Returns a context dict for the two states a template can present specifically - rate limited
    and maintenance - or adds messages.error for anything else and returns an empty dict.
    """
    if is_rate_limited_error(error):
        error_logger.warning("⚠️ Rate limited: %s", error)
        return build_rate_limited_context(request, error)
    if is_unavailable_error(error):
        # Keyed on `is_unavailable`, not `is_maintenance`, so a 502/504 or an undeclared 503 is
        # surfaced too rather than falling through to an empty list. The CONTEXT then decides what
        # the customer is told, which is where the maintenance/unavailable distinction lives.
        #
        # Warning, not error, when it is declared maintenance: paging someone about their own
        # maintenance window is how alerts get ignored. An undeclared outage is logged at error,
        # because nobody chose it. No `fallback_message` either - the specific notice replaces the
        # generic one rather than joining it.
        if is_maintenance_error(error):
            error_logger.warning("⚠️ Platform in maintenance: %s", error)
        else:
            error_logger.error("🔥 Platform unavailable (undeclared): %s", error)
        return build_maintenance_context(request, error)
    error_logger.error("🔥 %s", error)
    if fallback_message:
        messages.error(request, fallback_message)
    return {}


def render_platform_unavailable(request: HttpRequest, error: PlatformAPIError, *, status: int = 503) -> HttpResponse:
    """Render the existing degraded notice without claiming account data is missing."""
    context = build_maintenance_context(request, error)
    template = (
        "components/maintenance_inline_alert.html"
        if request.headers.get("HX-Request") == "true"
        else "common/platform_unavailable.html"
    )
    response = render(request, template, context, status=status)
    retry_after = get_retry_after_from_error(error)
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response
