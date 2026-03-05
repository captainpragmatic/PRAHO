"""
Helpers for user-facing rate-limit feedback in Portal views/templates.
"""

from __future__ import annotations

from django.contrib import messages
from django.http import HttpRequest
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
    record_rate_limit_banner(request, retry_after)
    return {
        "rate_limited": True,
        "rate_limit_retry_after": retry_after,
        "rate_limit_message": get_rate_limit_message(retry_after),
        "rate_limit_retry_url": request.get_full_path(),
    }
