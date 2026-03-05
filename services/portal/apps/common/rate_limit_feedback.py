"""
Helpers for user-facing rate-limit feedback in Portal views/templates.
"""

from __future__ import annotations

import math
import time
from typing import Any

from django.http import HttpRequest
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError

RATE_LIMIT_BANNER_UNTIL_KEY = "rate_limit_banner_until"


def _coerce_retry_after(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = math.ceil(float(value))
    except (TypeError, ValueError):
        return None
    return max(1, parsed)


def get_retry_after_from_error(error: Exception) -> int | None:
    if isinstance(error, PlatformAPIError):
        return _coerce_retry_after(error.retry_after)
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
    Store a short-lived warning banner in session so subsequent pages show
    explicit rate-limit feedback instead of silent degradation.
    """
    retry_seconds = min(max(_coerce_retry_after(retry_after) or 15, 5), 300)
    request.session[RATE_LIMIT_BANNER_UNTIL_KEY] = int(time.time()) + retry_seconds


def consume_rate_limit_banner(request: HttpRequest) -> dict[str, str] | None:
    until = request.session.get(RATE_LIMIT_BANNER_UNTIL_KEY)
    if not until:
        return None

    now = int(time.time())
    if now >= int(until):
        request.session.pop(RATE_LIMIT_BANNER_UNTIL_KEY, None)
        return None

    remaining = max(1, int(until) - now)
    return {
        "severity": "warning",
        "message": get_rate_limit_message(remaining),
        "cta_url": request.get_full_path(),
        "cta_text": _("Try again"),
    }
