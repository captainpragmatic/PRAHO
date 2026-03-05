"""
Centralized API exception handling for Platform service.
"""

from __future__ import annotations

import math
from http import HTTPStatus
from typing import Any

from rest_framework.exceptions import Throttled
from rest_framework.response import Response
from rest_framework.views import exception_handler


def _coerce_retry_after(value: Any) -> int | None:
    """Best-effort conversion to integer seconds."""
    try:
        retry_after = math.ceil(float(value))
    except (TypeError, ValueError):
        return None
    return max(1, retry_after)


def platform_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    """
    Normalize throttling responses for portal clients.

    Keeps DRF's `detail` field for compatibility while guaranteeing an
    explicit `error` and `retry_after` payload contract.
    """
    response = exception_handler(exc, context)
    if response is None:
        return None

    if response.status_code != HTTPStatus.TOO_MANY_REQUESTS:
        return response

    detail: str
    existing_data = response.data if isinstance(response.data, dict) else {}
    if isinstance(existing_data.get("detail"), str):
        detail = existing_data["detail"]
    elif isinstance(existing_data.get("error"), str):
        detail = existing_data["error"]
    else:
        detail = "Request was throttled."

    retry_after = None
    if isinstance(exc, Throttled):
        retry_after = _coerce_retry_after(getattr(exc, "wait", None))
    if retry_after is None:
        retry_after = _coerce_retry_after(existing_data.get("retry_after"))
    if retry_after is None:
        retry_after = _coerce_retry_after(response.headers.get("Retry-After"))
    if retry_after is None:
        retry_after = 60

    response.data = {
        "success": False,
        "error": "Too many requests",
        "detail": detail,
        "retry_after": retry_after,
        "status": 429,
    }
    response["Retry-After"] = str(retry_after)
    return response
