"""
Shared Retry-After parsing helpers for Portal.
"""

from __future__ import annotations

import math
import time
from email.utils import parsedate_to_datetime

from django.conf import settings

MAX_RETRY_AFTER_SECONDS: int = 300


def coerce_retry_after_seconds(value: int | float | str | None) -> int | None:
    """
    Convert Retry-After style values into positive integer seconds.

    Supports:
    - numeric seconds (int/float/string)
    - HTTP-date values
    """
    parsed: int | None = None
    if value is None:
        return parsed

    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)):
            return parsed
        parsed = math.ceil(float(value))
    else:
        text = str(value).strip()
        if not text:
            return parsed
        if text.isascii() and text.isdigit():
            parsed = int(text)
        else:
            try:
                target_dt = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError, OverflowError, OSError):
                return parsed
            parsed = math.ceil(target_dt.timestamp() - time.time())

    cap = int(getattr(settings, "RETRY_AFTER_MAX_SECONDS", MAX_RETRY_AFTER_SECONDS))
    return min(max(1, parsed), cap)
