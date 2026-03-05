"""
Shared Retry-After parsing helpers for Platform.
"""

from __future__ import annotations

import math
import time
from email.utils import parsedate_to_datetime
from typing import Any


def coerce_retry_after_seconds(value: Any) -> int | None:
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
        if text.isdigit():
            parsed = int(text)
        else:
            try:
                target_dt = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError):
                return parsed
            parsed = math.ceil(target_dt.timestamp() - time.time())

    return max(1, parsed)
