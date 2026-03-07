"""Single source of truth for rate limiting configuration.

All settings modules call ``configure_rate_limiting(globals(), ...)``
instead of manually declaring rate limiting flags independently.

The canonical setting is ``RATE_LIMITING_ENABLED``.
"""

from __future__ import annotations

import os
from typing import Any


def configure_rate_limiting(settings_ns: dict[str, Any], *, enabled: bool = True) -> None:
    """Set the ``RATE_LIMITING_ENABLED`` flag from a single boolean.

    Called from each settings module (base, dev, test, prod, staging, e2e).

    The env var ``RATE_LIMITING_ENABLED`` overrides the *enabled* default
    so ops can toggle rate limiting without a code change.
    """
    env_val = os.environ.get("RATE_LIMITING_ENABLED")
    val = env_val.lower() in ("1", "true", "yes") if env_val is not None else enabled

    settings_ns["RATE_LIMITING_ENABLED"] = val
