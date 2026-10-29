"""What Platform answers a portal login with, for tests that fake that answer (ADR-0017 section 5)."""

from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

LIFETIMES = {"standard": (timedelta(hours=24), timedelta(hours=1)), "remember": (timedelta(days=30), timedelta(days=7))}


def session_fields(tier: str = "standard") -> dict[str, str]:
    """A fresh session's tier and deadlines, as Platform's login and validation answers carry them."""
    absolute, idle = LIFETIMES[tier]
    now = timezone.now()
    return {
        "session_tier": tier,
        "session_expires_at": (now + absolute).isoformat(),
        "session_idle_deadline": (now + idle).isoformat(),
    }
