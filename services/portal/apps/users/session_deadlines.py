"""The deadlines Platform gave this portal session (ADR-0017 section 5). The portal computes none.

Platform owns each tier's lifetimes and answers every login and validation with the session's tier,
its absolute end and its idle deadline. The portal stores what Platform said, after checking that it
can be what Platform says: a known tier, aware times in the future, an idle deadline no later than
the end, and an end no further away than Platform's longest tier plus the clock difference Platform
accepts on a signed request. Anything else is treated like a login without a session.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from apps.api_client.services import PLATFORM_MAX_CLOCK_BEHIND_SECONDS

if TYPE_CHECKING:
    from collections.abc import Mapping

KNOWN_TIERS = frozenset({"standard", "remember", "customer_view"})
# A sanity bound on what Platform can answer, not a lifetime: Platform's longest tier.
LONGEST_SESSION = timedelta(days=30)
# Platform's clock may run this far ahead of the portal's and still accept a signed request.
CLOCK_ALLOWANCE = timedelta(seconds=PLATFORM_MAX_CLOCK_BEHIND_SECONDS)

TIER_KEY = "session_tier"
EXPIRES_KEY = "session_expires_at"
IDLE_KEY = "session_idle_deadline"


@dataclass(frozen=True)
class SessionDeadlines:
    tier: str
    expires_at: datetime
    idle_deadline: datetime


def _aware(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def from_platform(payload: Mapping[str, Any], now: datetime) -> SessionDeadlines | None:
    """The deadlines in a login or validation answer, or None when they cannot be Platform's."""
    tier = payload.get(TIER_KEY)
    expires_at = _aware(payload.get(EXPIRES_KEY))
    idle_deadline = _aware(payload.get(IDLE_KEY))
    if tier not in KNOWN_TIERS or expires_at is None or idle_deadline is None:
        return None
    if not now < idle_deadline <= expires_at <= now + LONGEST_SESSION + CLOCK_ALLOWANCE:
        return None
    return SessionDeadlines(str(tier), expires_at, idle_deadline)


def store(session: Any, deadlines: SessionDeadlines) -> None:
    session[TIER_KEY] = deadlines.tier
    session[EXPIRES_KEY] = deadlines.expires_at.isoformat()
    session[IDLE_KEY] = deadlines.idle_deadline.isoformat()


def stored(session: Any) -> SessionDeadlines | None:
    """What the session holds, without the freshness checks: past deadlines are the caller's to act on."""
    tier = session.get(TIER_KEY)
    expires_at = _aware(session.get(EXPIRES_KEY))
    idle_deadline = _aware(session.get(IDLE_KEY))
    if tier not in KNOWN_TIERS or expires_at is None or idle_deadline is None:
        return None
    return SessionDeadlines(str(tier), expires_at, idle_deadline)
