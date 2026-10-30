"""How long a customer's portal session lives, by tier (ADR-0017 section 5). The only owner of these values.

NIST SP 800-63B-4: a standard session is AAL2 (24 hours, 1 hour idle). "Remember me" is AAL1 (30 days,
with a 7-day idle limit), acceptable because every sensitive action needs a password check from the
last 300 seconds. A staff member's view as a customer (ADR-0065) is shorter than either. Staff accounts
never get the remembered tier. The portal computes no lifetime of its own: it follows the deadlines
Platform returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from .models import PortalSession

if TYPE_CHECKING:
    from .models import User


@dataclass(frozen=True)
class Lifetimes:
    absolute: timedelta
    idle: timedelta


TIERS: dict[str, Lifetimes] = {
    PortalSession.TIER_STANDARD: Lifetimes(absolute=timedelta(hours=24), idle=timedelta(hours=1)),
    PortalSession.TIER_REMEMBER: Lifetimes(absolute=timedelta(days=30), idle=timedelta(days=7)),
    PortalSession.TIER_CUSTOMER_VIEW: Lifetimes(absolute=timedelta(minutes=30), idle=timedelta(minutes=10)),
}


def lifetimes(tier: str) -> Lifetimes | None:
    """The tier's lifetimes, or None for a tier this policy does not know (its session must end)."""
    return TIERS.get(tier)


def tier_for(user: User, *, remember_me: bool) -> str:
    """The tier a login opens: remembered only for a customer who asked for it."""
    if remember_me is True and not user.is_staff_user:
        return PortalSession.TIER_REMEMBER
    return PortalSession.TIER_STANDARD
