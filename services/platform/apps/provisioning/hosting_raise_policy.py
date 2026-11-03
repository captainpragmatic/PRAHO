"""Pure bounded raise terms; expiry never changes the purchased allowance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

DEFAULT_RAISE_DURATION = timedelta(hours=72)
MAX_RAISE_DURATION = timedelta(days=7)


@dataclass(frozen=True)
class RaiseTerms:
    revision: int = 0
    extra_mib: int = 0
    expires_at: datetime | None = None

    def application_fields(self) -> dict[str, int | datetime | None]:
        return {
            "overlay_revision": self.revision,
            "overlay_extra_mib": self.extra_mib,
            "overlay_expires_at": self.expires_at,
        }


def maximum_raise_mib(assigned_mib: int | None) -> int:
    if type(assigned_mib) is not int or assigned_mib <= 0:
        return 0
    return min(assigned_mib // 4, 5120)


def validate_raise_duration(first_granted_at: datetime, expires_at: datetime, now: datetime) -> None:
    if (
        first_granted_at.tzinfo is None
        or expires_at.tzinfo is None
        or now.tzinfo is None
        or not now < expires_at <= first_granted_at + MAX_RAISE_DURATION
        or first_granted_at > now
    ):
        raise ValueError("A temporary raise must expire within seven days of its first grant")
