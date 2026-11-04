"""Integer-only hosting allowance policy; unknown is never interpreted as unlimited."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AllowanceSource = Literal["plan", "stored_default", "unlimited", "legacy_unknown"]
MIB_PER_GIB = 1024
BYTES_PER_MIB = 1024 * 1024
POLICY_VERSION = 1


@dataclass(frozen=True)
class Allowance:
    mib: int | None
    source: AllowanceSource


def resolve_allowance(plan_gib: object, stored_default_mib: object) -> Allowance:
    """Resolve a new assignment. Explicit zero at either level means unlimited."""
    if type(plan_gib) is int and plan_gib >= 0:
        return Allowance(plan_gib * MIB_PER_GIB, "plan")
    if plan_gib is not None:
        raise ValueError("A plan allowance must be a nonnegative integer or None")
    if type(stored_default_mib) is int and stored_default_mib >= 0:
        return Allowance(stored_default_mib, "stored_default")
    if stored_default_mib is not None:
        raise ValueError("A stored default must be a nonnegative integer or None")
    return Allowance(0, "unlimited")


def effective_disk_limit(allowance_mib: int | None, *, extra_mib: int = 0) -> int | None:
    """Purchased allowance plus bounded safety margin and an independently authorized raise."""
    if type(extra_mib) is not int or extra_mib < 0:
        raise ValueError("A raise must be a nonnegative integer")
    if allowance_mib is None:
        if extra_mib:
            raise ValueError("An unknown allowance cannot receive a raise")
        return None
    if type(allowance_mib) is not int or allowance_mib < 0:
        raise ValueError("An allowance must be a nonnegative integer or None")
    if allowance_mib == 0:
        if extra_mib:
            raise ValueError("An unlimited allowance cannot receive a raise")
        return 0
    maximum_raise = min(allowance_mib // 4, 5120)
    if extra_mib > maximum_raise:
        raise ValueError("The raise exceeds the assigned allowance's limit")
    return allowance_mib + min((allowance_mib + 9) // 10, 2048) + extra_mib
