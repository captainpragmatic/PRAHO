"""One explicit role policy shared by security views, services and navigation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.users.models import User


def can_view_security(user: User) -> bool:
    return bool(
        user.is_authenticated
        and user.is_active
        and (user.is_superuser or user.staff_role in {"admin", "support", "manager"})
    )


def can_manage_security(user: User) -> bool:
    return bool(user.is_authenticated and user.is_active and (user.is_superuser or user.staff_role == "admin"))


def can_revoke_security(user: User) -> bool:
    return can_view_security(user)
