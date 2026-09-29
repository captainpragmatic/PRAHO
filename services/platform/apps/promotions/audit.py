"""Audit conditional ledger updates that deliberately bypass model signals."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import Model

if TYPE_CHECKING:
    from apps.users.models import User


def audit_ledger_transition(instance: Model, previous: str, current: str, actor: User | None = None) -> None:
    """Call only after a successful conditional update, within its transaction."""
    from apps.audit.services import AuditService  # noqa: PLC0415

    AuditService.log_simple_event(
        "update",
        content_object=instance,
        user=actor,
        actor_type="user" if actor else "system",
        old_values={"status": previous},
        new_values={"status": current},
        description=f"Promotion ledger {instance._meta.label} status changed",
    )
