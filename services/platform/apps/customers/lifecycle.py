"""A customer's lifecycle status: what it means, and the one place code asks about it (ADR-0066).

Status describes where the customer is in its relationship with us. It never decides who may use
the Portal: that is the member's user and membership, and soft deletion.

- ``prospect``: no paid service yet. Staff-created customers start here.
- ``active``: has paid. A first paid invoice moves a prospect here.
- ``inactive``: no paid service any more. A new paid invoice moves it back to ``active``.
- ``suspended``: put on hold by staff. Its people keep reading, paying and opening tickets, but it gets
  no new or restored hosting and no DNS publication until staff unsuspend it.
"""

from __future__ import annotations

from typing import Any, Final

SUSPENDED: Final = "suspended"
# The reason the customer suspension cascade writes on a service, and the only one unsuspending lifts.
CUSTOMER_SUSPENSION_REASON: Final = "customer_suspended"
PAYMENT_OVERDUE_REASON: Final = "payment_overdue"


def is_suspended(customer_id: Any) -> bool:
    """Whether the customer is suspended now; reads the row as committed, deleted or not."""
    from .models import Customer  # noqa: PLC0415  # Deferred: models import signals

    return Customer.all_objects.filter(pk=customer_id, status=SUSPENDED).exists()


def hold_for_suspension(service: Any) -> bool:
    """Whether a payment must leave this service off because its customer is suspended.

    A service already off for non-payment is now held by the suspension instead: its reason becomes
    the cascade's, so unsuspending the customer resumes it (after the cascade's own paid-up check),
    rather than leaving a paid service off for good.

    Call it inside the transaction that restores the service: it locks the customer row, customer
    before Service as billing locks them, so a suspension committing at the same time is either seen
    here or runs its cascade after the restore. The caller then re-reads the Service under its lock.
    """
    from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007

    from .models import Customer  # noqa: PLC0415  # Deferred: models import signals

    customer = Customer.all_objects.select_for_update(of=("self",)).filter(pk=service.customer_id).first()
    if customer is None or customer.status != SUSPENDED:
        return False

    overdue = (
        Service.objects.select_for_update(of=("self",))
        .filter(pk=service.pk, status="suspended", suspension_reason=PAYMENT_OVERDUE_REASON)
        .first()
    )
    if overdue is not None:
        overdue.suspension_reason = CUSTOMER_SUSPENSION_REASON
        overdue.save(update_fields=["suspension_reason", "updated_at"])
        service.suspension_reason = CUSTOMER_SUSPENSION_REASON
    return True


# Who may take which transition. Suspend also suspends all the customer's hosting.
STATUS_ACTIONS: Final = ("activate", "deactivate", "reactivate", "suspend", "unsuspend")
_EVERY_ACTION: Final = frozenset(STATUS_ACTIONS)
_ACTIONS_BY_ROLE: Final = {
    "admin": _EVERY_ACTION,
    "manager": _EVERY_ACTION,
    "support": frozenset({"suspend", "unsuspend"}),
}


def role_status_actions(user: Any) -> frozenset[str]:
    """The transitions this staff member's role allows, whatever the customer's status."""
    from apps.common.decorators import is_administrator  # noqa: PLC0415  # Deferred: decorators import views

    if not getattr(user, "is_authenticated", False) or not getattr(user, "is_active", False):
        return frozenset()
    if is_administrator(user):
        return _EVERY_ACTION
    return _ACTIONS_BY_ROLE.get(getattr(user, "staff_role", "") or "", frozenset())


def status_actions(user: Any, customer: Any) -> list[str]:
    """The transitions this staff member may take on this customer now, in the order staff read them."""
    allowed = role_status_actions(user)
    available = {transition.name for transition in customer.get_available_status_transitions()}
    return [action for action in STATUS_ACTIONS if action in allowed and action in available]
