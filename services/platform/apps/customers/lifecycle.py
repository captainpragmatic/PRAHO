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
    rather than leaving a paid service off for good. The caller holds, or may take, the service lock.
    """
    if not is_suspended(service.customer_id):
        return False
    from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007

    locked = (
        Service.objects.select_for_update(of=("self",))
        .filter(pk=service.pk, status="suspended", suspension_reason=PAYMENT_OVERDUE_REASON)
        .first()
    )
    if locked is not None:
        locked.suspension_reason = CUSTOMER_SUSPENSION_REASON
        locked.save(update_fields=["suspension_reason", "updated_at"])
        service.suspension_reason = CUSTOMER_SUSPENSION_REASON
    return True
