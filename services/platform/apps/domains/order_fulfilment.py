"""A paid domain line follows the registrar's answer, not the request.

The line is claimed (pending to in progress) before anything goes to the registrar, so a line is
sent at most once. It completes when its domain becomes active, whichever path activates it: the
registrar's inline answer, reconciliation or a webhook. A refusal fails it: the customer reads a
plain note and staff read the reason.

Every decision about a line locks its order first, then the line, then its domain item, and reads
the order's status under that lock, so a claim, a cancellation and a completion see each other.
A sweep finishes what a lost completion, a lost enqueue or a killed worker left behind.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from .models import Domain, DomainOrderItem

if TYPE_CHECKING:
    from uuid import UUID

    from apps.orders.models import OrderItem

logger = logging.getLogger(__name__)

# The actions an order line sells; a renewal follows its own intent (DomainOperationService.renew).
ORDERABLE_DOMAIN_ACTIONS = ("register", "transfer")
# A claimed line with no domain after this long was never sent: the domain row exists before the
# registrar is asked.
STALLED_AFTER = timedelta(hours=1)


def _lock_line(domain_item: DomainOrderItem) -> OrderItem | None:
    """Lock the line's order, then the line; None when the line is not on the item's order."""
    from apps.orders.models import Order, OrderItem  # noqa: PLC0415  # Deferred: orders imports domains

    Order.objects.select_for_update(of=("self",)).filter(pk=domain_item.order_id).first()
    return (
        OrderItem.objects.select_for_update(of=("self",))
        .select_related("order")
        .filter(domain_order_item=domain_item, order_id=domain_item.order_id)
        .first()
    )


def claim_order_line(domain_item: DomainOrderItem) -> bool:
    """Start the paid line; False when it was already started or its order is not being provisioned."""
    with transaction.atomic():
        line = _lock_line(domain_item)
        if line is None or line.provisioning_status != "pending" or line.order.status != "provisioning":
            return False
        current = DomainOrderItem.objects.select_for_update().get(pk=domain_item.pk)
        if current.domain_id is not None or (current.action == "transfer" and not current.epp_code):
            return False
        # A customer may replace a pending code while this worker waits for the order lock.
        domain_item.epp_code = current.epp_code
        line.start_provisioning()
        line.save(update_fields=["provisioning_status", "updated_at"])
    return True


def fail_order_line(domain_item: DomainOrderItem, reason: str, *, notify_staff: bool = True) -> bool:
    """Fail a line nothing is pending for at the registrar, and tell staff why; False when it was not."""
    from apps.notifications.services import NotificationService  # noqa: PLC0415  # Deferred: avoids circular import

    with transaction.atomic():
        line = _lock_line(domain_item)
        linked_domain = (
            DomainOrderItem.objects.select_for_update()
            .filter(pk=domain_item.pk)
            .values_list("domain_id", flat=True)
            .first()
        )
        if line is None or line.provisioning_status != "in_progress" or linked_domain is not None:
            return False
        # The provisioning-failed email shows these notes to the customer; the reason goes to staff.
        line.provisioning_notes = _(
            "We could not complete this domain automatically. Our team will finish it and contact you."
        )
        line.fail_provisioning()
        line.save(update_fields=["provisioning_status", "provisioning_notes", "updated_at"])
    logger.warning("⚠️ [Domain] Order line %s failed: %s", line.pk, reason)
    if not notify_staff:
        return True
    NotificationService.send_admin_alert(
        subject=f"Domain order needs staff: {domain_item.domain_name}",
        message=f"The {domain_item.action} of {domain_item.domain_name} was not completed: {reason}",
        alert_type="warning",
        metadata={"order_id": str(domain_item.order_id), "order_item_id": str(line.pk)},
    )
    return True


def fulfil_order_item_for_domain(domain_id: UUID) -> int:
    """Complete the paid lines waiting on this domain if it is active; returns how many completed."""
    completed = 0
    waiting = DomainOrderItem.objects.filter(
        domain_id=domain_id, action__in=ORDERABLE_DOMAIN_ACTIONS, order_item__provisioning_status="in_progress"
    )
    for domain_item in waiting:
        with transaction.atomic():
            line = _lock_line(domain_item)
            if line is None or line.provisioning_status != "in_progress":
                continue
            if not Domain.objects.select_for_update().filter(pk=domain_id, status="active").exists():
                break
            line.complete_provisioning()
            line.save(update_fields=["provisioning_status", "provisioned_at", "updated_at"])
            completed += 1
    if completed:
        logger.info("✅ [Domain] Domain %s completed %d order line(s)", domain_id, completed)
    return completed


def sweep_domain_order_lines() -> int:
    """Finish what a lost completion, a lost enqueue or a killed worker left; returns the lines acted on."""
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: as everywhere tasks are queued

    stalled_before = timezone.now() - STALLED_AFTER
    paid = DomainOrderItem.objects.filter(action__in=ORDERABLE_DOMAIN_ACTIONS, order_item__isnull=False)
    acted = 0
    # The domain is active but its completion never ran.
    active_domains = paid.filter(order_item__provisioning_status="in_progress", domain__status="active")
    for domain_id in set(active_domains.values_list("domain_id", flat=True)):
        acted += fulfil_order_item_for_domain(domain_id)
    # Claimed, then the worker died before the registrar was asked.
    for domain_item in paid.filter(
        order_item__provisioning_status="in_progress", domain__isnull=True, order_item__updated_at__lt=stalled_before
    ):
        acted += fail_order_line(domain_item, _("It stalled after it was claimed, before the registrar was asked"))
    # Paid, but the processing task was never queued or never ran.
    never_picked_up = paid.filter(
        order_item__provisioning_status="pending",
        order__status="provisioning",
        order__updated_at__lt=stalled_before,
    ).filter(Q(action="register") | (Q(action="transfer") & ~Q(epp_code="")))
    for order_id in set(never_picked_up.values_list("order_id", flat=True)):
        async_task("apps.domains.tasks.process_order_domain_items", str(order_id))
        acted += 1
    return acted
