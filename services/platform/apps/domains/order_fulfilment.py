"""A paid domain line follows the registrar's answer, not the request.

The line is claimed (pending to in progress) before anything goes to the registrar, so a line is
sent at most once. It completes when its domain becomes active, whichever path activates it: the
registrar's inline answer, reconciliation or a webhook. A refusal fails it: the customer reads a
plain note and staff read the registrar's reason.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db import transaction
from django.utils.translation import gettext as _

from .models import Domain

if TYPE_CHECKING:
    from uuid import UUID

    from .models import DomainOrderItem

logger = logging.getLogger(__name__)


def claim_order_line(domain_item: DomainOrderItem) -> bool:
    """Start the paid line; False when it was already started or its order is not being provisioned."""
    from apps.orders.models import OrderItem  # noqa: PLC0415  # Deferred: orders imports domains

    with transaction.atomic():
        line = (
            OrderItem.objects.select_for_update(of=("self",)).select_related("order").get(domain_order_item=domain_item)
        )
        if line.provisioning_status != "pending" or line.order.status != "provisioning":
            return False
        line.start_provisioning()
        line.save(update_fields=["provisioning_status", "updated_at"])
    return True


def fail_order_line(domain_item: DomainOrderItem, reason: str) -> None:
    """Fail the line nothing is pending for at the registrar, and tell staff why."""
    from apps.notifications.services import NotificationService  # noqa: PLC0415  # Deferred: avoids circular import
    from apps.orders.models import OrderItem  # noqa: PLC0415  # Deferred: orders imports domains

    with transaction.atomic():
        line = OrderItem.objects.select_for_update(of=("self",)).get(domain_order_item=domain_item)
        if line.provisioning_status != "in_progress":
            return
        # The provisioning-failed email shows these notes to the customer; the reason goes to staff.
        line.provisioning_notes = _(
            "We could not complete this domain automatically. Our team will finish it and contact you."
        )
        line.fail_provisioning()
        line.save(update_fields=["provisioning_status", "provisioning_notes", "updated_at"])
    logger.warning("⚠️ [Domain] Order line %s failed: %s", line.pk, reason)
    NotificationService.send_admin_alert(
        subject=f"Domain order needs staff: {domain_item.domain_name}",
        message=f"The {domain_item.action} of {domain_item.domain_name} was not completed: {reason}",
        alert_type="warning",
        metadata={"order_id": str(domain_item.order_id), "order_item_id": str(line.pk)},
    )


def fulfil_order_item_for_domain(domain_id: UUID) -> int:
    """Complete the paid lines waiting on this domain if it is active; returns how many completed."""
    from apps.orders.models import OrderItem  # noqa: PLC0415  # Deferred: orders imports domains

    completed = 0
    with transaction.atomic():
        if not Domain.objects.filter(pk=domain_id, status="active").exists():
            return 0
        lines = OrderItem.objects.select_for_update(of=("self",)).filter(
            domain_order_item__domain_id=domain_id, provisioning_status="in_progress"
        )
        for line in lines:
            line.complete_provisioning()
            line.save(update_fields=["provisioning_status", "provisioned_at", "updated_at"])
            completed += 1
    if completed:
        logger.info("✅ [Domain] Domain %s completed %d order line(s)", domain_id, completed)
    return completed
