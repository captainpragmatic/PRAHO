"""Write-only customer transfer codes, and cleanup after a paid line becomes terminal."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.utils.translation import gettext as _

from apps.audit.services import DomainsAuditService

from .models import DomainOrderItem

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User

TRANSFER_CODE_PATTERN = re.compile(r"[\x21-\x7e]{1,64}", re.ASCII)
TRANSFER_CODE_ORDER_STATUSES = ("awaiting_payment", "paid", "in_review", "provisioning")


def receive_transfer_code(order_id: UUID, line_id: UUID, *, customer: Customer, actor: User, value: object) -> None:
    """Store a code on this customer's unsent transfer; only provisioning queues a worker."""
    from apps.orders.models import Order  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).
    from apps.orders.services import _enqueue_domain_item_processing  # noqa: PLC0415  # Avoid orders/domains cycle.

    code = value.strip() if isinstance(value, str) else ""
    if TRANSFER_CODE_PATTERN.fullmatch(code) is None:
        raise ValueError(_("Enter a transfer code of 1-64 printable ASCII characters without spaces."))
    with transaction.atomic():
        order = Order.objects.select_for_update(of=("self",)).get(pk=order_id, customer=customer)
        line = order.items.select_for_update(of=("self",)).get(pk=line_id)
        item = DomainOrderItem.objects.select_for_update().filter(order_item=line).first()
        if not line.is_domain_line or item is None or item.order_id != order.pk or item.action != "transfer":
            raise ValueError(_("This line is not a domain transfer."))
        if order.status not in TRANSFER_CODE_ORDER_STATUSES:
            raise ValueError(_("This order cannot accept a transfer code in its current state."))
        if line.provisioning_status not in ("pending", "failed") or item.domain_id is not None:
            raise ValueError(_("This transfer has already been dispatched or cannot be retried."))
        if line.provisioning_status == "failed":
            line.retry_provisioning()
            line.save(update_fields=["provisioning_status", "updated_at"])
        item.set_encrypted_epp_code(code)
        item.save(update_fields=["epp_code", "updated_at"])
        DomainsAuditService.log_domain_order_event(
            "domain_transfer_code_received",
            item,
            user=actor,
            description=_("A transfer code was received."),
        )
        if order.status == "provisioning":
            _enqueue_domain_item_processing(order)


def clear_terminal_transfer_code(line_id: UUID) -> None:
    """Re-read committed state under the order lock, so a rolled-back transition clears nothing."""
    from apps.orders.models import Order, OrderItem  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    order_id = OrderItem.objects.filter(pk=line_id).values_list("order_id", flat=True).first()
    if order_id is None:
        return
    with transaction.atomic():
        Order.objects.select_for_update(of=("self",)).get(pk=order_id)
        line = OrderItem.objects.select_for_update(of=("self",)).get(pk=line_id, order_id=order_id)
        if line.provisioning_status not in ("completed", "cancelled"):
            return
        item = (
            DomainOrderItem.objects.select_for_update()
            .filter(order_item=line, order_id=order_id, action="transfer")
            .first()
        )
        if item is not None and item.epp_code:
            item.epp_code = ""
            item.save(update_fields=["epp_code", "updated_at"])
