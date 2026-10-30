"""A paid service line follows its Service and, for hosting, its Virtualmin account.

One function decides every step for a line, whoever calls it: the provisioning task, the Virtualmin create
job when it finishes, and a sweep that finishes what a lost enqueue or a killed worker left behind. It
reads the current state under one lock order and only moves things forward, so calling it again is safe.

- A hosting line (a Virtualmin plan with a domain) activates its Service, which hands account creation to
  ADR-0019's automatic provisioning. The line completes once the Service's create job has completed and the
  account is active, and fails only when that job can no longer succeed on its own: in ``attention``, or
  failed with no automatic retry left.
- Any other line (SSL, email, backup, maintenance, cloud, or hosting without a domain) is started and left
  for staff: PRAHO provisions nothing for it, so its Service stays as it is and the line stays in progress.

Domain lines belong to their registrar (apps.domains.order_fulfilment).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.provisioning.models import Service
    from apps.users.models import User

    from .models import OrderItem


logger = logging.getLogger(__name__)

# A line confirmed this long ago and still pending lost its dispatch.
DISPATCH_LOST_AFTER = timedelta(minutes=10)
RECOVERY_BATCH = 200


def _is_automatic(service: Service) -> bool:
    """A Virtualmin hosting plan with a domain: the only kind PRAHO delivers by itself."""
    return service.service_plan.plan_type in service.VIRTUALMIN_HOSTING_PLAN_TYPES and bool(service.domain)


def _create_outcome(service: Service) -> str:
    """ "completed", "failed" or "waiting", from the Service's account and its latest create job."""
    from apps.provisioning.virtualmin_models import (  # noqa: PLC0415  # ADR-0007
        VirtualminAccount,
        VirtualminProvisioningJob,
    )

    account = VirtualminAccount.objects.filter(service=service).first()
    if account is None:
        return "waiting"
    job = (
        VirtualminProvisioningJob.objects.filter(account=account, operation="create_domain")
        .order_by("-created_at")
        .first()
    )
    if account.status == "active" and (job is None or job.status == "completed"):
        # No job: an account created or imported before line fulfilment existed.
        return "completed"
    if job is not None and (job.status == "attention" or (job.status == "failed" and job.next_retry_at is None)):
        return "failed"
    return "waiting"


def _lock(item_id: UUID | str) -> tuple[OrderItem, Service | None] | None:
    """Lock the line's order, its customer, the line, then its Service: the payment path's order
    (apps.promotions.locking takes orders, then the customer), so the customer's status read here is
    the one a concurrent suspension commits or waits behind."""
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007

    from .models import Order, OrderItem  # noqa: PLC0415  # Deferred: models import signals

    order_id = OrderItem.objects.filter(pk=item_id).values_list("order_id", flat=True).first()
    if order_id is None:
        return None
    order = Order.objects.select_for_update(of=("self",)).get(pk=order_id)
    Customer.all_objects.select_for_update(of=("self",)).filter(pk=order.customer_id).first()
    line = OrderItem.objects.select_for_update(of=("self",)).select_related("order").get(pk=item_id)
    if line.service_id is None:
        return line, None
    service = Service.objects.select_for_update(of=("self",)).select_related("service_plan").get(pk=line.service_id)
    return line, service


def fulfil_hosting_line(item_id: UUID | str) -> Result[str, str]:  # noqa: PLR0911  # One outcome per state
    """Move one service line as far as its current state allows.

    Returns "noop", "held", "left_for_staff", "in_progress", "completed" or "failed"; Err only when
    activating the Service failed, with every write of this call rolled back. "held": the customer is
    suspended, so nothing moves; recovery retries the line, and it moves once the customer is unsuspended.
    """
    from apps.customers.lifecycle import is_suspended  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.services import ProvisioningService  # noqa: PLC0415  # ADR-0007

    with transaction.atomic():
        locked = _lock(item_id)
        if locked is None:
            return Err(f"Order item {item_id} not found")
        line, service = locked
        if (
            line.order.status != "provisioning"
            or line.is_domain_line
            or line.provisioning_status not in ("pending", "in_progress")
            or service is None
        ):
            return Ok("noop")
        if is_suspended(line.order.customer_id):
            # Whether the line is new or already started, its service stays off until the customer is
            # unsuspended. Saving moves the line to the back of recovery's queue, so held lines cannot
            # starve the others; recovery retries it on every run, one cheap read each, until then.
            line.save(update_fields=["updated_at"])
            logger.info("⏸️ [Orders] Hosting line %s held: its customer is suspended", line.pk)
            return Ok("held")
        if line.provisioning_status == "pending":
            line.start_provisioning()
            line.save(update_fields=["provisioning_status", "updated_at"])
        if not _is_automatic(service):
            return Ok("left_for_staff")
        if service.status == "provisioning":
            activated = ProvisioningService.activate_service(service, f"Order {line.order.order_number} confirmed")
            if activated.is_err():
                # The line was already started above: returning Err from this block would commit that.
                transaction.set_rollback(True)
                logger.error("🔥 [Orders] Could not activate service for line %s: %s", line.pk, activated.unwrap_err())
                return Err(activated.unwrap_err())
        elif service.status != "active":
            return Ok("in_progress")
        outcome = _create_outcome(service)
        if outcome == "completed":
            line.complete_provisioning()
            line.save(update_fields=["provisioning_status", "provisioned_at", "updated_at"])
            logger.info("✅ [Orders] Hosting line %s completed", line.pk)
            return Ok("completed")
        if outcome == "failed":
            line.fail_provisioning()
            # The customer reads this note; the job keeps the technical reason for staff.
            line.provisioning_notes = _("We could not set up this service automatically. Our team will finish it.")
            line.save(update_fields=["provisioning_status", "provisioning_notes", "updated_at"])
            logger.error("🔥 [Orders] Hosting line %s failed: its account could not be created", line.pk)
            return Ok("failed")
        return Ok("in_progress")


def dispatch_held_lines(customer_id: Any) -> int:
    """Queue fulfilment again for a customer's open service lines; returns how many were queued.

    A suspension holds every open line (fulfil_hosting_line). Recovery re-picks a held pending line,
    but never a started one whose account has not finished, so unsuspending calls this. Re-running a
    line that is not held is harmless: fulfilment moves a line only as far as its state allows.
    """
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred

    from apps.common.transactions import best_effort_atomic  # noqa: PLC0415

    from .models import OrderItem  # noqa: PLC0415  # Deferred: models import signals
    from .tasks import get_task_time_limit  # noqa: PLC0415  # tasks imports this module

    item_ids = [
        str(item_id)
        for item_id in OrderItem.objects.filter(
            order__customer_id=customer_id,
            order__status="provisioning",
            provisioning_status__in=("pending", "in_progress"),
            service__isnull=False,
        )
        .exclude(product_type="domain")
        .values_list("pk", flat=True)
    ]
    queued = 0
    for item_id in item_ids:
        # One savepoint per job, as for confirmation's dispatch: a failed enqueue keeps the others,
        # and recovery picks up a line whose job was lost.
        with best_effort_atomic(logger=logger, scope="Orders", message=f"Failed to re-queue held line {item_id}"):
            async_task("apps.orders.tasks.provision_order_item", item_id, timeout=get_task_time_limit())
            queued += 1
    return queued


def recover_hosting_lines(limit: int = RECOVERY_BATCH) -> dict[str, int]:
    """Finish what a lost dispatch, a lost completion or a lost order completion left behind.

    Bounded: at most `limit` lines and `limit` orders a run, oldest first.
    """
    from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    from .models import Order, OrderItem  # noqa: PLC0415
    from .services import OrderService, StatusChangeData  # noqa: PLC0415  # services imports this module

    in_provisioning = OrderItem.objects.filter(order__status="provisioning").exclude(product_type="domain")
    finished_accounts = VirtualminAccount.objects.filter(status__in=("active", "error")).values("service_id")
    candidates = (
        in_provisioning.filter(
            Q(provisioning_status="pending", updated_at__lt=timezone.now() - DISPATCH_LOST_AFTER)
            | Q(provisioning_status="in_progress", service_id__in=finished_accounts)
            # Started, but its hosting never came on: held while the customer was suspended (ADR-0066).
            # Only hosting fulfilment turns on: a manual line stays "provisioning" for staff, and selecting
            # it would fill every batch ahead of hosting that can be recovered.
            | Q(
                provisioning_status="in_progress",
                service__status="provisioning",
                service__service_plan__plan_type__in=Service.VIRTUALMIN_HOSTING_PLAN_TYPES,
                updated_at__lt=timezone.now() - DISPATCH_LOST_AFTER,
            )
            & ~Q(service__domain="")
        )
        .order_by("updated_at")
        .values_list("pk", flat=True)[:limit]
    )
    lines = 0
    for item_id in list(candidates):
        result = fulfil_hosting_line(item_id)
        if result.is_err():
            logger.warning("⚠️ [Orders] Recovery could not fulfil line %s: %s", item_id, result.unwrap_err())
        elif result.unwrap() not in ("noop", "held"):
            lines += 1

    finished = (
        Order.objects.filter(status="provisioning")
        .annotate(open_lines=Count("items", filter=~Q(items__provisioning_status="completed")), lines=Count("items"))
        .filter(open_lines=0, lines__gt=0)
        .order_by("updated_at")[:limit]
    )
    orders = 0
    for order in finished:
        completed = OrderService.update_order_status(
            order, StatusChangeData(new_status="completed", notes="All items provisioned (recovered)")
        )
        if completed.is_ok():
            orders += 1
        else:
            logger.warning("⚠️ [Orders] Recovery could not complete order %s: %s", order.pk, completed.unwrap_err())
    return {"lines": lines, "orders": orders}


def complete_line_for_staff(item_id: UUID | str, *, actor: User, activate_service: bool) -> Result[str, str]:
    """Staff mark an open service line fulfilled, optionally activating its Service first.

    For lines PRAHO does not deliver itself (SSL, email, backup, maintenance, cloud), and for a hosting line
    finished by hand. The caller checks the staff role; this checks the state, under the same locks.
    """
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.services import ProvisioningService  # noqa: PLC0415  # ADR-0007

    with transaction.atomic():
        locked = _lock(item_id)
        if locked is None:
            return Err(_("This order line no longer exists."))
        line, service = locked
        if (
            line.order.status != "provisioning"
            or line.is_domain_line
            or line.provisioning_status not in ("pending", "in_progress")
        ):
            return Err(_("Only an open service line of an order being provisioned can be marked fulfilled."))
        if activate_service and service is not None and service.status == "provisioning":
            activated = ProvisioningService.activate_service(
                service, f"Activated by staff on {line.order.order_number}"
            )
            if activated.is_err():
                transaction.set_rollback(True)
                return Err(activated.unwrap_err())
        if line.provisioning_status == "pending":
            line.start_provisioning()
        line.complete_provisioning()
        line.save(update_fields=["provisioning_status", "provisioned_at", "updated_at"])
        AuditService.log_simple_event(
            event_type="order_item_fulfilled_by_staff",
            user=actor,
            content_object=line,
            description=f"Order line marked fulfilled by staff: {line.product_name}",
            actor_type="user",
            metadata={
                "order_id": str(line.order_id),
                "order_number": line.order.order_number,
                "service_id": str(service.pk) if service is not None else None,
                "service_activated": bool(activate_service and service is not None and service.status == "active"),
            },
        )
        logger.info("✅ [Orders] Staff marked line %s fulfilled", line.pk)
        return Ok("completed")
