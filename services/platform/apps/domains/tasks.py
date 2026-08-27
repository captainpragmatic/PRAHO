"""Domain lifecycle background tasks (Django-Q2)."""

from __future__ import annotations

import logging
from typing import Any

from django_q.models import Schedule
from django_q.tasks import schedule

from apps.domains.services import (
    DomainNotificationService,
    DomainOrderService,
    DomainReconciliationService,
    DomainReconciliationSummary,
)

logger = logging.getLogger(__name__)


def process_order_domain_items(order_id: str) -> dict[str, Any]:
    """Process a paid order's domain items (register/renew) off the request path.

    Enqueued by the orders service (transaction.on_commit) when an order enters
    provisioning: the registrar call is network I/O and must never run inside
    the order transaction. Per-item failure isolation lives in
    DomainOrderService.process_domain_order_items.
    """
    from apps.orders.models import Order  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        order = Order.objects.get(pk=order_id)
    except Order.DoesNotExist:
        logger.warning("⚠️ [Domains] Order %s no longer exists — skipping domain item processing", order_id)
        return {"success": False, "processed": 0, "error": "order not found"}

    processed = DomainOrderService.process_domain_order_items(order)
    # success must reflect the PAID intent, not merely "nothing crashed": the
    # per-item boundary swallows failures, so the Django-Q2 task result is the
    # durable signal that register/renew items remain unfulfilled.
    items_total = order.domain_items.filter(action__in=("register", "renew")).count()
    success = len(processed) >= items_total
    if success:
        logger.info("✅ [Domains] Processed %d domain item(s) for order %s", len(processed), order_id)
    else:
        logger.error(
            "🔥 [Domains] Order %s: %d of %d domain item(s) remain unprocessed",
            order_id,
            items_total - len(processed),
            items_total,
        )
    return {
        "success": success,
        "processed": len(processed),
        "items_total": items_total,
        "domains": [domain.name for domain in processed],
    }


def process_domain_renewal_notices() -> dict[str, Any]:
    """Send one renewal notice per matched schedule threshold, truthfully.

    A failed send leaves the domain unmarked so the next daily run retries it;
    the result reports every failure instead of claiming unconditional success.
    """
    from apps.notifications.services import NotificationService  # noqa: PLC0415  # Deferred: avoids circular import

    notified = 0
    errors = 0
    for domain, days_until_expiry in DomainNotificationService.due_renewal_notices():
        try:
            sent = NotificationService.send_customer_notification(
                customer_id=str(domain.customer_id),
                notification_type="domain_renewal_notice",
                context={
                    "customer_name": domain.customer.get_display_name(),
                    "domain_name": domain.name,
                    "days_until_expiry": days_until_expiry,
                    "expires_at": domain.expires_at,
                },
            )
        except Exception:
            logger.exception("🔥 [Domains] Renewal notice failed for %s", domain.name)
            sent = False
        if sent:
            DomainNotificationService.mark_renewal_notice_sent(domain, days_until_expiry)
            notified += 1
        else:
            errors += 1

    logger.info("📧 [Domains] Renewal notices sent: notified=%d errors=%d", notified, errors)
    return {
        "success": errors == 0,
        "notified": notified,
        "errors": errors,
        "message": f"Sent {notified} domain renewal notices, {errors} errors",
    }


def reconcile_pending_domain_operations() -> DomainReconciliationSummary:
    """Run one durable domain reconciliation batch (#258)."""
    return DomainReconciliationService.reconcile()


def setup_domain_scheduled_tasks() -> dict[str, str]:
    """Register both domain workers independently and idempotently."""
    results: dict[str, str] = {}

    renewal_schedule_name = "domains-renewal-notices"
    if Schedule.objects.filter(name=renewal_schedule_name).exists():
        results["renewal_notices"] = "already_exists"
    else:
        schedule(
            "apps.domains.tasks.process_domain_renewal_notices",
            schedule_type=Schedule.DAILY,
            name=renewal_schedule_name,
            cluster="praho-cluster",
        )
        results["renewal_notices"] = "created"

    reconciliation_schedule_name = "domains-reconcile-pending"
    if Schedule.objects.filter(name=reconciliation_schedule_name).exists():
        results["reconcile_pending"] = "already_exists"
    else:
        schedule(
            "apps.domains.tasks.reconcile_pending_domain_operations",
            schedule_type=Schedule.HOURLY,
            name=reconciliation_schedule_name,
            cluster="praho-cluster",
        )
        results["reconcile_pending"] = "created"

    return results
