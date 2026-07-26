"""Domain lifecycle background tasks (Django-Q2)."""

from __future__ import annotations

import logging
from typing import Any

from django_q.models import Schedule
from django_q.tasks import schedule

from apps.domains.services import DomainNotificationService

logger = logging.getLogger(__name__)


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


def setup_domain_scheduled_tasks() -> dict[str, str]:
    """Register the daily domain renewal-notice worker idempotently."""
    schedule_name = "domains-renewal-notices"
    if Schedule.objects.filter(name=schedule_name).exists():
        return {"renewal_notices": "already_exists"}

    schedule(
        "apps.domains.tasks.process_domain_renewal_notices",
        schedule_type=Schedule.DAILY,
        name=schedule_name,
        cluster="praho-cluster",
    )
    return {"renewal_notices": "created"}
