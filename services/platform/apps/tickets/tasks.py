"""Scheduled background tasks for support-ticket lifecycle policies."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TypedDict

from django.db import transaction
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import schedule

from apps.notifications.services import NotificationService
from apps.settings.services import SettingsService

from .models import Ticket
from .services import TicketStatusService

logger = logging.getLogger(__name__)

_DEFAULT_AUTO_CLOSE_INACTIVE_HOURS = 0
_AUTO_CLOSE_RESOLUTION = "auto_closed"


class AutoCloseResult(TypedDict):
    """Stable task result shown in Django-Q task history."""

    eligible: int
    closed: int
    notification_failures: int
    disabled: bool


def auto_close_inactive_tickets(*, now: datetime | None = None) -> AutoCloseResult:
    """Close stale tickets that are explicitly waiting for a customer response.

    A zero-hour policy disables the worker. Each candidate is rechecked under a
    row lock so a concurrent customer reply cannot be overwritten by the task.
    Customer notification happens only after the closure transaction commits.
    """
    inactive_hours = SettingsService.get_integer_setting(
        "tickets.auto_close_inactive_hours",
        _DEFAULT_AUTO_CLOSE_INACTIVE_HOURS,
    )
    if inactive_hours <= 0:
        return {"eligible": 0, "closed": 0, "notification_failures": 0, "disabled": True}

    run_at = now or timezone.now()
    cutoff = run_at - timedelta(hours=inactive_hours)
    candidate_ids = list(
        Ticket.objects.filter(
            status="waiting_on_customer",
            updated_at__lte=cutoff,
        )
        .order_by("pk")
        .values_list("pk", flat=True)
    )

    closed = 0
    notification_failures = 0
    for ticket_id in candidate_ids:
        notification: tuple[str, dict[str, object]] | None = None
        try:
            with transaction.atomic():
                ticket = Ticket.objects.select_for_update(of=("self",)).select_related("customer").get(pk=ticket_id)
                if ticket.status != "waiting_on_customer" or ticket.updated_at > cutoff:
                    continue

                TicketStatusService.close_ticket(ticket, _AUTO_CLOSE_RESOLUTION)
                notification = (
                    str(ticket.customer_id),
                    {
                        "customer_name": ticket.customer.get_display_name(),
                        "ticket_number": ticket.ticket_number,
                        "ticket_subject": ticket.title,
                        "inactive_hours": inactive_hours,
                    },
                )
        except Ticket.DoesNotExist:
            continue
        except Exception:
            logger.exception("Failed to auto-close inactive ticket %s", ticket_id)
            continue

        closed += 1
        customer_id, context = notification
        try:
            notified = NotificationService.send_customer_notification(
                customer_id=customer_id,
                notification_type="ticket_auto_closed",
                context=context,
            )
        except Exception:
            logger.exception("Failed to notify customer after auto-closing ticket %s", ticket_id)
            notified = False
        if not notified:
            notification_failures += 1

    logger.info(
        "Inactive-ticket auto-close finished: eligible=%d closed=%d notification_failures=%d",
        len(candidate_ids),
        closed,
        notification_failures,
    )
    return {
        "eligible": len(candidate_ids),
        "closed": closed,
        "notification_failures": notification_failures,
        "disabled": False,
    }


def setup_ticket_scheduled_tasks() -> dict[str, str]:
    """Register the hourly ticket lifecycle worker idempotently."""
    schedule_name = "tickets-auto-close-inactive"
    if Schedule.objects.filter(name=schedule_name).exists():
        return {"auto_close_inactive": "already_exists"}

    schedule(
        "apps.tickets.tasks.auto_close_inactive_tickets",
        schedule_type=Schedule.HOURLY,
        name=schedule_name,
        cluster="praho-cluster",
    )
    return {"auto_close_inactive": "created"}
