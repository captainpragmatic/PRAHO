"""Scheduled work for integrations: the webhook drains (#751 follow-up, M13)."""

from __future__ import annotations

# (result key, schedule name, function, schedule type, minutes)
_WEBHOOK_SCHEDULES: tuple[tuple[str, str, str, str, int], ...] = (
    ("pending", "webhooks-process-pending", "apps.integrations.webhooks.base.process_pending_webhooks", "I", 5),
    ("retry", "webhooks-retry-failed", "apps.integrations.webhooks.base.retry_failed_webhooks", "I", 5),
)


def setup_webhook_scheduled_tasks() -> dict[str, str]:
    """Register both webhook drains idempotently: pending deliveries and due retries, every five minutes."""
    from django_q.models import Schedule  # noqa: PLC0415  # Deferred scheduler boundary.
    from django_q.tasks import schedule  # noqa: PLC0415  # Deferred scheduler boundary.

    results = {}
    for result_key, name, func, schedule_type, minutes in _WEBHOOK_SCHEDULES:
        if Schedule.objects.filter(name=name).exists():
            results[result_key] = "already_exists"
            continue
        schedule(func, schedule_type=schedule_type, minutes=minutes, repeats=-1, name=name)
        results[result_key] = "created"
    return results
