"""Permitted UTC intervals for maintenance fixtures with relative schedules."""

from datetime import UTC, time, timedelta

from django.utils import timezone


def maintenance_policy_times() -> tuple[time, time]:
    """Return the permitted times used by ordinary maintenance admission fixtures."""
    now = timezone.now().astimezone(UTC)
    return (now - timedelta(hours=1)).time(), (now + timedelta(hours=12)).time()
