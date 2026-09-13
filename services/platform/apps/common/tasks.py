"""
Scheduled tasks for PRAHO common app.

Includes the daily system status check task.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.core.cache import cache
from django_q.models import Schedule

if TYPE_CHECKING:
    from apps.common.system_status import SubsystemStatus

logger = logging.getLogger(__name__)


_FX_FRESHNESS_ALERT_KEY = "fx_freshness_alert_level"


def _alert_on_fx_freshness(results: list[SubsystemStatus], ttl: int) -> None:
    """Alert staff when the FX-rates subsystem is RED/AMBER (#103).

    Runs only from the daily task (never in the request-path check functions). Dedups on
    the current level so a persistent state alerts once; a level change re-alerts; recovery
    (GREEN/GREY) clears the dedup so the next degradation alerts again.
    """
    from apps.common.system_status import StatusLevel  # noqa: PLC0415

    fx = next((r for r in results if r.name == "FX rates"), None)
    if fx is None or fx.level not in (StatusLevel.RED, StatusLevel.AMBER):
        cache.delete(_FX_FRESHNESS_ALERT_KEY)  # reset-on-recovery
        return
    if cache.get(_FX_FRESHNESS_ALERT_KEY) == fx.level.value:
        return  # already alerted at this level
    from apps.notifications.services import NotificationService  # noqa: PLC0415

    alert_type = "critical" if fx.level == StatusLevel.RED else "warning"
    if NotificationService.send_admin_alert(
        f"FX rates {fx.level.value.upper()}: {fx.message}", fx.detail, alert_type=alert_type
    ):
        cache.set(_FX_FRESHNESS_ALERT_KEY, fx.level.value, timeout=ttl)
    else:
        logger.error("🔥 [SystemStatus] FX freshness alert not delivered (recipients configured?)")


def system_status_check() -> None:
    """
    Daily system health check. Results cached for dashboard display.

    Scheduled to run at 3:00 AM (after the 2:00 AM backup cron).
    Also runs on first startup via setup_scheduled_tasks command.
    """
    from apps.common.system_status import (  # noqa: PLC0415
        CACHE_KEY,
        CACHE_TIMEOUT,
        StatusLevel,
        check_all_subsystems,
    )

    logger.info("🚀 [SystemStatus] Running daily system status check...")

    results = check_all_subsystems()
    cache.set(CACHE_KEY, results, timeout=CACHE_TIMEOUT)
    _alert_on_fx_freshness(results, CACHE_TIMEOUT)

    # Summary
    counts = dict.fromkeys(StatusLevel, 0)
    for r in results:
        counts[r.level] += 1

    logger.info(
        "✅ [SystemStatus] Check complete: %d green, %d amber, %d red, %d grey",
        counts[StatusLevel.GREEN],
        counts[StatusLevel.AMBER],
        counts[StatusLevel.RED],
        counts[StatusLevel.GREY],
    )


def setup_system_status_scheduled_tasks() -> dict[str, str]:
    """
    Register the system_status_check task with Django-Q2.

    Returns dict of task_name -> result ('created' or 'already_exists').
    """
    results: dict[str, str] = {}

    task_name = "system_status_check"
    func_path = "apps.common.tasks.system_status_check"

    if Schedule.objects.filter(name=task_name).exists():
        results[task_name] = "already_exists"
    else:
        Schedule.objects.create(
            name=task_name,
            func=func_path,
            schedule_type=Schedule.DAILY,
            # Run at 3:00 AM — after 2:00 AM backup cron
            minutes=0,
            repeats=-1,  # Repeat forever
        )
        results[task_name] = "created"

    return results
