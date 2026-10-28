"""
Scheduled tasks for PRAHO common app.

Includes the ten-minute system status check task.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

from django.core.cache import cache
from django.utils import timezone
from django_q.models import Schedule

if TYPE_CHECKING:
    from apps.common.system_status import SubsystemStatus

logger = logging.getLogger(__name__)


_FX_FRESHNESS_ALERT_KEY = "fx_freshness_alert_level"


def _alert_on_fx_freshness(results: list[SubsystemStatus], ttl: int) -> None:
    """Alert staff when the FX-rates subsystem is RED/AMBER (#103).

    Runs only from the scheduled task (never in the request-path check functions). Dedups on
    the current level so a persistent state alerts once; a level change re-alerts; recovery
    (GREEN/GREY) clears the dedup so the next degradation alerts again.
    """
    from apps.common.system_status import StatusLevel  # noqa: PLC0415

    fx = next((r for r in results if r.key == "fx"), None)
    if fx is None:
        return  # Missing evidence is not recovery.
    if fx.level not in (StatusLevel.RED, StatusLevel.AMBER):
        try:
            cache.delete(_FX_FRESHNESS_ALERT_KEY)  # reset-on-recovery
        except Exception:
            logger.warning("⚠️ [SystemStatus] FX alert recovery could not be cached")
        return
    try:
        if cache.get(_FX_FRESHNESS_ALERT_KEY) == fx.level.value:
            return  # already alerted at this level
    except Exception:
        logger.warning("⚠️ [SystemStatus] FX alert dedup unavailable; attempting delivery")
    from apps.notifications.services import NotificationService  # noqa: PLC0415

    alert_type = "critical" if fx.level == StatusLevel.RED else "warning"
    if NotificationService.send_admin_alert(
        f"FX rates {fx.level.value.upper()}: {fx.message}", str(fx.detail), alert_type=alert_type
    ):
        try:
            cache.set(_FX_FRESHNESS_ALERT_KEY, fx.level.value, timeout=ttl)
        except Exception:
            logger.warning("⚠️ [SystemStatus] FX alert delivered but dedup could not be saved")
    else:
        logger.error("🔥 [SystemStatus] FX freshness alert not delivered (recipients configured?)")


def system_status_check(*, force: bool = False) -> None:
    """
    Ten-minute system health check on the existing Q2 cluster.
    Also runs on first startup via setup_scheduled_tasks command.
    """
    from apps.common.system_status import (  # noqa: PLC0415
        CACHE_TIMEOUT,
        StatusLevel,
        run_status_refresh,
    )

    logger.info("🚀 [SystemStatus] Running system status check...")
    from apps.provisioning.scheduled_backups import schedule_customer_backup  # noqa: PLC0415

    try:
        schedule_customer_backup()
    except Exception:
        logger.error("🔥 [Backups] Scheduled admission failed; continuing system health checks")

    results = run_status_refresh(force=force).results
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


def cull_counters() -> dict[str, int]:
    """Sweep expired counter rows that the random cull on writes did not reach."""
    from apps.common import counters  # noqa: PLC0415  # Deferred: models are not ready when tasks import

    deleted = counters.cull_expired(batches=20)
    logger.info("🧹 [Counters] Culled %s expired counter rows", deleted)
    return {"deleted": deleted}


def setup_system_status_scheduled_tasks() -> dict[str, str]:
    """
    Register the system_status_check and counter_cull tasks with Django-Q2.

    Returns dict of task_name -> result ('created' or 'already_exists').
    """
    results: dict[str, str] = {}

    schedule, created = Schedule.objects.update_or_create(
        name="system_status_check",
        defaults={
            "func": "apps.common.tasks.system_status_check",
            "schedule_type": Schedule.MINUTES,
            "minutes": 10,
            "repeats": -1,
            "cluster": "praho-cluster",
        },
    )
    # Changing the cadence does not recalculate an existing Q2 next_run deadline.
    now = timezone.now()
    Schedule.objects.filter(pk=schedule.pk, next_run__gt=now + timedelta(minutes=10)).update(next_run=now)
    results["system_status_check"] = "created" if created else "already_exists"

    for task_name, func_path in (("counter_cull", "apps.common.tasks.cull_counters"),):
        if Schedule.objects.filter(name=task_name).exists():
            results[task_name] = "already_exists"
            continue
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
