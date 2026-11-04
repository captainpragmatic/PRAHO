"""Minute dispatch claims before enqueue; workers hold no database locks across gateway RPCs."""

from __future__ import annotations

import logging
from datetime import timedelta
from functools import partial
from time import monotonic
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import DatabaseError, InterfaceError, models, transaction
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import async_task

from apps.common.crowdsec_transport import CrowdSecRPCError

from . import repos, transport
from .models import SecurityAlert, SecurityDecision, SecuritySource

logger = logging.getLogger(__name__)
TASK = "apps.security.tasks.sync_source"
DISPATCH_BATCH = 100
TASK_TIMEOUT = 75
RETENTION_BATCH = 1000
RETENTION_SECONDS = 5.0


def _enqueue(source_id: UUID, token: UUID) -> None:
    try:
        async_task(TASK, str(source_id), str(token), timeout=TASK_TIMEOUT, sync=False)
    except (ValueError, RuntimeError, OSError, DatabaseError, InterfaceError):
        repos.fail_claim(source_id, token, "enqueue_failed")
        logger.exception("Security poll dispatch acknowledgement failed for source %s", source_id)


def dispatch_security_sync() -> dict[str, int]:
    if not repos.enabled():
        return {"queued": 0}
    queued = 0
    now = timezone.now()
    sources = (
        SecuritySource.objects.filter(sync_enabled=True, retired_at__isnull=True, sync_state__next_run__lte=now)
        .order_by("sync_state__next_run", "pk")
        .values_list("pk", flat=True)[:DISPATCH_BATCH]
    )
    for source_id in list(sources):
        with transaction.atomic():
            claim = repos.claim_for_queue(source_id)
            if claim is None:
                continue
            transaction.on_commit(partial(_enqueue, claim.source_id, claim.token), robust=True)
            queued += 1
    return {"queued": queued}


def sync_source(source_id: str, queued_token: str) -> dict[str, str]:
    try:
        source_uuid, token = UUID(source_id), UUID(queued_token)
    except (ValueError, TypeError):
        return {"state": "superseded"}
    claim = repos.consume_claim(source_uuid, token)
    if claim is None:
        return {"state": "superseded"}
    try:
        observation = transport.fetch(claim.connection, claim.alert_cursor)
        if not repos.publish_observation(claim, observation):
            return {"state": "superseded"}
        return {"state": "catching_up" if observation.snapshot["has_more"] else "ok"}
    except (CrowdSecRPCError, ValidationError, ValueError, OSError, TypeError):
        repos.fail_claim(source_uuid, claim.token, "unavailable")
        return {"state": "unavailable"}


def prune_security_history() -> dict[str, int]:
    now = timezone.now()
    deadline = monotonic() + RETENTION_SECONDS
    totals = {"expired": 0, "decisions": 0, "alerts": 0}
    cutoff = now - timedelta(days=30)
    while monotonic() < deadline:
        expired = list(
            SecurityDecision.objects.filter(ended_at__isnull=True, expires_at__lte=now)
            .order_by("expires_at", "pk")
            .values_list("pk", flat=True)[:RETENTION_BATCH]
        )
        totals["expired"] += SecurityDecision.objects.filter(pk__in=expired, ended_at__isnull=True).update(
            ended_at=models.F("expires_at"), updated_at=now
        )
        decisions = list(
            SecurityDecision.objects.filter(ended_at__lt=now - timedelta(days=90))
            .order_by("ended_at", "pk")
            .values_list("pk", flat=True)[:RETENTION_BATCH]
        )
        alerts = list(
            SecurityAlert.objects.filter(models.Q(source_created_at__lt=cutoff) | models.Q(created_at__lt=cutoff))
            .order_by("source_created_at", "pk")
            .values_list("pk", flat=True)[:RETENTION_BATCH]
        )
        totals["decisions"] += SecurityDecision.objects.filter(pk__in=decisions).delete()[0]
        totals["alerts"] += SecurityAlert.objects.filter(pk__in=alerts).delete()[0]
        if not expired and not decisions and not alerts:
            break
    return totals


def setup_security_scheduled_tasks() -> dict[str, str]:
    result = {}
    for name, function, minutes in (
        ("security-source-sync", "apps.security.tasks.dispatch_security_sync", 1),
        ("security-history-retention", "apps.security.tasks.prune_security_history", 60),
    ):
        schedule, created = Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": function,
                "schedule_type": Schedule.MINUTES,
                "minutes": minutes,
                "repeats": -1,
                "cluster": "praho-cluster",
            },
        )
        now = timezone.now()
        Schedule.objects.filter(pk=schedule.pk, next_run__gt=now + timedelta(minutes=minutes)).update(next_run=now)
        result[name] = "created" if created else "updated"
    return result
