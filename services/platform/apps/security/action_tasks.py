"""Bounded action work; loss after dispatch switches permanently to receipt reconciliation."""

from __future__ import annotations

from datetime import timedelta
from functools import partial
from typing import cast
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, InterfaceError, transaction
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import async_task

from apps.common.crowdsec_transport import CrowdSecRPCError

from . import action_repos, action_transport
from .models import SecurityActionTarget


def run_target(target_id: str) -> dict[str, str]:
    if (
        not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False)
        and not SecurityActionTarget.objects.filter(pk=target_id, dispatched_at__isnull=False).exists()
    ):
        return {"state": "disabled"}
    claim = action_repos.claim_target(UUID(target_id))
    if claim is None:
        return {"state": "superseded"}
    return execute_claim(target_id, str(claim.token))


def execute_claim(target_id: str, token: str) -> dict[str, str]:
    if (
        not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False)
        and not SecurityActionTarget.objects.filter(pk=target_id, dispatched_at__isnull=False).exists()
    ):
        return {"state": "disabled"}
    claim = action_repos.consume_target(UUID(target_id), UUID(token))
    if claim is None:
        return {"state": "superseded"}
    target = SecurityActionTarget.objects.get(pk=claim.target_id)
    if not claim.reconcile and not action_repos.mark_dispatched(claim):
        return {"state": "superseded"}
    try:
        operation = "receipt_get" if claim.reconcile else target.operation
        payload = {"request_id": str(target.request_id)} if claim.reconcile else target.payload
        result = action_transport.send_request(
            claim.connection,
            operation,
            cast("dict[str, object]", payload),
            None if claim.reconcile else target.request_id,
        )
        if (
            claim.reconcile
            and target.operation in {"revoke", "allowlist_replace"}
            and result.get("status") == "unknown"
            and result.get("evidence") == "mutation_uncertain"
            and getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False)
        ):
            if not action_repos.prepare_verified_repair(claim, result):
                target.refresh_from_db()
                return {"state": target.state}
            result = action_transport.send_request(claim.connection, target.operation, target.payload, target.request_id)
        action_repos.record_result(claim, result)
    except (CrowdSecRPCError, ValidationError, ValueError, TypeError, OSError, RuntimeError):
        action_repos.mark_unknown(claim)
    target.refresh_from_db()
    return {"state": target.state}


def dispatch_actions() -> dict[str, int]:
    candidates = SecurityActionTarget.objects.filter(
        state__in=("issued", "dispatching", "unknown"), next_run__lte=timezone.now()
    )
    if not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False):
        candidates = candidates.filter(dispatched_at__isnull=False)
    targets = list(candidates.order_by("next_run", "pk").values_list("pk", flat=True)[:20])
    queued = 0
    for target_id in targets:
        with transaction.atomic():
            claim = action_repos.claim_target(target_id)
            if claim is not None:
                transaction.on_commit(partial(_enqueue, claim), robust=True)
                queued += 1
    return {"queued": queued}


def _enqueue(claim: action_repos.ActionClaim) -> None:
    try:
        async_task(
            "apps.security.action_tasks.execute_claim", str(claim.target_id), str(claim.token), timeout=75, sync=False
        )
    except (ValueError, RuntimeError, OSError, DatabaseError, InterfaceError):
        action_repos.mark_unknown(claim)


def setup_action_scheduled_tasks() -> dict[str, str]:
    result = {}
    for name, function in (
        ("security-action-dispatch", "apps.security.action_tasks.dispatch_actions"),
        ("security-replication-admission", "apps.security.replication.dispatch_replication"),
    ):
        schedule, created = Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": function,
                "schedule_type": Schedule.MINUTES,
                "minutes": 1,
                "repeats": -1,
                "cluster": "praho-cluster",
            },
        )
        now = timezone.now()
        Schedule.objects.filter(pk=schedule.pk, next_run__gt=now + timedelta(minutes=1)).update(next_run=now)
        result[name] = "created" if created else "updated"
    return result
