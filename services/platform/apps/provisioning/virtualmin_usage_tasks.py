"""Hourly node polling. Q2 stores a small outcome, never a node payload."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from uuid import UUID, uuid4

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django_q.tasks import async_task

from . import virtualmin_usage_service as usage
from .virtualmin_models import VirtualminServer
from .virtualmin_usage_models import AccountUsageState, NodeUsageSyncState, UsageInterval, UsageReading

logger = logging.getLogger(__name__)
SNAPSHOT_LIMIT = 4 * 1024 * 1024
RETENTION_BATCH_SIZE = 1000
INTERVAL_SCAN_BATCH_SIZE = 100
RETENTION_TIME_BUDGET_SECONDS = 5
INTERVAL_RETENTION_CURSOR = "provisioning:usage:interval-retention-cursor:v1"


def transport_identity(server: VirtualminServer) -> str:
    deployment = getattr(server, "node_deployment", None)
    inputs = [server.hostname, server.ssh_port, settings.TIME_ZONE, "usage-v1"]
    if deployment is not None:
        from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415

        inputs.extend([str(deployment.pk), deployment.ipv4_address, deployment.hostname])
        inputs.extend(
            str(getattr(deployment, field.name)) for field in deployment._meta.fields if field.name.startswith("ssh_")
        )
        credential = (
            EncryptedCredential.objects.filter(pk=deployment.ssh_key_credential_id).first()
            if deployment.ssh_key_credential_id
            else None
        )
        if credential is not None:
            inputs.extend(
                [
                    str(credential.pk),
                    bytes(credential.encrypted_username).hex(),
                    bytes(credential.encrypted_password).hex(),
                    credential.is_active,
                    credential.expires_at.isoformat(),
                    credential.expires_at <= timezone.now(),
                ]
            )
    for setting in ("PRAHO_SSH_KNOWN_HOSTS_PATH", "VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH"):
        path = str(getattr(settings, setting, "") or "")
        inputs.append(path)
        try:
            inputs.append(hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else "")
        except OSError:
            inputs.append("unavailable")
    return salted_hmac("praho.usage.transport", json.dumps(inputs), algorithm="sha256").hexdigest()


def dispatch_usage_sync() -> dict[str, int]:
    if not usage.enabled():
        return {"queued": 0}
    queued = 0
    for server in VirtualminServer.objects.filter(status="active"):
        with transaction.atomic():
            state, _ = NodeUsageSyncState.objects.get_or_create(server=server)
            state = NodeUsageSyncState.objects.select_for_update().get(pk=state.pk)
            now = timezone.now()
            if state.next_run > now or (state.lease_until and state.lease_until > now):
                continue
            state.token = uuid4()
            state.lease_until = now + timedelta(seconds=330)
            # Coalesce dispatches in each UTC hour without carrying :10 jitter
            # into the following hour's eligibility check.
            state.next_run = now.astimezone(UTC).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            state.input_identity, state.last_attempt_at = transport_identity(server), now
            state.save()
            async_task(
                "apps.provisioning.virtualmin_usage_tasks.sync_node_usage",
                str(server.pk),
                str(state.token),
                timeout=300,
                sync=False,
            )
            queued += 1
    _prune_history()
    return {"queued": queued}


def _retained_totals(totals: dict[str, object], cutoff: datetime) -> dict[str, object]:
    retained = {}
    for key, value in totals.items():
        try:
            expired = isinstance(value, dict) and usage.timestamp(value.get("through")) < cutoff
        except ValueError:
            expired = False
        if not expired:
            retained[key] = value
    return retained


def _prune_interval_batch(cursor: str | None, cutoff: datetime, deadline: float) -> tuple[str | None, bool]:
    intervals = UsageInterval.objects.exclude(totals={}).order_by("pk").only("id", "totals")
    if cursor is not None:
        intervals = intervals.filter(pk__gt=cursor)
    batch = list(intervals[:INTERVAL_SCAN_BATCH_SIZE])
    processed = 0
    for interval in batch:
        if monotonic() >= deadline:
            break
        if _retained_totals(interval.totals, cutoff) != interval.totals:
            # Re-read under the row lock so pruning cannot overwrite a newer
            # monthly total published after the scan.
            with transaction.atomic():
                current = UsageInterval.objects.select_for_update().filter(pk=interval.pk).first()
                if current is not None:
                    current.totals = _retained_totals(current.totals, cutoff)
                    current.save(update_fields=["totals", "updated_at"])
        cursor = str(interval.pk)
        processed += 1
    finished = processed == len(batch) and len(batch) < INTERVAL_SCAN_BATCH_SIZE
    if finished:
        cache.delete(INTERVAL_RETENTION_CURSOR)
    elif cursor is not None:
        # Losing this technical cursor only restarts a safe, idempotent scan.
        cache.set(INTERVAL_RETENTION_CURSOR, cursor, timeout=86400)
    return cursor, finished


def _prune_history() -> None:
    """Drain bounded batches rather than falling behind a fleet's hourly writes."""
    cutoff = timezone.now() - timedelta(days=90)
    deadline = monotonic() + RETENTION_TIME_BUDGET_SECONDS
    old_readings = (
        UsageReading.objects.filter(taken_at__lt=cutoff)
        .exclude(pk__in=AccountUsageState.objects.exclude(disk_reading=None).values("disk_reading_id"))
        .exclude(pk__in=AccountUsageState.objects.exclude(bandwidth_reading=None).values("bandwidth_reading_id"))
        .order_by("taken_at", "pk")
    )
    old_intervals = UsageInterval.objects.filter(ended_at__lt=cutoff).order_by("ended_at", "pk")
    cursor = cache.get(INTERVAL_RETENTION_CURSOR)
    totals_finished = False
    while monotonic() < deadline:
        reading_ids = list(old_readings.values_list("pk", flat=True)[:RETENTION_BATCH_SIZE])
        old_readings.filter(pk__in=reading_ids).delete()
        if monotonic() >= deadline:
            break
        interval_ids = list(old_intervals.values_list("pk", flat=True)[:RETENTION_BATCH_SIZE])
        old_intervals.filter(pk__in=interval_ids).delete()
        if monotonic() >= deadline:
            break
        # Give every kind of retained history a turn even when readings have
        # a large backlog. The JSON scan resumes after its last examined UUID.
        if not totals_finished:
            cursor, totals_finished = _prune_interval_batch(cursor, cutoff, deadline)
        if not reading_ids and not interval_ids and totals_finished:
            break


def sync_node_usage(server_id: str, token: str) -> dict[str, int | str]:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

    server = VirtualminServer.objects.get(pk=UUID(server_id))
    if not usage.enabled():
        return {"state": "superseded"}
    with transaction.atomic():
        claim = (
            NodeUsageSyncState.objects.select_for_update()
            .filter(server=server, token=UUID(token), lease_until__gt=timezone.now())
            .first()
        )
        if claim is None:
            return {"state": "superseded"}
        # Consume the queue delivery token before any SSH. A duplicate delivery
        # cannot share a worker's publication token or perform another export.
        claim.token = uuid4()
        claim.save(update_fields=["token", "updated_at"])
    captured = usage.capture(server)
    through = timezone.now()
    start, _ = usage.month(through)
    intervals = [
        {
            "id": str(item.pk),
            "domain": item.account.domain,
            "domain_id": item.domain_id,
            "start": max(start, item.started_at).isoformat(),
            "end": min(through, item.ended_at or through).isoformat(),
        }
        for item in UsageInterval.objects.filter(server=server, started_at__lt=through).select_related("account")
        if (item.ended_at is None or item.ended_at > start)
        and item.account_id in captured
        and item.owner_scope == captured[item.account_id].scope
    ]
    try:
        result = AnsibleService().run_server_playbook(
            server, "virtualmin_usage_read.yml", {"usage_request": {"intervals": intervals}}, timeout_seconds=30
        )
        if result.is_err() or not result.unwrap().success:
            raise ValueError("Usage transport unavailable")
        output = result.unwrap().stdout
        if len(output) > SNAPSHOT_LIMIT * 2:
            raise ValueError("Usage response too large")
        matches = re.findall(r"PRAHO_USAGE_SNAPSHOT=([A-Za-z0-9+/=]+)", output)
        if len(matches) != 1:
            raise ValueError("Missing usage response")
        decoded = base64.b64decode(matches[0], validate=True)
        if len(decoded) > SNAPSHOT_LIMIT:
            raise ValueError("Usage response too large")
        server.refresh_from_db()
        if claim.input_identity != transport_identity(server):
            raise ValueError("Usage transport identity changed")
        payload = json.loads(decoded)
        count = usage.publish_snapshot(server.pk, payload, captured, token=claim.token)
        outcome = "ok"
        expected = set(
            server.accounts.filter(status__in=("active", "suspended")).values_list("domain", "virtualmin_username")
        )
        reported = {
            (str(row.get("domain")), str(row.get("username")))
            for row in payload["records"]
            if isinstance(row, dict) and row.get("present") is not False
        }
        if expected - reported:
            outcome = "missing_accounts"
        elif reported - expected:
            outcome = "unassigned_accounts"
    except (ValueError, OSError, TypeError):
        count, outcome = 0, "unavailable"
        logger.warning("⚠️ [Usage] Node %s usage could not be verified", server.pk)
    NodeUsageSyncState.objects.filter(pk=claim.pk, token=claim.token).update(
        token=None,
        lease_until=None,
        outcome=outcome,
        **({"last_success_at": through} if outcome in {"ok", "missing_accounts", "unassigned_accounts"} else {}),
    )
    return {"state": outcome, "published": count}
