"""Bounded dispatch and per-account DNS work; no HTTP request runs these probes inline."""

from __future__ import annotations

import logging
from datetime import timedelta
from functools import partial
from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django_q.tasks import async_task

from apps.provisioning import hosted_domain_dns_config as config

from . import hosted_domain_dns_service as service
from .hosted_domain_dns_models import HostedDomainDnsStatus
from .virtualmin_models import VirtualminAccount

logger = logging.getLogger(__name__)
TASK = "apps.provisioning.hosted_domain_dns_tasks.check_account_dns"


def _seed_missing(limit: int) -> None:
    accounts = VirtualminAccount.objects.filter(
        status__in=("active", "suspended"),
        account_hostname__retired_at__isnull=True,
        account_hostname__target_server__isnull=False,
        dns_status__isnull=True,
    ).order_by("pk")[:limit]
    HostedDomainDnsStatus.objects.bulk_create(
        [HostedDomainDnsStatus(account=account) for account in accounts], ignore_conflicts=True
    )


def _enqueue(account_id: str, token: UUID) -> None:
    try:
        async_task(TASK, account_id, lease_token=str(token), timeout=config.JOB_TIMEOUT, sync=False)
    except (ValueError, RuntimeError, OSError):
        # A task may have reached the broker before its acknowledgement was lost. Its token
        # becomes unusable, and a later bounded dispatch supplies the current token instead.
        HostedDomainDnsStatus.objects.filter(account_id=UUID(account_id), lease_token=token).update(
            lease_token=None, lease_until=None, next_check_at=timezone.now() + timedelta(seconds=config.RETRY_SECONDS)
        )
        logger.exception("DNS check dispatch failed; durable account work will be retried")


def dispatch_due_dns_checks() -> dict[str, int]:
    if not config.enabled():
        return {"queued": 0}
    limit = config.batch_size()
    _seed_missing(limit)
    now = timezone.now()
    due = list(
        HostedDomainDnsStatus.objects.filter(
            Q(next_check_at__lte=now) | Q(lease_until__lte=now), account__status__in=("active", "suspended")
        )
        .filter(Q(lease_token__isnull=True) | Q(lease_until__lte=now))
        .order_by("next_check_at", "pk")
        .values_list("account_id", flat=True)[:limit]
    )
    queued = 0
    for account_id in due:
        with transaction.atomic():
            claim, _reason = service.claim_check(str(account_id))
            if claim is None:
                continue
            transaction.on_commit(partial(_enqueue, str(account_id), claim.token), robust=True)
            queued += 1
    return {"queued": queued}


def check_account_dns(account_id: str, *, lease_token: str | None = None) -> dict[str, str]:
    try:
        account_id = str(UUID(account_id))
        token = UUID(lease_token) if lease_token else None
    except (TypeError, ValueError):
        return {"action": "excluded"}
    claim, reason = service.claim_check(account_id, token=token)
    if claim is None:
        return {"action": reason}
    try:
        report = service._probe(claim.snapshot)
    except Exception:
        # A monitoring failure is explicitly unknown; it cannot send an outage message or
        # manufacture a healthy baseline. Keep the error visible in worker logs for repair.
        logger.exception("Hosted-domain DNS probe failed for account %s", account_id)
        report = service.unknown_report("probe_failed")
    try:
        action = service.commit_check(claim, report)
    except service.DnsCheckLeaseLostError:
        action = "busy"
    return {"action": action}
