"""The hourly differential-chain schedule (ADR-0059).

Every hour the schedule looks at each account that backups may run for and takes the one backup
its chain is due for: a base when there is no live base or the base is old, a differential when
the base is live and the last backup of this chain is old. It decides from the chain itself, never
from error text:

* the node's evidence that a snapshot is absent or different ends the chain (that is done where the
  evidence arrives, fenced by epoch), so the next run finds no live base and takes a base;
* a failure that leaves the chain alone (the node was busy, a metadata read failed) is retried as
  the same role after a growing delay, and raises one alert when it has happened
  ``provisioning.chain_alert_after_failures`` times in a row (default 3). It never turns a differential into a base.

Jobs go through the admission staff use (account lock, exclusion, pins, budget), so a migration, a
restore, a delete, another backup or a job parked for an operator keeps the account out of the
sweep. Nothing is scheduled while ``provisioning.incremental_backups_enabled`` is off.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.core.cache import cache
from django.db.models import F, OuterRef, Subquery
from django.utils import timezone

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.settings.services import SettingsService

from .domain_veto import domain_disables_hosting
from .virtualmin_chain import ROLE_BASE, ROLE_DIFFERENTIAL, base_backup_id
from .virtualmin_migration_models import account_has_active_operation
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

if TYPE_CHECKING:
    from django.db.models import QuerySet

logger = logging.getLogger(__name__)

SCHEDULER_ACTOR = "system:chain-scheduler"
SCHEDULE_NAME = "virtualmin-chain-backups"

# Consecutive operational failures of an account's chain backups before staff are alerted: the default of
# provisioning.chain_alert_after_failures.
ALERT_AFTER_FAILURES = 3
# At most this many jobs are admitted per sweep, so enabling the flag on a large fleet spreads
# its first bases over several hours instead of queueing every account at once.
MAX_ADMISSIONS_PER_SWEEP = 20
# Sweeps in a row that stopped at the cap before staff are alerted: the fleet is larger than the schedule can serve.
DEFERRED_SWEEPS_ALERT = 6
_DEFERRED_SWEEPS_KEY = "chain-schedule-deferred-sweeps"
_DEFERRED_SWEEPS_TTL_SECONDS = 24 * 3600

_DEFAULT_BASE_INTERVAL_DAYS = 7
_DEFAULT_DIFFERENTIAL_INTERVAL_HOURS = 24
_FIRST_BACKOFF = timedelta(minutes=30)
_MAX_BACKOFF = timedelta(hours=24)
_STREAK_LOOKBACK = 50
_REFUSAL_ALERT_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class ChainDecision:
    """The one backup an account is due for and why."""

    role: str
    reason: str


def base_interval() -> timedelta:
    """Days between bases. A stored zero or negative value (written before validation) means the default."""
    days = SettingsService.get_integer_setting("provisioning.chain_base_interval_days", _DEFAULT_BASE_INTERVAL_DAYS)
    return timedelta(days=days if days > 0 else _DEFAULT_BASE_INTERVAL_DAYS)


def differential_interval() -> timedelta:
    """Hours between differentials. A stored zero or negative value means the default."""
    hours = SettingsService.get_integer_setting(
        "provisioning.chain_differential_interval_hours", _DEFAULT_DIFFERENTIAL_INTERVAL_HOURS
    )
    return timedelta(hours=hours if hours > 0 else _DEFAULT_DIFFERENTIAL_INTERVAL_HOURS)


def alert_after_failures() -> int:
    """Failures in a row before staff are alerted. A stored zero or negative value (written before validation) means the default."""
    threshold = SettingsService.get_integer_setting("provisioning.chain_alert_after_failures", ALERT_AFTER_FAILURES)
    return threshold if threshold > 0 else ALERT_AFTER_FAILURES


def backoff_for(streak: int) -> timedelta:
    """How long to wait after ``streak`` consecutive operational failures: 30 minutes, doubling, capped at a day."""
    if streak <= 0:
        return timedelta(0)
    doublings = min(streak - 1, 10)  # 30 minutes * 2**10 is far past the cap already
    return min(_FIRST_BACKOFF * (1 << doublings), _MAX_BACKOFF)


def failure_streak(account: VirtualminAccount) -> tuple[int, datetime | None]:
    """Consecutive operational failures of the account's chain jobs, and when the latest ended.

    Newest first, back to the last completed chain job. A failure counts only when it left the
    chain intact; one that ended the chain, and one an operator resolved, carry no such mark and
    are skipped rather than counted.
    """
    rows = (
        VirtualminProvisioningJob.objects.filter(
            account=account,
            operation="backup_domain",
            parameters__chain_role__in=(ROLE_BASE, ROLE_DIFFERENTIAL),
            status__in=("completed", "failed"),
            completed_at__isnull=False,
        )
        .order_by("-completed_at")
        .values_list("status", "result", "completed_at")[:_STREAK_LOOKBACK]
    )
    streak = 0
    latest: datetime | None = None
    for status, result, completed_at in rows:
        if status == "completed":
            break
        if (result or {}).get("chain_state") != "intact":
            continue
        streak += 1
        latest = latest or completed_at
    return streak, latest


def due_role(account: VirtualminAccount, now: datetime) -> ChainDecision | None:
    """The backup this account's chain is due for at ``now``, or None. Reads only the database."""
    base = account.chain_base
    if base is None or not account.chain_base_fingerprint:
        return ChainDecision(ROLE_BASE, "no_live_base")
    if not base_backup_id(account):
        return ChainDecision(ROLE_BASE, "base_evidence_unusable")
    base_done = base.completed_at or base.updated_at
    if now - base_done >= base_interval():
        return ChainDecision(ROLE_BASE, "base_interval_elapsed")
    latest_differential = (
        VirtualminProvisioningJob.objects.filter(
            account=account,
            operation="backup_domain",
            status="completed",
            completed_at__isnull=False,
            parameters__chain_role=ROLE_DIFFERENTIAL,
            parameters__base_job_id=str(base.pk),
        )
        .order_by("-completed_at")
        .values_list("completed_at", flat=True)
        .first()
    )
    last_backup = max(base_done, latest_differential) if latest_differential else base_done
    if now - last_backup >= differential_interval():
        return ChainDecision(ROLE_DIFFERENTIAL, "differential_interval_elapsed")
    return None


def _ineligible_reason(account: VirtualminAccount) -> str | None:
    """Why backups are not scheduled for this account at all, or None when they may be."""
    server = account.server
    if account.status != "active" or server.status != "active" or server.is_draining:
        return "ineligible"
    if account.service is None or account.service.status != "active" or domain_disables_hosting(account):
        return "ineligible"
    if getattr(server, "node_deployment", None) is None:
        return "unmanaged_node"  # chain steps run through the node's deployment; there is none to use
    return None


def _alert(account: VirtualminAccount, description: str, *, detail: dict[str, Any]) -> None:
    """Flag staff through the audit trail, as the server health alert does (severity high, review required)."""
    AuditService.log_event(
        AuditEventData(
            event_type="virtualmin_chain_backup_alert",
            content_object=account,
            description=description,
        ),
        AuditContext(
            actor_type="system",
            metadata={
                "source_app": "provisioning",
                "severity": "high",
                "requires_review": True,
                "operational_event": True,
                "domain": account.domain,
                **detail,
            },
        ),
    )


def note_chain_failure(job_id: Any) -> None:
    """Called when a chain job has failed: alert once when the account's streak reaches the threshold.

    The streak only grows when a job fails, so this runs exactly once per failure and fires on the
    failure that makes it N, never on the quiet sweeps in between.
    """
    job = VirtualminProvisioningJob.objects.select_related("account").filter(pk=job_id).first()
    if job is None or job.account is None or (job.result or {}).get("chain_state") != "intact":
        return
    streak, _ = failure_streak(job.account)
    if streak != alert_after_failures():
        return
    message = (job.status_message or "")[:300]
    logger.error("🔥 [ChainSchedule] %s: %s chain backups failed in a row: %s", job.account.domain, streak, message)
    _alert(
        job.account,
        f"Chain backups for {job.account.domain} failed {streak} times in a row; last error: {message}",
        detail={"consecutive_failures": streak, "job_id": str(job.pk)},
    )


def _alert_admission_refused(account: VirtualminAccount, role: str, error: str) -> None:
    """A refusal that is not the exclusion would repeat every hour: alert once a day per account and role."""
    if not cache.add(f"chain-schedule-refused:{account.pk}:{role}", 1, _REFUSAL_ALERT_TTL_SECONDS):
        return
    logger.error("🔥 [ChainSchedule] %s: %s backup refused at admission: %s", account.domain, role, error)
    _alert(
        account,
        f"The scheduled {role} backup for {account.domain} was refused at admission: {error[:300]}",
        detail={"role": role},
    )


def _consider(account: VirtualminAccount, now: datetime, outcome: dict[str, Any]) -> None:
    from .virtualmin_service import VirtualminBackupManagementService  # noqa: PLC0415  # Circular

    skipped: dict[str, int] = outcome["skipped"]

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    ineligible = _ineligible_reason(account)
    if ineligible is not None:
        skip(ineligible)
        return
    if account_has_active_operation(account):
        skip("excluded")
        return
    decision = due_role(account, now)
    if decision is None:
        skip("not_due")
        return
    streak, failed_at = failure_streak(account)
    if failed_at is not None and now < failed_at + backoff_for(streak):
        skip("backoff")
        return

    management = VirtualminBackupManagementService(account.server)
    take = management.take_base_backup if decision.role == ROLE_BASE else management.take_differential_backup
    result = take(account, initiated_by=SCHEDULER_ACTOR)
    if result.is_ok():
        job = result.unwrap()
        outcome["admitted"].append(
            {"domain": account.domain, "role": decision.role, "reason": decision.reason, "job_id": str(job.pk)}
        )
        logger.info("✅ [ChainSchedule] %s: %s admitted (%s)", account.domain, decision.role, decision.reason)
        return
    if account_has_active_operation(account):
        skip("excluded")  # another writer got the account between the check and the admission
        return
    skip("refused")
    _alert_admission_refused(account, decision.role, str(result.unwrap_err()))


def _note_deferral(deferred: bool) -> None:
    """Count sweeps in a row that stopped at the cap, and alert staff when that keeps happening.

    Ordering by staleness serves every account in turn, but a fleet bigger than the cap can serve
    in a day means some accounts wait longer than their interval: someone should raise the cap.
    """
    if not deferred:
        cache.delete(_DEFERRED_SWEEPS_KEY)
        return
    count = int(cache.get(_DEFERRED_SWEEPS_KEY, 0)) + 1
    cache.set(_DEFERRED_SWEEPS_KEY, count, _DEFERRED_SWEEPS_TTL_SECONDS)
    if count % DEFERRED_SWEEPS_ALERT:
        return
    message = (
        f"The chain-backup schedule stopped at its limit of {MAX_ADMISSIONS_PER_SWEEP} jobs in {count} sweeps in a row; "
        "some accounts wait longer than their backup interval"
    )
    logger.error("🔥 [ChainSchedule] %s", message)
    AuditService.log_event(
        AuditEventData(event_type="virtualmin_chain_schedule_deferred", description=message),
        AuditContext(
            actor_type="system",
            metadata={
                "source_app": "provisioning",
                "severity": "high",
                "requires_review": True,
                "operational_event": True,
                "consecutive_deferred_sweeps": count,
                "admissions_per_sweep": MAX_ADMISSIONS_PER_SWEEP,
            },
        ),
    )


def run_chain_backup_sweep(
    now: datetime | None = None, *, accounts: QuerySet[VirtualminAccount] | None = None
) -> dict[str, Any]:
    """One pass over the accounts: admit the base or differential each is due for.

    ``accounts`` narrows the pass (the lab proves the schedule on one account); production passes none.
    """
    outcome: dict[str, Any] = {"success": True, "enabled": False, "admitted": [], "skipped": {}, "errors": 0}
    if not SettingsService.get_boolean_setting("provisioning.incremental_backups_enabled", False):
        return outcome
    outcome["enabled"] = True
    now = now or timezone.now()
    candidates = (
        (accounts if accounts is not None else VirtualminAccount.objects.all())
        .filter(status="active", server__status="active", server__is_draining=False)
        .select_related("server", "server__node_deployment", "service", "chain_base")
        .annotate(
            last_chain_job_at=Subquery(
                VirtualminProvisioningJob.objects.filter(
                    account_id=OuterRef("pk"),
                    operation="backup_domain",
                    parameters__chain_role__in=(ROLE_BASE, ROLE_DIFFERENTIAL),
                )
                .order_by("-created_at")
                .values("created_at")[:1]
            )
        )
        # Stalest first: accounts that never had a chain job, then the oldest last one. A sweep that stops
        # at the cap must not always stop at the same accounts (pk order starved everything past the cap).
        .order_by(F("last_chain_job_at").asc(nulls_first=True), "pk")
    )
    for account in candidates.iterator(chunk_size=200):
        if len(outcome["admitted"]) >= MAX_ADMISSIONS_PER_SWEEP:
            outcome["deferred"] = True
            break
        try:
            _consider(account, now, outcome)
        except Exception:
            outcome["errors"] += 1
            logger.exception("🔥 [ChainSchedule] Could not consider account %s", account.pk)
    _note_deferral(bool(outcome.get("deferred")))
    logger.info(
        "✅ [ChainSchedule] Sweep done: %s admitted, skipped %s, %s errors",
        len(outcome["admitted"]),
        outcome["skipped"],
        outcome["errors"],
    )
    return outcome
