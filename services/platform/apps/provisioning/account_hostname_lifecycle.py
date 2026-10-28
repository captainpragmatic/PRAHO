"""Where an account's life meets its account name (ADR-0061 P1.7).

- `on_account_ready` runs on every path that finishes a create. Once the create commits, it
  enqueues `ensure_account_name`: the name's row is allocated, `target_server` set to the node now
  serving the account and the node made to serve the name. A separate publication job proves the
  current neutral site before syncing records, with its own task budget.
- `ensure_on_recreated_node` runs where a customer domain is recreated from nothing on a node: a
  migration's target after its restore and before it is activated (`enabled=False`: the
  activation restores each child's recorded state), a recovery, a restore that
  recreated the domain. On an in-place restore the name is still there and this changes nothing.
- `on_account_terminated` queues private retirement of the name. A rollback or a failed migration's cleanup deletes the
  customer domain on its target, which removes that node's copy of the name; it never retires it.

With `dns.account_hostnames_enabled` off no name is allocated, placed or published. Retirement of an
existing name still withdraws its records and removes private copies after native absence is proved.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.common.types import Err, Ok, Result, retriability_of

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname
from .account_name_lease import ACCOUNT_NAME_TASK_TIMEOUT_SECONDS
from .virtualmin_models import VirtualminAccount, VirtualminServer

if TYPE_CHECKING:
    from .account_hostname_service import EnsureOutcome

logger = logging.getLogger(__name__)

ENSURE_TASK = "apps.provisioning.account_hostname_lifecycle.ensure_account_name"
SYNC_TASK = "apps.provisioning.account_hostname_lifecycle.sync_account_name"
RETIRE_TASK = "apps.provisioning.account_hostname_lifecycle.retire_account_name"


def _dispatch(task: str, identity: str) -> None:
    """Each name's external work has its own budget, including when the queue defaults to inline."""
    from django_q.tasks import async_task  # noqa: PLC0415  # Optional queue boundary

    async_task(task, identity, timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, sync=False)


def on_account_ready(account: VirtualminAccount) -> None:
    """A create finished: once it commits, give the account its name on the node now serving it.

    Never raises: it runs inside the create, whose failure path deletes the new domain, and a name
    that is not queued here is picked up by the sweep.
    """
    try:
        if not config.account_hostnames_enabled():
            return
        account_id = str(account.pk)
        transaction.on_commit(lambda: _dispatch(ENSURE_TASK, account_id), robust=True)
    except Exception:  # A hook in someone else's operation: logged, never raised into it
        logger.exception("🔥 [AccountName] Could not queue the name for %s; the sweep picks it up", account.pk)


def queue_repair(account: VirtualminAccount) -> bool:
    """Staff's "Repair DNS": queue the name's node step and sync again; nothing is looked up here (P1.13).

    False when account names are off or the account has no live name to repair.
    """
    if not config.account_hostnames_enabled():
        return False
    # An account with no name yet gets one from the task; only a retired name stays retired.
    if AccountHostname.objects.filter(account=account, retired_at__isnull=False).exists():
        return False
    account_id = str(account.pk)
    transaction.on_commit(lambda: _dispatch(ENSURE_TASK, account_id), robust=True)
    return True


def ensure_account_name(account_id: str) -> dict[str, str]:
    """Task: allocate the name, point it at the account's node, serve it there and queue DNS publication.

    Idempotent. A step that fails is left to the reconcile sweep (P1.8), which converges the same
    way; nothing here undoes the account's own provisioning.
    """
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    if not config.account_hostnames_enabled():
        return {"outcome": "disabled"}
    account = VirtualminAccount.objects.select_related("server").filter(pk=account_id).first()
    if account is None or account.server is None or account.status not in service.SYNCABLE_STATUSES:
        return {"outcome": "not_ready"}
    hostname = service.allocate_account_hostname(account)
    if hostname.target_server_id is None:
        # Set once, at creation; afterwards only a cutover or a recovery moves it.
        AccountHostname.objects.filter(pk=hostname.pk, target_server__isnull=True).update(target_server=account.server)
        hostname.refresh_from_db()
    ensured = service.ensure_node_account_name(account, account.server, enabled=account.status == "active")
    if ensured.is_err():
        logger.warning("⚠️ [AccountName] Node step for %s left to the sweep: %s", account.domain, ensured.unwrap_err())
        return {"outcome": "node_failed"}
    # Placement/certificate work includes four guarded playbooks and its ACME
    # exchange. Publication's fifth guard and provider calls need another budget.
    _dispatch(SYNC_TASK, str(hostname.pk))
    return {"outcome": "sync_queued"}


def sync_account_name(hostname_id: str) -> dict[str, str]:
    """One publication job: fresh operation admission, strict neutral proof, then locked DNS sync."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Gateway boundary
    from .virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # Circular

    if not config.account_hostnames_enabled():
        return {"outcome": "disabled"}
    hostname = AccountHostname.objects.select_related("account").filter(pk=hostname_id, retired_at__isnull=True).first()
    if hostname is None or hostname.account is None:
        return {"outcome": "not_ready"}
    if account_has_active_operation(hostname.account):
        return {"outcome": "migration_locked"}
    synced = service.sync_account_hostname(hostname, skip_locked=True)
    if synced.is_err():
        logger.warning("⚠️ [AccountName] DNS for %s left to the sweep: %s", hostname.fqdn, synced.unwrap_err())
        return {"outcome": "dns_failed"}
    return {"outcome": synced.unwrap()}


def retire_account_name(hostname_id: str) -> dict[str, str]:
    """Retry DNS withdrawal and native-absence-required private cleanup for one terminated name."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Gateway boundary

    hostname = AccountHostname.objects.select_related("account").filter(pk=hostname_id).first()
    if hostname is None or hostname.retired_at is not None:
        return {"outcome": "retired"}
    if hostname.account is not None and hostname.account.status != "terminated":
        return {"outcome": "not_terminated"}
    retired = service.retire_account_hostname(hostname)
    if retired.is_err():
        logger.warning("⚠️ [AccountName] Retiring %s left to the sweep: %s", hostname.fqdn, retired.unwrap_err())
        return {"outcome": "retire_failed"}
    return {"outcome": "retired"}


def ensure_on_recreated_node(
    account: VirtualminAccount, server: VirtualminServer, *, enabled: bool
) -> Result[EnsureOutcome | None, str]:
    """A customer domain was recreated from nothing on `server`: put its account name back there.

    Ok(None) means there was nothing to put back (the feature is off, or the account has no name
    yet); otherwise the outcome says what the node now serves, which the cutover gates on.
    """
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    if not config.account_hostnames_enabled():
        return Ok(None)
    if not AccountHostname.objects.filter(account=account, retired_at__isnull=True).exists():
        return Ok(None)  # The account has no name yet: on_account_ready gives it one
    # The migration or restore calling this is the account's operation, so it is not refused by it.
    ensured = service.ensure_node_account_name(account, server, enabled=enabled, operation_owner=True)
    if ensured.is_err():
        return Err(ensured.unwrap_err(), retriability=retriability_of(ensured))
    return Ok(ensured.unwrap())


def on_account_terminated(account: VirtualminAccount) -> None:
    """The account is terminated: retire its name, once the termination commits."""
    try:
        hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    except Exception:  # A hook in the termination: logged, never raised into it; the sweep retires it
        logger.exception("🔥 [AccountName] Could not look up the name of %s; the sweep retires it", account.pk)
        return
    if hostname is None:
        return

    transaction.on_commit(lambda: _dispatch(RETIRE_TASK, str(hostname.pk)), robust=True)


SWEEP_BATCH = 50
RECHECK_AFTER = timedelta(hours=24)
# Per-name sweep dispatch cooldown: pending, failed or uncertain work must not create
# duplicate node/publication/retirement jobs every 15 minutes. Reads do not extend this clock.
NODE_STEP_BACKOFF = timedelta(hours=1)


def reconcile_account_names() -> dict[str, int]:
    """Every 15 minutes: converge the names that need it to their target server (ADR-0061 P1.8).

    Only names that need work are picked, at most SWEEP_BATCH a run: one never reconciled, or one not
    checked for RECHECK_AFTER. They are taken in rotation (`last_swept_at`, set on every pass whatever
    the outcome), so names that cannot be published yet (no certificate, budget spent) never hold the
    head of the queue against published names that are due a check.

    This dispatcher performs database work only. Placement, guarded DNS publication and private
    retirement each run in separate per-name jobs with explicit budgets. Dispatch claims are checked
    under the name's lock, including the retry cooldown, so concurrent sweeps do not duplicate work.
    """
    if not config.account_hostnames_enabled():
        return {"disabled": 1}
    retirements_queued = _finish_retirements()
    unnamed = _queue_unnamed_accounts()
    due = Q(last_reconciled_at__isnull=True) | Q(last_reconciled_at__lt=timezone.now() - RECHECK_AFTER)
    candidates = list(
        AccountHostname.objects.filter(
            due, _dispatch_due(), retired_at__isnull=True, account__isnull=False, target_server__isnull=False
        )
        .order_by(F("last_swept_at").asc(nulls_first=True))
        .values_list("pk", flat=True)[:SWEEP_BATCH]
    )
    counts = {"published": 0, "enqueued": unnamed + retirements_queued, "skipped": 0, "failed": 0, "retired": 0}
    for pk in candidates:
        try:
            counts[_sweep_one(pk)] += 1
        except Exception:  # One name's surprise must not stop the batch; it is logged and counted
            logger.exception("🔥 [AccountName] Sweep: name %s raised", pk)
            counts["failed"] += 1
    return counts


def _queue_unnamed_accounts() -> int:
    """Queue the ensure task for accounts that should have a name and have no complete one.

    The create's hook may never have queued it (the queue was down at the commit), or a worker died
    between allocating the row and setting its target; neither shows up among the names below.
    """
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    eligible = (
        VirtualminAccount.objects.filter(
            status__in=service.SYNCABLE_STATUSES, provisioned_at__isnull=False, server__isnull=False
        )
        .filter(
            Q(account_hostname__isnull=True)
            | Q(account_hostname__retired_at__isnull=True, account_hostname__target_server__isnull=True)
        )
        .filter(
            Q(account_hostname__last_swept_at__isnull=True)
            | Q(account_hostname__last_swept_at__lte=timezone.now() - NODE_STEP_BACKOFF)
        )
        .order_by(F("account_hostname__last_swept_at").asc(nulls_first=True))
    )
    queued = 0
    for account in eligible[:SWEEP_BATCH]:
        hostname = service.allocate_account_hostname(account)
        if _sweep_one(hostname.pk) == "enqueued":
            queued += 1
    return queued


def _finish_retirements() -> int:
    """Queue private cleanup fairly; unresolved placement must not starve later names."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    pending = (
        AccountHostname.objects.filter(_dispatch_due(), retired_at__isnull=True)
        .filter(Q(account__isnull=True) | Q(account__status="terminated"))
        .order_by(F("last_swept_at").asc(nulls_first=True))[:SWEEP_BATCH]
    )
    queued = 0
    for hostname in pending:
        try:
            with transaction.atomic():
                locked = service.lock_for_publication(hostname.pk, skip_locked=True)
                if locked is None or locked.retired_at is not None or not _may_dispatch(locked):
                    continue
                if locked.account is not None and locked.account.status != "terminated":
                    continue
                AccountHostname.objects.filter(pk=locked.pk).update(last_swept_at=timezone.now())
            _dispatch(RETIRE_TASK, str(hostname.pk))
            queued += 1
        except Exception:  # One name's surprise must not stop the sweep
            logger.exception("🔥 [AccountName] Sweep: queuing retirement of %s raised", hostname.fqdn)
    return queued


def _dispatch_due() -> Q:
    return Q(last_swept_at__isnull=True) | Q(last_swept_at__lte=timezone.now() - NODE_STEP_BACKOFF)


def _may_dispatch(hostname: AccountHostname) -> bool:
    return hostname.last_swept_at is None or timezone.now() - hostname.last_swept_at >= NODE_STEP_BACKOFF


def _sweep_one(pk: UUID) -> str:
    """One name's pass: which count it adds to."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway
    from .virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # Circular

    with transaction.atomic():
        hostname = service.lock_for_publication(pk, skip_locked=True)
        if hostname is None or hostname.retired_at is not None or not _may_dispatch(hostname):
            return "skipped"
        AccountHostname.objects.filter(pk=hostname.pk).update(last_swept_at=timezone.now())
        account = hostname.account
        busy = account is None or account_has_active_operation(account)
    if account is None or busy:
        return "skipped"
    # A name never reconciled, or one whose certificate is no longer on its node (a restore that recreated
    # the sub-server and then failed), needs its node step, not just a DNS sync.
    target = hostname.target_server
    needs_node_step = hostname.last_reconciled_at is None or (
        target is not None and not service.certificate_ready_on(hostname, target)
    )
    if needs_node_step and hostname.target_server_id in {None, account.server_id}:
        _dispatch(ENSURE_TASK, str(account.pk))
    else:
        _dispatch(SYNC_TASK, str(hostname.pk))
    return "enqueued"
