"""Where an account's life meets its account name (ADR-0061 P1.7).

- `on_account_ready` runs on every path that finishes a create. Once the create commits, it
  enqueues `ensure_account_name`: the name's row is allocated, `target_server` set to the node now
  serving the account, the node made to serve the name, and the records synced.
- `ensure_on_recreated_node` runs where a customer domain is recreated from nothing on a node: a
  migration's target after its restore and before it is activated (`enabled=False`: the
  activation's cascading enable turns the name on with the account), a recovery, a restore that
  recreated the domain. On an in-place restore the name is still there and this changes nothing.
- `on_account_terminated` retires the name. A rollback or a failed migration's cleanup deletes the
  customer domain on its target, which removes that node's copy of the name; it never retires it.

With `dns.account_hostnames_enabled` off none of this does anything: no row, no node call, no DNS.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from uuid import UUID

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.common.types import Err, Ok, Result, retriability_of

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname
from .account_name_lease import ACCOUNT_NAME_TASK_TIMEOUT_SECONDS
from .virtualmin_models import VirtualminAccount, VirtualminServer

logger = logging.getLogger(__name__)

ENSURE_TASK = "apps.provisioning.account_hostname_lifecycle.ensure_account_name"


def on_account_ready(account: VirtualminAccount) -> None:
    """A create finished: once it commits, give the account its name on the node now serving it."""
    if not config.account_hostnames_enabled():
        return
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: the queue is optional at import time

    account_id = str(account.pk)
    transaction.on_commit(
        lambda: async_task(ENSURE_TASK, account_id, timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS), robust=True
    )


def queue_repair(account: VirtualminAccount) -> bool:
    """Staff's "Repair DNS": queue the name's node step and sync again; nothing is looked up here (P1.13).

    False when account names are off or the account has no live name to repair.
    """
    if not config.account_hostnames_enabled():
        return False
    if not AccountHostname.objects.filter(account=account, retired_at__isnull=True).exists():
        return False
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: the queue is optional at import time

    account_id = str(account.pk)
    transaction.on_commit(
        lambda: async_task(ENSURE_TASK, account_id, timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS), robust=True
    )
    return True


def ensure_account_name(account_id: str) -> dict[str, str]:
    """Task: allocate the name, point it at the account's node, serve it there, sync its records.

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
    synced = service.sync_account_hostname(hostname)
    if synced.is_err():
        logger.warning("⚠️ [AccountName] DNS for %s left to the sweep: %s", account.domain, synced.unwrap_err())
        return {"outcome": "dns_failed"}
    return {"outcome": synced.unwrap()}


def ensure_on_recreated_node(
    account: VirtualminAccount, server: VirtualminServer, *, enabled: bool
) -> Result[None, str]:
    """A customer domain was recreated from nothing on `server`: put its account name back there."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    if not config.account_hostnames_enabled():
        return Ok(None)
    if not AccountHostname.objects.filter(account=account, retired_at__isnull=True).exists():
        return Ok(None)  # The account has no name yet: on_account_ready gives it one
    # The migration or restore calling this is the account's operation, so it is not refused by it.
    ensured = service.ensure_node_account_name(account, server, enabled=enabled, operation_owner=True)
    if ensured.is_err():
        return Err(ensured.unwrap_err(), retriability=retriability_of(ensured))
    return Ok(None)


def on_account_terminated(account: VirtualminAccount) -> None:
    """The account is terminated: retire its name, once the termination commits."""
    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway

    hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    if hostname is None:
        return

    def _retire() -> None:
        retired = service.retire_account_hostname(hostname)
        if retired.is_err():
            logger.warning("⚠️ [AccountName] Retiring %s left to the sweep: %s", hostname.fqdn, retired.unwrap_err())

    transaction.on_commit(_retire, robust=True)


SWEEP_BATCH = 50
RECHECK_AFTER = timedelta(hours=24)


def reconcile_account_names() -> dict[str, int]:
    """Every 15 minutes: converge the names that need it to their target server (ADR-0061 P1.8).

    Only names that need work are picked, at most SWEEP_BATCH a run: one never reconciled, or one not
    checked for RECHECK_AFTER. They are taken in rotation (`last_swept_at`, set on every pass whatever
    the outcome), so names that cannot be published yet (no certificate, budget spent) never hold the
    head of the queue against published names that are due a check.

    A name never reconciled gets its node step in its own task (ENSURE_TASK), since a node step can run
    an ACME exchange and two playbooks; the others are synced here, which is DNS calls only. The decision
    to skip is atomic: the row is locked and re-checked, and a name whose account is in a migration, a
    backup, a restore or a delete is left alone. Each name is guarded, so one cannot stop the batch.
    """
    if not config.account_hostnames_enabled():
        return {"disabled": 1}
    due = Q(last_reconciled_at__isnull=True) | Q(last_reconciled_at__lt=timezone.now() - RECHECK_AFTER)
    candidates = list(
        AccountHostname.objects.filter(due, retired_at__isnull=True, account__isnull=False, target_server__isnull=False)
        .order_by(F("last_swept_at").asc(nulls_first=True))
        .values_list("pk", flat=True)[:SWEEP_BATCH]
    )
    counts = {"published": 0, "enqueued": 0, "skipped": 0, "failed": 0}
    for pk in candidates:
        try:
            counts[_sweep_one(pk)] += 1
        except Exception:  # One name's surprise must not stop the batch; it is logged and counted
            logger.exception("🔥 [AccountName] Sweep: name %s raised", pk)
            counts["failed"] += 1
    return counts


def _sweep_one(pk: UUID) -> str:
    """One name's pass: which count it adds to."""
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: the queue is optional at import time

    from . import account_hostname_service as service  # noqa: PLC0415  # Deferred: imports the gateway
    from .virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # Circular

    with transaction.atomic():
        hostname = (
            AccountHostname.objects.select_for_update(skip_locked=True, of=("self",))
            .select_related("account", "account__server", "target_server")
            .filter(pk=pk, retired_at__isnull=True)
            .first()
        )
        if hostname is None:
            return "skipped"
        AccountHostname.objects.filter(pk=hostname.pk).update(last_swept_at=timezone.now())
        account = hostname.account
        busy = account is None or account_has_active_operation(account)
    if account is None or busy:
        return "skipped"
    if hostname.last_reconciled_at is None and account.server_id == hostname.target_server_id:
        async_task(ENSURE_TASK, str(account.pk), timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)
        return "enqueued"
    synced = service.sync_account_hostname(hostname)
    if synced.is_err():
        logger.warning("⚠️ [AccountName] Sweep: DNS for %s: %s", hostname.fqdn, synced.unwrap_err())
        return "failed"
    return "published" if synced.unwrap() == "published" else "skipped"
