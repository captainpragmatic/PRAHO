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

from django.db import transaction

from apps.common.types import Err, Ok, Result, retriability_of

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname
from .virtualmin_models import VirtualminAccount, VirtualminServer

logger = logging.getLogger(__name__)

ENSURE_TASK = "apps.provisioning.account_hostname_lifecycle.ensure_account_name"


def on_account_ready(account: VirtualminAccount) -> None:
    """A create finished: once it commits, give the account its name on the node now serving it."""
    if not config.account_hostnames_enabled():
        return
    from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: the queue is optional at import time

    account_id = str(account.pk)
    transaction.on_commit(lambda: async_task(ENSURE_TASK, account_id), robust=True)


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
    ensured = service.ensure_node_account_name(account, server, enabled=enabled)
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
