"""One node step at a time per account name (ADR-0061 P1.4, P1.10).

Creating the name's sub-server, linking its web root and installing its certificate all change what
one node serves for that name. Two tasks doing them at once (the create task, the sweep, a migration,
a renewal's install) could leave a node serving one certificate while PRAHO records another. The lease
is a single conditional UPDATE on the name's row, so it holds across processes and needs no cache; it
expires after NODE_LEASE, well past the longest node step (a link and an install, each bounded by
its playbook timeout, plus the ACME exchange's own deadline).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .account_hostname_models import AccountHostname

# Every account-name task (the ensure task, a renewal, an install) gets this queue timeout: room for a
# link and an install (each an SSH wait plus its playbook) and an ACME exchange. The node lease outlives
# it, so a worker the queue still lets run never loses the lease (test_account_name_bounds).
ACCOUNT_NAME_TASK_TIMEOUT_SECONDS = 1500
NODE_LEASE = timedelta(minutes=30)


def take_node_lease(hostname: AccountHostname) -> str | None:
    """The lease token when this caller now holds the name's node step, else None."""
    now = timezone.now()
    token = uuid.uuid4().hex
    taken = (
        AccountHostname.objects.filter(pk=hostname.pk)
        .filter(Q(node_lease_until__isnull=True) | Q(node_lease_until__lte=now))
        .update(node_lease_token=token, node_lease_until=now + NODE_LEASE)
    )
    return token if taken == 1 else None


def release_node_lease(hostname: AccountHostname, token: str) -> None:
    """Give the lease back, only if this caller still holds it."""
    AccountHostname.objects.filter(pk=hostname.pk, node_lease_token=token).update(
        node_lease_token="", node_lease_until=None
    )


@contextmanager
def node_lease(hostname: AccountHostname) -> Iterator[str | None]:
    """Hold the name's node step for the block; yields None when another caller holds it."""
    token = take_node_lease(hostname)
    try:
        yield token
    finally:
        if token is not None:
            release_node_lease(hostname, token)
