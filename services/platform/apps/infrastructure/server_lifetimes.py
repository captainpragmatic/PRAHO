"""Billable server lifetimes of a node deployment.

Each lifetime is one server's billable window. Every write that changes a lifetime runs in the same transaction
as the owner's row write beside it, and after it: a worker that lost its lease raises there, and both roll back.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from apps.infrastructure.deployment_lifecycle import owned_update

if TYPE_CHECKING:
    from apps.infrastructure.deployment_lifecycle import OperationLease
    from apps.infrastructure.models import NodeDeployment, NodeServerLifetime, NodeSize


def _model() -> type[NodeServerLifetime]:
    from apps.infrastructure.models import NodeServerLifetime  # noqa: PLC0415  # Deferred: models import lifecycle

    return NodeServerLifetime


def _new(deployment: NodeDeployment, size: NodeSize, started_at: datetime, **fields: Any) -> NodeServerLifetime:
    return _model().objects.create(
        deployment=deployment, node_size=size, monthly_cost_eur=size.monthly_cost_eur, started_at=started_at, **fields
    )


def save_legacy_window(deployment: NodeDeployment, ended_at: datetime) -> None:
    """Keep a window recorded only in the row's timestamps before lifetime accounting starts or is reset."""
    if deployment.started_at is None or _model().objects.filter(deployment=deployment).exists():
        return
    _new(
        deployment,
        deployment.node_size,
        deployment.started_at,
        ended_at=deployment.destroyed_at or ended_at,
        legacy=True,
    )


def open_pending_lifetime(
    lease: OperationLease, deployment: NodeDeployment, **fields: Any
) -> tuple[NodeServerLifetime | None, bool]:
    """At the create intent: the open unconfirmed lifetime, reused or new, and whether this call created it.

    Only an unconfirmed lifetime (an earlier attempt's lost create) is reused; one that already names a server is
    never inherited by a new create.
    """
    now = timezone.now()
    with transaction.atomic():
        owned_update(lease, deployment, **fields)
        save_legacy_window(deployment, now)
        pending = (
            _model()
            .objects.filter(deployment=deployment, ended_at__isnull=True, server_id="")
            .order_by("started_at")
            .first()
        )
        if pending is not None:
            return pending, False
        return _new(deployment, deployment.node_size, now), True


def confirm_lifetime(
    lease: OperationLease,
    deployment: NodeDeployment,
    lifetime: NodeServerLifetime | None,
    server_id: str,
    **fields: Any,
) -> None:
    """The create returned ``server_id`` (created or adopted): bind it to the lifetime this attempt holds."""
    with transaction.atomic():
        owned_update(lease, deployment, **fields)
        bound = 0
        if lifetime is not None:
            bound = (
                _model()
                .objects.filter(pk=lifetime.pk, ended_at__isnull=True, server_id__in=("", server_id))
                .update(server_id=server_id, updated_at=timezone.now())
            )
        if (
            not bound
            and not _model().objects.filter(deployment=deployment, ended_at__isnull=True, server_id=server_id).exists()
        ):
            _new(deployment, deployment.node_size, timezone.now(), server_id=server_id)


def discard_lifetime(
    lease: OperationLease, deployment: NodeDeployment, lifetime: NodeServerLifetime | None, **fields: Any
) -> None:
    """The create was provably refused: no server was billed, so the unconfirmed lifetime it opened goes."""
    with transaction.atomic():
        owned_update(lease, deployment, **fields)
        if lifetime is not None:
            _model().objects.filter(pk=lifetime.pk, ended_at__isnull=True, server_id="").delete()


def close_server_lifetimes(
    lease: OperationLease, deployment: NodeDeployment, *, server_id: str | None = None, **fields: Any
) -> int:
    """Teardown or cleanup proved the server(s) gone: close the open lifetimes (only ``server_id``'s if given)."""
    now = timezone.now()
    with transaction.atomic():
        owned_update(lease, deployment, **fields)
        open_rows = _model().objects.filter(deployment=deployment, ended_at__isnull=True)
        if server_id is not None:
            open_rows = open_rows.filter(server_id=server_id)
        return open_rows.update(ended_at=now, updated_at=now)


def open_lifetime_id(deployment: NodeDeployment, server_id: str) -> Any:
    """The open lifetime of ``server_id``, or None (a row whose window predates lifetimes)."""
    return (
        _model()
        .objects.filter(deployment=deployment, ended_at__isnull=True, server_id=server_id)
        .values_list("pk", flat=True)
        .first()
    )


def split_lifetime_for_resize(lifetime_id: Any, server_id: str, new_size: NodeSize) -> bool:
    """A resize finished: close the lifetime at the old rate and open its successor at the new one.

    Only while that lifetime is still open for that server: a teardown or re-deploy that closed it meanwhile is
    left alone, and no window is reopened. A ``lifetime_id`` of None (a row without lifetimes) changes nothing.
    """
    if lifetime_id is None:
        return False
    now = timezone.now()
    with transaction.atomic():
        lifetime = (
            _model()
            .objects.select_for_update()
            .filter(pk=lifetime_id, ended_at__isnull=True, server_id=server_id)
            .first()
        )
        if lifetime is None:
            return False
        lifetime.ended_at = now
        lifetime.save(update_fields=["ended_at", "updated_at"])
        _new(lifetime.deployment, new_size, now, server_id=server_id)
        return True


def start_lifetimes_at_resize(
    deployment: NodeDeployment, server_id: str, old_size: NodeSize, new_size: NodeSize
) -> bool:
    """The first resize of a row whose window predates lifetimes: keep that window at the old rate, then bill on.

    Nothing happens when the row already has lifetimes (``split_lifetime_for_resize`` handles those) or has no
    window of its own.
    """
    now = timezone.now()
    with transaction.atomic():
        if deployment.started_at is None or _model().objects.filter(deployment=deployment).exists():
            return False
        _new(deployment, old_size, deployment.started_at, ended_at=now, legacy=True)
        _new(deployment, new_size, now, server_id=server_id)
        return True


def delete_unconfirmed_lifetimes(deployment: NodeDeployment) -> int:
    """A never-created attestation: open lifetimes with no confirmed server billed nothing."""
    deleted, _ = _model().objects.filter(deployment=deployment, ended_at__isnull=True, server_id="").delete()
    return int(deleted)
