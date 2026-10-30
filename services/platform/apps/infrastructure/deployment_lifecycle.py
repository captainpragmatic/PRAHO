"""Operation ownership for NodeDeployment lifecycle writes.

A deployment's cloud resources are named by ``correlation_id``, which never changes. The worker
allowed to change the deployment's lifecycle state is named by ``operation_token``, which every claim
rotates. Each phase, failure and settlement write is a conditional update on that token, so a worker
that lost ownership (two retries racing, or recovery reclaiming a stuck row) writes nothing and stops.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)


class OperationOwnershipLostError(Exception):
    """The worker's operation token no longer owns the deployment; it must stop without writing."""


@dataclass(frozen=True)
class OperationLease:
    """Proof that one worker owns a deployment's lifecycle writes."""

    deployment_id: int
    token: uuid.UUID
    kind: str


# The deployment-log messages that record a firewall the deploy created and a key it uploaded.
FIREWALL_RECORD_PREFIX = "Firewall resource recorded:"
KEY_RECORD_PREFIX = "SSH key resource recorded:"


def attempt_resource_names(hostname: str, correlation_id: Any) -> tuple[str, str]:
    """The SSH key and firewall names a deploy attempt uses: (key, firewall)."""
    attempt = str(correlation_id)[:8]
    return f"praho-{hostname}-{attempt}", f"praho-fw-{hostname}-{attempt}"


def legacy_resource_names(hostname: str) -> tuple[str, str]:
    """The names used before resources were named per attempt: (key, firewall)."""
    return f"praho-{hostname}", f"praho-fw-{hostname}"


def unique_dns_owner_tag(correlation_id: Any) -> str:
    """The DNS owner tag unique to one deploy attempt, across PRAHO databases sharing a zone."""
    return f"praho:node-deploy:{correlation_id}"


def recorded_provider_resources(deployment: NodeDeployment) -> dict[str, list[str]]:
    """Firewall ids, firewall names and SSH key names the deployment log recorded, for every attempt."""
    from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import

    found: dict[str, list[str]] = {"firewall_ids": [], "firewall_names": [], "ssh_key_names": []}
    entries = NodeDeploymentLog.objects.filter(deployment=deployment).filter(
        Q(message__startswith=FIREWALL_RECORD_PREFIX) | Q(message__startswith=KEY_RECORD_PREFIX)
    )
    for details in entries.values_list("details", flat=True):
        if not isinstance(details, dict):
            continue
        for key, field_name in (
            ("firewall_ids", "firewall_id"),
            ("firewall_names", "firewall_name"),
            ("ssh_key_names", "ssh_key_name"),
        ):
            if details.get(field_name):
                found[key].append(str(details[field_name]))
    return found


def provider_token_fingerprint(api_token: str) -> str:
    """A one-way identifier for the provider token that created a deployment's resources."""
    return hashlib.sha256(api_token.encode()).hexdigest()[:32]


def claim_operation(  # noqa: PLR0911, PLR0913  # Every argument is one claim condition.
    deployment_id: int,
    *,
    from_states: Iterable[str],
    to_status: str,
    kind: str,
    expected_token: uuid.UUID | None = None,
    increment_retry: bool = False,
    stale_before: datetime | None = None,
    message: str = "",
    require_reconciled: bool = False,
) -> Result[OperationLease, str]:
    """Take ownership of a deployment under its row lock and move it to ``to_status``.

    The claim rotates ``operation_token``, so any earlier owner loses its writes. ``expected_token``
    restricts the claim to the holder of an earlier reservation, ``stale_before`` to a row that has not
    been written since (sweeps re-check age under the lock), and ``increment_retry`` counts the attempt
    in the same statement. ``require_reconciled`` refuses a row flagged for reconciliation.
    """
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    allowed = tuple(from_states)
    with transaction.atomic():
        # Join-free lock: a waited FOR UPDATE re-reads only the locked row.
        row = NodeDeployment.objects.select_for_update().filter(pk=deployment_id).first()
        if row is None:
            return Err(f"Deployment {deployment_id} not found")
        if row.status not in allowed:
            return Err(f"Cannot {kind} node in status '{row.status}'")
        if expected_token is not None and row.operation_token != expected_token:
            return Err(f"Cannot {kind} node: another operation owns it")
        if require_reconciled and row.needs_reconciliation:
            return Err(f"Cannot {kind} node: reconcile it first ({row.reconciliation_reason})")
        if stale_before is not None and row.updated_at >= stale_before:
            return Err(f"Cannot {kind} node: it was updated recently")
        if row.status != to_status and not row.is_valid_transition(to_status):
            return Err(f"Cannot transition from '{row.status}' to '{to_status}'")
        token = uuid.uuid4()
        updates: dict[str, Any] = {
            "status": to_status,
            "operation_token": token,
            "operation_kind": kind,
            "updated_at": timezone.now(),
        }
        if message:
            updates["status_message"] = message
        if increment_retry:
            updates["retry_count"] = F("retry_count") + 1
        NodeDeployment.objects.filter(pk=deployment_id).update(**updates)
    return Ok(OperationLease(deployment_id=deployment_id, token=token, kind=kind))


def reserve_operation(
    deployment_id: int, *, from_states: Iterable[str], kind: str, require_reconciled: bool = False
) -> Result[uuid.UUID, str]:
    """Reserve the next operation at enqueue time, without changing the status.

    The queued task claims only with this token, so of two clicks only the later reservation runs, and
    a task queued long ago is refused once any later claim or reservation has rotated the token.
    """
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    with transaction.atomic():
        row = NodeDeployment.objects.select_for_update().filter(pk=deployment_id).first()
        if row is None:
            return Err(f"Deployment {deployment_id} not found")
        if row.status not in tuple(from_states):
            return Err(f"Cannot {kind} node in status '{row.status}'")
        if require_reconciled and row.needs_reconciliation:
            return Err(f"Cannot {kind} node: reconcile it first ({row.reconciliation_reason})")
        token = uuid.uuid4()
        NodeDeployment.objects.filter(pk=deployment_id).update(
            operation_token=token, operation_kind=kind, updated_at=timezone.now()
        )
    return Ok(token)


def _apply(deployment: NodeDeployment, fields: dict[str, Any]) -> None:
    for name, value in fields.items():
        setattr(deployment, name, value)


def owned_update(lease: OperationLease, deployment: NodeDeployment, **fields: Any) -> None:
    """Write ``fields`` only while ``lease`` still owns the row; raise when it does not."""
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    values = {**fields, "updated_at": timezone.now()}
    updated = NodeDeployment.objects.filter(pk=lease.deployment_id, operation_token=lease.token).update(**values)
    if updated != 1:
        raise OperationOwnershipLostError(f"Deployment {lease.deployment_id} is no longer owned by this {lease.kind}")
    _apply(deployment, values)


def owned_transition(
    lease: OperationLease,
    deployment: NodeDeployment,
    to_status: str,
    message: str = "",
    *,
    release: bool = False,
    **fields: Any,
) -> None:
    """Move an owned row to ``to_status`` from the status this worker last wrote.

    ``release`` settles the operation: the token is cleared, so no worker owns the row until the next
    claim. An invalid transition raises ``ValidationError``; a lost lease raises
    ``OperationOwnershipLostError``. Neither writes.
    """
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    if not deployment.is_valid_transition(to_status):
        raise ValidationError(f"Cannot transition from '{deployment.status}' to '{to_status}'")
    values: dict[str, Any] = {**fields, "status": to_status, "updated_at": timezone.now()}
    if message:
        values["status_message"] = message
    if release:
        values["operation_token"] = None
        values["operation_kind"] = ""
    updated = NodeDeployment.objects.filter(
        pk=lease.deployment_id, operation_token=lease.token, status=deployment.status
    ).update(**values)
    if updated != 1:
        raise OperationOwnershipLostError(f"Deployment {lease.deployment_id} is no longer owned by this {lease.kind}")
    _apply(deployment, values)


def still_owns(lease: OperationLease) -> bool:
    """Whether ``lease`` still owns its row; a check before an external call, not a write guard."""
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    return NodeDeployment.objects.filter(pk=lease.deployment_id, operation_token=lease.token).exists()


def invalidate_stale_operation(
    deployment_id: int,
    *,
    from_states: Iterable[str],
    to_status: str,
    stale_before: datetime,
    message: str,
) -> bool:
    """Recovery: take a stuck row away from its owner, re-checking status and age under the lock.

    The token is cleared, so a worker that was only slow, not dead, finds its next write refused.
    Returns whether the row was recovered.
    """
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    with transaction.atomic():
        row = NodeDeployment.objects.select_for_update().filter(pk=deployment_id).first()
        if row is None or row.status not in tuple(from_states) or row.updated_at >= stale_before:
            return False
        if not row.is_valid_transition(to_status):
            return False
        NodeDeployment.objects.filter(pk=deployment_id).update(
            status=to_status,
            status_message=message,
            operation_token=None,
            operation_kind="",
            updated_at=timezone.now(),
        )
    logger.warning("⚠️ [Deployment] Recovered stuck deployment %s to %s", deployment_id, to_status)
    return True
