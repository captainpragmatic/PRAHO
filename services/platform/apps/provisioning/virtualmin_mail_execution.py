"""Fenced mail-attempt bookkeeping; no native effects, completion or mail-mode transitions.

Read-only prerequisite refusals can defer pristine opt-ins for at most 24 hours.
Uncertain running work always retains account exclusion in needs_review; a timeout
never authorizes replaying or discarding its native effects. Dispatch is separate.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result

from .account_hostname_models import AccountHostname
from .account_hostname_service import lock_for_publication
from .domain_veto import blocking_domain_status
from .service_models import Service
from .virtualmin_mail_enrollment import MAX_PROPOSAL_BYTES, PROPOSAL_LIFETIME, _digest, _json_copy, _owner
from .virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation, mail_generation
from .virtualmin_migration_models import account_has_active_operation
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

MAIL_EXECUTION_LEASE = timedelta(minutes=75)
# This covers one bounded setup step, including the supported one-time SSH
# repair. Future workers renew between steps; no whole-workflow bound is implied.
MAIL_PREPARATION_LIFETIME = timedelta(hours=24)
MAIL_PREPARATION_RETRY = timedelta(minutes=15)
_PREPARATION_REASONS = frozenset({"mail_node_certificate_unproven", "mail_dns_source_unavailable"})
_PREPARATION_EXPIRED = "mail_prerequisites_expired"
_DIGEST = re.compile(r"[a-f0-9]{64}")
_PHASES = {"claimed": "preflight", "preflight": "native_inflight"}
_PARK_CODES = frozenset({"mail_native_outcome_unknown", "mail_execution_interrupted", "mail_native_preparation_failed"})
_STATE_CODES = _PARK_CODES | {
    "mail_execution_ownership_expired",
    "mail_execution_state_uncertain",
    "mail_execution_forbidden",
    "mail_generation_changed",
    "mail_account_unavailable",
    "mail_hosting_held",
    "mail_operation_active",
    "mail_mode_conflict",
    "mail_execution_invalid_consent",
    _PREPARATION_EXPIRED,
}
_MAX_EVIDENCE_BYTES = 2048
_MAX_EVIDENCE_ITEMS = 5


@dataclass(frozen=True)
class MailExecutionLease:
    operation_id: UUID
    token: UUID
    generation: str
    checkpoint: str
    expires_at: datetime


@dataclass(frozen=True)
class _Context:
    account: VirtualminAccount
    server: VirtualminServer
    name: AccountHostname | None
    service: Service
    configuration: VirtualminMailConfiguration


class _ExecutionRefusalError(ValueError):
    """Only fixed, bounded public codes cross this service boundary."""


def _identifier(value: UUID | str) -> UUID:
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise _ExecutionRefusalError("mail_operation_missing") from error


@contextmanager
def _locked(identifier: UUID) -> Iterator[tuple[_Context, VirtualminMailOperation]]:
    seed = (
        VirtualminMailOperation.objects.filter(pk=identifier)
        .values("configuration_id", "configuration__account_id")
        .first()
    )
    if seed is None:
        raise _ExecutionRefusalError("mail_operation_missing")
    with transaction.atomic():
        account = (
            VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
            .filter(pk=seed["configuration__account_id"])
            .first()
        )
        if account is None:
            raise _ExecutionRefusalError("mail_operation_missing")
        server = VirtualminServer.objects.select_for_update(of=("self",), no_key=True).get(pk=account.server_id)
        name_id = AccountHostname.objects.filter(account_id=account.pk).values_list("pk", flat=True).first()
        name = lock_for_publication(name_id) if name_id is not None else None
        account.refresh_from_db()  # Fresh canonical relations after the publication-lock wait.
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=account.service_id)
        configuration = (
            VirtualminMailConfiguration.objects.select_for_update().filter(pk=seed["configuration_id"]).first()
        )
        operation = VirtualminMailOperation.objects.select_for_update().filter(pk=identifier).first()
        if configuration is None or operation is None or configuration.account_id != account.pk:
            raise _ExecutionRefusalError("mail_operation_missing")
        yield _Context(account, server, name, service, configuration), operation


def _consent(operation: VirtualminMailOperation, context: _Context) -> bool:
    try:
        envelope = _json_copy(operation.confirmed_plan, maximum=MAX_PROPOSAL_BYTES, wrapped=True)
        wanted = {
            "account_id": str(context.account.pk),
            "service_id": str(context.service.pk),
            "customer_id": str(context.service.customer_id),
            "actor_id": str(operation.requested_by_id),
            "target_generation": operation.target_generation,
            "intent": operation.intent,
        }
        if type(envelope.get("version")) is not int or envelope["version"] != 1:
            return False
        if any(envelope.get(key) != value for key, value in wanted.items()):
            return False
        UUID(envelope["proposal_id"])
        if not isinstance(envelope.get("plan"), dict) or _DIGEST.fullmatch(operation.consent_digest) is None:
            return False
        created, expires = parse_datetime(envelope["created_at"]), parse_datetime(envelope["expires_at"])
        return bool(
            created is not None
            and expires is not None
            and timezone.is_aware(created)
            and timezone.is_aware(expires)
            and created <= operation.created_at <= expires
            and expires - created == PROPOSAL_LIFETIME
            and hmac.compare_digest(_digest(envelope), operation.consent_digest)
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def _eligibility(context: _Context, operation: VirtualminMailOperation) -> str:
    from apps.users.models import User  # noqa: PLC0415  # ADR-0007: current canonical authorization.

    account, service, name = context.account, context.service, context.name
    actor = User.objects.filter(pk=operation.requested_by_id, is_active=True).first()
    if operation.requested_customer_id != service.customer_id or not _owner(service.customer_id, actor):
        return "mail_execution_forbidden"
    generation = mail_generation(account)
    if not generation or generation != operation.target_generation:
        return "mail_generation_changed"
    if (
        name is None
        or name.retired_at is not None
        or name.target_server_id != account.server_id
        or account.server_id != context.server.pk
        or context.server.status != "active"
        or account.status not in {"active", "suspended"}
        or service.status not in {"active", "suspended"}
    ):
        return "mail_account_unavailable"
    if operation.intent == "enable" and (
        account.status != "active" or service.status != "active" or blocking_domain_status(account) is not None
    ):
        return "mail_hosting_held"
    return _operation_conflict(context, operation)


def _operation_conflict(context: _Context, operation: VirtualminMailOperation) -> str:
    account, name = context.account, context.name
    if (
        account.restore_hold
        or (name is not None and name.previous_ttl is not None)
        or account_has_active_operation(account, ignore_mail_operation_id=operation.pk)
        or VirtualminProvisioningJob.objects.filter(account_id=account.pk, status="running").exists()
    ):
        return "mail_operation_active"
    expected_mode = {"enable": "external", "disable": "hosted"}.get(operation.intent)
    if context.configuration.mode != expected_mode:
        return "mail_mode_conflict"
    return "" if _consent(operation, context) else "mail_execution_invalid_consent"


def _state(operation: VirtualminMailOperation) -> dict[str, str]:
    return {
        "status": operation.status if operation.status in VirtualminMailOperation.Status.values else "unrecognized",
        "checkpoint": operation.checkpoint
        if operation.checkpoint in {"", "claimed", "preflight", "native_inflight"}
        else "unrecognized",
        "error_code": operation.error_code
        if operation.error_code == "" or operation.error_code in _STATE_CODES
        else "unrecognized",
    }


def _cas(operation: VirtualminMailOperation, *, live: bool = False, **changes: Any) -> None:
    before = _state(operation)
    expected = VirtualminMailOperation.objects.filter(
        pk=operation.pk,
        status=operation.status,
        checkpoint=operation.checkpoint,
        lease_token=operation.lease_token,
        target_generation=operation.target_generation,
    )
    if live:
        expected = expected.filter(lease_expires_at__gt=timezone.now())
    changes["updated_at"] = timezone.now()
    # fsm-bypass: attempt status/checkpoints are operational CharFields; protected mail mode is untouched.
    if expected.update(**changes) != 1:
        raise _ExecutionRefusalError("mail_execution_lease_lost")
    for key, value in changes.items():
        setattr(operation, key, value)
    after = _state(operation)
    if before != after:
        from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: explicit CAS mutation audit.

        AuditService.log_simple_event(
            "configuration_changed",
            content_object=operation,
            actor_type="system",
            description="Hosted mail operation progressed",
            old_values=before,
            new_values=after,
            metadata={"component": "hosting_mail"},
        )


def _park(operation: VirtualminMailOperation, code: str) -> None:
    _cas(operation, status="needs_review", error_code=code, lease_token=None, lease_expires_at=None)


def _lease(operation: VirtualminMailOperation) -> MailExecutionLease:
    if operation.lease_token is None or operation.lease_expires_at is None:
        raise _ExecutionRefusalError("mail_execution_lease_lost")
    return MailExecutionLease(
        operation.pk,
        operation.lease_token,
        operation.target_generation,
        operation.checkpoint,
        operation.lease_expires_at,
    )


def claim_mail_operation(identifier: UUID | str) -> Result[MailExecutionLease, str]:
    """Grant only a pristine due intent; interrupted running effects require operator review."""
    try:
        with _locked(_identifier(identifier)) as (context, operation):
            state_refusal = _claim_state(operation)
            if state_refusal:
                return Err(state_refusal)
            refused = _eligibility(context, operation)
            if refused:
                return Err(refused)
            _cas(
                operation,
                status="running",
                checkpoint="claimed",
                lease_token=uuid4(),
                lease_expires_at=timezone.now() + MAIL_EXECUTION_LEASE,
            )
            return Ok(_lease(operation))
    except _ExecutionRefusalError as error:
        return Err(str(error))


def defer_mail_preparation(
    identifier: UUID | str, *, generation: str, reason: str
) -> Result[Literal["queued", "cancelled"], str]:
    """Consume a fixed read-only refusal; never cancel work that acquired execution ownership.

    Workers call this only after prerequisites are observed unavailable. Age alone
    does not expire confirmed consent or prevent a now-ready pristine claim.
    """
    try:
        if not isinstance(reason, str) or reason not in _PREPARATION_REASONS:
            raise _ExecutionRefusalError("mail_invalid_error_code")
        with _locked(_identifier(identifier)) as (context, operation):
            if not isinstance(generation, str) or generation != operation.target_generation:
                raise _ExecutionRefusalError("mail_generation_changed")
            if operation.intent != "enable":
                raise _ExecutionRefusalError("mail_preparation_not_enable")
            if operation.status == "cancelled" and operation.error_code == _PREPARATION_EXPIRED:
                return Ok("cancelled")
            state_refusal = _claim_state(operation)
            if state_refusal not in {"", "mail_execution_not_due"}:
                # Return inside the transaction so uncertainty parking is committed.
                return Err(state_refusal)
            now = timezone.now()
            deadline = operation.created_at + MAIL_PREPARATION_LIFETIME
            if now >= deadline:
                # System cleanup may release untouched expired intent even after
                # owner/target changes. It never applies that obsolete intent.
                _cas(operation, status="cancelled", error_code=_PREPARATION_EXPIRED, resume_after=None)
                return Ok("cancelled")
            refused = _eligibility(context, operation)
            if refused:
                raise _ExecutionRefusalError(refused)
            if operation.resume_after is None or not now < operation.resume_after <= deadline:
                _cas(operation, resume_after=min(now + MAIL_PREPARATION_RETRY, deadline))
            return Ok("queued")
    except _ExecutionRefusalError as error:
        return Err(str(error))


def _claim_state(operation: VirtualminMailOperation) -> str:
    if operation.status == "running":
        return _running_claim_state(operation)
    unknown_queued = operation.status == "queued" and (
        operation.lease_token
        or operation.lease_expires_at
        or operation.checkpoint
        or operation.result != {}
        or operation.error_code
    )
    if unknown_queued:
        _park(operation, "mail_execution_state_uncertain")
        return "mail_execution_requires_review"
    if operation.status == "needs_review":
        return "mail_execution_requires_review"
    if operation.status != "queued":
        return "mail_execution_not_queued"
    if operation.resume_after is not None and operation.resume_after > timezone.now():
        return "mail_execution_not_due"
    return ""


def _running_claim_state(operation: VirtualminMailOperation) -> str:
    try:
        _result_evidence(operation)
    except _ExecutionRefusalError:
        _park(operation, "mail_execution_state_uncertain")
        return "mail_execution_requires_review"
    if operation.lease_token and operation.lease_expires_at and operation.lease_expires_at > timezone.now():
        return "mail_execution_busy"
    _park(operation, "mail_execution_ownership_expired")
    return "mail_execution_requires_review"


def _owned(context: _Context, operation: VirtualminMailOperation, lease: MailExecutionLease) -> str:
    if (
        operation.status != "running"
        or operation.lease_token != lease.token
        or operation.target_generation != lease.generation
    ):
        return "mail_execution_lease_lost"
    if operation.lease_expires_at is None or operation.lease_expires_at <= timezone.now():
        _park(operation, "mail_execution_ownership_expired")
        return "mail_execution_requires_review"
    try:
        _result_evidence(operation)
    except _ExecutionRefusalError:
        _park(operation, "mail_execution_state_uncertain")
        return "mail_execution_requires_review"
    refused = _eligibility(context, operation)
    if refused:
        _park(operation, refused)
        return "mail_execution_requires_review"
    return ""


def renew_mail_operation(lease: MailExecutionLease) -> Result[MailExecutionLease, str]:
    """Renew only the matching live worker after rechecking current ownership and generation."""
    try:
        with _locked(lease.operation_id) as (context, operation):
            refused = _owned(context, operation, lease)
            if refused:
                return Err(refused)
            _cas(operation, live=True, lease_expires_at=timezone.now() + MAIL_EXECUTION_LEASE)
            return Ok(_lease(operation))
    except _ExecutionRefusalError as error:
        return Err(str(error))


def _evidence(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or len(value) > _MAX_EVIDENCE_ITEMS:
        raise _ExecutionRefusalError("mail_invalid_checkpoint")
    output: dict[str, object] = {}
    for key, item in value.items():
        if not _evidence_item(key, item):
            raise _ExecutionRefusalError("mail_invalid_checkpoint")
        output[key] = item
    if len(json.dumps(output).encode()) > _MAX_EVIDENCE_BYTES:
        raise _ExecutionRefusalError("mail_invalid_checkpoint")
    return output


def _evidence_item(key: str, value: object) -> bool:
    if key == "domain_id":
        return isinstance(value, str) and re.fullmatch(r"[0-9]{1,32}", value) is not None
    if key in {"inventory_sha256", "plan_sha256"}:
        return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
    return (
        key in {"mailbox_count", "alias_count"}
        and type(value) is int
        and 0 <= value <= (1000 if key == "mailbox_count" else 2000)
    )


def _result_evidence(operation: VirtualminMailOperation) -> dict[str, object]:
    if operation.checkpoint == "claimed" and operation.result == {}:
        return {}
    result = operation.result
    if (
        operation.checkpoint not in {"preflight", "native_inflight"}
        or not isinstance(result, dict)
        or set(result) != {"version", "generation", "checkpoint", "evidence"}
        or type(result.get("version")) is not int
        or result["version"] != 1
        or result.get("generation") != operation.target_generation
        or result.get("checkpoint") != operation.checkpoint
    ):
        raise _ExecutionRefusalError("mail_execution_state_uncertain")
    return _evidence(result["evidence"])


def checkpoint_mail_operation(
    lease: MailExecutionLease, *, checkpoint: str, evidence: Mapping[str, object]
) -> Result[MailExecutionLease, str]:
    """CAS pre-native progress only. native_inflight is intent, never a success receipt."""
    try:
        if _PHASES.get(lease.checkpoint) != checkpoint:
            raise _ExecutionRefusalError("mail_invalid_checkpoint")
        bounded = _evidence(evidence)
        with _locked(lease.operation_id) as (context, operation):
            refused = _owned(context, operation, lease)
            if refused:
                return Err(refused)
            if operation.checkpoint != lease.checkpoint:
                return Err("mail_execution_lease_lost")
            retained = _result_evidence(operation)
            if any(key in retained and retained[key] != value for key, value in bounded.items()):
                return Err("mail_invalid_checkpoint")
            _cas(
                operation,
                live=True,
                checkpoint=checkpoint,
                result={
                    "version": 1,
                    "generation": operation.target_generation,
                    "checkpoint": checkpoint,
                    "evidence": {**retained, **bounded},
                },
            )
            return Ok(_lease(operation))
    except _ExecutionRefusalError as error:
        return Err(str(error))


def park_mail_operation(lease: MailExecutionLease, *, code: str) -> Result[None, str]:
    """A live owner can retain uncertainty; raw backend errors and credentials are never stored."""
    if code not in _PARK_CODES:
        return Err("mail_invalid_error_code")
    try:
        with _locked(lease.operation_id) as (context, operation):
            refused = _owned(context, operation, lease)
            if refused:
                return Err(refused)
            _park(operation, code)
            return Ok(None)
    except _ExecutionRefusalError as error:
        return Err(str(error))
