"""Offline owner consent for hosted mail; native and DNS workers consume queued intent later."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result

from .account_hostname_models import AccountHostname
from .account_hostname_service import lock_for_publication
from .domain_veto import blocking_domain_status
from .service_models import Service
from .virtualmin_mail_models import (
    MAIL_OPEN_OPERATION_STATUSES,
    VirtualminMailConfiguration,
    VirtualminMailOperation,
    mail_generation,
)
from .virtualmin_migration_models import account_has_active_operation
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from apps.users.models import User

type MailIntent = Literal["enable", "disable"]

PROPOSAL_LIFETIME = timedelta(minutes=20)
MAX_PLAN_BYTES = 65536
MAX_PROPOSAL_BYTES = MAX_PLAN_BYTES + 4096
MAX_PLAN_DEPTH = 10
MAX_PLAN_NODES = 2048
MAX_PLAN_STRING = 8192
MAX_PLAN_KEY = 256
MAX_PLAN_INTEGER = 2**63 - 1
_DIGEST = re.compile(r"[a-f0-9]{64}")


class MailEnrollmentProposal(TypedDict):
    version: int
    proposal_id: str
    intent: MailIntent
    target_generation: str
    consent_digest: str
    expires_at: str
    plan: dict[str, Any]


class _EnrollmentRefusalError(ValueError):
    """A bounded service refusal, safe to map to a fixed public explanation."""


@dataclass(frozen=True)
class _Context:
    account: VirtualminAccount
    service: Service
    name: AccountHostname
    generation: str
    actor_id: int


def _owner(customer_id: int, actor: User | None) -> bool:
    from apps.users.models import CustomerMembership  # noqa: PLC0415  # ADR-0007: current authorization at the seam.

    return bool(
        actor is not None
        and actor.pk is not None
        and CustomerMembership.objects.filter(
            customer_id=customer_id,
            customer__deleted_at__isnull=True,
            user_id=actor.pk,
            user__is_active=True,
            is_active=True,
            role="owner",
        ).exists()
    )


def _locked(account: VirtualminAccount, actor: User | None) -> _Context:
    """Match cutover's Account→Server→Name→Service order; no public caller bypasses ownership."""
    current = VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).filter(pk=account.pk).first()
    if current is None or actor is None or actor.pk is None or not _owner(current.service.customer_id, actor):
        raise _EnrollmentRefusalError("mail_forbidden")
    server = VirtualminServer.objects.select_for_update(of=("self",), no_key=True).get(pk=current.server_id)
    identifier = (
        AccountHostname.objects.filter(account_id=current.pk, retired_at__isnull=True)
        .values_list("pk", flat=True)
        .first()
    )
    name = lock_for_publication(identifier) if identifier is not None else None
    if (
        name is None
        or name.account_id != current.pk
        or name.target_server_id != server.pk
        or name.retired_at is not None
    ):
        raise _EnrollmentRefusalError("mail_account_unavailable")
    current.refresh_from_db()
    service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=current.service_id)
    if not _owner(service.customer_id, actor):
        raise _EnrollmentRefusalError("mail_forbidden")
    generation = mail_generation(current)
    if not generation or current.server_id != server.pk or server.status != "active":
        raise _EnrollmentRefusalError("mail_account_unavailable")
    return _Context(current, service, name, generation, actor.pk)


def _admission(context: _Context, intent: str) -> None:
    account, service, name = context.account, context.service, context.name
    if intent not in {"enable", "disable"}:
        raise _EnrollmentRefusalError("mail_invalid_intent")
    if account.status not in {"active", "suspended"} or service.status not in {"active", "suspended"}:
        raise _EnrollmentRefusalError("mail_account_unavailable")
    if intent == "enable" and (
        account.status != "active" or service.status != "active" or blocking_domain_status(account) is not None
    ):
        raise _EnrollmentRefusalError("mail_hosting_held")
    if (
        account.restore_hold
        or name.previous_ttl is not None
        or account_has_active_operation(account)
        or VirtualminProvisioningJob.objects.filter(account=account, status="running").exists()
        or VirtualminMailOperation.objects.filter(
            configuration__account=account, status__in=MAIL_OPEN_OPERATION_STATUSES
        ).exists()
    ):
        raise _EnrollmentRefusalError("mail_operation_active")


def _valid_scalar(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return abs(value) <= MAX_PLAN_INTEGER
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, str) and len(value) <= MAX_PLAN_STRING


def _json_children(value: Any) -> Iterable[Any]:
    if isinstance(value, list | dict) and len(value) > MAX_PLAN_NODES:
        raise _EnrollmentRefusalError("mail_invalid_plan")
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if any(not isinstance(key, str) or len(key) > MAX_PLAN_KEY for key in value):
            raise _EnrollmentRefusalError("mail_invalid_plan")
        return value.values()
    if _valid_scalar(value):
        return ()
    raise _EnrollmentRefusalError("mail_invalid_plan")


def _json_copy(value: Any, *, maximum: int, wrapped: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _EnrollmentRefusalError("mail_invalid_plan")
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > MAX_PLAN_DEPTH + int(wrapped) or count > MAX_PLAN_NODES + (32 if wrapped else 0):
            raise _EnrollmentRefusalError("mail_invalid_plan")
        stack.extend((child, depth + 1) for child in _json_children(item))
    try:
        wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(wire.encode("utf-8")) > maximum:
            raise _EnrollmentRefusalError("mail_invalid_plan")
    except (ValueError, UnicodeError) as error:
        raise _EnrollmentRefusalError("mail_invalid_plan") from error
    copied: dict[str, Any] = json.loads(wire)
    return copied


def _digest(proposal: dict[str, Any]) -> str:
    wire = json.dumps(proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(wire.encode("utf-8")).hexdigest()


def _mode(configuration: VirtualminMailConfiguration | None, intent: str) -> None:
    mode = configuration.mode if configuration is not None else "external"
    if (intent == "enable" and mode != "external") or (intent == "disable" and mode != "hosted"):
        raise _EnrollmentRefusalError("mail_mode_conflict")


def prepare_mail_enrollment(
    account: VirtualminAccount, *, actor: User | None, intent: MailIntent, plan: dict[str, Any]
) -> Result[MailEnrollmentProposal, str]:
    """Stage a bounded server-built plan for owner review. HTTP must never supply an invented DNS plan.

    The later DNS/native planning seam supplies actual observations; this method only binds its exact
    JSON to current ownership. A proposal and queued operation make no readiness or completion claim.
    """
    try:
        with transaction.atomic():
            context = _locked(account, actor)
            _admission(context, intent)
            confirmed = _json_copy(plan, maximum=MAX_PLAN_BYTES)
            configuration = (
                VirtualminMailConfiguration.objects.select_for_update().filter(account=context.account).first()
            )
            _mode(configuration, intent)
            if configuration is None:
                configuration = VirtualminMailConfiguration.objects.create(account=context.account)
            now = timezone.now()
            proposal: dict[str, Any] = {
                "version": 1,
                "proposal_id": str(uuid4()),
                "account_id": str(context.account.pk),
                "service_id": str(context.service.pk),
                "customer_id": str(context.service.customer_id),
                "actor_id": str(context.actor_id),
                "target_generation": context.generation,
                "intent": intent,
                "created_at": now.isoformat(),
                "expires_at": (now + PROPOSAL_LIFETIME).isoformat(),
                "plan": confirmed,
            }
            consent_digest = _digest(proposal)
            configuration.proposal = {**proposal, "consent_digest": consent_digest}
            configuration.save(update_fields=["proposal", "updated_at"])
            return Ok(
                MailEnrollmentProposal(
                    version=1,
                    proposal_id=proposal["proposal_id"],
                    intent=intent,
                    target_generation=context.generation,
                    consent_digest=consent_digest,
                    expires_at=proposal["expires_at"],
                    plan=_json_copy(confirmed, maximum=MAX_PLAN_BYTES),
                )
            )
    except _EnrollmentRefusalError as error:
        return Err(str(error))
    except (ValidationError, IntegrityError):
        return Err("mail_request_conflict")


def _proposal(stored: Any, context: _Context, intent: str, identifier: UUID, consent_digest: str) -> dict[str, Any]:
    envelope = _json_copy(stored, maximum=MAX_PROPOSAL_BYTES, wrapped=True)
    saved_digest = envelope.pop("consent_digest", "")
    expected = {
        "version": 1,
        "proposal_id": str(identifier),
        "account_id": str(context.account.pk),
        "service_id": str(context.service.pk),
        "customer_id": str(context.service.customer_id),
        "actor_id": str(context.actor_id),
        "target_generation": context.generation,
        "intent": intent,
    }
    if any(envelope.get(key) != value for key, value in expected.items()):
        raise _EnrollmentRefusalError("mail_stale_proposal")
    if (
        not isinstance(saved_digest, str)
        or not hmac.compare_digest(saved_digest, consent_digest)
        or not hmac.compare_digest(_digest(envelope), consent_digest)
    ):
        raise _EnrollmentRefusalError("mail_consent_mismatch")
    created_raw, expires_raw = envelope.get("created_at"), envelope.get("expires_at")
    created = parse_datetime(created_raw) if isinstance(created_raw, str) else None
    expires = parse_datetime(expires_raw) if isinstance(expires_raw, str) else None
    now = timezone.now()
    if (
        created is None
        or expires is None
        or timezone.is_naive(created)
        or timezone.is_naive(expires)
        or not created <= now < expires
        or expires - created != PROPOSAL_LIFETIME
    ):
        raise _EnrollmentRefusalError("mail_stale_proposal")
    return envelope


def request_mail_enrollment(  # noqa: PLR0913  # Explicit actor scope and immutable consent fields.
    account: VirtualminAccount,
    *,
    actor: User | None,
    intent: MailIntent,
    proposal_id: UUID | str,
    consent_digest: str,
    submission_id: UUID | str,
) -> Result[VirtualminMailOperation, str]:
    """Persist exactly one authenticated owner request; uncertain work never becomes another attempt."""
    try:
        proposal_uuid, submission_uuid = UUID(str(proposal_id)), UUID(str(submission_id))
        if not isinstance(consent_digest, str) or _DIGEST.fullmatch(consent_digest) is None:
            raise _EnrollmentRefusalError("mail_consent_mismatch")
        with transaction.atomic():
            context = _locked(account, actor)
            configuration = (
                VirtualminMailConfiguration.objects.select_for_update().filter(account=context.account).first()
            )
            existing = VirtualminMailOperation.objects.filter(
                requested_customer_id=context.service.customer_id,
                requested_by_id=context.actor_id,
                submission_id=submission_uuid,
            ).first()
            if existing is not None:
                if (
                    configuration is None
                    or existing.configuration_id != configuration.pk
                    or existing.intent != intent
                    or existing.target_generation != context.generation
                    or existing.consent_digest != consent_digest
                    or existing.confirmed_plan.get("proposal_id") != str(proposal_uuid)
                ):
                    raise _EnrollmentRefusalError("mail_submission_conflict")
                # Replaying this exact receipt does not dispatch, resume or create any work.
                return Ok(existing)
            _admission(context, intent)
            _mode(configuration, intent)
            if configuration is None:
                raise _EnrollmentRefusalError("mail_stale_proposal")
            confirmed = _proposal(configuration.proposal, context, intent, proposal_uuid, consent_digest)
            operation = VirtualminMailOperation.objects.create(
                configuration=configuration,
                requested_customer_id=context.service.customer_id,
                requested_by_id=context.actor_id,
                submission_id=submission_uuid,
                intent=intent,
                target_generation=context.generation,
                consent_digest=consent_digest,
                confirmed_plan=confirmed,
            )
            return Ok(operation)
    except _EnrollmentRefusalError as error:
        return Err(str(error))
    except (ValueError, TypeError):
        return Err("mail_invalid_request")
    except (ValidationError, IntegrityError):
        return Err("mail_submission_conflict")
