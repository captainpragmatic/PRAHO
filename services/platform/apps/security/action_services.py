"""Audited staff intent is durable before tasks can dispatch it to any host."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4, uuid5

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .action_repos import lock_sources, refresh_request
from .action_transport import digest, payload_digest
from .models import (
    SecurityActionRequest,
    SecurityActionTarget,
    SecurityAllowlist,
    SecurityDecision,
    SecurityDecisionSuppression,
    SecurityManagedDecision,
    SecurityReplication,
    SecuritySource,
    SecuritySyncState,
)
from .permissions import can_manage_security, can_revoke_security
from .transport import capture_connection

if TYPE_CHECKING:
    from apps.users.models import User

MAX_TARGETS = 100
MAX_CIDRS = 256
FRESH_SECONDS = 180
MAX_REASON_LENGTH = 2000
NODE_BAN_SECONDS = 4 * 3600
PORTAL_BAN_SECONDS = 5 * 60
REVOKE_LOCK_ATTEMPTS = 3


def authorize(actor: User, *, revoke: bool = False) -> None:
    if not (can_revoke_security(actor) if revoke else can_manage_security(actor)):
        raise PermissionDenied(_("Your active staff role cannot issue this security action."))


def require_facility() -> None:
    if not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False):
        raise ValidationError(_("Host security mutations are disabled; existing uncertain actions remain readable."))


def reason_text(reason: str) -> str:
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON_LENGTH:
        raise ValidationError(_("Explain the security action using up to 2000 characters."))
    return reason.strip()


def canonical_address(scope: str, value: str) -> str:
    try:
        if scope == "ip":
            address = ipaddress.ip_address(value)
            if getattr(address, "scope_id", None):
                raise ValueError("Scoped address")
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            return str(address)
        if scope == "range":
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0 or (
                isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped is not None
            ):
                raise ValueError("Unsupported range")
            return str(network)
    except ValueError as error:
        raise ValidationError(_("Use a canonical public IP address or a specific canonical CIDR.")) from error
    raise ValidationError(_("Only IP and CIDR security scopes are supported."))


def overlaps(first: str, second: str) -> bool:
    left, right = ipaddress.ip_network(first, strict=False), ipaddress.ip_network(second, strict=False)
    return left.version == right.version and left.overlaps(right)


def require_create(source: SecuritySource, payload: dict[str, object] | None = None) -> None:
    state = SecuritySyncState.objects.get(source=source)
    now = timezone.now()
    health = state.health
    if (
        source.retired_at is not None
        or state.last_published_generation != source.generation
        or state.last_decision_sync_at is None
        or not 0 <= (now - state.last_decision_sync_at).total_seconds() <= FRESH_SECONDS
        or state.outcome in {"never", "identity_changed", "unavailable", "superseded", "reconfigured"}
        or health.get("simulation") is not False
        or any(health.get(name, {}).get("active") is not True for name in ("engine", "bouncer"))
        or any(health.get(name, {}).get("qualified") is not True for name in ("configuration", "firewall", "clock"))
    ):
        raise ValidationError(_("New bans require fresh canonical enforcing protection and qualified clocks."))
    if payload:
        desired = SecurityAllowlist.objects.filter(source=source).first()
        if desired and any(overlaps(cast("str", payload["value"]), cidr) for cidr in desired.cidrs):
            raise ValidationError(_("The requested ban overlaps a staff protected network."))


def audit(action: SecurityActionRequest) -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415 -- business audit boundary

    AuditService.log_simple_event(
        "configuration_changed",
        user=action.actor,
        actor_type="user" if action.actor_id else "system",
        content_object=action,
        description="Issued audited CrowdSec host action",
        metadata={"source_app": "security", "security_action": action.kind},
        new_values={
            "payload_digest": action.payload_digest,
            "reason": action.reason,
            "targets": list(action.targets.values_list("source_id", flat=True)),
        },
    )


def request_record(  # noqa: PLR0913 -- canonical intent, actor and original remain separate audit bindings.
    kind: str,
    key: UUID,
    payload: dict[str, object],
    actor: User | None,
    reason: str,
    decision: SecurityDecision | None = None,
) -> tuple[SecurityActionRequest, bool]:
    canonical = {"kind": kind, "payload": payload, "actor": str(actor.pk) if actor else None, "reason": reason}
    checksum = digest(canonical)
    try:
        with transaction.atomic():
            request, created = SecurityActionRequest.objects.get_or_create(
                idempotency_key=key,
                defaults={
                    "kind": kind,
                    "payload": canonical,
                    "payload_digest": checksum,
                    "actor": actor,
                    "reason": reason,
                    "decision": decision,
                },
            )
    except IntegrityError:
        request, created = SecurityActionRequest.objects.get(idempotency_key=key), False
    if request.payload_digest != checksum:
        raise ValidationError(_("This idempotency identity already belongs to a different action payload."))
    return request, created


def target_record(
    action: SecurityActionRequest,
    source: SecuritySource,
    operation: str,
    payload: dict[str, object],
    *,
    expires_at: datetime | None = None,
) -> SecurityActionTarget:
    connection = capture_connection(source)
    return SecurityActionTarget.objects.create(
        action=action,
        source=source,
        operation=operation,
        payload=payload,
        payload_digest=payload_digest(operation, payload),
        source_generation=source.generation,
        connection_identity=connection.identity,
        provenance_id=cast("str | None", payload.get("provenance_id")),
        revision=cast("int", payload["revision"]),
        expires_at=expires_at,
    )


@transaction.atomic
def issue_ban(  # noqa: PLR0913 -- explicit audited web API fields remain independently validated.
    *,
    actor: User,
    reason: str,
    idempotency_key: UUID,
    source_ids: list[UUID],
    scope: str,
    value: str,
    duration_seconds: int,
) -> SecurityActionRequest:
    authorize(actor)
    require_facility()
    reason = reason_text(reason)
    value = canonical_address(scope, value)
    if (
        type(duration_seconds) is not int
        or not 1 <= duration_seconds <= NODE_BAN_SECONDS
        or not 1 <= len(set(source_ids)) <= MAX_TARGETS
    ):
        raise ValidationError(_("Choose a finite ban duration and a bounded enrolled target list."))
    sources = lock_sources(source_ids)
    action, created = request_record(
        "ban",
        idempotency_key,
        {
            "sources": sorted(str(key) for key in sources),
            "scope": scope,
            "value": value,
            "duration_seconds": duration_seconds,
        },
        actor,
        reason,
    )
    if not created:
        return action
    for source in sources.values():
        payload = {
            "provenance_id": str(uuid4()),
            "revision": 1,
            "kind": "manual",
            "scope": scope,
            "value": value,
            "source": None,
        }
        require_create(source, payload)
        expires = action.created_at + timedelta(
            seconds=min(duration_seconds, PORTAL_BAN_SECONDS if source.kind == "portal" else NODE_BAN_SECONDS)
        )
        payload["expires_at"] = expires.astimezone(UTC).isoformat()
        target_record(action, source, "ban_put", payload, expires_at=expires)
    audit(action)
    return action


def decision_fingerprint(decision: SecurityDecision) -> dict[str, object]:
    return {
        "id": decision.remote_id,
        "created_at": decision.source_created_at.astimezone(UTC).isoformat(),
        "expires_at": decision.expires_at.astimezone(UTC).isoformat(),
        "scenario": decision.scenario,
        "type": decision.type,
        "scope": decision.scope,
        "value": decision.value,
        "origin": decision.origin,
        "simulated": decision.simulated,
    }


def _lock_revoke_sources(decision: SecurityDecision) -> dict[UUID, SecuritySource]:
    """Restart the entire ordered lock set if an admission won the root Source first."""
    for _attempt in range(REVOKE_LOCK_ATTEMPTS):
        source_ids = [
            decision.source_id,
            *SecurityReplication.objects.filter(decision=decision).values_list("target_source_id", flat=True),
        ]
        with transaction.atomic():
            sources = lock_sources(source_ids)
            current = set(
                SecurityReplication.objects.filter(decision=decision).values_list("target_source_id", flat=True)
            )
            if current.issubset(sources):
                return sources
            # Rolling back this savepoint releases its VM/Source locks before retrying,
            # so a newly discovered target never changes the global lock order.
            transaction.set_rollback(True)
    raise ValidationError(_("Replica admission changed during revocation; reload and retry this request."))


@transaction.atomic
def issue_revoke(*, actor: User, reason: str, idempotency_key: UUID, decision_id: UUID) -> SecurityActionRequest:
    authorize(actor, revoke=True)
    require_facility()
    reason = reason_text(reason)
    decision = SecurityDecision.objects.get(pk=decision_id)
    requested_id = decision.pk
    clicked_mapping = SecurityManagedDecision.objects.filter(
        source_id=decision.source_id, remote_id=decision.remote_id
    ).first()
    if clicked_mapping:
        replica_origin = SecurityReplication.objects.filter(provenance_id=clicked_mapping.provenance_id).first()
        if replica_origin:
            original = replica_origin.decision
            if original is None:
                raise ValidationError(
                    _("The original decision summary expired; reconcile this historical managed record.")
                )
            decision = original
    sources = _lock_revoke_sources(decision)
    action, created = request_record(
        "revoke",
        idempotency_key,
        {"decision": str(decision.pk), "requested_decision": str(requested_id)},
        actor,
        reason,
        decision,
    )
    if not created:
        return action
    SecurityDecisionSuppression.objects.get_or_create(
        source_id=decision.source_id, remote_id=decision.remote_id, defaults={"decision": decision, "action": action}
    )
    mapping = SecurityManagedDecision.objects.filter(source_id=decision.source_id, remote_id=decision.remote_id).first()
    provenance = (
        mapping.provenance_id if mapping else uuid5(decision.source.installation_id, f"native:{decision.remote_id}")
    )
    previous = (
        SecurityActionTarget.objects.filter(source_id=decision.source_id, provenance_id=provenance)
        .order_by("-revision")
        .first()
    )
    payload = {
        "provenance_id": str(provenance),
        "revision": (previous.revision + 1) if previous else 1,
        "decision": None if mapping else decision_fingerprint(decision),
    }
    target_record(
        action,
        sources[decision.source_id],
        "revoke",
        payload,
        expires_at=mapping.issuing_target.expires_at if mapping else decision.expires_at,
    )
    for replica in SecurityReplication.objects.select_for_update().filter(decision=decision).order_by("pk"):
        replica.revision += 1
        created_target = replica.create_target
        if created_target is not None and created_target.dispatched_at is None:
            SecurityActionTarget.objects.filter(pk=created_target.pk, dispatched_at__isnull=True).update(
                state="superseded",
                claim_token=None,
                claim_phase="",
                lease_until=None,
                evidence={"local": "suppressed_before_dispatch"},
            )
            refresh_request(created_target.action_id)
        payload = {"provenance_id": str(replica.provenance_id), "revision": replica.revision, "decision": None}
        replica.revoke_target = target_record(
            action, sources[replica.target_source_id], "revoke", payload, expires_at=replica.expires_at
        )
        replica.save(update_fields=["revision", "revoke_target", "updated_at"])
    refresh_request(action.pk)
    audit(action)
    return action


@transaction.atomic
def replace_allowlist(  # noqa: PLR0913 -- reviewed revision is an independent concurrency fence.
    *,
    actor: User,
    reason: str,
    idempotency_key: UUID,
    source_id: UUID,
    cidrs: list[str],
    expected_revision: int | None = None,
) -> SecurityActionRequest:
    authorize(actor)
    require_facility()
    reason = reason_text(reason)
    if not isinstance(cidrs, list) or len(cidrs) > MAX_CIDRS:
        raise ValidationError(_("The complete staff allowlist is too large."))
    canonical = sorted({canonical_address("range", value) for value in cidrs})
    source = lock_sources([source_id])[source_id]
    if source.retired_at is not None:
        raise ValidationError(_("Retired source history cannot receive a new allowlist action."))
    if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
        raise ValidationError(_("The reviewed staff allowlist revision is invalid."))
    action, created = request_record(
        "allowlist",
        idempotency_key,
        {"source": str(source_id), "cidrs": canonical, "expected_revision": expected_revision},
        actor,
        reason,
    )
    if not created:
        return action
    current = SecurityAllowlist.objects.filter(source=source).first()
    if expected_revision is not None and expected_revision != (current.revision if current else 0):
        raise ValidationError(
            _("The staff allowlist changed since this form was reviewed; reload it before replacing it.")
        )
    allowlist = current or SecurityAllowlist.objects.create(source=source)
    allowlist.revision += 1
    allowlist.cidrs = canonical
    allowlist.save()
    target_record(action, source, "allowlist_replace", {"revision": allowlist.revision, "cidrs": canonical})
    audit(action)
    return action
