"""Every action lock acquires all VM roots, then sources, then target rows; RPC is outside."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .locks import lock_node
from .models import (
    SecurityActionRequest,
    SecurityActionTarget,
    SecurityAllowlist,
    SecurityManagedDecision,
    SecurityReplication,
    SecuritySource,
)
from .transport import SourceConnection, capture_connection

LEASE_SECONDS = 120
TERMINAL = frozenset({"succeeded", "rejected", "superseded", "expired"})


def lock_sources(source_ids: list[UUID]) -> dict[UUID, SecuritySource]:
    anchors = list(SecuritySource.objects.filter(pk__in=source_ids).values("pk", "kind", "virtualmin_server_id"))
    nodes = {
        key: lock_node(key)
        for key in sorted(
            {
                row["virtualmin_server_id"]
                for row in anchors
                if row["kind"] == "node" and row["virtualmin_server_id"] is not None
            }
        )
    }
    sources = {
        source.pk: source
        for source in SecuritySource.objects.select_for_update().filter(pk__in=source_ids).order_by("pk")
    }
    if len(sources) != len(set(source_ids)):
        raise ValidationError(_("An enrolled physical security source is unavailable."))
    for row in anchors:
        source = sources[row["pk"]]
        if (source.kind, source.virtualmin_server_id) != (row["kind"], row["virtualmin_server_id"]):
            raise ValidationError(_("The physical node binding changed during action acquisition."))
        if source.kind == "node" and source.virtualmin_server_id is not None:
            server = nodes.get(source.virtualmin_server_id)
            if server is None:
                raise ValidationError(_("The bound security node is unavailable."))
            source.virtualmin_server = server
    return sources


def _locked(target_id: UUID) -> tuple[SecurityActionTarget, SecuritySource]:
    anchor = SecurityActionTarget.objects.values("source_id", "action__decision__source_id").get(pk=target_id)
    ids = [anchor["source_id"]]
    if anchor["action__decision__source_id"] is not None:
        ids.append(anchor["action__decision__source_id"])
    sources = lock_sources(ids)
    target = SecurityActionTarget.objects.select_for_update().get(pk=target_id)
    return target, sources[target.source_id]


@transaction.atomic
def refresh_request(action_id: UUID) -> None:
    action = SecurityActionRequest.objects.select_for_update().get(pk=action_id)
    states = set(action.targets.values_list("state", flat=True))
    pending_create = (
        action.kind == "revoke"
        and action.decision_id is not None
        and SecurityReplication.objects.filter(
            decision_id=action.decision_id,
            expires_at__gt=timezone.now(),
            create_target__state__in=("issued", "dispatching", "unknown"),
        ).exists()
    )
    if "unknown" in states or "dispatching" in states or pending_create:
        status = "unknown"
    elif "issued" in states or not states:
        status = "pending"
    elif states == {"succeeded"}:
        status = "complete"
    elif len(states) == 1 and states <= {"rejected", "superseded", "expired"}:
        status = next(iter(states))
    else:
        status = "partial"
    SecurityActionRequest.objects.filter(pk=action_id).update(status=status, updated_at=timezone.now())


def _refresh_related(target: SecurityActionTarget) -> None:
    refresh_request(target.action_id)
    suppressed = (
        SecurityActionRequest.objects.filter(kind="revoke", decision__replications__create_target=target)
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    for action_id in suppressed:
        refresh_request(action_id)


@dataclass(frozen=True)
class ActionClaim:
    target_id: UUID
    token: UUID
    generation: int
    identity: str
    connection: SourceConnection
    reconcile: bool


def _clear(target: SecurityActionTarget, state: str, evidence: dict[str, object]) -> None:
    target.state, target.evidence = state, evidence
    target.claim_token, target.lease_until = None, None
    target.claim_phase = ""
    target.next_run = timezone.now() + timedelta(minutes=1)
    target.save()
    _refresh_related(target)


@transaction.atomic
def claim_target(target_id: UUID) -> ActionClaim | None:
    target, source = _locked(target_id)
    now = timezone.now()
    if target.state in TERMINAL or (
        target.claim_token is not None and target.lease_until is not None and target.lease_until > now
    ):
        return None
    if target.expires_at is not None and target.expires_at <= now:
        _clear(target, "expired", {"local": "fixed_expiry_elapsed"})
        return None
    reconcile = target.dispatched_at is not None
    try:
        connection = capture_connection(source)
    except ValidationError:
        _clear(target, "unknown" if reconcile else "superseded", {"local": "connection_unavailable"})
        return None
    if not reconcile and (
        source.retired_at is not None
        or source.generation != target.source_generation
        or connection.identity != target.connection_identity
    ):
        _clear(target, "unknown" if target.dispatched_at else "superseded", {"local": "enrollment_changed"})
        return None
    target.claim_token, target.lease_until = uuid4(), now + timedelta(seconds=LEASE_SECONDS)
    target.claim_phase = "queued"
    target.save(update_fields=["claim_token", "claim_phase", "lease_until", "updated_at"])
    return ActionClaim(target.pk, target.claim_token, source.generation, connection.identity, connection, reconcile)


@transaction.atomic
def consume_target(target_id: UUID, token: UUID) -> ActionClaim | None:
    target, source = _locked(target_id)
    if target.claim_token != token or target.claim_phase != "queued":
        return None
    try:
        connection = capture_connection(source)
    except ValidationError:
        _clear(target, "unknown" if target.dispatched_at else "superseded", {"local": "connection_unavailable"})
        return None
    if (
        target.lease_until is None
        or target.lease_until <= timezone.now()
        or (
            not target.dispatched_at
            and (
                source.retired_at is not None
                or source.generation != target.source_generation
                or connection.identity != target.connection_identity
            )
        )
    ):
        _clear(target, "unknown" if target.dispatched_at else "superseded", {"local": "queued_authority_changed"})
        return None
    target.claim_token, target.claim_phase = uuid4(), "running"
    target.lease_until = timezone.now() + timedelta(seconds=LEASE_SECONDS)
    target.save(update_fields=["claim_token", "claim_phase", "lease_until", "updated_at"])
    return ActionClaim(
        target.pk,
        target.claim_token,
        source.generation,
        connection.identity,
        connection,
        target.dispatched_at is not None,
    )


def _current(target: SecurityActionTarget, source: SecuritySource, claim: ActionClaim) -> bool:
    try:
        identity = capture_connection(source).identity
    except ValidationError:
        return False
    return (
        target.claim_token == claim.token
        and target.claim_phase == "running"
        and target.lease_until is not None
        and target.lease_until > timezone.now()
        and source.generation == claim.generation
        and identity == claim.identity
    )


@transaction.atomic
def mark_dispatched(claim: ActionClaim) -> bool:
    target, source = _locked(claim.target_id)
    if target.claim_token != claim.token:
        return False
    if target.operation == "allowlist_replace":
        current = SecurityAllowlist.objects.filter(source=source).first()
        if current is None or current.revision != target.revision or current.cidrs != target.payload.get("cidrs"):
            _clear(target, "unknown" if target.dispatched_at else "superseded", {"local": "newer_staff_list_revision"})
            return False
    if (
        not _current(target, source, claim)
        or source.retired_at is not None
        or not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False)
    ):
        _clear(target, "unknown" if target.dispatched_at else "superseded", {"local": "enrollment_changed"})
        return False
    if target.operation == "ban_put":
        from .action_services import require_create  # noqa: PLC0415 -- action policy boundary

        try:
            require_create(source, target.payload)
            if target.payload.get("kind") == "replica":
                from .replication import valid_origin  # noqa: PLC0415 -- current replication authorization

                original = target.action.decision
                if (
                    not source.sync_enabled
                    or not getattr(settings, "PRAHO_CROWDSEC_REPLICATION_ENABLED", False)
                    or original is None
                    or not valid_origin(original)
                ):
                    raise ValidationError(_("The original detection is no longer approved for copying."))
        except ValidationError:
            _clear(target, "superseded", {"local": "create_authority_withdrawn"})
            return False
    target.state, target.dispatched_at = "dispatching", target.dispatched_at or timezone.now()
    target.save(update_fields=["state", "dispatched_at", "updated_at"])
    refresh_request(target.action_id)
    return True


@transaction.atomic
def mark_unknown(claim: ActionClaim) -> None:
    target, _ = _locked(claim.target_id)
    if target.claim_token == claim.token:
        _clear(target, "unknown" if target.dispatched_at else "issued", {"local": "remote_result_unknown"})


@transaction.atomic
def record_result(claim: ActionClaim, result: dict[str, object]) -> bool:
    target, source = _locked(claim.target_id)
    if target.claim_token != claim.token:
        return False
    if not _current(target, source, claim):
        _clear(target, "unknown", {"local": "enrollment_changed_after_dispatch"})
        return False
    if result == {"status": "unknown", "evidence": "no_receipt"}:
        _clear(target, "unknown", result)
        return True
    status = _bound_receipt(target, result)
    if target.operation == "ban_put" and status == "succeeded" and target.provenance_id:
        for remote_id in cast("list[int]", result["decision_ids"]):
            mapping, _created = SecurityManagedDecision.objects.get_or_create(
                source=source,
                remote_id=remote_id,
                defaults={"provenance_id": target.provenance_id, "issuing_target": target},
            )
            if mapping.provenance_id != target.provenance_id:
                raise ValidationError(_("A physical decision ID changed its managed provenance."))
    target.reconciled_at = timezone.now()
    _clear(target, status, result)
    return True


def _bound_receipt(target: SecurityActionTarget, result: dict[str, object]) -> str:
    if (
        result.get("request_id"),
        result.get("operation"),
        result.get("payload_digest"),
        result.get("provenance_id"),
        result.get("revision"),
    ) != (
        str(target.request_id),
        target.operation,
        target.payload_digest,
        str(target.provenance_id) if target.provenance_id else None,
        target.revision,
    ):
        raise ValidationError(_("The action receipt does not bind the issued request."))
    expiry = result.get("expires_at")
    if expiry is not None and (
        target.expires_at is None or datetime.fromisoformat(cast("str", expiry)) > target.expires_at
    ):
        raise ValidationError(_("The host cannot extend an issued action's immutable expiry."))
    status = cast("str", result["status"])
    if status not in {"unknown", "succeeded", "superseded", "rejected"}:
        raise ValidationError(_("The action result is unsupported."))
    return status


@transaction.atomic
def prepare_verified_repair(claim: ActionClaim, result: dict[str, object]) -> bool:
    target, source = _locked(claim.target_id)
    if target.claim_token != claim.token:
        return False
    if (
        target.operation not in {"revoke", "allowlist_replace"}
        or _bound_receipt(target, result) != "unknown"
        or result.get("evidence") != "mutation_uncertain"
    ):
        raise ValidationError(
            _("Only positively observed late decision evidence can authorize an issued revoke or allowlist repair.")
        )
    target.evidence, target.reconciled_at = result, timezone.now()
    target.save(update_fields=["evidence", "reconciled_at", "updated_at"])
    if source.retired_at is not None or not getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False):
        _clear(target, "unknown", result)
        return False
    return mark_dispatched(claim)
