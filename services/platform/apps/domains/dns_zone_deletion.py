"""Explicit whole-zone removal requires a real export and a proven, cached-out move away."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from . import dns_zone_checks as checks
from . import dns_zone_services as service
from .dns_zone_models import HostedZone, HostedZoneOperation
from .dns_zone_record_services import current_manifest, lock_data_zone

if TYPE_CHECKING:
    from apps.users.models import User

SHA256_LENGTH = 64
# The parent is observed outside the zone's locks, whose wait has no bound. An observation started
# longer ago than this when the locks are held is repeated before any provider deletion.
PROOF_MAX_AGE = timedelta(seconds=30)
# A parent whose lookups always outlast PROOF_MAX_AGE would bounce the delete forever. After this many
# stale observations in a row (about an hour of retries) the delete parks for staff review instead.
STALE_PROOF_LIMIT = 12
STALE_PROOF_PARK_CODE = "move_away_proof_stale_limit"
STALE_PROOFS = "stale_proofs"


def _export_current(zone: HostedZone, digest: str) -> bool:
    receipt = zone.deletion
    revision = zone.revisions.get(number=zone.current_revision)
    manifest = current_manifest(zone) if zone.records.exists() else revision.manifest
    return bool(
        len(digest) == SHA256_LENGTH
        and receipt.get("export_digest") == digest
        and receipt.get("export_revision") == zone.current_revision
        and receipt.get("export_manifest_digest") == service._digest(manifest)
    )


def _cancel_idle_poll(zone: HostedZone) -> bool:
    previous = zone.operations.filter(status__in=service.LIVE_OPERATIONS).first()
    if previous is None:
        return True
    if previous.kind != "activate" or (previous.lease_until and previous.lease_until > timezone.now()):
        return False
    previous.status = "failed"  # fsm-bypass: operation status is a CharField; supersede an idle poll.
    previous.last_error = "superseded_by_customer_intent"
    previous.save(update_fields=["status", "last_error", "updated_at"])
    return True


def request_zone_delete(
    zone: HostedZone, expected_revision: int, export_digest: str, *, actor: User | None
) -> Result[HostedZoneOperation, str]:
    with transaction.atomic():
        current = lock_data_zone(zone, actor)
        if current is None:
            return Err("zone_access_denied")
        if current.current_revision != expected_revision or not _export_current(current, export_digest):
            return Err("current_export_required")
        from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415

        if (
            current.status in {"deleted", "deleting"}
            or current.managed_ttl_evidence
            or (current.account is not None and account_has_active_operation(current.account))
        ):
            return Err("zone_operation_busy")
        existing = current.operations.filter(kind="delete", status__in=service.LIVE_OPERATIONS).first()
        if existing:
            return Ok(existing)
        if not _cancel_idle_poll(current):
            return Err("zone_operation_busy")
        revision = current.revisions.get(number=expected_revision)
        operation = HostedZoneOperation.objects.create(
            zone=current,
            revision=revision,
            kind="delete",
            phase="delete_inventory",
            evidence={"export_digest": export_digest, "manifest_digest": current.deletion["export_manifest_digest"]},
        )
        service._audit(
            current,
            "dns_zone_delete_requested",
            actor=actor,
            metadata={"operation": str(operation.pk), "revision": expected_revision, "digest": export_digest},
        )
        return Ok(operation)


def request_operation_retry(zone: HostedZone, *, actor: User | None) -> Result[HostedZoneOperation, str]:
    with transaction.atomic():
        current = lock_data_zone(zone, actor)
        if current is None:
            return Err("zone_access_denied")
        operation = current.operations.select_for_update().filter(status="parked").first()
        if operation is None or operation.revision.number != current.current_revision:
            return Err("parked_current_operation_required")
        if operation.phase == "create_zone_inflight":
            return Err("zone_create_requires_manual_reconciliation")
        if operation.lease_until and operation.lease_until > timezone.now():
            return Err("zone_operation_busy")
        prepared = _prepare_registrar_retry(operation, current)
        if prepared.is_err():
            return Err(prepared.unwrap_err())
        operation.status = "waiting"  # fsm-bypass: CharField operation status; explicit retry under its row lock.
        if operation.kind == "delete":
            operation.phase = "delete_parent"
            # A retry observes the parent afresh: earlier stale observations no longer count.
            operation.evidence = {key: value for key, value in operation.evidence.items() if key != STALE_PROOFS}
        elif operation.kind == "activate":
            # A parked poll proves nothing about the provider now: the whole chain runs again,
            # under a poll deadline of its own.
            operation.phase = "activation_identity"
            operation.cursor = 0
            operation.evidence = {**operation.evidence, "poll_started_at": timezone.now().isoformat()}
        operation.last_error = ""
        operation.next_attempt_at = timezone.now()
        operation.save(
            update_fields=[
                "status",
                "phase",
                "cursor",
                "evidence",
                "registrar_operation",
                "last_error",
                "next_attempt_at",
                "updated_at",
            ]
        )
        service._audit(
            current,
            "dns_zone_retry_requested",
            actor=actor,
            metadata={"operation": str(operation.pk), "revision": current.current_revision, "phase": operation.phase},
        )
        return Ok(operation)


def _prepare_registrar_retry(operation: HostedZoneOperation, zone: HostedZone) -> Result[None, str]:
    previous = operation.registrar_operation
    if operation.kind != "switch" or previous is None or previous.state != "failed":
        return Ok(None)
    if zone.domain is None:
        return Err("registrar_failure_requires_review")
    from .services import DomainLifecycleService  # noqa: PLC0415

    result = DomainLifecycleService.prepare_nameserver_update(
        zone.domain, list(zone.assigned_nameservers), operation_id=uuid4(), retry_of=previous.pk
    )
    if result.is_err():
        return Err(result.unwrap_err())
    operation.evidence = {**operation.evidence, "registrar_previous_attempt": str(previous.pk)}
    operation.registrar_operation = result.unwrap()
    operation.phase = "switch_inventory"
    return Ok(None)


def _inventory(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        if not _export_current(zone, operation.evidence["export_digest"]):
            raise ValueError("current_export_required")
        if zone.provider_zone_id:
            result = worker.get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
            if result.is_err():
                return worker._provider_failure(result, identifier, token, code="delete_inventory_unproven")
            if not worker.inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
        worker._save(operation, token, phase="delete_parent")
        return 0


def _waited(evidence: dict[str, Any], key: str, ttl: int) -> bool:
    when = parse_datetime(str(evidence[key]))
    return bool(when is not None and timezone.is_aware(when) and timezone.now() >= when + timedelta(seconds=ttl))


def _move_away(
    operation: HostedZoneOperation, zone: HostedZone, proof: dict[str, Any]
) -> tuple[dict[str, Any], bool, bool]:
    """Fold one parent observation into the evidence: (evidence, moved away, cache wait complete).

    Any change in the observed delegation restarts both waits: caches may hold whatever the parent
    served in between, including our own nameservers.
    """
    evidence = dict(operation.evidence)
    old_ds_ttl = max(
        int(evidence.get("old_ds_ttl", 0)),
        int(operation.revision.crosscheck.get("ds_ttl", 0)),
        int(zone.activation.get("ds_ttl", 0)),
        int(proof.get("ds_ttl", 0)),
    )
    old_ns_ttl = max(
        int(evidence.get("old_ns_ttl", 0)),
        int(zone.activation.get("parent_ns_ttl", 0)),
        int(zone.readiness.get("parent_ns_ttl", 0)),
        int(proof.get("ns_ttl", 0)),
    )
    evidence.update(old_ds_ttl=old_ds_ttl, old_ns_ttl=old_ns_ttl)
    observed = sorted(proof.get("nameservers") or [])
    moved = (
        proof.get("state") == "verified"
        and bool(observed)
        and not set(observed).intersection(zone.assigned_nameservers)
        and not proof.get("ds")
    )
    if not moved or evidence.get("parent_nameservers") != observed:
        evidence.pop("parent_moved_since", None)
        evidence.pop("ds_absent_since", None)
    evidence["parent_nameservers"] = observed
    if not moved:
        return evidence, False, False
    evidence.setdefault("parent_moved_since", timezone.now().isoformat())
    evidence.setdefault("ds_absent_since", timezone.now().isoformat())
    waited = _waited(evidence, "parent_moved_since", old_ns_ttl) and _waited(evidence, "ds_absent_since", old_ds_ttl)
    return evidence, True, waited


def _parent(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    original = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    proof = checks.handover_snapshot(original.zone.name)
    with worker._guard(identifier, token) as (operation, zone):
        evidence, moved, waited = _move_away(operation, zone, proof)
        if not moved:
            worker._save(operation, token, evidence=evidence, last_error="move_away_proof_required")
            return worker.RETRY_SECONDS
        worker._save(operation, token, evidence=evidence)
        if not waited:
            return worker.RETRY_SECONDS
        if not _export_current(zone, evidence["export_digest"]):
            raise ValueError("current_export_required")
        zone.deletion = {
            **zone.deletion,
            "revision": operation.revision.number,
            "export_verified": True,
            "parent_moved_away": True,
            "ds_safe": True,
            "checked_at": timezone.now().isoformat(),
        }
        if zone.status != "deleting":
            zone.start_deleting()
        zone.last_error = ""
        zone.save()
        worker._save(operation, token, phase="delete_provider_inflight", evidence=evidence)
        return 0


def _delete(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    # A worker can stop for any length of time after this phase commits. Every attempt observes
    # the parent again rather than trusting the move-away proof that admitted the phase.
    original = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    observed_at = timezone.now()
    proof = checks.handover_snapshot(original.zone.name)
    with worker._guard(identifier, token) as (operation, zone):
        evidence, moved, waited = _move_away(operation, zone, proof)
        stale = int(evidence.pop(STALE_PROOFS, 0))
        if not waited:
            zone.deletion = {**zone.deletion, "parent_moved_away": False, "ds_safe": False}
            zone.save(update_fields=["deletion", "updated_at"])
            refusal = {} if moved else {"last_error": "move_away_proof_required"}
            worker._save(operation, token, phase="delete_parent", evidence=evidence, **refusal)
            return worker.RETRY_SECONDS
        if timezone.now() - observed_at > PROOF_MAX_AGE:
            if stale + 1 >= STALE_PROOF_LIMIT:
                worker._park(identifier, token, STALE_PROOF_PARK_CODE)
                return 0
            worker._save(
                operation, token, evidence={**evidence, STALE_PROOFS: stale + 1}, last_error="move_away_proof_stale"
            )
            return worker.RETRY_SECONDS
        if zone.provider_zone_id:
            expected = tuple(service.spec_from_record(record) for record in zone.records.filter(desired_deleted=False))
            result = worker.get_zone_gateway(zone.provider).delete_zone(
                service.provider_binding(zone), expected_records=expected
            )
            if result.is_err():
                if retriability_of(result) == Retriability.NOT_RETRIABLE:
                    worker._park(identifier, token, "zone_delete_refused")
                    return 0
                # DELETE of this immutable owned binding is idempotent, including a lost response.
                worker._save(
                    operation, token, phase="delete_parent", evidence=evidence, last_error="zone_delete_unconfirmed"
                )
                return worker.RETRY_SECONDS
        zone.deletion = {**zone.deletion, "provider_absent": True}
        zone.mark_deleted()
        zone.save()
        worker._save(operation, token, status="completed", evidence=evidence, last_error="")
        service._audit(
            zone, "dns_zone_state_changed", metadata={"status": "deleted", "revision": zone.current_revision}
        )
        return 0


def deletion_tick(identifier: UUID, token: UUID) -> int:
    phase = HostedZoneOperation.objects.values_list("phase", flat=True).get(pk=identifier)
    handler = {"delete_inventory": _inventory, "delete_parent": _parent, "delete_provider_inflight": _delete}.get(phase)
    if handler is None:
        raise ValueError("unsupported_delete_phase")
    return handler(identifier, token)
