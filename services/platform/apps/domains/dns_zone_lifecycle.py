"""Nameserver-switch intents and bounded provider/delegation activation polling."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result

from . import dns_zone_checks as checks
from . import dns_zone_services as service
from .dns_zone_models import HostedZone, HostedZoneOperation

if TYPE_CHECKING:
    from apps.users.models import User

FREE_ACTIVATION_INTERVAL = 3600
PAID_ACTIVATION_INTERVAL = 300
POLL_SECONDS = 300
POLL_DEADLINE = timedelta(days=7)


def request_nameserver_switch(  # noqa: PLR0911  # One refusal per precondition, suspension included
    zone: HostedZone, expected_revision: int, *, actor: User | None
) -> Result[HostedZoneOperation, str]:
    with transaction.atomic():
        locked = service._locked_zone(zone, actor)
        if locked is None:
            return Err("zone_access_denied")
        current, account, hostname = locked
        if service.publication_held(current.customer_id, actor):
            return Err("customer_suspended")
        if current.current_revision != expected_revision or not current.can_offer_nameservers():
            return Err("switch_proof_required")
        if service.validate_zone_binding(current, account, hostname).is_err():
            return Err("stale_import_target")
        operation = current.operations.filter(status__in=service.LIVE_OPERATIONS).first()
        if operation and (
            operation.kind != "activate"
            or (operation.lease_token and operation.lease_until and operation.lease_until > timezone.now())
        ):
            return Err("zone_operation_busy")
        if operation is None:
            operation = HostedZoneOperation(
                zone=current,
                revision=current.revisions.get(number=expected_revision),
                kind="activate",
                phase="activation_identity",
                evidence={
                    key: current.readiness[key] for key in ("ds_absent_since", "old_ds_ttl") if key in current.readiness
                },
            )
        if current.domain is not None and service.can_switch_registrar(current):
            from .services import DomainLifecycleService  # noqa: PLC0415

            prepared = DomainLifecycleService.prepare_nameserver_update(
                current.domain, list(current.assigned_nameservers), operation_id=operation.pk
            )
            if prepared.is_err():
                return Err(prepared.unwrap_err())
            operation.registrar_operation = prepared.unwrap()
            operation.kind = "switch"
            operation.phase = "switch_inventory"
        operation.next_attempt_at = timezone.now()
        operation.evidence = {**operation.evidence, **service.staff_evidence(actor)}
        operation.save()
        service._audit(
            current,
            "dns_zone_switch_requested",
            actor=actor,
            metadata={"operation": str(operation.pk), "revision": expected_revision},
        )
        return Ok(operation)


def _identity(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        raw_started = operation.evidence.get("poll_started_at")
        started = parse_datetime(raw_started) if isinstance(raw_started, str) else None
        if timezone.now() - (started or operation.created_at) > POLL_DEADLINE:
            raise ValueError("activation_deadline")
        result = worker.get_zone_gateway(zone.provider).read_zone(service.provider_binding(zone))
        if result.is_ok():
            identity = result.unwrap()
            if tuple(sorted(identity.nameservers)) != tuple(sorted(zone.assigned_nameservers)):
                raise ValueError("assigned_nameservers_changed")
            zone.provider_status = identity.status
            zone.provider_plan = identity.plan
            zone.save(update_fields=["provider_status", "provider_plan", "updated_at"])
            raw = operation.evidence.get("next_activation_trigger")
            next_trigger = parse_datetime(raw) if isinstance(raw, str) else None
            raw_last = zone.activation.get("last_activation_trigger_at")
            last = parse_datetime(raw_last) if isinstance(raw_last, str) else None
            if last is not None:
                interval = FREE_ACTIVATION_INTERVAL if zone.provider_plan == "free" else PAID_ACTIVATION_INTERVAL
                next_trigger = last + timedelta(seconds=interval)
            trigger = identity.status != "active" and (next_trigger is None or next_trigger <= timezone.now())
            worker._save(operation, token, phase="activation_trigger" if trigger else "activation_inventory")
            return 0
    return worker._provider_failure(result, identifier, token, code="activation_status_unproven")


def _trigger(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        interval = FREE_ACTIVATION_INTERVAL if zone.provider_plan == "free" else PAID_ACTIVATION_INTERVAL
        issued = timezone.now()
        zone.activation = {**zone.activation, "last_activation_trigger_at": issued.isoformat()}
        zone.save(update_fields=["activation", "updated_at"])
        worker._save(
            operation,
            token,
            phase="activation_inventory",
            evidence={
                **operation.evidence,
                "next_activation_trigger": (issued + timedelta(seconds=interval)).isoformat(),
            },
        )
    with worker._guard(identifier, token) as (_operation, zone):
        result = worker.get_zone_gateway(zone.provider).trigger_activation(service.provider_binding(zone))
    return 0 if result.is_ok() else POLL_SECONDS


def _inventory(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        result = worker.get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            if not worker.inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
            worker._save(
                operation,
                token,
                phase="activation_assigned",
                cursor=0,
                evidence={**operation.evidence, "inventory_checked_at": timezone.now().isoformat()},
            )
            return 0
    return worker._provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _assigned(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    operation = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    manifest = [
        {"name": row.name, "record_type": row.record_type, "rdata": row.rdata, "ttl": row.ttl}
        for row in operation.zone.records.filter(desired_deleted=False)
    ]
    proof = checks.probe_provider_batch(
        operation.zone.name, manifest, tuple(operation.zone.assigned_nameservers), operation.cursor
    )
    if not proof["ok"]:
        with worker._guard(identifier, token) as (_operation, zone):
            zone.readiness = {}
            zone.save(update_fields=["readiness", "updated_at"])
        return POLL_SECONDS
    worker._phase(
        identifier, token, "activation_dnssec" if proof["complete"] else "activation_assigned", cursor=proof["cursor"]
    )
    return 0


def _dnssec(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        result = worker.get_zone_gateway(zone.provider).get_dnssec(service.provider_binding(zone))
        if result.is_ok():
            status = result.unwrap()
            zone.dnssec = {"status": status.status, "ds": status.ds}
            zone.save(update_fields=["dnssec", "updated_at"])
            worker._save(operation, token, phase="activation_parent")
            return 0
    return worker._provider_failure(result, identifier, token, code="provider_dnssec_unproven")


def _ds_matches(parent: list[str], provider: str) -> bool:
    try:
        desired = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, provider)
        return any(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, value) == desired for value in parent)
    except (ValueError, dns.exception.DNSException):
        return False


def _restore_failed(zone: HostedZone) -> None:
    """A retried operation proved readiness again: leave `failed` the way a retried apply does."""
    if zone.status == "failed" and zone.can_offer_nameservers():
        zone.retry()
        zone.await_nameservers()
        zone.last_error = ""


def _parent(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    original = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    proof = checks.handover_snapshot(original.zone.name)
    with worker._guard(identifier, token) as (operation, zone):
        evidence = dict(operation.evidence)
        expected_ns = sorted(zone.assigned_nameservers)
        delegated = proof.get("state") == "verified" and sorted(proof["nameservers"]) == expected_ns
        if (
            not delegated
            and not zone.activation.get("activated_at")
            and not service._crosscheck_current(operation.revision)
        ):
            zone.readiness = {}
            zone.save(update_fields=["readiness", "updated_at"])
            worker._start_source_refresh(operation, token, "activation_identity")
            return 0
        same_provider_ds = (
            delegated
            and zone.provider_status == "active"
            and zone.dnssec.get("status") == "active"
            and _ds_matches(proof.get("ds", []), str(zone.dnssec.get("ds", "")))
        )
        if proof.get("state") != "verified" or (proof.get("ds") and not same_provider_ds):
            evidence.pop("ds_absent_since", None)
            evidence["old_ds_ttl"] = max(int(evidence.get("old_ds_ttl", 0)), int(proof.get("ds_ttl", 0)))
            zone.readiness = {}
            zone.save(update_fields=["readiness", "updated_at"])
            worker._save(
                operation, token, phase="activation_identity", evidence=evidence, last_error="parent_ds_unproven"
            )
            return POLL_SECONDS
        absent = evidence.setdefault("ds_absent_since", timezone.now().isoformat())
        old_ttl = max(int(operation.revision.crosscheck.get("ds_ttl", 0)), int(evidence.get("old_ds_ttl", 0)))
        when = parse_datetime(absent)
        if not same_provider_ds and (when is None or timezone.now() < when + timedelta(seconds=old_ttl)):
            worker._save(operation, token, phase="activation_identity", evidence=evidence)
            return POLL_SECONDS
        zone.readiness = {
            "revision": operation.revision.number,
            "complete": True,
            "ds_safe": True,
            "checked_at": timezone.now().isoformat(),
            "ds_absent_since": absent,
            "old_ds_ttl": old_ttl,
            "parent_ns_ttl": int(proof.get("ns_ttl", 0)),
        }
        if delegated and zone.provider_status == "active":
            zone.activation = {
                **zone.activation,
                "revision": operation.revision.number,
                "parent_ns_verified": True,
                "inventory_verified": True,
                "parent_ns_ttl": int(proof.get("ns_ttl", 0)),
                "ds_ttl": int(proof.get("ds_ttl", 0)),
            }
            _restore_failed(zone)
            if zone.status == "awaiting_ns":
                zone.activate()
            zone.last_error = ""
            zone.save()
            worker._save(operation, token, status="completed", evidence=evidence, last_error="")
            service._audit(
                zone, "dns_zone_state_changed", metadata={"status": zone.status, "revision": zone.current_revision}
            )
            return 0
        _restore_failed(zone)
        zone.save(update_fields=["readiness", "status", "last_error", "updated_at"])
        worker._save(operation, token, phase="activation_identity", evidence=evidence)
        return POLL_SECONDS


def activation_tick(identifier: UUID, token: UUID) -> int:
    operation = HostedZoneOperation.objects.get(pk=identifier)
    if operation.phase == "refresh_source":
        from . import dns_zone_tasks as worker  # noqa: PLC0415

        return worker._refresh_source(identifier, token)
    handlers = {
        "queued": _identity,
        "activation_identity": _identity,
        "activation_trigger": _trigger,
        "activation_inventory": _inventory,
        "activation_assigned": _assigned,
        "activation_dnssec": _dnssec,
        "activation_parent": _parent,
    }
    handler = handlers.get(operation.phase)
    if handler is None:
        raise ValueError("unsupported_activation_phase")
    return handler(identifier, token)


def _switch_inventory(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        result = worker.get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            if not worker.inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
            worker._save(operation, token, phase="switch_assigned", cursor=0)
            return 0
    return worker._provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _switch_assigned(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    operation = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    from .dns_zone_record_services import current_manifest  # noqa: PLC0415

    proof = checks.probe_provider_batch(
        operation.zone.name,
        current_manifest(operation.zone),
        tuple(operation.zone.assigned_nameservers),
        operation.cursor,
    )
    if not proof["ok"]:
        return POLL_SECONDS
    worker._phase(
        identifier, token, "switch_parent" if proof["complete"] else "switch_assigned", cursor=proof["cursor"]
    )
    return 0


def _switch_parent(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    original = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    proof = checks.handover_snapshot(original.zone.name)
    with worker._guard(identifier, token) as (operation, zone):
        evidence = dict(operation.evidence)
        delegated = proof.get("state") == "verified" and sorted(proof.get("nameservers", [])) == sorted(
            zone.assigned_nameservers
        )
        if (
            not delegated
            and not zone.activation.get("activated_at")
            and not service._crosscheck_current(operation.revision)
        ):
            worker._start_source_refresh(operation, token, "switch_inventory")
            return 0
        if proof.get("state") != "verified" or proof.get("ds"):
            evidence.pop("ds_absent_since", None)
            evidence["old_ds_ttl"] = max(int(evidence.get("old_ds_ttl", 0)), int(proof.get("ds_ttl", 0)))
            zone.readiness = {}
            zone.save(update_fields=["readiness", "updated_at"])
            worker._save(operation, token, phase="switch_inventory", evidence=evidence, last_error="old_ds_present")
            return POLL_SECONDS
        absent = evidence.setdefault("ds_absent_since", timezone.now().isoformat())
        old_ttl = max(int(operation.revision.crosscheck.get("ds_ttl", 0)), int(evidence.get("old_ds_ttl", 0)))
        when = parse_datetime(absent)
        if when is None or not timezone.is_aware(when) or timezone.now() < when + timedelta(seconds=old_ttl):
            worker._save(operation, token, phase="switch_inventory", evidence=evidence)
            return POLL_SECONDS
        worker._save(
            operation,
            token,
            phase="switch_final_inventory",
            evidence={
                **evidence,
                "switch_parent_checked_at": timezone.now().isoformat(),
                "already_delegated": delegated,
            },
        )
        return 0


def _switch_final_inventory(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, zone):
        checked = parse_datetime(str(operation.evidence.get("switch_parent_checked_at", "")))
        if checked is None or not timezone.is_aware(checked) or checked < timezone.now() - service.CROSSCHECK_MAX_AGE:
            worker._save(operation, token, phase="switch_inventory")
            return 0
        result = worker.get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            if not worker.inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
            worker._save(
                operation,
                token,
                phase="switch_submit",
                evidence={**operation.evidence, "switch_checked_at": timezone.now().isoformat()},
            )
            return 0
    return worker._provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _switch_submit(identifier: UUID, token: UUID) -> int:
    from . import dns_zone_tasks as worker  # noqa: PLC0415
    from .services import DomainLifecycleService  # noqa: PLC0415

    with worker._guard(identifier, token) as (operation, _zone):
        registrar_operation = operation.registrar_operation
        if registrar_operation is None:
            raise ValueError("registrar_intent_required")
        checked = parse_datetime(str(operation.evidence.get("switch_checked_at", "")))
        stale = (
            checked is None or not timezone.is_aware(checked) or checked < timezone.now() - service.CROSSCHECK_MAX_AGE
        )
        source_stale = (
            not operation.evidence.get("already_delegated")
            and not _zone.activation.get("activated_at")
            and not service._crosscheck_current(operation.revision)
        )
        if registrar_operation.state == "pending" and (stale or source_stale):
            worker._save(operation, token, phase="switch_inventory")
            return 0
        worker._save(operation, token, phase="switch_submitted")
    result = DomainLifecycleService.resume_nameserver_update(registrar_operation)
    registrar_operation.refresh_from_db()
    if result.is_err() and registrar_operation.state not in {"submitted", "completed"}:
        raise ValueError("registrar_switch_unconfirmed")
    # Submitted operations are observed by the registrar reconciler and parent DNS;
    # they are never changed back to pending merely because the response was lost.
    with worker._guard(identifier, token) as (operation, _zone):
        worker._save(operation, token, kind="activate", phase="activation_identity", last_error="")
    return 0


def switch_tick(identifier: UUID, token: UUID) -> int:
    operation = HostedZoneOperation.objects.get(pk=identifier)
    if operation.phase == "refresh_source":
        from . import dns_zone_tasks as worker  # noqa: PLC0415

        return worker._refresh_source(identifier, token)
    handler = {
        "switch_inventory": _switch_inventory,
        "switch_assigned": _switch_assigned,
        "switch_parent": _switch_parent,
        "switch_final_inventory": _switch_final_inventory,
        "switch_submit": _switch_submit,
        "switch_submitted": _switch_submit,
    }.get(operation.phase)
    if handler is None:
        raise ValueError("unsupported_switch_phase")
    return handler(identifier, token)
