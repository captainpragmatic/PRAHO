"""Bounded DNS operation ticks; write-ahead intent survives a worker dying during provider I/O."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import timedelta
from functools import partial
from typing import Any
from uuid import UUID, uuid4

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django_q.tasks import async_task

from apps.common.transactions import is_outside_transaction
from apps.common.types import Result, Retriability, retriability_of
from apps.infrastructure.dns_zone_gateway import ProviderZoneRecord, ZoneGateway, ZoneInventory, ZoneRecordSpec
from apps.infrastructure.dns_zone_gateway import get_zone_gateway as gateway_for_provider
from apps.settings.services import SettingsService

from . import dns_zone_checks as checks
from . import dns_zone_services as service
from .dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation, HostedZoneRecord

logger = logging.getLogger(__name__)
JOB_TIMEOUT = 120
LEASE_SECONDS = 180
RETRY_SECONDS = 300
DISPATCH_BATCH = 20
TASK = "apps.domains.dns_zone_tasks.advance_zone_operation"


class ZoneLeaseLostError(RuntimeError):
    pass


def get_zone_gateway(provider: str) -> ZoneGateway:
    """One provider seam shared by the lifecycle workers and their outcome tests."""
    return gateway_for_provider(provider)


def _save(operation: HostedZoneOperation, token: UUID, **fields: Any) -> None:
    fields["updated_at"] = timezone.now()
    if not HostedZoneOperation.objects.filter(
        pk=operation.pk, lease_token=token, lease_until__gt=timezone.now()
    ).update(**fields):
        raise ZoneLeaseLostError("DNS operation lost its lease")
    for name, value in fields.items():
        setattr(operation, name, value)


@contextmanager
def _guard(identifier: UUID, token: UUID) -> Iterator[tuple[HostedZoneOperation, HostedZone]]:
    from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    original = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    with transaction.atomic():
        # Established monitoring belongs to the customer's zone (ADR-0061 §5): its own row and provider
        # binding are checked, never whether the hosting that enrolled it is still live.
        independent = original.kind in {"edit", "delete"} or (
            original.kind == "activate" and bool(original.zone.activation.get("activated_at"))
        )
        account = None
        hostname = None
        if independent:
            from .dns_zone_record_services import lock_data_zone  # noqa: PLC0415

            zone = lock_data_zone(original.zone, None)
            if zone is None:
                raise ValueError("stale_enrollment_binding")
        else:
            account = (
                VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
                .filter(pk=original.zone.account_id)
                .first()
                if original.zone.account_id
                else None
            )
            hostname = service._name_for_account(account) if account is not None else None
            if account is not None:
                account.refresh_from_db()
            zone = HostedZone.objects.select_for_update().get(pk=original.zone_id)
        operation = HostedZoneOperation.objects.select_for_update().select_related("revision").get(pk=identifier)
        if operation.lease_token != token or operation.lease_until is None or operation.lease_until <= timezone.now():
            raise ZoneLeaseLostError("DNS operation lost its lease")
        if operation.revision.number != zone.current_revision:
            raise ZoneLeaseLostError("DNS operation belongs to a superseded revision")
        if not independent:
            if (
                account is None
                or hostname is None
                or service.validate_zone_binding(
                    zone, account, hostname, require_target=operation.kind != "crosscheck"
                ).is_err()
            ):
                raise ValueError("stale_enrollment_binding")
            binding = service.capture_enrollment_binding(account, hostname)
            keys = (
                tuple(binding)
                if not (operation.kind == "activate" and zone.activation.get("activated_at"))
                else tuple(key for key in binding if key not in {"target_id", "ipv4", "ipv6"})
            )
            if any(binding[key] != operation.revision.binding.get(key) for key in keys):
                raise ValueError("stale_import_target")
        if (
            operation.kind == "apply"
            and account is not None
            and hostname is not None
            and (
                account_has_active_operation(account) or hostname.previous_ttl is not None or zone.managed_ttl_evidence
            )
        ):
            raise ValueError("hosting_operation_busy")
        _save(operation, token, lease_until=timezone.now() + timedelta(seconds=LEASE_SECONDS))
        yield operation, zone


def _claim(identifier: UUID, supplied: UUID | None = None, *, dispatch: bool = False) -> UUID | None:
    now = timezone.now()
    with transaction.atomic():
        rows = HostedZoneOperation.objects.filter(pk=identifier, status__in=("pending", "running", "waiting"))
        if supplied is not None:
            rows = rows.filter(lease_token=supplied, lease_until__gt=now, worker_started_at__isnull=True)
        else:
            rows = rows.filter(Q(lease_token__isnull=True) | Q(lease_until__lte=now), next_attempt_at__lte=now)
        token = supplied or uuid4()
        if not rows.update(
            lease_token=token,
            lease_until=now + timedelta(seconds=LEASE_SECONDS),
            status="running",
            worker_started_at=None if dispatch else now,
            updated_at=now,
        ):
            return None
        return token


def _park(identifier: UUID, token: UUID, code: str) -> None:
    zone_id = HostedZoneOperation.objects.values_list("zone_id", flat=True).get(pk=identifier)
    with transaction.atomic():
        zone = HostedZone.objects.select_for_update().get(pk=zone_id)
        operation = HostedZoneOperation.objects.select_for_update().get(pk=identifier)
        _save(operation, token, status="parked", last_error=code)
        if zone.status not in {"failed", "deleted"}:
            zone.fail()
        zone.last_error = code
        zone.readiness = {}
        zone.save()
        service._audit(zone, "dns_zone_operation_parked", metadata={"operation": str(identifier), "code": code})


def _phase(identifier: UUID, token: UUID, phase: str, *, evidence: dict[str, Any] | None = None, **fields: Any) -> None:
    with _guard(identifier, token) as (operation, _zone):
        _save(
            operation, token, phase=phase, evidence=evidence if evidence is not None else operation.evidence, **fields
        )


def _provider_failure(
    result: Result[Any, str], identifier: UUID, token: UUID, *, code: str, retry_phase: str | None = None
) -> int:
    if retriability_of(result) == Retriability.RETRIABLE:
        if retry_phase:
            _phase(identifier, token, retry_phase)
        return RETRY_SECONDS
    if retry_phase and retriability_of(result) == Retriability.NOT_RETRIABLE:
        _phase(identifier, token, retry_phase)
    _park(identifier, token, code)
    return 0


def _crosscheck(identifier: UUID, token: UUID, *, continuation: str | None = None) -> int:
    operation = HostedZoneOperation.objects.select_related("revision", "zone").get(pk=identifier)
    source = operation.revision
    pointer = source.crosscheck.get("source_revision")
    if pointer:
        source = HostedZoneImportRevision.objects.get(zone_id=operation.zone_id, pk=UUID(str(pointer)))
    raw_started = str(operation.revision.crosscheck.get("started_at", ""))
    started = parse_datetime(raw_started)
    reset = (
        operation.cursor == 0
        or started is None
        or not timezone.is_aware(started)
        or started < timezone.now() - service.CROSSCHECK_MAX_AGE
    )
    cursor = 0 if reset else operation.cursor
    started_at = timezone.now().isoformat() if reset else raw_started
    result = checks.probe_import_batch(operation.zone.name, source.inventory, cursor)
    with _guard(identifier, token) as (operation, _zone):
        revision = operation.revision
        previous = revision.crosscheck
        revision.crosscheck = {
            **previous,
            **result,
            "started_at": started_at,
            "observations": {**({} if reset else previous.get("observations", {})), **result.get("observations", {})},
        }
        revision.crosscheck["ds_ttl"] = max(int(previous.get("ds_ttl", 0)), int(result.get("ds_ttl", 0)))
        revision.save(update_fields=["crosscheck"])
        finished = result["ok"] and result["complete"]
        _save(
            operation,
            token,
            cursor=0 if continuation and finished else result["cursor"],
            phase=continuation if continuation and finished else operation.phase,
            status="completed" if continuation is None and finished else "running",
        )
    if not result["ok"]:
        # Both are facts about the uploaded inventory, so a retry could never clear them.
        if result.get("error") in {"source_record_missing_from_inventory", "source_owner_uncheckable"}:
            _park(identifier, token, str(result["error"]))
            return 0
        return RETRY_SECONDS
    return 0


def _refresh_source(identifier: UUID, token: UUID) -> int:
    operation = HostedZoneOperation.objects.get(pk=identifier)
    return _crosscheck(identifier, token, continuation=str(operation.evidence.get("source_resume", "queued")))


def _start_source_refresh(operation: HostedZoneOperation, token: UUID, continuation: str) -> None:
    _save(
        operation,
        token,
        phase="refresh_source",
        cursor=0,
        evidence={**operation.evidence, "source_resume": continuation},
    )


def _preflight(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        if not zone.activation.get("activated_at") and not service._crosscheck_current(operation.revision):
            _start_source_refresh(operation, token, "queued")
            return 0
        if zone.provider_zone_id:
            _save(operation, token, phase="inventory")
            return 0
        account_id = str(SettingsService.get_setting("dns.cloudflare_account_id", "") or "")
        if not account_id:
            raise ValueError("zone_provider_not_configured")
        result = get_zone_gateway(zone.provider).list_zones(account_id, zone.name)
        if result.is_ok() and not result.unwrap():
            _save(
                operation,
                token,
                phase="create_zone",
                evidence={**operation.evidence, "provider_account_id": account_id},
            )
            return 0
    if result.is_ok():
        _park(identifier, token, "preexisting_provider_zone")
        return 0
    return _provider_failure(result, identifier, token, code="provider_preflight_failed")


def _create_zone(identifier: UUID, token: UUID) -> int:
    _phase(identifier, token, "create_zone_inflight")  # Commit intent before the request can escape.
    with _guard(identifier, token) as (operation, zone):
        result = get_zone_gateway(zone.provider).create_zone(operation.evidence["provider_account_id"], zone.name)
        if result.is_ok():
            identity = result.unwrap()
            if (
                identity.binding.name != zone.name
                or identity.binding.account_id != operation.evidence["provider_account_id"]
            ):
                raise ValueError("provider_binding_mismatch")
            zone.provider_account_id = identity.binding.account_id
            zone.provider_zone_id = identity.binding.zone_id
            zone.provider_status = identity.status
            zone.assigned_nameservers = list(identity.nameservers)
            zone.provider_plan = identity.plan
            zone.save()
            _save(operation, token, phase="inventory")
            return 0
    return _provider_failure(result, identifier, token, code="zone_create_unconfirmed", retry_phase="create_zone")


def _inventory(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        result = get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            inventory = result.unwrap()
            known = {str(row.pk): row.owner_tag for row in zone.records.all()}
            if any(known.get(row.spec.local_id) != row.spec.owner_tag for row in inventory.records):
                raise ValueError("unowned_provider_records")
            if operation.kind == "edit" and not _edit_inventory_safe(operation, zone, inventory):
                raise ValueError("provider_record_drift")
            _save(
                operation,
                token,
                phase="publish",
                evidence={**operation.evidence, "inventory": [asdict(row) for row in inventory.records]},
            )
            return 0
    return _provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _edit_inventory_safe(operation: HostedZoneOperation, zone: HostedZone, inventory: ZoneInventory) -> bool:
    previous = {row["id"]: service.spec_from_manifest(row) for row in operation.evidence.get("prior_manifest", [])}
    desired = {str(row.pk): service.spec_from_record(row) for row in zone.records.filter(desired_deleted=False)}
    actual = {row.spec.local_id: row.spec for row in inventory.records}
    if len(actual) != len(inventory.records):
        return False
    if any(identifier in desired and identifier not in actual for identifier in previous):
        return False
    return all(
        spec == previous.get(identifier) or spec == desired.get(identifier) for identifier, spec in actual.items()
    )


def _remote_rows(operation: HostedZoneOperation) -> list[ProviderZoneRecord]:
    return [
        ProviderZoneRecord(row["id"], ZoneRecordSpec(**row["spec"])) for row in operation.evidence.get("inventory", [])
    ]


def _same(remote: ProviderZoneRecord, record: HostedZoneRecord) -> bool:
    return remote.spec == service.spec_from_record(record)


def _record_applied(record: HostedZoneRecord, remote: ProviderZoneRecord, revision: int) -> None:
    record.provider_record_id = remote.id
    record.applied_revision = revision
    record.applied_rdata = record.rdata
    record.applied_ttl = remote.spec.ttl
    record.save(update_fields=["provider_record_id", "applied_revision", "applied_rdata", "applied_ttl", "updated_at"])


def _publish(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        remote = _remote_rows(operation)
        selected: ProviderZoneRecord | None
        rows = list(zone.records.select_for_update().order_by("pk"))
        for record in rows:
            matching = [row for row in remote if row.spec.local_id == str(record.pk)]
            if len(matching) > 1:
                raise ValueError("duplicate_owned_provider_records")
            if record.desired_deleted:
                if matching:
                    action, selected = "delete", matching[0]
                    break
                continue
            if matching and _same(matching[0], record):
                _record_applied(record, matching[0], operation.revision.number)
                continue
            if operation.kind == "edit" and record.managed_by == "praho":
                raise ValueError("managed_record_drift")
            action, selected = ("update", matching[0]) if matching else ("create", None)
            break
        else:
            _save(operation, token, phase="verify_inventory")
            return 0
        evidence = {
            **operation.evidence,
            "mutation": {
                "action": action,
                "record_id": str(record.pk),
                "provider_record_id": selected.id if selected else "",
            },
        }
        _save(operation, token, phase=f"record_{action}_inflight", evidence=evidence)
    return _mutate_record(identifier, token, action)


def _mutate_record(identifier: UUID, token: UUID, action: str) -> int:
    with _guard(identifier, token) as (operation, zone):
        mutation = operation.evidence["mutation"]
        record = zone.records.select_for_update().get(pk=mutation["record_id"])
        gateway, binding = get_zone_gateway(zone.provider), service.provider_binding(zone)
        result: Result[Any, str]
        if action == "delete":
            result = gateway.delete_record(binding, mutation["provider_record_id"], expected_owner_tag=record.owner_tag)
        elif action == "update":
            result = gateway.update_record(binding, mutation["provider_record_id"], service.spec_from_record(record))
        else:
            result = gateway.create_record(binding, service.spec_from_record(record))
        if result.is_ok():
            remaining = [row for row in _remote_rows(operation) if row.spec.local_id != str(record.pk)]
            if action == "delete":
                record.evidence = {
                    **record.evidence,
                    "provider_absent": True,
                    "deleted_provider_id": mutation["provider_record_id"],
                }
                record.save(update_fields=["evidence", "updated_at"])
            else:
                applied = result.unwrap()
                if not isinstance(applied, ProviderZoneRecord):
                    raise ValueError("provider_record_unproven")
                if not _same(applied, record):
                    _save(operation, token, phase="inventory")
                    return RETRY_SECONDS
                _record_applied(record, applied, operation.revision.number)
                remaining.append(applied)
            _save(
                operation,
                token,
                phase="publish",
                evidence={**operation.evidence, "inventory": [asdict(row) for row in remaining]},
            )
            return 0
    if action == "create" and retriability_of(result) == Retriability.UNKNOWN:
        return RETRY_SECONDS  # Next tick observes its UUID; it must not blindly repeat POST.
    return _provider_failure(result, identifier, token, code=f"record_{action}_unconfirmed", retry_phase="inventory")


def _recover_record_create(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        result = get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            record = zone.records.get(pk=operation.evidence["mutation"]["record_id"])
            matching = [
                row
                for row in result.unwrap().records
                if row.spec.local_id == str(record.pk) and row.spec.owner_tag == record.owner_tag
            ]
            if len(matching) == 1 and _same(matching[0], record):
                _record_applied(record, matching[0], operation.revision.number)
                _save(operation, token, phase="inventory")
                return 0
            raise ValueError("record_create_unconfirmed")
    return _provider_failure(result, identifier, token, code="record_create_unconfirmed")


def inventory_matches(zone: HostedZone, inventory: ZoneInventory) -> bool:
    expected = {str(record.pk): record for record in zone.records.filter(desired_deleted=False)}
    actual = inventory.records
    return (
        inventory.identity.binding == service.provider_binding(zone)
        and len(expected) == len(actual)
        and {row.spec.local_id for row in actual} == set(expected)
        and all(_same(row, expected[row.spec.local_id]) for row in actual)
    )


def _verify_inventory(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        result = get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            if not inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
            _save(operation, token, phase="assigned", cursor=0)
            return 0
    return _provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _assigned(identifier: UUID, token: UUID) -> int:
    operation = HostedZoneOperation.objects.select_related("zone").get(pk=identifier)
    manifest = [
        {"name": row.name, "record_type": row.record_type, "rdata": row.rdata, "ttl": row.ttl}
        for row in operation.zone.records.filter(desired_deleted=False)
    ]
    result = checks.probe_provider_batch(
        operation.zone.name, manifest, tuple(operation.zone.assigned_nameservers), operation.cursor
    )
    if not result["ok"]:
        return RETRY_SECONDS
    _phase(identifier, token, "handover" if result["complete"] else "assigned", cursor=result["cursor"])
    return 0


def _handover(identifier: UUID, token: UUID) -> int:
    original = HostedZoneOperation.objects.select_related("zone", "revision").get(pk=identifier)
    if original.kind == "edit" and original.zone.activation.get("activated_at"):
        _phase(identifier, token, "final_inventory")
        return 0
    if not service._crosscheck_current(original.revision):
        with _guard(identifier, token) as (operation, _zone):
            _start_source_refresh(operation, token, "handover")
        return 0
    proof = checks.handover_snapshot(original.zone.name)
    with _guard(identifier, token) as (operation, _zone):
        if proof["state"] != "verified" or proof["ds"]:
            evidence = dict(operation.evidence)
            evidence.pop("ds_absent_since", None)
            evidence["old_ds_ttl"] = max(int(evidence.get("old_ds_ttl", 0)), int(proof.get("ds_ttl", 0)))
            _save(
                operation,
                token,
                evidence=evidence,
                last_error="old_ds_present" if proof.get("ds") else "parent_ds_unproven",
            )
            return RETRY_SECONDS
        evidence = dict(operation.evidence)
        absent = evidence.setdefault("ds_absent_since", timezone.now().isoformat())
        old_ttl = max(int(operation.revision.crosscheck.get("ds_ttl", 0)), int(evidence.get("old_ds_ttl", 0)))
        when = parse_datetime(absent)
        _save(operation, token, evidence=evidence)
        if when is None or timezone.now() < when + timedelta(seconds=old_ttl):
            return RETRY_SECONDS
        _save(
            operation,
            token,
            phase="final_inventory",
            evidence={
                **evidence,
                "old_ds_ttl": old_ttl,
                "handover_at": timezone.now().isoformat(),
                "parent_ns_ttl": int(proof.get("ns_ttl", 0)),
            },
        )
    return 0


def _complete_apply(operation: HostedZoneOperation, zone: HostedZone, token: UUID) -> None:
    zone.applied_revision = operation.revision.number
    zone.readiness = {
        "revision": operation.revision.number,
        "complete": True,
        "ds_safe": True,
        "checked_at": timezone.now().isoformat(),
        **{
            key: operation.evidence[key]
            for key in ("ds_absent_since", "old_ds_ttl", "parent_ns_ttl")
            if key in operation.evidence
        },
    }
    if zone.status == "failed":
        zone.retry()
    if zone.status == "pending_import":
        zone.await_nameservers()
    zone.last_error = ""
    zone.save()
    _save(operation, token, status="completed", last_error="")
    if not zone.activation.get("activated_at"):
        HostedZoneOperation.objects.create(
            zone=zone,
            revision=operation.revision,
            kind="activate",
            status="waiting",
            phase="activation_identity",
            evidence={
                key: operation.evidence[key] for key in ("ds_absent_since", "old_ds_ttl") if key in operation.evidence
            },
            next_attempt_at=timezone.now() + timedelta(seconds=RETRY_SECONDS),
        )
    service._audit(zone, "dns_zone_state_changed", metadata={"status": zone.status, "revision": zone.current_revision})


def _final_inventory(identifier: UUID, token: UUID) -> int:
    with _guard(identifier, token) as (operation, zone):
        if not (operation.kind == "edit" and zone.activation.get("activated_at")):
            if not service._crosscheck_current(operation.revision):
                _start_source_refresh(operation, token, "handover")
                return 0
            checked = parse_datetime(str(operation.evidence.get("handover_at", "")))
            if (
                checked is None
                or not timezone.is_aware(checked)
                or checked < timezone.now() - service.CROSSCHECK_MAX_AGE
            ):
                _save(operation, token, phase="handover")
                return 0
        result = get_zone_gateway(zone.provider).list_records(service.provider_binding(zone))
        if result.is_ok():
            if not inventory_matches(zone, result.unwrap()):
                raise ValueError("provider_inventory_mismatch")
            _complete_apply(operation, zone, token)
            return 0
    return _provider_failure(result, identifier, token, code="provider_inventory_unproven")


def _step(identifier: UUID, token: UUID) -> int:
    from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # ADR-0007

    operation = HostedZoneOperation.objects.select_related("zone", "zone__account", "zone__account_hostname").get(
        pk=identifier
    )
    if (
        operation.kind == "activate"
        and operation.zone.account is not None
        and (
            account_has_active_operation(operation.zone.account)
            or operation.zone.managed_ttl_evidence
            or (
                operation.zone.account_hostname is not None and operation.zone.account_hostname.previous_ttl is not None
            )
        )
    ):
        return RETRY_SECONDS
    if operation.kind == "crosscheck":
        return _crosscheck(identifier, token)
    if operation.kind == "activate":
        from .dns_zone_lifecycle import activation_tick  # noqa: PLC0415

        return activation_tick(identifier, token)
    if operation.kind == "switch":
        from .dns_zone_lifecycle import switch_tick  # noqa: PLC0415

        return switch_tick(identifier, token)
    if operation.kind == "delete":
        from .dns_zone_deletion import deletion_tick  # noqa: PLC0415

        return deletion_tick(identifier, token)
    return _apply_step(operation, token)


def _apply_step(operation: HostedZoneOperation, token: UUID) -> int:
    identifier = operation.pk
    mutations = {
        "queued",
        "create_zone",
        "publish",
        "record_update_inflight",
        "record_delete_inflight",
        "handover",
        "final_inventory",
    }
    if (
        operation.phase in mutations
        and not operation.zone.activation.get("activated_at")
        and not service._crosscheck_current(operation.revision)
    ):
        with _guard(identifier, token) as (current, _zone):
            _start_source_refresh(current, token, operation.phase)
        return 0
    handlers = {
        "queued": _preflight,
        "create_zone": _create_zone,
        "inventory": _inventory,
        "publish": _publish,
        "record_create_inflight": _recover_record_create,
        "verify_inventory": _verify_inventory,
        "assigned": _assigned,
        "handover": _handover,
        "final_inventory": _final_inventory,
        "refresh_source": _refresh_source,
    }
    if operation.phase == "create_zone_inflight":
        raise ValueError("zone_create_unconfirmed")
    if operation.phase in {"record_update_inflight", "record_delete_inflight"}:
        return _mutate_record(identifier, token, operation.phase.split("_")[1])
    handler = handlers.get(operation.phase)
    if handler is None:
        raise ValueError("unsupported_zone_operation_phase")
    return handler(identifier, token)


def _enqueue(identifier: str, token: UUID | None = None) -> None:
    kwargs = {"lease_token": str(token)} if token else {}
    try:
        async_task(TASK, identifier, timeout=JOB_TIMEOUT, sync=False, **kwargs)
    except (OSError, ValueError, RuntimeError):
        if token:
            HostedZoneOperation.objects.filter(
                pk=UUID(identifier), lease_token=token, worker_started_at__isnull=True
            ).update(  # fsm-bypass: CharField operation status; recover only this unstarted lease claim.
                lease_token=None,
                lease_until=None,
                status="waiting",
                next_attempt_at=timezone.now() + timedelta(seconds=RETRY_SECONDS),
            )
        logger.exception("DNS zone work remains durable after a queue failure")


def advance_zone_operation(operation_id: str, *, lease_token: str | None = None) -> dict[str, str]:
    if not is_outside_transaction():
        return {"action": "transaction_required"}
    try:
        identifier = UUID(operation_id)
        supplied = UUID(lease_token) if lease_token else None
    except (TypeError, ValueError):
        return {"action": "excluded"}
    token = _claim(identifier, supplied)
    if token is None:
        return {"action": "busy"}
    delay = 0
    try:
        delay = _step(identifier, token)
    except ZoneLeaseLostError:
        return {"action": "busy"}
    except ValueError as error:
        _park(identifier, token, str(error)[:200])
    with transaction.atomic():
        operation = HostedZoneOperation.objects.select_for_update().get(pk=identifier)
        status = operation.status if operation.status in {"completed", "parked", "failed"} else "waiting"
        _save(
            operation,
            token,
            lease_token=None,
            lease_until=None,
            worker_started_at=None,
            status=status,
            next_attempt_at=timezone.now() + timedelta(seconds=delay),
        )
        if status == "waiting" and not delay:
            transaction.on_commit(partial(_enqueue, str(identifier)), robust=True)
    return {"action": status, "phase": operation.phase}


def _seed_activation_checks(now: Any) -> None:
    cutoff = (now - timedelta(minutes=30)).isoformat()
    candidates = (
        HostedZone.objects.filter(
            status__in=("active", "awaiting_ns"),
            current_revision=F("confirmed_revision"),
            applied_revision=F("current_revision"),
        )
        .exclude(provider_zone_id="")
        .filter(Q(readiness__checked_at__lte=cutoff) | ~Q(readiness__has_key="checked_at"))
        .exclude(operations__status__in=service.LIVE_OPERATIONS)
        .order_by("updated_at", "pk")
        .values_list("pk", flat=True)[:DISPATCH_BATCH]
    )
    for identifier in candidates:
        with transaction.atomic():
            zone = HostedZone.objects.select_for_update().get(pk=identifier)
            if zone.operations.filter(status__in=service.LIVE_OPERATIONS).exists():
                continue
            revision = zone.revisions.get(number=zone.current_revision)
            HostedZoneOperation.objects.create(
                zone=zone,
                revision=revision,
                kind="activate",
                phase="activation_identity",
                next_attempt_at=now,
                evidence={
                    key: zone.readiness[key] for key in ("ds_absent_since", "old_ds_ttl") if key in zone.readiness
                },
            )


def dispatch_zone_operations() -> dict[str, int]:
    now = timezone.now()
    _seed_activation_checks(now)
    due = (
        HostedZoneOperation.objects.filter(status__in=("pending", "running", "waiting"), next_attempt_at__lte=now)
        .filter(Q(lease_token__isnull=True) | Q(lease_until__lte=now))
        .order_by("next_attempt_at", "pk")[:DISPATCH_BATCH]
    )
    queued = 0
    for operation in due:
        token = _claim(operation.pk, dispatch=True)
        if token:
            transaction.on_commit(partial(_enqueue, str(operation.pk), token), robust=True)
            queued += 1
    return {"queued": queued}
