"""Customer web slots participate in the fresh account-name publication fence.

Callers hold AccountHostname before zone rows (UUID order). Provider results and
partial writes are committed as evidence; no tenant record or whole zone is removed
when hosting terminates. Imported revisions remain immutable historical inventories.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result, retriability_of
from apps.infrastructure.dns_zone_gateway import (
    MAX_RECORD_TTL,
    MIN_RECORD_TTL,
    ProviderZoneRecord,
    ZoneBinding,
    ZoneGateway,
    ZoneRecordSpec,
    ZoneRecordType,
    get_zone_gateway,
)

from . import account_hostname_config as config

if TYPE_CHECKING:
    from apps.domains.dns_zone_models import HostedZone, HostedZoneRecord

    from .account_hostname_models import AccountHostname
    from .virtualmin_models import VirtualminAccount

TtlMode = Literal["current", "lower", "restore"]
CreatePermits = dict[str, str]


def assert_move_ready(account: VirtualminAccount) -> None:
    """Admission holds the Account lock also taken by customer zone intent writers."""
    from apps.domains.dns_zone_models import HostedZoneOperation  # noqa: PLC0415  # ADR-0007

    if (
        HostedZoneOperation.objects.filter(
            zone__account_id=account.pk,
            status__in=("pending", "running", "waiting", "parked"),
        )
        .exclude(kind__in=("activate", "crosscheck"))
        .exists()
    ):
        raise ValueError("Resolve the customer DNS zone's pending or uncertain mutation before moving the account")


def _prepare_creates(pk: UUID, mode: TtlMode, *, skip_locked: bool) -> Result[CreatePermits, str]:
    from apps.domains.dns_zone_models import HostedZone  # noqa: PLC0415  # ADR-0007

    from .account_hostname_service import _syncable, lock_for_publication  # noqa: PLC0415  # Publication facade

    if not HostedZone.objects.filter(account_hostname_id=pk).exclude(status="deleted").exists():
        return Ok({})
    try:
        # The stable row UUID and creation nonce must survive a worker dying during
        # the later provider transaction. An application caller cannot nest this
        # phase inside another transaction and still claim a durable intent.
        with transaction.atomic(durable=True):
            hostname = lock_for_publication(pk, skip_locked=skip_locked)
            if hostname is None or _syncable(hostname) is not None:
                return Ok({})
            if mode == "restore" and (hostname.previous_ttl is None or not hostname.records):
                return Ok({})
            zones = _zones(hostname)
            for zone in zones:
                valid = _ownership(zone, hostname)
                if valid.is_err():
                    raise ValueError(valid.unwrap_err())
            permits = {}
            for zone in zones:
                if not _enrolled(zone):
                    continue
                previous = [(str(row.pk), row.rdata_digest, row.desired_deleted) for row in _web_rows(zone)]
                rows = _refresh_families(zone, hostname, _web_rows(zone))
                if previous != [(str(row.pk), row.rdata_digest, row.desired_deleted) for row in rows]:
                    zone.readiness = {}
                    zone.save(update_fields=["readiness", "updated_at"])
                for row in rows:
                    if row.desired_deleted or row.provider_record_id or row.evidence.get("create_issued"):
                        continue
                    nonce = str(uuid4())
                    row.evidence = {
                        **row.evidence,
                        "create_issued": True,
                        "create_nonce": nonce,
                        "create_rdata_digest": row.rdata_digest,
                    }
                    row.save(update_fields=["evidence", "updated_at"])
                    permits[str(row.pk)] = nonce
            return Ok(permits)
    except (RuntimeError, ValueError) as error:
        return Err(str(error))


def _release_unused_creates(pk: UUID, permits: CreatePermits) -> None:
    if not permits:
        return
    from apps.domains.dns_zone_models import HostedZoneRecord  # noqa: PLC0415  # ADR-0007

    from .account_hostname_service import lock_for_publication  # noqa: PLC0415  # Publication facade

    with transaction.atomic(durable=True):
        if lock_for_publication(pk) is None:
            return
        rows = (
            HostedZoneRecord.objects.select_for_update()
            .filter(pk__in=permits, zone__account_hostname_id=pk)
            .order_by("pk")
        )
        for row in rows:
            if not row.provider_record_id and row.evidence.get("create_nonce") == permits[str(row.pk)]:
                row.evidence = {**row.evidence, "create_issued": False, "create_nonce": ""}
                row.save(update_fields=["evidence", "updated_at"])


@contextmanager
def publication_intents(
    pk: UUID, *, mode: TtlMode = "current", skip_locked: bool = False
) -> Iterator[Result[CreatePermits, str]]:
    prepared = _prepare_creates(pk, mode, skip_locked=skip_locked)
    try:
        yield prepared
    finally:
        if prepared.is_ok():
            # Permits disappear from this map immediately BEFORE each POST. Only
            # this process can prove that its remaining permits were never sent.
            _release_unused_creates(pk, prepared.unwrap())


def rdata_digest(data: dict[str, Any]) -> str:
    return hashlib.sha256(bytes.fromhex(str(data["wire"]))).hexdigest()


def record_spec(row: HostedZoneRecord, *, ttl: int) -> ZoneRecordSpec:
    return ZoneRecordSpec(
        local_id=str(row.pk),
        name=row.name,
        record_type=cast(ZoneRecordType, row.record_type),
        ttl=ttl,
        rdata=str(row.rdata["text"]),
        owner_tag=row.owner_tag,
    )


def zone_binding(zone: HostedZone) -> ZoneBinding:
    return ZoneBinding(zone.provider, zone.provider_account_id, zone.provider_zone_id, zone.name)


def advance_target_locked(hostname: AccountHostname) -> None:
    """Advance runtime target evidence inside the ownership commit, without provider I/O.

    Immutable uploaded revisions keep their original target binding. A pending
    nameserver assistant consequently requires fresh confirmation after a move.
    """
    from apps.domains.dns_zone_services import capture_enrollment_binding  # noqa: PLC0415  # ADR-0007

    for zone in _zones(hostname):
        valid = _ownership(zone, hostname)
        if valid.is_err():
            raise ValueError(valid.unwrap_err())
        if hostname.account is None:
            raise ValueError("Managed DNS target has no hosting account")
        binding = capture_enrollment_binding(hostname.account, hostname)
        if zone.enrollment_binding != binding:
            zone.enrollment_binding, zone.readiness = binding, {}
            zone.save(update_fields=["enrollment_binding", "readiness", "updated_at"])


def _routing_snapshot(hostname: AccountHostname) -> tuple[str, tuple[str, ...], str, str | None]:
    rows = []
    names: set[str] = set()
    for zone in _zones(hostname):
        valid = _ownership(zone, hostname)
        if valid.is_err():
            raise ValueError(valid.unwrap_err())
        if not _enrolled(zone) or not (zone.status == "active" or zone.activation.get("activated_at")):
            continue
        web = _web_rows(zone)
        rows.append(
            {
                "zone": str(zone.pk),
                "customer": zone.customer_id,
                "service": zone.service_id,
                "revision": zone.current_revision,
                "status": zone.status,
                "records": [
                    (str(row.pk), row.name, row.rdata_digest, row.desired_deleted, row.applied_revision) for row in web
                ],
            }
        )
        names.update(row.name for row in web if not row.desired_deleted)
    target = hostname.target_server
    ipv4 = str(target.ipv4_address) if target and target.ipv4_address else ""
    ipv6 = str(target.ipv6_address) if target and target.ipv6_address else None
    generation = hashlib.sha256(
        json.dumps(
            {
                "name": str(hostname.pk),
                "target": str(hostname.target_server_id),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "zones": rows,
            },
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    return generation, tuple(sorted(names)), ipv4, ipv6


def observe_routing(hostname: AccountHostname) -> Result[dict[str, Any], str]:
    """Prove all active managed frontends outside locks, then recheck the binding."""
    from apps.infrastructure.dns_agreement import routing_agreement  # noqa: PLC0415  # External worker-only transport

    from .account_hostname_service import lock_for_publication  # noqa: PLC0415  # Publication seam imports this module

    try:
        with transaction.atomic():
            locked = lock_for_publication(hostname.pk)
            if locked is None:
                return Err("Managed DNS account name is unavailable")
            generation, names, ipv4, ipv6 = _routing_snapshot(locked)
        observations = {name: asdict(routing_agreement(name, ipv4, ipv6)) for name in names}
        with transaction.atomic():
            locked = lock_for_publication(hostname.pk)
            if locked is None or _routing_snapshot(locked)[0] != generation:
                return Err("Managed DNS ownership changed during authoritative checks")
        return Ok(
            {
                "checked_at": timezone.now().isoformat(),
                "generation": generation,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "agreed": all(item["agreed"] for item in observations.values()),
                "records": observations,
            }
        )
    except ValueError as error:
        return Err(str(error))


def routing_is_current_locked(hostname: AccountHostname, proof: dict[str, Any]) -> bool:
    return proof.get("agreed") is True and proof.get("generation") == _routing_snapshot(hostname)[0]


def _zones(hostname: AccountHostname) -> list[HostedZone]:
    from apps.domains.dns_zone_models import HostedZone  # noqa: PLC0415  # ADR-0007

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Managed DNS publication requires the account-name transaction")
    return list(
        HostedZone.objects.select_for_update()
        .filter(account_hostname_id=hostname.pk)
        .exclude(status="deleted")
        .order_by("pk")
    )


def _ownership(zone: HostedZone, hostname: AccountHostname) -> Result[None, str]:
    account = hostname.account
    if account is None or (
        zone.account_id != account.pk
        or zone.service_id != account.service_id
        or zone.customer_id != account.service.customer_id
        or zone.name != account.domain.lower().rstrip(".")
    ):
        return Err("Customer-zone ownership changed; staff reconciliation is required")
    if zone.status == "deleting":
        return Err("Customer-zone deletion is in progress")
    return Ok(None)


def _web_rows(zone: HostedZone) -> list[HostedZoneRecord]:
    return list(
        zone.records.select_for_update()
        .filter(
            managed_by="praho",
            name__in=(zone.name, "www." + zone.name),
            record_type__in=("A", "AAAA", "CNAME"),
        )
        .order_by("pk")
    )


def _enrolled(zone: HostedZone) -> bool:
    # Pending drafts without a conclusively owned/applied provider inventory never
    # acquire publication authority. An error after activation retains that authority.
    return bool(zone.provider_zone_id and zone.applied_revision is not None)


def _spec_matches(actual: ProviderZoneRecord, expected: ZoneRecordSpec, *, ttl: bool = True) -> bool:
    return (
        actual.spec.owner_tag == expected.owner_tag
        and actual.spec.name == expected.name
        and actual.spec.record_type == expected.record_type
        and actual.spec.rdata == expected.rdata
        and actual.spec.proxied is False
        and (not ttl or actual.spec.ttl == expected.ttl)
    )


def _ttl_snapshot(
    gateway: ZoneGateway, zone: HostedZone, row: HostedZoneRecord, permits: CreatePermits
) -> Result[dict[str, Any], str]:
    if not row.provider_record_id:
        if str(row.pk) in permits and permits[str(row.pk)] == row.evidence.get("create_nonce"):
            return Ok({"slot": row.managed_slot, "previous_ttl": row.ttl, "introduced": True})
        recovered = _recover_create(gateway, zone_binding(zone), row, record_spec(row, ttl=row.ttl))
        if recovered.is_err():
            return Err(recovered.unwrap_err(), retriability=retriability_of(recovered))
    current = gateway.get_record(zone_binding(zone), row.provider_record_id, expected_owner_tag=row.owner_tag)
    if current.is_err():
        return Err(current.unwrap_err(), retriability=retriability_of(current))
    found = current.unwrap()
    if (
        type(found.spec.ttl) is not int
        or not MIN_RECORD_TTL <= found.spec.ttl <= MAX_RECORD_TTL
        or not _spec_matches(found, record_spec(row, ttl=row.ttl), ttl=False)
    ):
        return Err("A managed frontend changed or its TTL cannot be safely bounded and restored")
    return Ok(
        {
            "slot": row.managed_slot,
            "name": row.name,
            "record_type": row.record_type,
            "previous_ttl": found.spec.ttl,
            "provider_record_id": found.id,
            "previous_rdata": found.spec.rdata,
        }
    )


def begin_lowering_locked(
    hostname: AccountHostname, *, epoch: datetime, create_permits: CreatePermits
) -> Result[int, str]:
    """Snapshot each real provider TTL before any write, including www CNAME."""
    maximum = 0
    prepared = []
    from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415  # Cutover identity, not retry clock

    operation_id = str(
        VirtualminMigration.objects.filter(account_id=hostname.account_id, status="lowering_ttl")
        .values_list("pk", flat=True)
        .first()
        or "manual"
    )
    for zone in _zones(hostname):
        valid = _ownership(zone, hostname)
        if valid.is_err():
            return Err(valid.unwrap_err())
        if not _enrolled(zone):
            continue
        evidence = dict(zone.managed_ttl_evidence or {})
        if evidence and (
            evidence.get("hostname_id") != str(hostname.pk)
            or evidence.get("operation_id") != operation_id
            or hostname.previous_ttl is None
        ):
            return Err("A different cutover still owns the managed TTL evidence")
        evidence = evidence or {
            "hostname_id": str(hostname.pk),
            "operation_id": operation_id,
            "started_at": epoch.isoformat(),
            "slots": {},
            "maximum": 0,
        }
        slots = dict(evidence["slots"])
        gateway = get_zone_gateway(zone.provider)
        for row in _web_rows(zone):
            if row.desired_deleted or str(row.pk) in slots:
                continue
            snapshot = _ttl_snapshot(gateway, zone, row, create_permits)
            if snapshot.is_err():
                return Err(snapshot.unwrap_err(), retriability=retriability_of(snapshot))
            slots[str(row.pk)] = snapshot.unwrap()
            evidence["maximum"] = max(int(evidence["maximum"]), int(slots[str(row.pk)]["previous_ttl"]))
        evidence["slots"] = slots
        prepared.append((zone, evidence))
        maximum = max(maximum, int(evidence["maximum"]))
    for zone, evidence in prepared:
        zone.managed_ttl_evidence = evidence
        zone.readiness = {}
        zone.save(update_fields=["managed_ttl_evidence", "readiness", "updated_at"])
    return Ok(maximum)


def _new_family(
    zone: HostedZone, base: HostedZoneRecord, kind: str, data: dict[str, str], allow_create: bool
) -> HostedZoneRecord:
    from apps.domains.dns_zone_models import HostedZoneRecord  # noqa: PLC0415  # ADR-0007

    if not allow_create:
        raise ValueError("Managed DNS needs a committed creation intent for the current target")
    if (
        zone.records.filter(name=base.name, record_type__in=("A", "AAAA", "CNAME"), desired_deleted=False)
        .exclude(managed_by="praho")
        .exists()
    ):
        raise ValueError("An unmanaged record competes with this managed web owner")
    return HostedZoneRecord.objects.create(
        zone=zone,
        name=base.name,
        record_type=kind,
        rdata=data,
        rdata_digest=rdata_digest(data),
        ttl=base.ttl,
        managed_by="praho",
        managed_slot=("apex" if base.name == zone.name else "www") + ":" + kind,
        desired_revision=zone.current_revision,
    )


def _refresh_families(
    zone: HostedZone, hostname: AccountHostname, rows: list[HostedZoneRecord], *, allow_create: bool = True
) -> list[HostedZoneRecord]:
    from apps.domains.dns_zone_import import make_record_data  # noqa: PLC0415  # ADR-0007

    server = hostname.target_server
    if server is None:
        return rows
    address_owners = {row.name for row in rows if row.record_type in {"A", "AAAA"}}
    for name in sorted(address_owners):
        base = next(row for row in rows if row.name == name and row.record_type in {"A", "AAAA"})
        for kind, address in (("A", server.ipv4_address), ("AAAA", server.ipv6_address)):
            row = next((row for row in rows if row.name == name and row.record_type == kind), None)
            if not address:
                if row is not None and not row.desired_deleted:
                    row.desired_deleted = True
                    row.save(update_fields=["desired_deleted", "updated_at"])
                continue
            data = make_record_data(kind, str(address), origin=zone.name)
            if row is None:
                row = _new_family(zone, base, kind, data, allow_create)
                rows.append(row)
            elif row.rdata != data or row.desired_deleted:
                row.rdata, row.rdata_digest, row.desired_deleted = data, rdata_digest(data), False
                row.save(update_fields=["rdata", "rdata_digest", "desired_deleted", "updated_at"])
    for row in rows:
        if row.record_type == "CNAME":
            data = make_record_data("CNAME", hostname.fqdn + ".", origin=zone.name)
            if row.rdata != data or row.desired_deleted:
                row.rdata, row.rdata_digest, row.desired_deleted = data, rdata_digest(data), False
                row.save(update_fields=["rdata", "rdata_digest", "desired_deleted", "updated_at"])
    return rows


def _ttl_for(zone: HostedZone, row: HostedZoneRecord, hostname: AccountHostname, mode: TtlMode) -> int:
    snapshot = (zone.managed_ttl_evidence or {}).get("slots", {}).get(str(row.pk), {})
    if mode == "restore":
        return int(snapshot.get("previous_ttl", row.ttl))
    if mode == "lower" or hostname.previous_ttl is not None:
        return config.account_cutover_ttl_seconds()
    return row.ttl


def _recover_create(
    gateway: ZoneGateway, binding: ZoneBinding, row: HostedZoneRecord, spec: ZoneRecordSpec
) -> Result[None, str]:
    inventory = gateway.list_records(binding)
    if inventory.is_err():
        return Err(inventory.unwrap_err(), retriability=retriability_of(inventory))
    matches = [record for record in inventory.unwrap().records if record.spec.owner_tag == row.owner_tag]
    if len(matches) != 1 or (
        matches[0].spec.name != spec.name
        or matches[0].spec.record_type != spec.record_type
        or matches[0].spec.proxied is not False
    ):
        return Err("A managed record creation has an unresolved outcome")
    row.provider_record_id = matches[0].id
    row.save(update_fields=["provider_record_id", "updated_at"])
    return Ok(None)


def _delete_row(gateway: ZoneGateway, binding: ZoneBinding, row: HostedZoneRecord) -> Result[None, str]:
    if row.provider_record_id:
        deleted = gateway.delete_record(binding, row.provider_record_id, expected_owner_tag=row.owner_tag)
        if deleted.is_err():
            return Err(deleted.unwrap_err(), retriability=retriability_of(deleted))
    row.provider_record_id, row.applied_ttl, row.applied_rdata = "", None, {}
    row.evidence = {**row.evidence, "create_issued": False, "delete_confirmed_at": timezone.now().isoformat()}
    row.applied_revision = row.desired_revision
    row.save(
        update_fields=[
            "provider_record_id",
            "applied_ttl",
            "applied_rdata",
            "applied_revision",
            "evidence",
            "updated_at",
        ]
    )
    return Ok(None)


def _apply_row(
    zone: HostedZone,
    row: HostedZoneRecord,
    hostname: AccountHostname,
    mode: TtlMode,
    create_permits: CreatePermits | None = None,
) -> Result[None, str]:
    gateway = get_zone_gateway(zone.provider)
    binding = zone_binding(zone)
    permits = create_permits if create_permits is not None else {}
    spec = record_spec(row, ttl=_ttl_for(zone, row, hostname, mode))
    first_create = str(row.pk) in permits and permits[str(row.pk)] == row.evidence.get("create_nonce")
    if not row.provider_record_id and row.evidence.get("create_issued") and (row.desired_deleted or not first_create):
        recovered = _recover_create(gateway, binding, row, spec)
        if recovered.is_err():
            return recovered
    if row.desired_deleted:
        return _delete_row(gateway, binding, row)
    if not row.provider_record_id:
        if not first_create or row.evidence.get("create_rdata_digest") != row.rdata_digest:
            return Err("Managed DNS creation needs a fresh committed intent for this target")
        permits.pop(str(row.pk))
        result = gateway.create_record(binding, spec)
    else:
        result = gateway.update_record(binding, row.provider_record_id, spec)
    if result.is_err():
        return Err(result.unwrap_err(), retriability=retriability_of(result))
    actual = result.unwrap()
    # Even a partial or stale readback is evidence. Keep original TTLs until a
    # subsequent worker confirms the complete set, rather than trusting an ACK.
    row.provider_record_id = actual.id
    row.applied_rdata = {"text": actual.spec.rdata}
    row.applied_ttl = actual.spec.ttl
    row.applied_revision = row.desired_revision if _spec_matches(actual, spec) else None
    row.evidence = {**row.evidence, "confirmed_at": timezone.now().isoformat()}
    row.save(
        update_fields=[
            "provider_record_id",
            "applied_rdata",
            "applied_ttl",
            "applied_revision",
            "evidence",
            "updated_at",
        ]
    )
    if not _spec_matches(actual, spec, ttl=False):
        return Err("The provider has not confirmed managed routing")
    return Ok(None)


def sync_managed_locked(
    hostname: AccountHostname, *, mode: TtlMode = "current", create_permits: CreatePermits | None = None
) -> Result[None, str]:
    for zone in _zones(hostname):
        valid = _ownership(zone, hostname)
        if valid.is_err():
            return valid
        if not _enrolled(zone):
            continue
        try:
            rows = _refresh_families(zone, hostname, _web_rows(zone), allow_create=False)
        except ValueError as error:
            return Err(str(error))
        if hostname.previous_ttl is not None and not zone.managed_ttl_evidence:
            return Err("Managed records joined a cutover without original TTL evidence")
        if zone.managed_ttl_evidence:
            slots = dict(zone.managed_ttl_evidence["slots"])
            added = False
            for row in rows:
                if str(row.pk) not in slots:
                    # A new address family has no old cached answer. Its stable
                    # slot still restores the enrollment's ordinary TTL.
                    slots[str(row.pk)] = {"slot": row.managed_slot, "previous_ttl": row.ttl, "introduced": True}
                    added = True
            if added:
                zone.managed_ttl_evidence = {**zone.managed_ttl_evidence, "slots": slots}
                zone.save(update_fields=["managed_ttl_evidence", "updated_at"])
                type(hostname).objects.filter(pk=hostname.pk).update(ttl_confirmed_at=None)
                hostname.ttl_confirmed_at = None
        for row in rows:
            applied = _apply_row(zone, row, hostname, mode, create_permits)
            if applied.is_err():
                return applied
    return Ok(None)


def ttls_confirmed_locked(hostname: AccountHostname, *, restoring: bool = False) -> bool:
    for zone in _zones(hostname):
        if not _enrolled(zone):
            continue
        if _ownership(zone, hostname).is_err():
            return False
        if not zone.managed_ttl_evidence:
            if hostname.previous_ttl is not None:
                return False
            continue
        rows = _web_rows(zone)
        by_id = {str(row.pk): row for row in rows}
        snapshots = zone.managed_ttl_evidence.get("slots", {})
        if set(by_id) - set(snapshots):
            return False
        for identifier, snapshot in snapshots.items():
            row = by_id.get(identifier)
            if row is None:
                return False
            ttl = int(snapshot["previous_ttl"]) if restoring else config.account_cutover_ttl_seconds()
            deleted_unconfirmed = row.desired_deleted and bool(row.provider_record_id or row.applied_rdata)
            live_unconfirmed = not row.desired_deleted and (
                row.applied_ttl != ttl
                or row.applied_revision != row.desired_revision
                or row.applied_rdata.get("text") != row.rdata.get("text")
            )
            if deleted_unconfirmed or live_unconfirmed:
                return False
    return True


def clear_restored_locked(hostname: AccountHostname) -> bool:
    if not ttls_confirmed_locked(hostname, restoring=True):
        return False
    for zone in _zones(hostname):
        if zone.managed_ttl_evidence:
            zone.managed_ttl_evidence = {}
            zone.save(update_fields=["managed_ttl_evidence", "updated_at"])
    return True


def withdraw_managed_locked(hostname: AccountHostname) -> Result[None, str]:
    for zone in _zones(hostname):
        orphan = (
            hostname.account_id is None
            and zone.account_id is None
            and zone.enrollment_binding.get("hostname_id") == str(hostname.pk)
        )
        valid = Ok(None) if orphan else _ownership(zone, hostname)
        if valid.is_err():
            return valid
        if not _enrolled(zone):
            continue
        for row in _web_rows(zone):
            row.desired_deleted = True
            row.save(update_fields=["desired_deleted", "updated_at"])
            applied = _apply_row(zone, row, hostname, "current")
            if applied.is_err():
                return applied
    return Ok(None)
