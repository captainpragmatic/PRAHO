"""Worker-only source binding for managed mail DNS; no publication or readiness changes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING
from uuid import UUID

import dns.exception
from django.db import connection, transaction

from apps.common.types import Err, Ok, Result, retriability_of
from apps.infrastructure.dns_zone_gateway import (
    ProviderZoneRecord,
    ZoneBinding,
    ZoneInventory,
    canonical_dns_name,
    canonical_rdata,
    get_zone_gateway,
)

from .domain_veto import blocking_domain_status
from .virtualmin_mail_dns import MAX_RECORDS, MailDnsRecord, MailDnsSnapshot, mail_dns_snapshot_digest
from .virtualmin_mail_enrollment import MailIntent, _EnrollmentRefusalError, _locked

if TYPE_CHECKING:
    from apps.users.models import User

    from .virtualmin_models import VirtualminAccount


@dataclass(frozen=True)
class ManagedMailDnsBinding:
    zone_id: UUID
    provider: ZoneBinding
    account_id: UUID
    service_id: int
    customer_id: int
    hostname_id: UUID
    generation: str
    revision: int
    resource_digest: str


@dataclass(frozen=True)
class ManagedMailDnsSource:
    binding: ManagedMailDnsBinding
    snapshot: MailDnsSnapshot


class _SourceRefusalError(ValueError):
    """Only fixed public codes escape provider or mutable model state."""


def _capture(account: VirtualminAccount, actor: User | None, intent: MailIntent) -> ManagedMailDnsBinding:
    from apps.domains.dns_zone_models import HostedZone  # noqa: PLC0415  # ADR-0007
    from apps.domains.dns_zone_services import (  # noqa: PLC0415  # ADR-0007
        LIVE_OPERATIONS,
        provider_binding,
        validate_zone_binding,
    )

    with transaction.atomic(durable=True):
        context = _locked(account, actor)
        current, service, name = context.account, context.service, context.name
        if intent not in {"enable", "disable"}:
            raise _SourceRefusalError("mail_invalid_intent")
        if current.status not in {"active", "suspended"} or service.status not in {"active", "suspended"}:
            raise _SourceRefusalError("mail_account_unavailable")
        if intent == "enable" and (
            current.status != "active" or service.status != "active" or blocking_domain_status(current) is not None
        ):
            raise _SourceRefusalError("mail_hosting_held")
        if current.restore_hold or name.previous_ttl is not None:
            raise _SourceRefusalError("mail_operation_active")
        zones = list(
            HostedZone.objects.select_for_update()
            .filter(account_id=current.pk, name=current.domain.lower().rstrip("."))
            .exclude(status="deleted")
            .order_by("pk")[:2]
        )
        if len(zones) != 1:
            raise _SourceRefusalError("mail_dns_source_unavailable")
        zone = zones[0]
        if (
            zone.status != "active"
            or not zone.current_revision
            or zone.confirmed_revision != zone.current_revision
            or zone.applied_revision != zone.current_revision
            or validate_zone_binding(zone, current, name).is_err()
            or zone.operations.filter(status__in=LIVE_OPERATIONS).exclude(kind__in=("activate", "crosscheck")).exists()
        ):
            raise _SourceRefusalError("mail_dns_source_unavailable")
        try:
            provider = provider_binding(zone)
        except ValueError as error:
            raise _SourceRefusalError("mail_dns_source_unavailable") from error
        return ManagedMailDnsBinding(
            zone.pk,
            provider,
            current.pk,
            current.service_id,
            service.customer_id,
            name.pk,
            context.generation,
            zone.current_revision,
            "",
        )


def _inventory(anchor: ManagedMailDnsBinding, inventory: ZoneInventory) -> tuple[MailDnsSnapshot, str]:
    if inventory.identity.binding != anchor.provider or inventory.identity.status != "active":
        raise _SourceRefusalError("mail_dns_source_identity_changed")
    if not isinstance(inventory.records, tuple) or len(inventory.records) > MAX_RECORDS:
        raise _SourceRefusalError("mail_dns_source_invalid")
    identifiers: set[str] = set()
    records: list[MailDnsRecord] = []
    resources: list[tuple[str, dict[str, object]]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in inventory.records:
        if (
            not isinstance(row, ProviderZoneRecord)
            or not isinstance(row.id, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", row.id) is None
            or row.id in identifiers
        ):
            raise _SourceRefusalError("mail_dns_source_invalid")
        identifiers.add(row.id)
        spec = row.spec
        record = MailDnsRecord(
            canonical_dns_name(spec.name),
            spec.record_type,
            spec.ttl,
            canonical_rdata(spec.record_type, spec.rdata, origin=anchor.provider.name),
            spec.owner_tag,
            spec.proxied,
        )
        key = (record.name, record.record_type, record.rdata)
        if key in seen:
            raise _SourceRefusalError("mail_dns_source_invalid")
        seen.add(key)
        records.append(record)
        resources.append((row.id, asdict(record)))
    rows = tuple(records)
    digest = mail_dns_snapshot_digest(anchor.provider.name, anchor.revision, rows)
    resource_wire = json.dumps(
        {"binding": asdict(anchor), "records": sorted(resources, key=lambda item: item[0])},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return MailDnsSnapshot(anchor.provider.name, anchor.revision, digest, rows), hashlib.sha256(
        resource_wire
    ).hexdigest()


def observe_managed_mail_dns_source(
    account: VirtualminAccount, *, actor: User | None, intent: MailIntent
) -> Result[ManagedMailDnsSource, str]:
    """Observe complete provider records and reject an ownership or resource change during I/O."""
    try:
        if connection.in_atomic_block:
            raise _SourceRefusalError("mail_dns_source_requires_worker")
        anchor = _capture(account, actor, intent)
        inventory = get_zone_gateway(anchor.provider.provider).list_records(anchor.provider)
        if inventory.is_err():
            return Err("mail_dns_source_unavailable", retriability=retriability_of(inventory))
        snapshot, resource_digest = _inventory(anchor, inventory.unwrap())
        try:
            current = _capture(account, actor, intent)
        except _SourceRefusalError as error:
            raise _SourceRefusalError("mail_dns_source_changed") from error
        if current != anchor:
            raise _SourceRefusalError("mail_dns_source_changed")
        return Ok(ManagedMailDnsSource(replace(anchor, resource_digest=resource_digest), snapshot))
    except (_SourceRefusalError, _EnrollmentRefusalError) as error:
        return Err(str(error))
    except (ValueError, TypeError, AttributeError, dns.exception.DNSException):
        return Err("mail_dns_source_invalid")
