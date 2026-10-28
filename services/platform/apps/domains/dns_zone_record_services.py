"""Customer record intents and complete export receipts remain separate from hosting lifetime."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, Unpack
from uuid import UUID, uuid4

import dns.exception
from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_zone_gateway import validate_record_spec
from apps.provisioning.account_hostname_service import lock_for_publication

from . import dns_zone_services as service
from .dns_zone_import import ZoneImportError, make_record_data, parse_zone_file, render_zone_file
from .dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation, HostedZoneRecord
from .dns_zone_record_types import RecordChange, RecordMutation

if TYPE_CHECKING:
    from apps.users.models import User


def lock_data_zone(zone: HostedZone, actor: User | None, *, readonly: bool = False) -> HostedZone | None:
    """Fence linked hosting first; DNS data authority always belongs to the zone's own customer."""
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    account = (
        VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
        .select_related("service")
        .filter(pk=zone.account_id)
        .first()
        if zone.account_id
        else None
    )
    if zone.account_hostname_id:
        lock_for_publication(zone.account_hostname_id)
    if account is not None:
        account.refresh_from_db()
    current = HostedZone.objects.select_for_update(of=("self",)).select_related("service").get(pk=zone.pk)
    if not service._actor_allowed(current.customer_id, actor, readonly=readonly):
        return None
    return current


def current_manifest(zone: HostedZone) -> list[dict[str, Any]]:
    return [
        {
            "id": str(row.pk),
            "name": row.name,
            "record_type": row.record_type,
            "ttl": row.ttl,
            "rdata": row.rdata,
            "rdata_digest": row.rdata_digest,
            "managed_by": row.managed_by,
            "managed_slot": row.managed_slot,
        }
        for row in zone.records.filter(desired_deleted=False).order_by("name", "record_type", "pk")
    ]


def infrastructure(zone: HostedZone, revision: HostedZoneImportRevision) -> list[dict[str, Any]]:
    rows = list(revision.replacements)
    if zone.activation.get("activated_at") or zone.can_offer_nameservers():
        rows = [row for row in rows if row["record_type"] != "NS"]
        for name in zone.assigned_nameservers:
            rows.append(
                {
                    "name": zone.name,
                    "record_type": "NS",
                    "ttl": 300,
                    "rdata": make_record_data("NS", name + "."),
                    "infrastructure": True,
                }
            )
    return rows


def _editable(zone: HostedZone) -> str:
    from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # ADR-0007

    if zone.status in {"deleting", "deleted"} or not zone.provider_zone_id:
        return "zone_not_editable"
    active = zone.operations.filter(status__in=service.LIVE_OPERATIONS).first()
    if active and active.kind != "activate":
        return "zone_operation_busy"
    if active and active.lease_token and active.lease_until and active.lease_until > timezone.now():
        return "zone_operation_busy"
    if zone.managed_ttl_evidence or (zone.account is not None and account_has_active_operation(zone.account)):
        return "hosting_operation_busy"
    if zone.account_id is None and zone.records.filter(managed_by="praho", desired_deleted=False).exists():
        return "managed_withdrawal_required"
    return ""


def _record_data(record_type: str, text: str, origin: str) -> dict[str, str]:
    """Customer record text is parsed only here; every parser refusal is the fixed invalid-record answer."""
    try:
        return make_record_data(record_type, text, origin=origin)
    except (ValueError, dns.exception.DNSException) as error:
        raise ValueError("invalid_record") from error


def _change_rows(
    zone: HostedZone,
    manifest: list[dict[str, Any]],
    change: RecordChange,
) -> list[dict[str, Any]]:
    record_id = change.record_id
    current = next((row for row in manifest if row["id"] == str(record_id)), None) if record_id else None
    if record_id and current is None:
        raise ValueError("record_not_found")
    if current and current["managed_by"] == "praho":
        raise ValueError("managed_record")
    output = [row for row in manifest if row is not current]
    if change.delete:
        if current is None:
            raise ValueError("record_not_found")
        return output
    identifier = str(record_id or uuid4())
    row: dict[str, Any] = {
        "id": identifier,
        "name": change.name,
        "record_type": change.record_type.upper(),
        "ttl": change.ttl,
        "rdata": _record_data(change.record_type.upper(), change.rdata, zone.name),
        "managed_by": "customer",
        "managed_slot": "",
    }
    checked = validate_record_spec(service.spec_from_manifest(row), zone_name=zone.name)
    if checked.is_err():
        raise ValueError("invalid_record")
    normalized = checked.unwrap()
    row.update(name=normalized.name, rdata=_record_data(normalized.record_type, normalized.rdata, zone.name))
    row["rdata_digest"] = hashlib.sha256(bytes.fromhex(row["rdata"]["wire"])).hexdigest()
    if any(
        (other["name"], other["record_type"], other["rdata_digest"])
        == (row["name"], row["record_type"], row["rdata_digest"])
        for other in output
    ):
        raise ValueError("duplicate_record")
    at_owner = [other for other in output if other["name"] == row["name"]]
    managed = [other for other in at_owner if other["managed_by"] == "praho"]
    if managed and (
        row["record_type"] in {"A", "AAAA", "CNAME"} or any(other["record_type"] == "CNAME" for other in managed)
    ):
        raise ValueError("managed_owner")
    if (row["record_type"] == "CNAME" and at_owner) or any(other["record_type"] == "CNAME" for other in at_owner):
        raise ValueError("cname_conflict")
    output.append(row)
    return sorted(output, key=lambda item: (item["name"], item["record_type"], item["rdata_digest"]))


def request_record_change(
    zone: HostedZone,
    expected_revision: int,
    *,
    actor: User | None,
    **change: Unpack[RecordMutation],
) -> Result[HostedZoneImportRevision, str]:
    with transaction.atomic():
        current = lock_data_zone(zone, actor)
        if current is None:
            return Err("zone_access_denied")
        if current.current_revision != expected_revision:
            return Err("stale_import_revision")
        refusal = _editable(current)
        if refusal:
            return Err(refusal)
        source = current.revisions.get(number=current.current_revision)
        before = current_manifest(current)
        try:
            manifest = _change_rows(current, before, RecordChange(**change))
            service.ensure_provable_rrsets(manifest)
            raw = render_zone_file(current.name, manifest, infrastructure=infrastructure(current, source))
            parsed = parse_zone_file(raw, current.name)
            counts: dict[tuple[str, str], int] = {}
            for row in manifest:
                key = row["name"], row["record_type"]
                counts[key] = counts.get(key, 0) + len(row["rdata"]["text"])
                if counts[key] > service.MAX_RRSET_CONTENT_LENGTH:
                    raise ValueError("rrset_content_limit")
        except (ZoneImportError, ValueError) as error:
            return Err(error.code if isinstance(error, ZoneImportError) else str(error))
        current.operations.filter(
            kind="activate", status__in=service.LIVE_OPERATIONS
        ).update(  # fsm-bypass: operation status is a CharField; supersede an idle poll.
            status="failed", last_error="superseded_by_customer_intent"
        )
        revision = HostedZoneImportRevision.objects.create(
            zone=current,
            number=expected_revision + 1,
            raw_upload=raw,
            raw_digest=parsed.raw_digest,
            inventory_digest=parsed.digest,
            manifest_digest=service._digest(manifest),
            inventory=[item.as_dict() for item in parsed.records],
            manifest=manifest,
            replacements=[item.as_dict() for item in parsed.replacements],
            normalizations=[{"kind": "customer_record_change", "before": before, "after": manifest}],
            binding=current.enrollment_binding,
            valid=True,
            crosscheck={
                "complete": True,
                "ok": True,
                "basis": "existing_owned_zone",
                "checked_at": timezone.now().isoformat(),
                "source_revision": source.crosscheck.get("source_revision", str(source.pk)),
                "ds_ttl": int(source.crosscheck.get("ds_ttl", 0)),
            },
            confirmed_at=timezone.now(),
            confirmed_by=actor,
        )
        HostedZoneRecord.objects.filter(zone=current).update(desired_deleted=True)
        for row in manifest:
            HostedZoneRecord.objects.update_or_create(
                pk=UUID(row["id"]),
                defaults={
                    "zone": current,
                    "name": row["name"],
                    "record_type": row["record_type"],
                    "rdata": row["rdata"],
                    "rdata_digest": row["rdata_digest"],
                    "ttl": row["ttl"],
                    "managed_by": row["managed_by"],
                    "managed_slot": row["managed_slot"],
                    "desired_revision": revision.number,
                    "desired_deleted": False,
                },
            )
        current.current_revision = current.confirmed_revision = revision.number
        current.readiness = {}
        current.save(update_fields=["current_revision", "confirmed_revision", "readiness", "updated_at"])
        operation = HostedZoneOperation.objects.create(
            zone=current, revision=revision, kind="edit", evidence={"prior_manifest": before}
        )
        service._audit(
            current,
            "dns_zone_record_change_requested",
            actor=actor,
            metadata={"operation": str(operation.pk), "revision": revision.number, "digest": revision.manifest_digest},
        )
        return Ok(revision)


def export_zone_file(zone: HostedZone, *, actor: User | None) -> Result[bytes, str]:
    with transaction.atomic():
        # A technical write: the receipt it records is the precondition of a whole-zone deletion.
        current = lock_data_zone(zone, actor)
        if current is None:
            return Err("zone_access_denied")
        if current.status in {"deleting", "deleted"}:
            return Err("zone_not_exportable")
        source = current.revisions.filter(number=current.current_revision, valid=True).first()
        if source is None:
            return Err("valid_zone_revision_required")
        manifest = current_manifest(current) if current.records.exists() else source.manifest
        try:
            raw = render_zone_file(current.name, manifest, infrastructure=infrastructure(current, source))
            parse_zone_file(raw, current.name)
        except ZoneImportError as error:
            return Err(error.code)
        digest = hashlib.sha256(raw).hexdigest()
        current.deletion = {
            **current.deletion,
            "export_digest": digest,
            "export_revision": current.current_revision,
            "export_manifest_digest": service._digest(manifest),
            "exported_by": str(actor.pk) if actor else "system",
            "exported_at": timezone.now().isoformat(),
        }
        current.save(update_fields=["deletion", "updated_at"])
        service._audit(
            current, "dns_zone_exported", actor=actor, metadata={"revision": current.current_revision, "digest": digest}
        )
        return Ok(raw)
