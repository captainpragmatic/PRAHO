"""Offline zone intents and exact revision/tenant/target confirmation boundaries."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Unpack, cast
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_probes import MAX_RECORDS as MAX_PROBE_RECORDS
from apps.infrastructure.dns_zone_gateway import ZoneBinding, ZoneRecordSpec, ZoneRecordType, validate_record_spec
from apps.provisioning.account_hostname_hosting import records_published
from apps.provisioning.account_hostname_service import lock_for_publication

from .dns_zone_import import (
    MAX_UPLOAD_BYTES,
    ZoneImportError,
    make_record_data,
    normalize_zone_name,
    parse_zone_file,
    render_zone_file,
)
from .dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation, HostedZoneRecord
from .dns_zone_record_types import RecordMutation

if TYPE_CHECKING:
    from apps.provisioning.account_hostname_models import AccountHostname
    from apps.provisioning.virtualmin_models import VirtualminAccount
    from apps.users.models import User

CROSSCHECK_MAX_AGE = timedelta(hours=1)
LIVE_OPERATIONS = ("pending", "running", "waiting", "parked")
# A source check that failed on the uploaded inventory itself: no retry of that inventory can pass.
SUPERSEDABLE_SOURCE_CODES = frozenset({"source_record_missing_from_inventory", "source_owner_uncheckable"})
# Evidence an apply operation records on reaching the provider (create, read-back, record write).
_PROVIDER_STAGE_EVIDENCE = frozenset({"provider_account_id", "inventory", "mutation"})
MAX_RRSET_CONTENT_LENGTH = 8192
MAX_PUBLIC_PAGE_SIZE = 100


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def capture_enrollment_binding(account: VirtualminAccount, hostname: AccountHostname) -> dict[str, Any]:
    """Read canonical ownership again; callers supply the current locked account/name for mutations."""
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    account = VirtualminAccount.objects.select_related("service", "server").get(pk=account.pk)
    if (
        hostname.account_id != account.pk
        or hostname.retired_at is not None
        or hostname.target_server_id is None
        or account.status not in {"active", "suspended"}
        or account.service.status not in {"active", "suspended"}
        or account.server_id != hostname.target_server_id
    ):
        raise ValueError("hosting_name_unavailable")
    target = hostname.target_server
    if target is None:
        raise ValueError("hosting_name_unavailable")
    return {
        "customer_id": str(account.service.customer_id),
        "service_id": str(account.service_id),
        "account_id": str(account.pk),
        "hostname_id": str(hostname.pk),
        "name": normalize_zone_name(account.domain),
        "account_name": hostname.fqdn,
        "target_id": str(hostname.target_server_id),
        "ipv4": str(target.ipv4_address or ""),
        "ipv6": str(target.ipv6_address or ""),
    }


def validate_zone_binding(
    zone: HostedZone, account: VirtualminAccount, hostname: AccountHostname, *, require_target: bool = True
) -> Result[None, str]:
    try:
        current = capture_enrollment_binding(account, hostname)
    except ValueError as error:
        return Err(str(error))
    keys: tuple[str, ...] = ("customer_id", "service_id", "account_id", "hostname_id", "name", "account_name")
    if require_target:
        keys += ("target_id", "ipv4", "ipv6")
        if not account_name_published(hostname, current):
            return Err("hosting_name_unpublished")
    if (
        str(zone.customer_id) != current["customer_id"]
        or str(zone.service_id) != current["service_id"]
        or str(zone.account_id) != current["account_id"]
        or str(zone.account_hostname_id) != current["hostname_id"]
        or zone.name != current["name"]
        or any(zone.enrollment_binding.get(key) != current[key] for key in keys)
    ):
        return Err("stale_enrollment_binding")
    return Ok(None)


def account_name_published(hostname: AccountHostname, binding: dict[str, Any]) -> bool:
    records = hostname.records or {}
    return bool(
        records_published(hostname)
        and records.get("A", {}).get("applied") == binding["ipv4"]
        and (records.get("AAAA", {}).get("applied") or "") == binding["ipv6"]
    )


def provider_binding(zone: HostedZone) -> ZoneBinding:
    if not zone.provider_account_id or not zone.provider_zone_id:
        raise ValueError("provider_zone_unbound")
    return ZoneBinding(zone.provider, zone.provider_account_id, zone.provider_zone_id, zone.name)


def _actor_allowed(customer_id: int | str, actor: User | None, *, readonly: bool = False) -> bool:
    if actor is None:
        return True  # Internal callers; API callers always pass their authenticated user.
    if not actor.is_active:
        return False
    if actor.is_staff_user:
        return True
    from apps.users.models import CustomerMembership  # noqa: PLC0415

    membership = CustomerMembership.objects.filter(customer_id=customer_id, user=actor, is_active=True)
    return membership.exists() if readonly else membership.filter(role__in=("owner", "tech")).exists()


def _audit(zone: HostedZone, action: str, *, actor: User | None = None, metadata: dict[str, Any] | None = None) -> None:
    from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

    AuditService.log_event(
        AuditEventData(
            event_type=action, content_object=zone, description="Customer DNS zone", new_values=metadata or {}
        ),
        AuditContext(user=actor, actor_type="user" if actor else "system", metadata={"source_app": "domains"}),
    )


def _name_for_account(account: VirtualminAccount) -> AccountHostname | None:
    from apps.provisioning.account_hostname_models import AccountHostname  # noqa: PLC0415  # ADR-0007

    row = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    return lock_for_publication(row.pk) if row else None


def _manifest(
    zone: HostedZone, inventory: list[dict[str, Any]], binding: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ensure_provable_rrsets(inventory)
    names = {zone.name, f"www.{zone.name}"}
    before = [item for item in inventory if item["name"] in names and item["record_type"] in {"A", "AAAA", "CNAME"}]
    output = [
        {**item, "managed_by": "imported", "managed_slot": ""}
        for item in inventory
        if not item.get("infrastructure") and item not in before
    ]
    ttl = min((int(item["ttl"]) for item in before), default=300)
    for kind, value in (("A", binding["ipv4"]), ("AAAA", binding["ipv6"])):
        if value:
            output.append(
                {
                    "name": zone.name,
                    "record_type": kind,
                    "rdata": make_record_data(kind, value),
                    "ttl": ttl,
                    "managed_by": "praho",
                    "managed_slot": f"apex:{kind}",
                }
            )
    www = f"www.{zone.name}"
    direct = any(item["name"] == www and item["record_type"] in {"A", "AAAA"} for item in before)
    other_at_www = any(item["name"] == www for item in output)
    www_values = (
        [(kind, binding[key]) for kind, key in (("A", "ipv4"), ("AAAA", "ipv6")) if binding[key]]
        if direct or other_at_www
        else [("CNAME", binding["account_name"] + ".")]
    )
    for kind, value in www_values:
        output.append(
            {
                "name": www,
                "record_type": kind,
                "rdata": make_record_data(kind, value),
                "ttl": ttl,
                "managed_by": "praho",
                "managed_slot": f"www:{kind}",
            }
        )
    previous: dict[str, str] = {}
    for record in zone.records.all():
        previous[record.managed_slot or f"{record.name}:{record.record_type}:{record.rdata_digest}"] = str(record.pk)
    old = zone.revisions.filter(number=zone.current_revision).first()
    for item in old.manifest if old else []:
        previous.setdefault(
            item["managed_slot"] or f"{item['name']}:{item['record_type']}:{item['rdata_digest']}", item["id"]
        )
    sizes: dict[tuple[str, str], int] = {}
    identities: set[tuple[str, str, str]] = set()
    for item in output:
        item["id"] = str(uuid4())
        checked = validate_record_spec(spec_from_manifest(item), zone_name=zone.name)
        if checked.is_err():
            raise ValueError("provider_unrepresentable_record")
        normalized = checked.unwrap()
        item["name"] = normalized.name
        item["rdata"] = make_record_data(normalized.record_type, normalized.rdata, origin=zone.name)
        item["rdata_digest"] = hashlib.sha256(bytes.fromhex(item["rdata"]["wire"])).hexdigest()
        identity = item["name"], item["record_type"], item["rdata_digest"]
        if identity in identities:
            raise ValueError("provider_unrepresentable_record")
        identities.add(identity)
        slot = item["managed_slot"] or f"{item['name']}:{item['record_type']}:{item['rdata_digest']}"
        item["id"] = previous.get(slot, str(uuid4()))
        key = item["name"], item["record_type"]
        sizes[key] = sizes.get(key, 0) + len(item["rdata"]["text"])
        if sizes[key] > MAX_RRSET_CONTENT_LENGTH:
            raise ValueError("provider_unrepresentable_record")
    output.sort(key=lambda item: (item["name"], item["record_type"], item["rdata_digest"]))
    parse_zone_file(
        render_zone_file(zone.name, output, infrastructure=[item for item in inventory if item.get("infrastructure")]),
        zone.name,
    )
    return output, [
        {
            "kind": "managed_frontend",
            "before": before,
            "after": [item for item in output if item["managed_by"] == "praho"],
        }
    ]


def ensure_provable_rrsets(rows: list[dict[str, Any]]) -> None:
    counts: dict[tuple[str, str], int] = {}
    for row in rows:
        if row.get("infrastructure"):
            continue
        key = row["name"], row["record_type"]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > MAX_PROBE_RECORDS:
            raise ZoneImportError("rrset_record_limit")


def spec_from_manifest(item: dict[str, Any]) -> ZoneRecordSpec:
    return ZoneRecordSpec(
        str(item["id"]),
        str(item["name"]),
        cast(ZoneRecordType, item["record_type"]),
        int(item["ttl"]),
        str(item["rdata"]["text"]),
        f"praho:hosted-zone-record:{item['id']}",
    )


def spec_from_record(record: HostedZoneRecord) -> ZoneRecordSpec:
    return ZoneRecordSpec(
        str(record.pk),
        record.name,
        cast(ZoneRecordType, record.record_type),
        record.ttl,
        str(record.rdata["text"]),
        record.owner_tag,
        record.proxied,
    )


def _preview_binding(
    account: VirtualminAccount, actor: User | None
) -> Result[tuple[AccountHostname, dict[str, Any]], str]:
    hostname = _name_for_account(account)
    account.refresh_from_db()
    if not _actor_allowed(account.service.customer_id, actor):
        return Err("zone_access_denied")
    if hostname is None:
        return Err("hosting_name_unavailable")
    try:
        return Ok((hostname, capture_enrollment_binding(account, hostname)))
    except ValueError as error:
        return Err(str(error))


def _supersedable(operation: HostedZoneOperation) -> bool:
    """A parked source check that provably never reached the provider, so a corrected upload may replace it.

    A crosscheck operation only observes DNS. An apply operation qualifies only if it never left
    `queued`: its source refresh began at preflight and it holds no provider-stage evidence.
    Every other parked or live operation keeps the zone busy.
    """
    if (
        operation.status != "parked"
        or operation.last_error not in SUPERSEDABLE_SOURCE_CODES
        or operation.registrar_operation_id is not None
        or (operation.lease_until is not None and operation.lease_until > timezone.now())
    ):
        return False
    if operation.kind == "crosscheck":
        return True
    return (
        operation.kind == "apply"
        and operation.phase == "refresh_source"
        and operation.evidence.get("source_resume") == "queued"
        and not _PROVIDER_STAGE_EVIDENCE & operation.evidence.keys()
    )


def _supersede(operation: HostedZoneOperation, zone: HostedZone, revision: int) -> tuple[str, bool]:
    """End the parked check under the zone and operation locks: its park code, and whether the zone reopened.

    A zone never applied was failed by this check alone, so it is importing again. A zone applied before
    stays failed until its next completed apply restores it, as any failed zone does. The caller saves the zone.
    """
    code = operation.last_error
    operation.status = "failed"  # fsm-bypass: CharField operation status; replaced under its row lock.
    operation.last_error = "superseded_by_upload"
    operation.evidence = {**operation.evidence, "superseded": {"code": code, "by_revision": revision}}
    operation.lease_token = None
    operation.lease_until = None
    operation.save(update_fields=["status", "last_error", "evidence", "lease_token", "lease_until", "updated_at"])
    if zone.last_error != code:
        return code, False
    zone.last_error = ""
    if zone.status != "failed" or zone.applied_revision is not None or zone.activation.get("activated_at"):
        return code, False
    zone.retry()
    return code, True


def preview_zone_import(
    account: VirtualminAccount, raw: bytes, *, actor: User | None = None
) -> Result[HostedZoneImportRevision, str]:
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    if len(raw) > MAX_UPLOAD_BYTES:
        return Err("upload_limit")
    with transaction.atomic():
        account = (
            VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
            .select_related("service")
            .get(pk=account.pk)
        )
        prepared = _preview_binding(account, actor)
        if prepared.is_err():
            return Err(prepared.unwrap_err())
        hostname, binding = prepared.unwrap()
        zone = HostedZone.objects.select_for_update().filter(name=binding["name"]).exclude(status="deleted").first()
        if zone is None:
            from .models import Domain  # noqa: PLC0415

            registered = Domain.objects.filter(name=binding["name"], customer_id=account.service.customer_id).first()
            zone = HostedZone.objects.create(
                customer_id=account.service.customer_id,
                service=account.service,
                account=account,
                account_hostname=hostname,
                domain=registered,
                name=binding["name"],
                enrollment_binding=binding,
            )
        if validate_zone_binding(zone, account, hostname, require_target=False).is_err():
            return Err("stale_enrollment_binding")
        # Account, zone, then operation: the order the zone worker locks in, so a park and this upload serialize.
        live = zone.operations.select_for_update().filter(status__in=LIVE_OPERATIONS).first()
        if zone.status in {"deleting", "deleted"} or (live is not None and not _supersedable(live)):
            return Err("zone_operation_busy")
        errors: list[dict[str, Any]] = []
        inventory: list[dict[str, Any]] = []
        manifest: list[dict[str, Any]] = []
        normalizations: list[dict[str, Any]] = []
        digest = ""
        replacements: list[dict[str, Any]] = []
        try:
            parsed = parse_zone_file(raw, zone.name)
            inventory = [item.as_dict() for item in parsed.records]
            replacements = [item.as_dict() for item in parsed.replacements]
            normalizations = [{"kind": "duplicate_collapsed", **item.as_dict()} for item in parsed.duplicates]
            digest = parsed.digest
            manifest, managed_diff = _manifest(zone, inventory, binding)
            normalizations.extend(managed_diff)
        except ZoneImportError as error:
            inventory = [item.as_dict() for item in error.records] if error.records else inventory
            errors = [{"code": error.code, "line": error.line}]
        except ValueError:
            errors = [{"code": "provider_unrepresentable_record", "line": 0}]
        number = zone.current_revision + 1
        revision = HostedZoneImportRevision.objects.create(
            zone=zone,
            number=number,
            raw_upload=raw,
            raw_digest=hashlib.sha256(raw).hexdigest(),
            inventory_digest=digest or _digest(inventory),
            manifest_digest=_digest(manifest),
            inventory=inventory,
            manifest=manifest,
            replacements=replacements,
            normalizations=normalizations,
            binding=binding,
            valid=not errors,
            errors=errors,
        )
        metadata: dict[str, Any] = {"revision": number, "valid": revision.valid, "digest": revision.inventory_digest}
        reopened = False
        if live is not None:
            code, reopened = _supersede(live, zone, number)
            metadata.update(superseded_operation=str(live.pk), superseded_code=code)
        zone.current_revision = number
        zone.readiness = {}
        zone.save(update_fields=["current_revision", "readiness", "last_error", "status", "updated_at"])
        _audit(zone, "dns_zone_import_staged", actor=actor, metadata=metadata)
        if reopened:
            _audit(
                zone,
                "dns_zone_state_changed",
                actor=actor,
                metadata={"status": zone.status, "revision": number, "reason": "superseded_by_upload"},
            )
        return Ok(revision)


def _locked_zone(zone: HostedZone, actor: User | None) -> tuple[HostedZone, VirtualminAccount, AccountHostname] | None:
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415  # ADR-0007

    if zone.account_id is None:
        return None
    account = (
        VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
        .select_related("service")
        .filter(pk=zone.account_id)
        .first()
    )
    if account is None or not _actor_allowed(account.service.customer_id, actor):
        return None
    hostname = _name_for_account(account)
    account.refresh_from_db()
    if not _actor_allowed(account.service.customer_id, actor):
        return None
    if hostname is None:
        return None
    current = HostedZone.objects.select_for_update().get(pk=zone.pk)
    if validate_zone_binding(current, account, hostname, require_target=False).is_err():
        return None
    return current, account, hostname


def _crosscheck_current(revision: HostedZoneImportRevision) -> bool:
    checked = revision.crosscheck.get("checked_at")
    try:
        when = parse_datetime(checked) if isinstance(checked, str) else None
        raw_started = revision.crosscheck.get("started_at", checked)
        started = parse_datetime(raw_started) if isinstance(raw_started, str) else None
    except ValueError:
        return False
    return bool(
        revision.crosscheck.get("complete") is True
        and revision.crosscheck.get("ok") is True
        and when is not None
        and timezone.is_aware(when)
        and when >= timezone.now() - CROSSCHECK_MAX_AGE
        and started is not None
        and timezone.is_aware(started)
        and started >= timezone.now() - CROSSCHECK_MAX_AGE
    )


def request_crosscheck(
    zone: HostedZone, expected_revision: int, *, actor: User | None = None
) -> Result[HostedZoneOperation, str]:
    with transaction.atomic():
        locked = _locked_zone(zone, actor)
        if locked is None:
            return Err("zone_access_denied")
        zone, _account, _hostname = locked
        revision = zone.revisions.filter(number=expected_revision, valid=True).first()
        if revision is None or zone.current_revision != expected_revision:
            return Err("stale_import_revision")
        previous = zone.operations.filter(status__in=LIVE_OPERATIONS).first()
        if previous:
            return (
                Ok(previous)
                if previous.kind == "crosscheck" and previous.revision_id == revision.pk
                else Err("zone_operation_busy")
            )
        operation = HostedZoneOperation.objects.create(zone=zone, revision=revision, kind="crosscheck")
        _audit(
            zone,
            "dns_zone_crosscheck_requested",
            actor=actor,
            metadata={"operation": str(operation.pk), "revision": expected_revision},
        )
        return Ok(operation)


def confirm_import(
    zone: HostedZone, expected_revision: int, manifest_digest: str, *, actor: User | None = None
) -> Result[HostedZone, str]:
    with transaction.atomic():
        locked = _locked_zone(zone, actor)
        if locked is None:
            return Err("zone_access_denied")
        zone, account, hostname = locked
        revision = zone.revisions.select_for_update().filter(number=expected_revision, valid=True).first()
        if (
            revision is None
            or zone.current_revision != expected_revision
            or revision.manifest_digest != manifest_digest
        ):
            return Err("stale_import_revision")
        if zone.confirmed_revision == zone.applied_revision == expected_revision and revision.confirmed_at is not None:
            return Ok(zone)
        refusal = _confirmation_refusal(zone, revision, account, hostname)
        if refusal:
            return Err(refusal)
        if zone.operations.filter(status__in=LIVE_OPERATIONS).exists():
            return Ok(zone) if zone.confirmed_revision == expected_revision else Err("zone_operation_busy")
        HostedZoneRecord.objects.filter(zone=zone).update(desired_deleted=True)
        for item in revision.manifest:
            HostedZoneRecord.objects.update_or_create(
                pk=UUID(item["id"]),
                defaults={
                    "zone": zone,
                    "name": item["name"],
                    "record_type": item["record_type"],
                    "rdata": item["rdata"],
                    "rdata_digest": item["rdata_digest"],
                    "ttl": item["ttl"],
                    "managed_by": item["managed_by"],
                    "managed_slot": item["managed_slot"],
                    "desired_revision": expected_revision,
                    "desired_deleted": False,
                },
            )
        revision.confirmed_at = timezone.now()
        revision.confirmed_by = actor
        revision.save(update_fields=["confirmed_at", "confirmed_by"])
        zone.confirmed_revision = expected_revision
        zone.enrollment_binding = revision.binding
        zone.save(update_fields=["confirmed_revision", "enrollment_binding", "updated_at"])
        HostedZoneOperation.objects.create(zone=zone, revision=revision, kind="apply")
        _audit(
            zone,
            "dns_zone_import_confirmed",
            actor=actor,
            metadata={"revision": expected_revision, "digest": manifest_digest},
        )
        return Ok(zone)


def _confirmation_refusal(
    zone: HostedZone, revision: HostedZoneImportRevision, account: VirtualminAccount, hostname: AccountHostname
) -> str:
    from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # ADR-0007

    if capture_enrollment_binding(account, hostname) != revision.binding:
        return "stale_import_target"
    if not account_name_published(hostname, revision.binding):
        return "hosting_name_unpublished"
    if account_has_active_operation(account) or hostname.previous_ttl is not None or zone.managed_ttl_evidence:
        return "hosting_operation_busy"
    return "" if _crosscheck_current(revision) else "source_crosscheck_required"


def _public_record(row: dict[str, Any]) -> dict[str, Any]:
    data = row.get("rdata", {})
    return {
        "id": str(row.get("id", "")),
        "name": str(row.get("name", "")),
        "record_type": str(row.get("record_type", "")),
        "ttl": row.get("ttl"),
        "rdata": str(data.get("text", "")) if isinstance(data, dict) else str(data),
        "managed_by": str(row.get("managed_by", "imported")),
        "managed": row.get("managed_by") == "praho",
        "line": row.get("line"),
        "infrastructure": row.get("infrastructure") is True,
    }


def _public_normalization(row: dict[str, Any], offset: int, size: int) -> dict[str, Any]:
    result = {"kind": row.get("kind", "")}
    if "before" in row:
        result.update(
            before=[_public_record(item) for item in row["before"][offset : offset + size]],
            after=[_public_record(item) for item in row["after"][offset : offset + size]],
            before_total=len(row["before"]),
            after_total=len(row["after"]),
        )
    else:
        result.update(_public_record(row))
    return result


def cached_zone_status(
    zone: HostedZone, *, page: int = 1, page_size: int = MAX_PUBLIC_PAGE_SIZE, actor: User | None = None
) -> dict[str, Any]:
    """Database-only projection: never expose stale or unproven switch instructions.

    With an actor, an export receipt is shown only to the member who downloaded that export.
    """
    zone = HostedZone.objects.select_related("account", "account_hostname").get(pk=zone.pk)
    revision = zone.revisions.defer("raw_upload").filter(number=zone.current_revision).first()
    current = False
    if zone.account is not None and zone.account_hostname is not None:
        current = validate_zone_binding(zone, zone.account, zone.account_hostname).is_ok()
        if current and revision is not None:
            binding = capture_enrollment_binding(zone.account, zone.account_hostname)
            keys = (
                tuple(binding)
                if not zone.activation.get("activated_at")
                else tuple(key for key in binding if key not in {"target_id", "ipv4", "ipv6"})
            )
            current = all(binding[key] == revision.binding.get(key) for key in keys)
    ready = current and zone.can_offer_nameservers() and zone.status in {"awaiting_ns", "active"}
    inventory = revision.inventory if revision else []
    manifest = revision.manifest if revision else []
    normalizations = revision.normalizations if revision else []
    records = zone.records.filter(desired_deleted=False).order_by("name", "record_type", "pk")
    record_count = records.count()
    page_size = min(MAX_PUBLIC_PAGE_SIZE, max(2, page_size))
    groups = [row for row in normalizations if "before" in row]
    ordinary = [row for row in normalizations if "before" not in row]
    ordinary_size = max(1, page_size - len(groups))
    nested = max([max(len(item.get("before", [])), len(item.get("after", []))) for item in groups], default=0)
    pages = max(
        1,
        math.ceil(max(len(inventory), len(manifest), record_count, nested) / page_size),
        math.ceil(len(ordinary) / ordinary_size),
    )
    page = min(pages, max(1, page))
    offset = (page - 1) * page_size
    ordinary_offset = (page - 1) * ordinary_size
    shown_normalizations = groups + ordinary[ordinary_offset : ordinary_offset + ordinary_size]
    return {
        "version": 1,
        "id": str(zone.pk),
        "name": zone.name,
        "status": zone.status,
        "revision": zone.current_revision,
        "valid": bool(revision and revision.valid),
        "manifest_digest": revision.manifest_digest if revision else "",
        "nameservers": zone.assigned_nameservers if ready else [],
        "stale": not current,
        "pending": zone.operations.filter(status__in=LIVE_OPERATIONS).exists(),
        "error": zone.last_error,
        "errors": revision.errors if revision else [],
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "inventory_total": len(inventory),
        "manifest_total": len(manifest),
        "records_total": record_count,
        "normalizations_total": len(normalizations),
        "inventory": [_public_record(row) for row in inventory[offset : offset + page_size]],
        "normalizations": [_public_normalization(row, offset, page_size) for row in shown_normalizations],
        "manifest": [_public_record(row) for row in manifest[offset : offset + page_size]],
        "crosscheck": {key: revision.crosscheck.get(key) for key in ("complete", "ok", "cursor", "total", "error")}
        if revision
        else {},
        "records": [
            _public_record(
                {
                    "id": row.pk,
                    "name": row.name,
                    "record_type": row.record_type,
                    "rdata": row.rdata,
                    "ttl": row.ttl,
                    "managed_by": row.managed_by,
                }
            )
            for row in records[offset : offset + page_size]
        ],
        "can_switch_registrar": can_switch_registrar(zone) if ready else False,
        "export_digest": _current_export_digest(zone, revision, actor),
        "dnssec": {key: zone.dnssec.get(key, "") for key in ("status", "ds")} if zone.status == "active" else {},
    }


def exported_by(zone: HostedZone, actor: User | None) -> bool:
    """A customer's deletion rests on an export that member downloaded, not on another member's receipt."""
    return actor is None or zone.deletion.get("exported_by") == str(actor.pk)


def _current_export_digest(zone: HostedZone, revision: HostedZoneImportRevision | None, actor: User | None) -> str:
    if (
        revision is None
        or zone.deletion.get("export_revision") != zone.current_revision
        or not exported_by(zone, actor)
    ):
        return ""
    from .dns_zone_record_services import current_manifest  # noqa: PLC0415

    manifest = current_manifest(zone) if zone.records.exists() else revision.manifest
    return (
        str(zone.deletion.get("export_digest", ""))
        if zone.deletion.get("export_manifest_digest") == _digest(manifest)
        else ""
    )


def can_switch_registrar(zone: HostedZone) -> bool:
    from django.conf import settings  # noqa: PLC0415

    from .gateways import BaseRegistrarGateway, RegistrarGatewayFactory  # noqa: PLC0415

    domain = zone.domain
    if (
        domain is None
        or domain.name != zone.name
        or domain.customer_id != zone.customer_id
        or domain.status != "active"
    ):
        return False
    adapter = RegistrarGatewayFactory._gateways.get(domain.registrar.name)
    return bool(
        getattr(settings, "REGISTRAR_ADAPTERS_VERIFIED", False)
        and adapter is not None
        and adapter._do_update_nameservers is not BaseRegistrarGateway._do_update_nameservers
        and RegistrarGatewayFactory.serves_operator(domain.registrar)
        and domain.registrar.status == "active"
    )


def request_record_change(
    zone: HostedZone,
    expected_revision: int,
    *,
    actor: User | None = None,
    **mutation: Unpack[RecordMutation],
) -> Result[HostedZoneImportRevision, str]:
    from .dns_zone_record_services import request_record_change as change  # noqa: PLC0415

    return change(zone, expected_revision, actor=actor, **mutation)


def export_zone_file(zone: HostedZone, *, actor: User | None = None) -> Result[bytes, str]:
    from .dns_zone_record_services import export_zone_file as export  # noqa: PLC0415

    return export(zone, actor=actor)


def request_nameserver_switch(
    zone: HostedZone, expected_revision: int, *, actor: User | None = None
) -> Result[HostedZoneOperation, str]:
    from .dns_zone_lifecycle import request_nameserver_switch as switch  # noqa: PLC0415

    return switch(zone, expected_revision, actor=actor)


def request_zone_delete(
    zone: HostedZone, expected_revision: int, export_digest: str, *, actor: User | None = None
) -> Result[HostedZoneOperation, str]:
    from .dns_zone_deletion import request_zone_delete as remove  # noqa: PLC0415

    return remove(zone, expected_revision, export_digest, actor=actor)


def request_operation_retry(zone: HostedZone, *, actor: User | None = None) -> Result[HostedZoneOperation, str]:
    from .dns_zone_deletion import request_operation_retry as retry  # noqa: PLC0415

    return retry(zone, actor=actor)
