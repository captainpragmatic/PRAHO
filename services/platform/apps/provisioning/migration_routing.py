"""Frontend routing observations and cache clocks for retained source bridges."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_agreement import Agreement, routing_agreement

from .account_hostname_config import bridge_window_hours

if TYPE_CHECKING:
    from apps.users.models import User

    from .migration_bridge_service import BridgePreparation
    from .virtualmin_migration_models import MigrationBridge, VirtualminMigration
    from .virtualmin_models import VirtualminServer

MAX_FRONTEND_NAMES = 12
MAX_FQDN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_ATTESTATION_LENGTH = 1000


def _inventory(names: tuple[str, ...] | list[str]) -> list[str]:
    if not names or len(names) > MAX_FRONTEND_NAMES:
        raise ValueError("The frontend DNS inventory is missing or exceeds the probe limit")
    normalised = sorted({name.lower().rstrip(".") for name in names})
    for name in normalised:
        if (
            len(name) > MAX_FQDN_LENGTH
            or "." not in name
            or any(not label or len(label) > MAX_LABEL_LENGTH for label in name.split("."))
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name)
        ):
            raise ValueError("The frontend DNS inventory contains an invalid name")
    return normalised


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def _ttl(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("The original customer DNS TTL is unknown; its cache lifetime cannot be bounded")
    return value


def _snapshot_ttl(observed: Agreement) -> int:
    """Only complete authority evidence bounds caches; an opaque origin may still have known TTLs."""
    ttl = _ttl(observed.ttl)
    if observed.agreed:
        return ttl
    # A completed address mismatch still exposes every authority's cache TTL. Discovery,
    # missing/failed questions, divergent aliases and unfinished CNAME chains do not.
    complete_mismatch = bool(observed.detail) and all(
        ": answered " in problem and ", expected " in problem for problem in observed.detail.split("; ")
    )
    questions: dict[tuple[str, str], list[str]] = {}
    for answer in observed.answers:
        if answer.error:
            raise ValueError("The original customer DNS TTL is incomplete on an authoritative server")
        _ttl(answer.ttl)
        key = (getattr(answer, "queried_name", ""), answer.nameserver)
        questions.setdefault(key, []).append(answer.record_type)
    if not complete_mismatch or not questions or any(sorted(types) != ["A", "AAAA"] for types in questions.values()):
        raise ValueError("The original customer DNS TTL lacks complete authoritative routing evidence")
    return ttl


def _ipv4(server: VirtualminServer) -> str:
    address = server.ipv4_address or getattr(getattr(server, "node_deployment", None), "ipv4_address", "")
    if not address:
        raise ValueError("The routing node has no IPv4 address")
    return str(address)


def snapshot_frontends(migration: VirtualminMigration, names: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Capture old cache bounds before commit; a later shorter TTL never erases an earlier bound."""
    from .account_hostname_models import AccountHostname  # noqa: PLC0415

    hostname = AccountHostname.objects.get(account_id=migration.account_id, retired_at__isnull=True)
    names_to_check = _inventory(
        list(dict.fromkeys((*names, migration.account.domain, f"www.{migration.account.domain}", hostname.fqdn)))
    )
    saved = dict(migration.barrier_state.get("frontend_dns_before", {}))
    source = migration.source_server
    for name in names_to_check:
        observed = routing_agreement(name, _ipv4(source), source.ipv6_address or None, allow_absent=True)
        previous = saved.get(name, {})
        ttl = _snapshot_ttl(observed)
        if "ttl" in previous:
            ttl = max(ttl, _ttl(previous["ttl"]))
        saved[name] = {"ttl": ttl, "checked_at": timezone.now().isoformat(), "observation": asdict(observed)}
    return saved


def retained_ttl(snapshots: dict[str, dict[str, Any]]) -> int:
    return max((_ttl(value.get("ttl")) for value in snapshots.values()), default=0)


def prepare_frontend_snapshot(migration: VirtualminMigration, preparation: BridgePreparation) -> dict[str, Any]:
    """The source certificate must cover retention plus the longest precommit customer cache."""
    snapshots = snapshot_frontends(migration, preparation.dns_names)
    required_until = timezone.now() + timedelta(hours=bridge_window_hours() + 1, seconds=retained_ttl(snapshots))
    if preparation.certificate_not_after <= required_until:
        raise ValueError("Bridge certificates do not cover the window and original customer DNS TTLs")
    return {
        "certificate_not_after": preparation.certificate_not_after.isoformat(),
        "dns_names": sorted(snapshots),
        "frontend_dns_before": snapshots,
    }


def _attested(bridge: MigrationBridge, names: list[str], agreement: Agreement, now: datetime) -> bool:
    """Only a current staff statement about opaque external origins may supplement DNS evidence."""
    statement = bridge.evidence.get("routing_attestation")
    if not isinstance(statement, dict):
        return False
    expires = _date(statement.get("expires_at"))
    if (
        expires is None
        or expires <= now
        or not statement.get("actor")
        or not statement.get("note")
        or statement.get("target_id") != str(bridge.target_server_id)
        or statement.get("ipv4") != _ipv4(bridge.target_server)
        or statement.get("ipv6") != (bridge.target_server.ipv6_address or "")
        or statement.get("names") != sorted(names)
    ):
        return False
    # A statement cannot override records that demonstrably still publish this source,
    # or a failed DNS query. It is for a public proxy whose private origin staff inspected.
    # Only a completed address mismatch is an opaque-origin candidate. Missing, mixed-alias,
    # cycle and timeout results have their own refusal details and cannot be attested away.
    if not agreement.detail or not all(
        ": answered " in problem and ", expected " in problem for problem in agreement.detail.split("; ")
    ):
        return False
    try:
        addresses = {ipaddress.ip_address(address) for answer in agreement.answers for address in answer.addresses}
        source_addresses = {ipaddress.ip_address(_ipv4(bridge.source_server))}
        if bridge.source_server.ipv6_address:
            source_addresses.add(ipaddress.ip_address(bridge.source_server.ipv6_address))
    except ValueError:
        return False
    return (
        bool(addresses)
        and all(address.is_global for address in addresses)
        and not any(answer.error for answer in agreement.answers)
        and not (addresses & source_addresses)
    )


def observe_frontends(
    bridge: MigrationBridge, *, now: datetime | None = None
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Require fresh routing and age each old frontend TTL after its first target confirmation."""
    checked = now or timezone.now()
    try:
        names = _inventory(bridge.evidence.get("dns_names", []))
    except ValueError as error:
        return {}, [str(error)]
    saved = bridge.evidence.get("routing", {})
    before = bridge.evidence.get("frontend_dns_before", {})
    results: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for name in names:
        agreement = routing_agreement(
            name, _ipv4(bridge.target_server), bridge.target_server.ipv6_address or None, allow_absent=True
        )
        prior = saved.get(name, {})
        try:
            ttl = _ttl(before.get(name, {}).get("ttl"))
            ttl = max(ttl, _ttl(prior["ttl"])) if "ttl" in prior else ttl
        except ValueError as error:
            results[name] = {
                "ttl": None,
                "checked_at": checked.isoformat(),
                "agreed": False,
                "confirmed_at": None,
                "cache_until": None,
                "attested": False,
                "observation": asdict(agreement),
            }
            errors.append(f"{name}: {error}")
            continue
        # A stale answer can expose a larger cache bound than the precommit snapshot.
        if not agreement.agreed and agreement.ttl is not None:
            ttl = max(ttl, _ttl(agreement.ttl))
        attested = not agreement.agreed and _attested(bridge, names, agreement, checked)
        verified = agreement.agreed or attested
        confirmed = (_date(prior.get("confirmed_at")) or checked) if verified else None
        until = confirmed + timedelta(seconds=ttl) if confirmed is not None else None
        results[name] = {
            "ttl": ttl,
            "checked_at": checked.isoformat(),
            "agreed": verified,
            "confirmed_at": confirmed.isoformat() if confirmed else None,
            "cache_until": until.isoformat() if until else None,
            "attested": attested,
            "observation": asdict(agreement),
        }
        if not verified:
            errors.append(f"{name}: {agreement.detail or 'Customer DNS does not reach the target'}")
        elif until is not None and until > checked:
            errors.append(f"{name}: waiting for old customer DNS caches until {until.isoformat()}")
    return results, errors


def _attestation_expiry(bridge: MigrationBridge, names: list[str]) -> datetime:
    before = bridge.evidence.get("frontend_dns_before", {})
    ttl = max(
        retained_ttl({name: before.get(name, {}) for name in names}), retained_ttl(bridge.evidence.get("routing", {}))
    )
    expires = timezone.now() + timedelta(seconds=max(ttl, bridge_window_hours() * 3600)) + timedelta(hours=1)
    certificate_deadline = _date(bridge.evidence.get("certificate_not_after"))
    if certificate_deadline is None or expires >= certificate_deadline:
        raise ValueError("The bridge certificates do not cover this origin statement and its cache wait")
    return expires


def attest_proxy_origin(bridge: MigrationBridge, actor: User | None, fields: Mapping[str, str]) -> Result[None, str]:
    """Record a staff inspection bound to this target, its current addresses, and the complete inventory.

    Caller holds the bridge row lock and has excluded cleanup workers. The statement supplements
    opaque public addresses; every cleanup still needs fresh DNS and may never override the source.
    """
    from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

    from .account_hostname_models import AccountHostname  # noqa: PLC0415
    from .virtualmin_models import VirtualminAccount, VirtualminServer  # noqa: PLC0415

    if actor is None or not (actor.is_staff or actor.is_superuser):
        return Err("Only staff may attest an external proxy origin")
    try:
        names = _inventory(bridge.evidence.get("dns_names", []))
    except ValueError as error:
        return Err(str(error))
    target = VirtualminServer.objects.get(pk=bridge.target_server_id)
    account = VirtualminAccount.objects.get(pk=bridge.migration.account_id)
    if (
        account.server_id != target.pk
        or not AccountHostname.objects.filter(account=account, target_server=target, retired_at__isnull=True).exists()
        or fields.get("target_id") != str(target.pk)
        or fields.get("ipv4") != _ipv4(target)
        or fields.get("ipv6", "") != (target.ipv6_address or "")
    ):
        return Err("The origin statement does not match current target ownership and addresses")
    note = fields.get("note", "").strip()
    if not note or len(note) > MAX_ATTESTATION_LENGTH:
        return Err("Describe the inspected external proxy origin in at most 1000 characters")
    try:
        expires = _attestation_expiry(bridge, names)
    except ValueError as error:
        return Err(str(error))
    statement = {
        "actor": str(actor.pk),
        "note": note,
        "target_id": str(target.pk),
        "ipv4": _ipv4(target),
        "ipv6": target.ipv6_address or "",
        "names": names,
        "checked_at": timezone.now().isoformat(),
        "expires_at": expires.isoformat(),
    }
    bridge.evidence = {**bridge.evidence, "routing_attestation": statement}
    bridge.save(update_fields=["evidence", "updated_at"])
    AuditService.log_event(
        AuditEventData(
            event_type="virtualmin_bridge_origin_attested",
            content_object=bridge,
            description="Staff verified the external proxy origin for the committed target",
            new_values=statement,
        ),
        AuditContext(user=actor, actor_type="user", metadata={"source_app": "provisioning"}),
    )
    return Ok(None)
