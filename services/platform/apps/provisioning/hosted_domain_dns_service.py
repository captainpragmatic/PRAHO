"""Offline public status and lease-fenced publication of background DNS observations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, TypedDict, cast
from uuid import UUID, uuid4

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.common.types import Err, Ok, Result
from apps.provisioning import hosted_domain_dns_config as config

from .account_hostname_hosting import dns_instructions, records_published
from .account_hostname_models import AccountHostname
from .hosted_domain_dns_models import HostedDomainDnsStatus
from .virtualmin_migration_models import MigrationBridge, account_has_active_migration
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

if TYPE_CHECKING:
    from apps.users.models import User

COMPONENTS = ("apex", "www", "caa", "dnssec", "mx")
OBSERVATION_STATES = frozenset({"healthy", "broken", "unknown", "not_applicable"})
MAX_RESULT_BYTES = 65536


class PublicComponent(TypedDict):
    state: str
    code: str


class PublicDnsStatus(TypedDict):
    version: int
    state: str
    dns_path: str
    pending: bool
    stale: bool
    checked_at: str | None
    account_name: str | None
    instructions: list[dict[str, str]]
    components: dict[str, PublicComponent]


@dataclass(frozen=True)
class TargetSnapshot:
    account: VirtualminAccount
    account_name: str
    ipv4: str
    ipv6: str | None
    generation: str
    scope: str
    unavailable: str = ""
    maintenance: bool = False


@dataclass(frozen=True)
class CheckClaim:
    snapshot: TargetSnapshot
    token: UUID


class DnsCheckLeaseLostError(RuntimeError):
    """No stale DNS result or notification may outlive its work claim."""


def _digest(values: object) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def _bridge_window(account: VirtualminAccount) -> tuple[bool, list[str | bool] | None]:
    """A retained working bridge permits old routing only until its recorded deadline."""
    bridge = (
        MigrationBridge.objects.filter(
            migration__account=account,
            migration__cutover_committed_at__isnull=False,
            target_server_id=account.server_id,
            domain=account.domain,
        )
        .order_by("-created_at")
        .first()
    )
    if bridge is None:
        return False, None
    deadline = bridge.evidence.get("expires_at")
    fenced = bool(bridge.evidence.get("source_fenced_control"))
    try:
        expires = parse_datetime(deadline) if isinstance(deadline, str) else None
    except ValueError:
        expires = None
    serving = bool(
        bridge.status
        in {MigrationBridge.Status.PENDING, MigrationBridge.Status.ACTIVE, MigrationBridge.Status.REMOVING_SOURCE}
        and not fenced
        and expires is not None
        and timezone.is_aware(expires)
        and expires > timezone.now()
    )
    # Keep identity after expiry/teardown: dropping it could resurrect a pre-bridge
    # green observation when maintenance changes back to False.
    return serving, [str(bridge.pk), bridge.status, str(deadline), fenced]


def _snapshot(account: VirtualminAccount) -> TargetSnapshot:
    account = VirtualminAccount.objects.select_related("server", "service__customer").get(pk=account.pk)
    name = (
        AccountHostname.objects.select_related("target_server").filter(account=account, retired_at__isnull=True).first()
    )
    unavailable = "" if account.status in {"active", "suspended"} else "account_unavailable"
    if name is None or name.target_server_id != account.server_id or not records_published(name):
        unavailable = unavailable or "account_name_unavailable"
    target = name.target_server if name is not None else None
    ipv4 = str(target.ipv4_address or "") if target is not None else ""
    ipv6 = str(target.ipv6_address) if target is not None and target.ipv6_address else None
    if not ipv4:
        unavailable = unavailable or "target_unavailable"
    retained_bridge, bridge_generation = _bridge_window(account)
    maintenance = (
        bool(account.restore_hold)
        or retained_bridge
        or account_has_active_migration(account)
        or (
            VirtualminProvisioningJob.objects.filter(account=account, operation__in=("restore_domain", "delete_domain"))
            .exclude(status__in=("completed", "failed"))
            .exists()
        )
    )
    fqdn = name.fqdn if name is not None else ""
    scope = _digest([str(account.service_id), str(account.service.customer_id), account.domain, fqdn])
    generation = _digest(
        [
            scope,
            str(account.server_id),
            str(name.target_server_id) if name else "",
            ipv4,
            ipv6,
            account.status,
            unavailable,
            maintenance,
            bridge_generation,
        ]
    )
    return TargetSnapshot(account, fqdn, ipv4, ipv6, generation, scope, unavailable, maintenance)


def _state(row: HostedDomainDnsStatus | None) -> str:
    return "unknown" if row is None or row.healthy is None else "healthy" if row.healthy else "broken"


def _pending(row: HostedDomainDnsStatus | None, now: datetime) -> bool:
    return bool(
        row
        and (
            (row.lease_token and row.lease_until and row.lease_until > now)
            or (row.requested_at and (row.checked_at is None or row.requested_at > row.checked_at))
        )
    )


def _public_components(row: HostedDomainDnsStatus | None, reason: str) -> dict[str, PublicComponent]:
    stored = row.results.get("components", {}) if row else {}
    return {
        key: {
            "state": "unknown" if reason else str(stored.get(key, {}).get("state", "unknown")),
            "code": reason or str(stored.get(key, {}).get("code", "not_checked")),
        }
        for key in COMPONENTS
    }


def cached_status(account: VirtualminAccount) -> PublicDnsStatus:
    """Read only database state; invalidate green immediately when routing or maintenance changes."""
    snapshot = _snapshot(account)
    row = HostedDomainDnsStatus.objects.filter(account_id=account.pk).first()
    now = timezone.now()
    stale = bool(
        row
        and (
            row.expected_generation != snapshot.generation
            or row.checked_at is None
            or row.checked_at < now - timedelta(seconds=2 * config.interval_seconds())
        )
    )
    reason = (
        "monitoring_disabled"
        if not config.enabled()
        else snapshot.unavailable or ("maintenance" if snapshot.maintenance else "stale_result" if stale else "")
    )
    applicable = not snapshot.unavailable and config.enabled()
    instructions = list(dns_instructions(snapshot.account.domain, snapshot.account_name)) if applicable else []
    state = "not_applicable" if not applicable else "unknown" if reason else _state(row)
    return {
        "version": 1,
        "state": state,
        "dns_path": row.dns_path if row and not reason else "unknown",
        "pending": applicable and _pending(row, now),
        "stale": stale,
        "checked_at": row.checked_at.isoformat() if row and row.checked_at else None,
        "account_name": snapshot.account_name if applicable else None,
        "instructions": instructions,
        "components": _public_components(row, reason),
    }


def _actor_allowed(account: VirtualminAccount, actor: User | None) -> bool:
    if actor is None:
        return True  # Internal system callers; HTTP endpoints always pass their authenticated actor.
    if not actor.is_active:
        return False
    if actor.is_staff_user:
        return True
    from apps.users.models import CustomerMembership  # noqa: PLC0415

    return CustomerMembership.objects.filter(
        user=actor, customer_id=account.service.customer_id, is_active=True, role__in=("owner", "tech")
    ).exists()


def _audit(
    account: VirtualminAccount,
    action: str,
    *,
    actor: User | None = None,
    old: dict[str, Any] | None = None,
    new: dict[str, Any] | None = None,
) -> None:
    from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

    AuditService.log_event(
        AuditEventData(
            event_type=action,
            content_object=account,
            description="Hosted domain DNS monitoring",
            old_values=old or {},
            new_values=new or {},
        ),
        AuditContext(user=actor, actor_type="user" if actor else "system", metadata={"source_app": "provisioning"}),
    )


def request_recheck(account: VirtualminAccount, *, actor: User | None = None) -> Result[dict[str, Any], str]:
    """Mark bounded due work. Neither a manual request nor a cached read performs DNS or enqueues a fanout."""
    queued = False
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().select_related("service").get(pk=account.pk)
        snapshot = _snapshot(account)
        if not _actor_allowed(account, actor):
            return Err("Only an active owner or technical contact may recheck DNS")
        if not config.enabled() or snapshot.unavailable or snapshot.maintenance:
            return Err("DNS checks are unavailable while this account is unpublished or in maintenance")
        row, _ = HostedDomainDnsStatus.objects.select_for_update().get_or_create(account=account)
        now = timezone.now()
        recent = row.requested_at and row.requested_at > now - timedelta(seconds=config.recheck_cooldown_seconds())
        active = row.lease_token and row.lease_until and row.lease_until > now
        if not recent and not active:
            row.requested_at = now
            row.next_check_at = now
            row.save(update_fields=["requested_at", "next_check_at", "updated_at"])
            queued = True
            _audit(account, "hosting_dns_recheck_requested", actor=actor, new={"pending": True})
    value: dict[str, Any] = dict(cached_status(account))
    value["queued"] = queued
    return Ok(value)


def claim_check(account_id: str, *, token: UUID | None = None) -> tuple[CheckClaim | None, str]:
    """CAS a work claim under the account lock; release all locks before a DNS packet is sent."""
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
        if account is None or not config.enabled():
            return None, "excluded"
        row, _ = HostedDomainDnsStatus.objects.get_or_create(account=account)
        snapshot = _snapshot(account)
        now = timezone.now()
        rows = HostedDomainDnsStatus.objects.filter(pk=row.pk)
        if token is not None:
            rows = rows.filter(lease_token=token, lease_until__gt=now)
        else:
            rows = rows.filter(Q(lease_token__isnull=True) | Q(lease_until__lte=now))
            if row.next_check_at > now and not (row.lease_token and row.lease_until and row.lease_until <= now):
                return None, "not_due"
        token = token or uuid4()
        if not rows.update(
            lease_token=token,
            lease_until=now + timedelta(seconds=config.LEASE_SECONDS),
            next_check_at=now + timedelta(seconds=config.interval_seconds()),
            updated_at=now,
        ):
            return None, "busy"
        if snapshot.unavailable or snapshot.maintenance:
            HostedDomainDnsStatus.objects.filter(pk=row.pk, lease_token=token).update(
                lease_token=None, lease_until=None, next_check_at=now + timedelta(seconds=config.RETRY_SECONDS)
            )
            return None, "maintenance" if snapshot.maintenance else "excluded"
        return CheckClaim(snapshot, token), "claimed"


def _probe(snapshot: TargetSnapshot) -> dict[str, Any]:
    from apps.infrastructure.dns_probes import ProbeTarget, probe_hosted_domain_dns  # noqa: PLC0415

    return dict(
        probe_hosted_domain_dns(
            ProbeTarget(snapshot.account.domain, snapshot.account_name, snapshot.ipv4, snapshot.ipv6, hosted_mail=False)
        )
    )


def unknown_report(code: str) -> dict[str, Any]:
    return {
        "version": 1,
        "dns_path": "unknown",
        "components": {key: {"state": "unknown", "code": code, "evidence": {}} for key in COMPONENTS},
    }


def _checked_report(result: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(result, allow_nan=False)
    if len(encoded.encode()) > MAX_RESULT_BYTES or result.get("version") != 1:
        raise ValueError("Unusable DNS report version or size")
    components = result.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise ValueError("The DNS report does not contain every component")
    for item in components.values():
        if (
            not isinstance(item, dict)
            or item.get("state") not in OBSERVATION_STATES
            or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", str(item.get("code", ""))) is None
        ):
            raise ValueError("Unusable DNS component")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", str(result.get("dns_path", ""))) is None:
        raise ValueError("Unusable DNS path")
    return cast(dict[str, Any], json.loads(encoded))


def _apply_observation(row: HostedDomainDnsStatus, result: dict[str, Any], now: datetime) -> None:
    components = result["components"]
    states = {item["state"] for item in components.values()}
    row.healthy = False if "broken" in states else None if "unknown" in states or "healthy" not in states else True
    edges = []
    for key, item in components.items():
        previous = row.component_history.get(key, {})
        if item["state"] == "broken" and previous.get("state") == "healthy":
            edges.append(key)
        if item["state"] in {"healthy", "broken"}:
            row.component_history[key] = {"state": item["state"], "code": item["code"], "checked_at": now.isoformat()}
    if row.healthy is True:
        row.last_healthy_at = now
        row.first_failed_at = row.incident_id = row.notified_at = row.alert_email_log_id = None
        row.notification_pending = False
        row.incident_components = []
    elif row.healthy is False and row.incident_id is None:
        row.first_failed_at = now
        row.incident_id = uuid4()
        row.incident_components = [key for key, item in components.items() if item["state"] == "broken"]
        row.notification_pending = bool(edges)
    if row.healthy is False and edges and row.alert_email_log_id is None and row.notified_at is None:
        # An initially broken component has no notification baseline. Another
        # component can later fail from a known healthy state in the same incident.
        row.notification_pending = True
        row.incident_components = [key for key, item in components.items() if item["state"] == "broken"]


def _notify(account: VirtualminAccount, row: HostedDomainDnsStatus, snapshot: TargetSnapshot, now: datetime) -> None:
    if not row.notification_pending or row.alert_email_log_id or row.incident_id is None:
        return
    from apps.customers.services import get_customer_locale  # noqa: PLC0415
    from apps.notifications.services import EmailService  # noqa: PLC0415

    customer = account.service.customer
    www, apex = dns_instructions(account.domain, snapshot.account_name)
    sent = EmailService.send_template_email(
        template_key="hosting_dns_broken",
        recipient=customer.primary_email,
        customer=customer,
        locale=get_customer_locale(customer),
        async_send=True,
        tags={"dns_incident": str(row.incident_id), "account_id": str(account.pk)},
        context={
            "customer_name": customer.get_display_name(),
            "domain": account.domain,
            "account_name": snapshot.account_name,
            "dns_problems": ", ".join(row.incident_components),
            "detected_at": row.first_failed_at.isoformat() if row.first_failed_at else now.isoformat(),
            "www_record": f"{www['type']} {www['name']} -> {www['value']}",
            "apex_record": f"{apex['type']} {apex['name']} -> {apex['value']}",
        },
    )
    if sent.email_log_id:
        row.alert_email_log_id = UUID(sent.email_log_id)
        row.notification_pending = False
        row.notified_at = now


def _reset_scope(row: HostedDomainDnsStatus, scope: str) -> None:
    if row.results and row.results.get("_scope") != scope:
        row.component_history = {}
        row.first_failed_at = row.incident_id = row.notified_at = row.alert_email_log_id = None
        row.last_healthy_at = None
        row.notification_pending = False
        row.incident_components = []


def commit_check(claim: CheckClaim, report: dict[str, Any]) -> str:
    """Publish only against the current account generation and an unexpired matching lease."""
    try:
        result = _checked_report(report)
    except (TypeError, ValueError):
        result = unknown_report("invalid_probe_result")
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().filter(pk=claim.snapshot.account.pk).first()
        if account is None:
            return "excluded"
        row = HostedDomainDnsStatus.objects.select_for_update().get(account=account)
        now = timezone.now()
        rows = HostedDomainDnsStatus.objects.filter(pk=row.pk, lease_token=claim.token, lease_until__gt=now)
        if not rows.update(lease_until=now + timedelta(seconds=config.LEASE_SECONDS)):
            return "busy"
        if not config.enabled():
            rows.update(
                lease_token=None,
                lease_until=None,
                next_check_at=now + timedelta(seconds=config.RETRY_SECONDS),
                updated_at=now,
            )
            return "excluded"
        current = _snapshot(account)
        if current.generation != claim.snapshot.generation or current.unavailable or current.maintenance:
            rows.update(lease_token=None, lease_until=None, next_check_at=now, updated_at=now)
            return "stale"
        previous = {
            key: {"state": value.get("state"), "code": value.get("code")}
            for key, value in row.results.get("components", {}).items()
        }
        _reset_scope(row, current.scope)
        _apply_observation(row, result, now)
        _notify(current.account, row, current, now)
        row.results = {**result, "_scope": current.scope}
        row.dns_path = result["dns_path"]
        row.checked_at = now
        row.expected_generation = current.generation
        fields = {
            field: getattr(row, field)
            for field in (
                "results",
                "component_history",
                "healthy",
                "dns_path",
                "checked_at",
                "expected_generation",
                "last_healthy_at",
                "first_failed_at",
                "incident_id",
                "incident_components",
                "notification_pending",
                "alert_email_log_id",
                "notified_at",
            )
        }
        fields.update(lease_token=None, lease_until=None, updated_at=now)
        if not rows.filter(lease_until__gt=timezone.now()).update(**fields):
            raise DnsCheckLeaseLostError("DNS check lost its lease before publication")
        observed = {key: {"state": item["state"], "code": item["code"]} for key, item in result["components"].items()}
        if previous != observed:
            _audit(account, "hosting_dns_state_changed", old=previous, new=observed)
        return _state(row)
