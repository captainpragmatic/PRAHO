"""Retryable bridge retention after the cutover releases the account's operation lock."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import async_task, schedule

from apps.common.types import Err, Ok, Result

from .account_hostname_config import bridge_window_hours
from .account_hostname_models import AccountHostname
from .virtualmin_migration_models import MigrationBridge
from .virtualmin_models import VirtualminAccount

logger = logging.getLogger(__name__)
# Twelve bounded DNS probes, three SSH/playbook steps and TTL restoration can
# exceed one hour. The cleanup lease and every scheduled wake share this budget.
BRIDGE_TASK_TIMEOUT = 7200
BRIDGE_RETRY = timedelta(minutes=5)
TASK = "apps.provisioning.migration_bridge_cleanup.cleanup_bridge"

if TYPE_CHECKING:
    from apps.users.models import User

    from .virtualmin_migration_service import VirtualminMigrationService


class BridgeOwnershipError(ValueError):
    """The retained source or current account no longer belongs to this operation."""


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def schedule_bridge_cleanup(migration_id: UUID | str, until: datetime | None = None) -> bool:
    """The durable deadline survives dispatch failure; the reclaim sweep redelivers due work."""
    with transaction.atomic():
        bridge = MigrationBridge.objects.select_for_update().filter(migration_id=UUID(str(migration_id))).first()
        if bridge is None or bridge.status in {"torn_down", "failed"}:
            return False
        expires = _date(bridge.evidence.get("expires_at"))
        if expires is None:
            expires = timezone.now() + timedelta(hours=bridge_window_hours())
            certificate_deadline = _date(bridge.evidence.get("certificate_not_after"))
            if certificate_deadline is not None:
                expires = min(expires, certificate_deadline - timedelta(hours=1))
            bridge.evidence = {**bridge.evidence, "expires_at": expires.isoformat()}
        due = until or expires
        bridge.evidence = {**bridge.evidence, "next_run": due.isoformat()}
        bridge.save(update_fields=["evidence", "updated_at"])
    try:
        schedule(
            TASK,
            str(migration_id),
            schedule_type=Schedule.ONCE,
            next_run=due,
            name=f"bridge-cleanup-{migration_id}-{int(due.timestamp())}",
            q_options={"timeout": BRIDGE_TASK_TIMEOUT},
        )
    except (ValueError, RuntimeError, OSError):
        logger.exception("🔥 [MigrationBridge] Cleanup dispatch failed; reclaim will retry %s", migration_id)
        return False
    return True


def _progress(bridge_id: UUID, token: str, fields: dict[str, Any], *, transition_name: str = "") -> None:
    with transaction.atomic():
        bridge = MigrationBridge.objects.select_for_update().get(pk=bridge_id)
        until = _date(bridge.evidence.get("lease_until"))
        if bridge.evidence.get("lease_token") != token or until is None or until <= timezone.now():
            raise BridgeOwnershipError("Bridge cleanup lease lost")
        if transition_name:
            getattr(bridge, transition_name)()
        # Keep conservative source capacity until the authoritative node statistics refresh.
        # A retry after deletion and a refresh cannot safely infer a further decrement.
        bridge.evidence = {**bridge.evidence, **fields}
        bridge.save()


def _release(bridge_id: UUID, token: str) -> None:
    with transaction.atomic():
        bridge = MigrationBridge.objects.select_for_update().get(pk=bridge_id)
        if bridge.evidence.get("lease_token") == token:
            bridge.evidence = {
                key: value for key, value in bridge.evidence.items() if key not in {"lease_token", "lease_until"}
            }
            bridge.save(update_fields=["evidence", "updated_at"])


def _guard(bridge_id: UUID, token: str) -> None:
    """Revalidate and renew ownership immediately before a destructive remote step."""
    with transaction.atomic():
        bridge = MigrationBridge.objects.select_for_update().get(pk=bridge_id)
        until = _date(bridge.evidence.get("lease_until"))
        if bridge.evidence.get("lease_token") != token or until is None or until <= timezone.now():
            raise BridgeOwnershipError("Bridge cleanup lease lost")
        account = VirtualminAccount.objects.get(pk=bridge.migration.account_id)
        hostname = AccountHostname.objects.filter(account=account).first()
        terminated = account.status == "terminated"
        if account.server_id != bridge.target_server_id or hostname is None:
            raise BridgeOwnershipError("The account no longer belongs to the committed target")
        if terminated:
            if hostname.retired_at is None or hostname.records or hostname.target_server_id is not None:
                raise ValueError("Termination has not verified DNS withdrawal; cleanup will retry")
        elif hostname.retired_at is not None or hostname.target_server_id != bridge.target_server_id:
            raise BridgeOwnershipError("The hostname no longer belongs to the committed target")
        bridge.evidence = {
            **bridge.evidence,
            "lease_until": (timezone.now() + timedelta(seconds=BRIDGE_TASK_TIMEOUT + 60)).isoformat(),
        }
        bridge.save(update_fields=["evidence", "updated_at"])


def _claim(migration_id: str, token: str) -> tuple[MigrationBridge | None, str]:
    with transaction.atomic():
        bridge = (
            MigrationBridge.objects.select_for_update()
            .select_related("migration", "target_server")
            .get(migration_id=UUID(migration_id))
        )
        if bridge.status in {"torn_down", "failed"}:
            return None, bridge.status
        if bridge.migration.status != "completed":
            return None, "waiting"
        expires = _date(bridge.evidence.get("expires_at"))
        if (expires is None or expires > timezone.now()) and bridge.migration.account.status != "terminated":
            transaction.on_commit(lambda: schedule_bridge_cleanup(migration_id))
            return None, "waiting"
        leased_until = _date(bridge.evidence.get("lease_until"))
        if bridge.evidence.get("lease_token") and leased_until and leased_until > timezone.now():
            return None, "busy"
        bridge.evidence = {
            **bridge.evidence,
            "lease_token": token,
            "lease_until": (timezone.now() + timedelta(seconds=BRIDGE_TASK_TIMEOUT + 60)).isoformat(),
        }
        bridge.save(update_fields=["evidence", "updated_at"])
    return bridge, "claimed"


def _verify_routing(bridge: MigrationBridge, token: str) -> None:
    from apps.infrastructure.dns_agreement import authoritative_agreement  # noqa: PLC0415

    from .migration_bridge_service import verify_bridge  # noqa: PLC0415
    from .migration_routing import observe_frontends  # noqa: PLC0415

    if bridge.migration.account.status == "terminated":
        return
    hostname = AccountHostname.objects.get(account_id=bridge.migration.account_id)
    ipv4 = bridge.target_server.ipv4_address
    if not ipv4:
        raise ValueError("The committed target has no IPv4 address")
    agreement = authoritative_agreement(hostname.fqdn, ipv4, bridge.target_server.ipv6_address or None)
    routing, waiting = observe_frontends(bridge)
    _progress(bridge.pk, token, {"routing": routing, "owned_dns": asdict(agreement)})
    if not agreement.agreed:
        raise ValueError(agreement.detail or "Authoritative DNS no longer agrees")
    if waiting:
        raise ValueError("; ".join(waiting))
    if not bridge.evidence.get("teardown_started"):
        verified = verify_bridge(bridge.migration)
        if verified.is_err():
            raise ValueError(verified.unwrap_err())


def _remove_content(bridge: MigrationBridge, token: str, service: VirtualminMigrationService) -> None:
    if bridge.evidence.get("source_removed"):
        return
    migration = bridge.migration
    if bridge.evidence.get("delete_issued"):
        idle = service._barrier(migration, "idle", token=str(uuid4()))
        if idle.is_ok() and idle.unwrap().outcome == "busy":
            raise ValueError("Waiting for the node's API operations to finish before checking source deletion")
        if idle.is_err() or not idle.unwrap().ok:
            raise BridgeOwnershipError("A previous source deletion is not proven idle; staff must review it")
    rows = service._listing(service._gateway(migration.source_server))
    source = next((row for row in rows if row["domain"] == bridge.domain), None)
    if source is not None:
        if source["username"] != migration.account.virtualmin_username:
            raise BridgeOwnershipError("The retained source domain has a different owner")
        if source["enabled"] is not False:
            raise BridgeOwnershipError("The retained source domain is no longer fenced")
        _guard(bridge.pk, token)
        _progress(bridge.pk, token, {"delete_issued": True})
        try:
            service._command(migration, migration.source_server, "delete-domain")
        except RuntimeError as error:
            raise BridgeOwnershipError(f"Source deletion needs review before teardown: {error}") from error
        rows = service._listing(service._gateway(migration.source_server))
        if any(row["domain"] == bridge.domain for row in rows):
            raise ValueError("Source deletion could not be verified")
    _progress(bridge.pk, token, {"source_removed": True})


def _remove_transport(bridge: MigrationBridge, token: str) -> None:
    from .migration_bridge_service import remove_bridge  # noqa: PLC0415

    if bridge.evidence.get("bridge_removed"):
        return
    _progress(bridge.pk, token, {"teardown_started": True})
    _guard(bridge.pk, token)
    removed = remove_bridge(bridge.migration, source_removed=True)
    if removed.is_err():
        raise ValueError(removed.unwrap_err())
    _progress(bridge.pk, token, {"bridge_removed": True})


def _retire_source_guard(bridge: MigrationBridge, token: str) -> None:
    from .account_hostname_service import retire_removed_node_name  # noqa: PLC0415  # Node gateway imports

    if bridge.evidence.get("source_guard_retired"):
        return
    _guard(bridge.pk, token)
    retired = retire_removed_node_name(bridge.migration.account, bridge.migration.source_server)
    if retired.is_err():
        raise ValueError(f"Source neutral guard private cleanup is unproven: {retired.unwrap_err()}")
    _progress(bridge.pk, token, {"source_guard_retired": True})


def cleanup_bridge(migration_id: str) -> dict[str, str]:
    """Reverify routing, remove source and transport, retire its private name guard, then restore TTLs."""
    from .virtualmin_migration_service import VirtualminMigrationService  # noqa: PLC0415

    token = uuid4().hex
    bridge, action = _claim(migration_id, token)
    if bridge is None:
        return {"action": action}
    try:
        migration = bridge.migration
        service = VirtualminMigrationService()
        _guard(bridge.pk, token)
        _verify_routing(bridge, token)
        if bridge.status == "active":
            _progress(bridge.pk, token, {}, transition_name="start_removing_source")
        _remove_content(bridge, token, service)
        _remove_transport(bridge, token)
        _retire_source_guard(bridge, token)
        _guard(bridge.pk, token)
        service._restore_ttl(migration)
        _progress(bridge.pk, token, {"ttl_restored": True, "last_error": ""}, transition_name="tear_down")
        if migration.drain_id is not None:
            from .virtualmin_drain_service import NodeDrainService  # noqa: PLC0415

            NodeDrainService.finalize_managed_drain(migration.drain_id)
        return {"action": "torn_down"}
    except BridgeOwnershipError as error:
        # Ownership changes need staff; stale workers may never write another worker's evidence.
        try:
            _progress(bridge.pk, token, {"last_error": str(error)}, transition_name="fail")
        except BridgeOwnershipError:
            return {"action": "busy"}
        return {"action": "failed"}
    except (ValueError, RuntimeError, OSError, ObjectDoesNotExist) as error:
        _progress(bridge.pk, token, {"last_error": str(error)})
        schedule_bridge_cleanup(migration_id, timezone.now() + BRIDGE_RETRY)
        return {"action": "retrying"}
    finally:
        _release(bridge.pk, token)


def reclaim_bridges() -> int:
    """Bounded redelivery when a schedule or a worker vanished."""
    now = timezone.now()
    queued = 0
    candidates = MigrationBridge.objects.filter(
        status__in=["active", "removing_source"],
        migration__status="completed",
        updated_at__lt=now - BRIDGE_RETRY,
    ).order_by("updated_at")[:5]
    for bridge in candidates:
        due = _date(bridge.evidence.get("next_run")) or _date(bridge.evidence.get("expires_at"))
        leased = _date(bridge.evidence.get("lease_until"))
        if due is None:
            schedule_bridge_cleanup(bridge.migration_id)
            continue
        terminated = bridge.migration.account.status == "terminated"
        if (terminated or due <= now) and (leased is None or leased <= now):
            async_task(TASK, str(bridge.migration_id), timeout=BRIDGE_TASK_TIMEOUT)
            queued += 1
    return queued


def control_bridge(  # noqa: PLR0911  # Each staff action and ownership refusal has a distinct outcome
    migration_id: UUID, *, action: str, actor: User | None, attestation: Mapping[str, str] | None = None
) -> Result[MigrationBridge, str]:
    """Staff may extend an idle bridge or retry its failed forward cleanup."""
    from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415

    with transaction.atomic():
        bridge = MigrationBridge.objects.select_for_update().filter(migration_id=migration_id).first()
        if bridge is None or bridge.status == "torn_down":
            return Err("The bridge is no longer awaiting cleanup")
        if bridge.migration.status != "completed":
            return Err("The cutover must converge before its bridge window can be managed")
        lease_until = _date(bridge.evidence.get("lease_until"))
        if lease_until and lease_until > timezone.now():
            return Err("A cleanup worker currently owns this bridge; retry shortly")
        if action == "attest":
            from .migration_routing import attest_proxy_origin  # noqa: PLC0415

            attested = attest_proxy_origin(bridge, actor, attestation or {})
            if attested.is_err():
                return Err(attested.unwrap_err())
            due = timezone.now()
        elif action == "extend":
            expires = max(_date(bridge.evidence.get("expires_at")) or timezone.now(), timezone.now())
            due = expires + timedelta(hours=bridge_window_hours())
            certificate_deadline = _date(bridge.evidence.get("certificate_not_after"))
            if certificate_deadline is None or due + timedelta(hours=1) >= certificate_deadline:
                return Err("The bridge certificates are not verified through the proposed extension")
            bridge.evidence = {**bridge.evidence, "expires_at": due.isoformat(), "next_run": due.isoformat()}
            bridge.save(update_fields=["evidence", "updated_at"])
            AuditService.log_event(
                AuditEventData(
                    event_type="virtualmin_bridge_extended",
                    content_object=bridge,
                    description="Migration bridge retention extended",
                    new_values={"expires_at": due.isoformat()},
                ),
                AuditContext(
                    user=actor, actor_type="user" if actor else "system", metadata={"source_app": "provisioning"}
                ),
            )
        elif action == "retry" and bridge.status == "failed":
            due = timezone.now()
            bridge.retry_cleanup()
            bridge.evidence = {**bridge.evidence, "last_error": "", "next_run": due.isoformat()}
            bridge.save()
        else:
            return Err("This bridge action is not available")
        transaction.on_commit(lambda: schedule_bridge_cleanup(migration_id, due), robust=True)
        return Ok(bridge)
