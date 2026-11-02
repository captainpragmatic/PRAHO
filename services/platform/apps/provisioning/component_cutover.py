"""Forward-only ownership publication for an independently held component target."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from .component_migration_transport import component_network_current, run_source_operation
from .component_target_transport import run_target_operation
from .virtualmin_migration_models import MigrationBridge, VirtualminMigration
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from uuid import UUID

    from .virtualmin_migration_service import VirtualminMigrationService


def _current(migration: VirtualminMigration, token: UUID) -> VirtualminMigration:
    current = VirtualminMigration.objects.select_for_update().get(pk=migration.pk)
    if (
        current.contract != VirtualminMigration.Contract.IMPORTED_WEB
        or current.status != "verifying"
        or current.lease_token != token
        or current.worker_lease_expires_at is None
        or current.worker_lease_expires_at <= timezone.now()
        or current.cutover_committed_at is not None
        or current.component_approval_id is None
        or current.component_source_obligation_id is None
    ):
        raise ValueError("Component publication no longer owns its admitted verifying worker")
    state = current.barrier_state
    if (
        state.get("component_bridge_verified") is not True
        or re.fullmatch(r"[0-9a-f]{64}", current.archive_sha256) is None
        or not isinstance(state.get("component_target_receipt_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", state["component_target_receipt_sha256"]) is None
        or not isinstance(state.get("target_domain_id"), str)
        or re.fullmatch(r"[0-9]{1,30}", state["target_domain_id"]) is None
    ):
        raise ValueError("The selected archive, held target and origin TLS route are not independently verified")
    if current.cancel_requested and state.get("component_source_seal_intent") is not True:
        raise ValueError("Component migration was cancelled before forward-only seal intent")
    return current


def _record(engine: VirtualminMigrationService, migration: VirtualminMigration, token: UUID, key: str) -> None:
    with transaction.atomic():
        current = _current(migration, token)
        migration.refresh_from_db()
        engine._move(migration, token, "verifying", barrier_state={**current.barrier_state, key: True})


def _publish(engine: VirtualminMigrationService, migration: VirtualminMigration, token: UUID) -> None:
    from .managed_dns_service import advance_target_locked  # noqa: PLC0415 -- publication boundary
    from .virtualmin_usage_service import move_interval  # noqa: PLC0415 -- billing lifetime boundary

    with transaction.atomic():
        current = _current(migration, token)
        if not all(
            current.barrier_state.get(key) is True
            for key in ("component_source_seal_intent", "component_target_sealed", "component_source_sealed")
        ):
            raise ValueError("Both native copies must refuse compensation before ownership publication")
        account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=current.account_id)
        servers = {
            server.pk: server
            for server in VirtualminServer.objects.select_for_update(no_key=True)
            .filter(pk__in=(current.source_server_id, current.target_server_id))
            .order_by("pk")
        }
        source, target = servers[current.source_server_id], servers[current.target_server_id]
        approval = current.component_approval
        obligation = current.component_source_obligation
        if (
            approval is None
            or obligation is None
            or hasattr(obligation, "release")
            or account.server_id != source.pk
            or account.restore_hold
            or source.security_operation
            or target.security_operation
            or source.status != "active"
            or target.status != "active"
            or source.security_state not in {"acknowledged_source_only", "verified_web"}
            or connection_identity(source) != approval.review.source_identity
            or connection_identity(target) != approval.review.target_identity
            or destination_refusal(target) is not None
        ):
            raise ValueError("The admitted account, current connections or retained source authority changed")
        current.source_server, current.target_server = source, target
        if not component_network_current(current):
            raise ValueError("The admitted component bridge addresses changed before publication")
        hostname = engine._locked_account_name(account, source_id=source.pk)
        if (hostname.fqdn if hostname else "") != current.pre_migration_snapshot["component_account_name"]:
            raise ValueError("The reviewed account hostname changed before component publication")
        migration.refresh_from_db()
        engine._move(migration, token, "activating", cutover_committed_at=timezone.now())
        move_interval(account.pk, target.pk)
        account.server = target
        account.save(update_fields=["server", "updated_at"])
        if hostname is not None:
            hostname.target_server = target
            hostname.save(update_fields=["target_server", "updated_at"])
            advance_target_locked(hostname)
        MigrationBridge.objects.create(
            migration=current,
            source_server=source,
            target_server=target,
            domain=account.domain,
            evidence={
                **{
                    key: current.barrier_state[key]
                    for key in ("certificate_not_after", "dns_names", "frontend_dns_before")
                    if key in current.barrier_state
                },
                "component_source_retained": True,
            },
        )
        VirtualminServer.objects.filter(pk=target.pk).update(
            current_domains=F("current_domains") + 1, updated_at=timezone.now()
        )
        migration.account = account


def commit_component_cutover(engine: VirtualminMigrationService, migration: VirtualminMigration, token: UUID) -> None:
    """An uncertain seal always resumes forward; cancellation cannot reopen either sealed copy."""
    with transaction.atomic():
        current = _current(migration, token)
        intent = current.barrier_state.get("component_source_seal_intent") is True
    migration.refresh_from_db()
    if not intent:
        run_source_operation(migration, token, "source_verify")
        target = run_target_operation(migration, token, "target_verify")
        if target["target_receipt_sha256"] != migration.barrier_state["component_target_receipt_sha256"]:
            raise ValueError("The held target changed before forward-only publication intent")
        _record(engine, migration, token, "component_source_seal_intent")
    # The target must fence already-dispatched removal before the source seal
    # removes rollback authority. Every retry rechecks both exact native seals.
    run_target_operation(migration, token, "target_seal")
    _record(engine, migration, token, "component_target_sealed")
    run_source_operation(migration, token, "source_commit")
    _record(engine, migration, token, "component_source_sealed")
    _publish(engine, migration, token)
