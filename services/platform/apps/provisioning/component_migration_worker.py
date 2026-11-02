"""Leased imported-website orchestration; retained source services never use domain migration callbacks."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from cryptography import x509
from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.permissions import can_deploy_nodes

from . import account_hostname_service
from .account_hostname_lifecycle import ensure_on_recreated_node
from .account_hostname_service import retire_removed_node_name
from .component_bridge_transport import run_bridge_operation
from .component_cutover import commit_component_cutover
from .component_migration_manifest import ComponentManifest
from .component_migration_transfer import transfer_selected_archive
from .component_migration_transport import component_network_current, run_source_operation
from .component_target_transport import run_target_operation
from .migration_bridge_service import BridgePreparation
from .migration_enabled_state import EnabledPolicy, activation_guard, current_policy, record_activation
from .migration_routing import observe_frontends, prepare_frontend_snapshot
from .virtualmin_migration_models import PRE_COMMIT_STATUSES, MigrationBridge, VirtualminMigration
from .virtualmin_migration_service import (
    TTL_POLL_SECONDS,
    MigrationDeferredError,
    MigrationLeaseLostError,
    VirtualminMigrationService,
)
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_node_capability import destination_refusal

if TYPE_CHECKING:
    from apps.users.models import User

logger = logging.getLogger(__name__)
_FORWARD_PHASES = frozenset({"activating", "bridging", "repointing"})


def _forward_only(migration: VirtualminMigration) -> bool:
    return (
        migration.cutover_committed_at is not None
        or migration.barrier_state.get("component_source_seal_intent") is True
    )


class ComponentMigrationWorker(VirtualminMigrationService):
    """Every remote mutation has its own native identity receipt and current lease guard."""

    def _state(self, migration: VirtualminMigration, token: UUID, **fields: object) -> None:
        self._store_barrier_state(migration, token, {**migration.barrier_state, **fields})

    @staticmethod
    def _assert_contract(migration: VirtualminMigration) -> None:
        approval, obligation = migration.component_approval, migration.component_source_obligation
        if (
            migration.contract != VirtualminMigration.Contract.IMPORTED_WEB
            or approval is None
            or obligation is None
            or approval.review.account_id != migration.account_id
            or approval.review.source_server_id != migration.source_server_id
            or approval.review.target_server_id != migration.target_server_id
            or obligation.source_server_id != migration.source_server_id
            or hasattr(obligation, "release")
        ):
            raise ValueError(
                "The component worker requires its consumed approval and unresolved retained source obligation"
            )
        ComponentManifest.parse(approval.review.manifest).assert_ready()

    def _quiesce(self, migration: VirtualminMigration, token: UUID) -> None:
        self._state(migration, token, component_source_hold_issued=True)
        run_source_operation(migration, token, "source_hold")
        run_source_operation(migration, token, "source_verify")
        self._move(migration, token, "backing_up")

    def _backup(self, migration: VirtualminMigration, token: UUID) -> None:
        receipt = run_source_operation(migration, token, "source_export")
        self._move(
            migration,
            token,
            "fetching",
            archive_sha256=receipt["export"]["sha256"],
            barrier_state={**migration.barrier_state, "component_export": receipt["export"]},
        )

    def _transfer(self, migration: VirtualminMigration, token: UUID) -> None:
        transfer_selected_archive(self, migration, token)

    def _restore(self, migration: VirtualminMigration, token: UUID) -> None:
        self._move(migration, token, "restoring", restore_issued=True)
        prepared = run_target_operation(migration, token, "target_prepare")
        self._state(migration, token, target_domain_id=prepared["target_domain_id"])
        restored = run_target_operation(migration, token, "target_restore")
        self._move(
            migration,
            token,
            "verifying",
            barrier_state={
                **migration.barrier_state,
                "component_target_receipt_sha256": restored["target_receipt_sha256"],
            },
        )

    def _prepare_bridge(self, migration: VirtualminMigration, token: UUID) -> None:
        if migration.pre_migration_snapshot["component_account_name"]:
            named = ensure_on_recreated_node(migration.account, migration.target_server, enabled=False)
            outcome = named.unwrap() if named.is_ok() else None
            if outcome is None or outcome.enabled or not outcome.certificate_installed or not outcome.neutral:
                raise ValueError("The reviewed target account name is not independently neutral and TLS ready")
        self._state(migration, token, component_bridge_source_prepare_issued=True)
        manifest = run_bridge_operation(migration, token, "prepare")
        self._state(migration, token, component_bridge_manifest=manifest, component_bridge_origin_issued=True)
        certificate = run_bridge_operation(migration, token, "origin_install", manifest=manifest)
        if not isinstance(certificate, str) or not certificate:
            raise ValueError("The component bridge has no public origin certificate")
        self._state(migration, token, component_bridge_origin_certificate=certificate)
        run_bridge_operation(migration, token, "origin_verify", origin_certificate=certificate)
        certificates = [
            certificate,
            *(row["public_certificate"] for row in manifest["vhosts"] if row.get("public_certificate")),
        ]
        deadline = min(x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc for pem in certificates)
        names = tuple(sorted({name for row in manifest["vhosts"] for name in row["names"]}))
        frontend = prepare_frontend_snapshot(migration, BridgePreparation(certificate, deadline, names))
        self._state(migration, token, **frontend, component_bridge_verified=True)

    def _verify(self, migration: VirtualminMigration, token: UUID) -> None:
        if not _forward_only(migration):
            run_source_operation(migration, token, "source_verify")
            target = run_target_operation(migration, token, "target_verify")
            if target["target_receipt_sha256"] != migration.barrier_state.get("component_target_receipt_sha256"):
                raise ValueError("The selected held target changed after restoration")
            self._prepare_bridge(migration, token)
        commit_component_cutover(self, migration, token)

    def _converge_policy(self, migration: VirtualminMigration, token: UUID) -> EnabledPolicy:
        for _attempt in range(2):
            policy = current_policy(migration.account)
            self._move(migration, token, migration.status)
            run_target_operation(migration, token, "target_policy", enabled=policy.enabled)
            if current_policy(migration.account) == policy:
                return policy
        raise MigrationDeferredError(
            timezone.now() + timedelta(seconds=1), "Hosting policy changed during component activation"
        )

    def _activate(self, migration: VirtualminMigration, token: UUID) -> None:
        with activation_guard(migration, token):
            if not migration.barrier_state.get("component_target_activation_issued"):
                self._state(
                    migration,
                    token,
                    component_target_activation_issued=True,
                    component_target_activation_enabled=current_policy(migration.account).enabled,
                )
            enabled = migration.barrier_state.get("component_target_activation_enabled")
            if type(enabled) is not bool:
                raise ValueError("The target activation lost its original explicit enabled policy")
            if migration.barrier_state.get("component_target_activation_native_complete") is not True:
                run_target_operation(migration, token, "target_activate", enabled=enabled)
                self._state(migration, token, component_target_activation_native_complete=True)
            policy = self._converge_policy(migration, token)
            self._state(migration, token, component_target_activation_complete=True)
            record_activation(self, migration, token, policy, "bridging")

    def _bridge(self, migration: VirtualminMigration, token: UUID) -> None:
        self._converge_policy(migration, token)
        certificate = migration.barrier_state.get("component_bridge_origin_certificate")
        if not isinstance(certificate, str):
            raise ValueError("The committed component bridge lost its pinned public origin trust")
        run_bridge_operation(migration, token, "install", origin_certificate=certificate)
        run_bridge_operation(migration, token, "verify")
        with transaction.atomic():
            bridge = MigrationBridge.objects.select_for_update().get(migration=migration)
            if bridge.status == MigrationBridge.Status.PENDING:
                bridge.activate()
                bridge.save()
            self._move(migration, token, "repointing")

    def _publish_name(self, migration: VirtualminMigration, token: UUID) -> dict[str, Any] | None:
        from apps.infrastructure.dns_agreement import authoritative_agreement  # noqa: PLC0415 -- routing read boundary

        from .account_hostname_models import AccountHostname  # noqa: PLC0415 -- optional name boundary
        from .managed_dns_service import observe_routing  # noqa: PLC0415 -- fenced provider publisher

        expected = migration.pre_migration_snapshot["component_account_name"]
        if not expected:
            return None
        hostname = AccountHostname.objects.get(account=migration.account, retired_at__isnull=True)
        if hostname.fqdn != expected or hostname.target_server_id != migration.target_server_id:
            raise ValueError("The committed component account hostname changed")
        published = account_hostname_service.sync_account_hostname(hostname)
        if published.is_err():
            raise MigrationDeferredError(timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), published.unwrap_err())
        network = migration.pre_migration_snapshot["component_network"]
        agreement = authoritative_agreement(hostname.fqdn, network["target_ipv4"], network["target_ipv6"] or None)
        managed = observe_routing(hostname)
        if not agreement.agreed or managed.is_err() or not managed.unwrap()["agreed"]:
            self._state(migration, token, component_name_dns=asdict(agreement))
            raise MigrationDeferredError(
                timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), "Waiting for committed component hostname routing"
            )
        return managed.unwrap()

    def _repoint(self, migration: VirtualminMigration, token: UUID) -> None:
        self._converge_policy(migration, token)
        bridge = MigrationBridge.objects.get(migration=migration, status=MigrationBridge.Status.ACTIVE)
        route = run_source_operation(migration, token, "source_route")
        self._state(migration, token, component_routing=route)
        managed = self._publish_name(migration, token)
        routing, waiting = observe_frontends(bridge)
        with transaction.atomic():
            bridge = MigrationBridge.objects.select_for_update().get(pk=bridge.pk)
            bridge.evidence = {**bridge.evidence, "routing": routing}
            bridge.save(update_fields=["evidence", "updated_at"])
            self._state(migration, token, frontend_dns=routing)
        if waiting:
            raise MigrationDeferredError(timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), "; ".join(waiting))
        self._complete_component(migration, token, managed)

    def _complete_component(self, migration: VirtualminMigration, token: UUID, managed: dict[str, Any] | None) -> None:
        from .managed_dns_service import routing_is_current_locked  # noqa: PLC0415 -- final publication fence
        from .migration_bridge_cleanup import schedule_bridge_cleanup  # noqa: PLC0415 -- durable retirement scheduling

        with transaction.atomic():
            VirtualminMigration.objects.select_for_update().get(pk=migration.pk)
            account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=migration.account_id)
            servers = {
                server.pk: server
                for server in VirtualminServer.objects.select_for_update(no_key=True)
                .filter(pk__in=(migration.source_server_id, migration.target_server_id))
                .order_by("pk")
            }
            migration.source_server, migration.target_server = (
                servers[migration.source_server_id],
                servers[migration.target_server_id],
            )
            target = migration.target_server
            if (
                account.server_id != target.pk
                or destination_refusal(target)
                or not component_network_current(migration)
            ):
                raise ValueError("Committed target or admitted network changed before component completion")
            hostname = self._locked_account_name(account, source_id=target.pk)
            if (hostname.fqdn if hostname else "") != migration.pre_migration_snapshot["component_account_name"]:
                raise ValueError("The admitted optional hostname changed before component completion")
            if hostname is not None and (managed is None or not routing_is_current_locked(hostname, managed)):
                raise MigrationDeferredError(
                    timezone.now() + timedelta(seconds=TTL_POLL_SECONDS), "Component DNS generation changed"
                )
            self._move(migration, token, "repointing", dns_converged_at=timezone.now())
            self._finish(migration, token, "completed")
            transaction.on_commit(lambda: schedule_bridge_cleanup(migration.pk), robust=True)

    def _compensate(self, migration: VirtualminMigration, token: UUID) -> None:
        if _forward_only(migration):
            raise ValueError(
                "A sealed component source requires forward reconciliation; never reopen or remove either copy"
            )
        state = migration.barrier_state
        for issued, completed, action in (
            ("component_bridge_source_prepare_issued", "component_bridge_source_removed", "remove"),
            ("component_bridge_origin_issued", "component_bridge_origin_removed", "origin_remove"),
        ):
            if state.get(issued) and not state.get(completed):
                run_bridge_operation(migration, token, action)
                self._state(migration, token, **{completed: True})
        if migration.restore_issued and not migration.barrier_state.get("component_target_removed"):
            run_target_operation(migration, token, "target_remove")
            retired = retire_removed_node_name(migration.account, migration.target_server)
            if retired.is_err():
                raise ValueError("Target optional-name private cleanup is unproven: " + retired.unwrap_err())
            self._state(migration, token, component_target_removed=True)
        if state.get("component_source_hold_issued") and not migration.barrier_state.get("component_source_released"):
            run_source_operation(migration, token, "source_release")
            self._state(migration, token, component_source_released=True)
        self._finish(migration, token, "rolled_back", migration.error_detail)

    def execute(self, migration: VirtualminMigration, lease_token: UUID) -> Result[VirtualminMigration, str]:
        handlers = {
            "pending": self._begin,
            "quiescing": self._quiesce,
            "backing_up": self._backup,
            "fetching": self._transfer,
            "pushing": self._transfer,
            "restoring": self._restore,
            "verifying": self._verify,
            "activating": self._activate,
            "bridging": self._bridge,
            "repointing": self._repoint,
            "compensating": self._compensate,
        }
        try:
            self._assert_contract(migration)
            if migration.resume_after is not None:
                self._move(migration, lease_token, migration.status, resume_after=None)
            while migration.status in handlers and not migration.parked_phase:
                if not migration.renew_lease(lease_token, self.lease_ttl):
                    raise MigrationLeaseLostError("Component worker lease expired or ownership changed")
                migration.refresh_from_db()
                if migration.cancel_requested and not _forward_only(migration):
                    if migration.status == "pending":
                        self._finish(
                            migration, lease_token, "failed", "Component migration cancelled before source holds"
                        )
                        break
                    if migration.status in PRE_COMMIT_STATUSES:
                        self._move(migration, lease_token, "compensating", error_detail="Component migration cancelled")
                phase = migration.status
                handlers[phase](migration, lease_token)
                if phase in PRE_COMMIT_STATUSES and migration.status != phase:
                    raise MigrationDeferredError(
                        timezone.now() + timedelta(seconds=1), "Continue the component migration checkpoint"
                    )
        except MigrationDeferredError as deferral:
            self._defer(migration, lease_token, deferral)
        except Exception as error:
            logger.exception("🔥 [ComponentMigration] Native checkpoint needs review: %s", migration.pk)
            migration.refresh_from_db()
            if not migration.renew_lease(lease_token, self.lease_ttl):
                return Err("Component worker lease lost; current owner must reconcile its native receipts")
            if migration.status == "compensating":
                self._park_compensation(migration, lease_token, str(error))
            else:
                self._move(migration, lease_token, migration.status, parked_phase=migration.status)
                self._finish(migration, lease_token, "needs_review", str(error))
        return Ok(migration)


def resolve_component_migration(
    migration: VirtualminMigration, *, actor: User | None, note: str
) -> Result[VirtualminMigration, str]:
    if actor is None or not actor.is_active or not can_deploy_nodes(actor) or not note.strip():
        return Err("An active deployment operator and an explicit native receipt review are required")
    engine, token = ComponentMigrationWorker(), uuid4()
    if not migration.acquire_lease(token, engine.lease_ttl):
        return Err("A worker currently owns this component migration; retry shortly")
    try:
        migration.refresh_from_db()
        engine._assert_contract(migration)
        if migration.status not in {"needs_review", "compensating"}:
            return Err("Only an interrupted component migration can be resolved manually")
        if migration.cutover_committed_at is not None:
            phase = migration.parked_phase if migration.parked_phase in _FORWARD_PHASES else "activating"
        else:
            phase = "verifying" if _forward_only(migration) else "compensating"
        with transaction.atomic():
            engine._move(
                migration,
                token,
                phase,
                parked_phase="",
                error_detail="Native component receipts reviewed: " + note.strip(),
            )
            engine._audit(migration, "keep_target" if _forward_only(migration) else "keep_source", actor=actor)
            migration.transition(token, phase, phase, lease_token=None, worker_lease_expires_at=None)
            transaction.on_commit(lambda: engine._enqueue(migration.pk))
        return Ok(migration)
    except ValueError as error:
        return Err(str(error))
    finally:
        migration.refresh_from_db()
        migration.transition(token, migration.status, migration.status, lease_token=None, worker_lease_expires_at=None)
