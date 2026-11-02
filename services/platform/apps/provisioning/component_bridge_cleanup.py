"""Retire component bridges while preserving native source mail, DNS and Unix responsibility."""

from __future__ import annotations

import base64
import json
import re
from datetime import timedelta
from typing import Any
from uuid import UUID

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone

from .account_hostname_models import AccountHostname
from .component_bridge_transport import bridge_operation_variables, run_bridge_operation
from .component_migration_transport import component_network_current, source_operation_variables
from .component_target_transport import target_operation_variables
from .migration_bridge_cleanup import (
    BRIDGE_RETRY,
    BRIDGE_TASK_TIMEOUT,
    BridgeOwnershipError,
    _date,
    _progress,
    schedule_bridge_cleanup,
)
from .virtualmin_migration_models import MigrationBridge, VirtualminMigration
from .virtualmin_models import VirtualminServer
from .virtualmin_security import connection_identity

MAX_RETIREMENT_RECEIPT_BASE64 = 16384


def _owned(bridge_id: UUID, token: str) -> MigrationBridge:
    bridge = MigrationBridge.objects.select_related(
        "migration__account",
        "migration__component_approval__review",
        "migration__component_source_obligation",
        "source_server",
        "target_server",
    ).get(pk=bridge_id)
    migration = bridge.migration
    expires = _date(bridge.evidence.get("lease_until"))
    approval, obligation = migration.component_approval, migration.component_source_obligation
    if (
        bridge.evidence.get("lease_token") != UUID(token).hex
        or expires is None
        or expires <= timezone.now()
        or bridge.status not in {"active", "removing_source"}
        or migration.contract != VirtualminMigration.Contract.IMPORTED_WEB
        or migration.status != "completed"
        or migration.cutover_committed_at is None
        or migration.account.server_id != bridge.target_server_id
        or approval is None
        or obligation is None
        or hasattr(obligation, "release")
        or connection_identity(bridge.source_server) != approval.review.source_identity
        or connection_identity(bridge.target_server) != approval.review.target_identity
        or bridge.source_server.security_operation
        or bridge.target_server.security_operation
    ):
        raise BridgeOwnershipError("Component cleanup lost its lease, admitted endpoints or retained source authority")
    migration.source_server, migration.target_server = bridge.source_server, bridge.target_server
    if not component_network_current(migration):
        raise BridgeOwnershipError("The component cleanup network differs from its admitted addresses")
    if not all(
        migration.barrier_state.get(key) is True
        for key in ("component_source_sealed", "component_target_sealed", "component_target_activation_complete")
    ):
        raise BridgeOwnershipError(
            "Both native seals and proven target activation are required before component cleanup"
        )
    frozen_name = migration.pre_migration_snapshot["component_account_name"]
    hostname = AccountHostname.objects.filter(account=migration.account).first()
    if (hostname.fqdn if hostname else "") != frozen_name:
        raise BridgeOwnershipError("The component account hostname changed before source cleanup")
    if hostname is not None:
        if migration.account.status == "terminated":
            if hostname.retired_at is None or hostname.target_server_id is not None or hostname.records:
                raise ValueError("Wait for verified platform hostname withdrawal before component cleanup")
        elif hostname.retired_at is not None or hostname.target_server_id != bridge.target_server_id:
            raise BridgeOwnershipError("The platform hostname no longer belongs to the component target")
    return bridge


def _guard(bridge: MigrationBridge, token: str) -> MigrationBridge:
    with transaction.atomic():
        MigrationBridge.objects.select_for_update().get(pk=bridge.pk)
        current = _owned(bridge.pk, token)
        current.evidence = {
            **current.evidence,
            "lease_until": (timezone.now() + timedelta(seconds=BRIDGE_TASK_TIMEOUT + 60)).isoformat(),
        }
        current.save(update_fields=["evidence", "updated_at"])
    return current


def cleanup_variables(migration: VirtualminMigration, token: UUID, action: str, bridge_id: UUID) -> dict[str, Any]:
    if action not in {"verify", "remove", "origin_remove"}:
        raise ValueError("Component bridge cleanup permits only verification and exact owned retirement")
    return {**bridge_operation_variables(migration, token, action), "component_bridge_cleanup": str(bridge_id)}


def bridge_cleanup_refusal(server: VirtualminServer, values: dict[str, Any]) -> str | None:
    try:
        operation = values["component_bridge_operation"]
        token = UUID(operation["worker_token"])
        bridge = _owned(UUID(values["component_bridge_cleanup"]), token.hex)
        action = values["component_bridge_action"]
        expected = cleanup_variables(bridge.migration, token, action, bridge.pk)
        expected_server = bridge.target_server if action == "origin_remove" else bridge.source_server
        if (
            values != expected
            or server.pk != expected_server.pk
            or connection_identity(server) != connection_identity(expected_server)
        ):
            return "The component bridge cleanup side or public scope changed"
        if action == "remove" and bridge.status != "removing_source":
            return "Component bridge retirement requires the source-removal phase"
        if action == "origin_remove" and not bridge.evidence.get("source_components_removed"):
            return "Retire the exact source components before removing their target origin"
    except (KeyError, ValueError, TypeError, AttributeError, ObjectDoesNotExist) as error:
        return "Component bridge cleanup authority is unavailable: " + str(error)
    return None


def _retirement_variables(bridge: MigrationBridge, token: str) -> dict[str, Any]:
    values = source_operation_variables(bridge.migration, UUID(token), "source_hold")
    values["component_action"] = "source_retire"
    values["component_operation"]["cleanup_bridge_id"] = str(bridge.pk)
    return values


def source_retirement_refusal(server: VirtualminServer, values: dict[str, Any] | None) -> str | None:
    try:
        supplied = values or {}
        operation = supplied["component_operation"]
        token = UUID(operation["worker_token"]).hex
        bridge = _owned(UUID(operation["cleanup_bridge_id"]), token)
        if (
            supplied != _retirement_variables(bridge, token)
            or server.pk != bridge.source_server_id
            or connection_identity(server) != connection_identity(bridge.source_server)
            or bridge.status != "removing_source"
            or bridge.evidence.get("bridge_removed") is not True
        ):
            return "Source component retirement requires its exact lease, retained identity and removed source bridge"
    except (KeyError, ValueError, TypeError, AttributeError, ObjectDoesNotExist) as error:
        return "Source component retirement authority is unavailable: " + str(error)
    return None


def _target_artifact_variables(bridge: MigrationBridge, token: str) -> dict[str, Any]:
    values = target_operation_variables(bridge.migration, UUID(token), "target_verify")
    values["component_action"] = "target_retire_artifacts"
    values["component_operation"]["cleanup_bridge_id"] = str(bridge.pk)
    return values


def target_artifact_retirement_refusal(server: VirtualminServer, values: dict[str, Any] | None) -> str | None:
    try:
        supplied = values or {}
        operation = supplied["component_operation"]
        token = UUID(operation["worker_token"]).hex
        bridge = _owned(UUID(operation["cleanup_bridge_id"]), token)
        if (
            supplied != _target_artifact_variables(bridge, token)
            or server.pk != bridge.target_server_id
            or connection_identity(server) != connection_identity(bridge.target_server)
            or bridge.status != "removing_source"
            or bridge.evidence.get("source_components_removed") is not True
            or bridge.evidence.get("origin_removed") is not True
        ):
            return "Target staging retirement requires completed source and bridge cleanup under its exact lease"
    except (KeyError, ValueError, TypeError, AttributeError, ObjectDoesNotExist) as error:
        return "Target staging retirement authority is unavailable: " + str(error)
    return None


def _retire_target_artifacts(bridge: MigrationBridge, token: str) -> None:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- enrolled native transport

    values = _target_artifact_variables(bridge, token)
    if refusal := target_artifact_retirement_refusal(bridge.target_server, values):
        raise BridgeOwnershipError(refusal)
    result = AnsibleService().run_server_playbook(
        bridge.target_server, "virtualmin_component.yml", values, timeout_seconds=600
    )
    if result.is_err() or not result.unwrap().success:
        raise ValueError("Private target staging retirement is uncertain; preserve its owned receipts")
    if refusal := target_artifact_retirement_refusal(bridge.target_server, values):
        raise BridgeOwnershipError(refusal)
    encoded = re.findall(r"PRAHO_COMPONENT_RESULT=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(encoded) != 1 or len(encoded[0]) > MAX_RETIREMENT_RECEIPT_BASE64:
        raise ValueError("Target staging retirement returned ambiguous evidence")
    receipt = json.loads(base64.b64decode(encoded[0], validate=True))
    if receipt != {
        "operation_id": str(bridge.migration_id),
        "action": "target_retire_artifacts",
        "phase": "artifacts_retired",
        "target_domain_id": bridge.migration.barrier_state["target_domain_id"],
    }:
        raise ValueError("Target staging retirement returned another operation's native identity")


def _retire_source(bridge: MigrationBridge, token: str) -> None:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- enrolled native transport

    values = _retirement_variables(bridge, token)
    if refusal := source_retirement_refusal(bridge.source_server, values):
        raise BridgeOwnershipError(refusal)
    result = AnsibleService().run_server_playbook(
        bridge.source_server, "virtualmin_component.yml", values, timeout_seconds=600
    )
    if result.is_err() or not result.unwrap().success:
        raise ValueError("Source component retirement is uncertain; preserve all native receipts and retained services")
    if refusal := source_retirement_refusal(bridge.source_server, values):
        raise BridgeOwnershipError(refusal)
    encoded = re.findall(r"PRAHO_COMPONENT_RESULT=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(encoded) != 1 or len(encoded[0]) > MAX_RETIREMENT_RECEIPT_BASE64:
        raise ValueError("Source component retirement returned ambiguous evidence")
    receipt = json.loads(base64.b64decode(encoded[0], validate=True))
    if receipt != {"operation_id": str(bridge.migration_id), "action": "source_retire", "phase": "retired"}:
        raise ValueError("Source component retirement did not prove its exact retained-service outcome")


def cleanup_component_bridge(bridge: MigrationBridge, token: str, _service: Any) -> dict[str, str]:
    """The caller releases the claimed bridge lease; no whole-domain source deletion is reachable."""
    from .migration_routing import observe_frontends  # noqa: PLC0415 -- fresh authoritative/cache proof

    try:
        bridge = _guard(bridge, token)
        if bridge.migration.account.status != "terminated":
            routing, waiting = observe_frontends(bridge)
            _progress(bridge.pk, token, {"routing": routing})
            if waiting:
                raise ValueError("; ".join(waiting))
            if not bridge.evidence.get("teardown_started"):
                run_bridge_operation(bridge.migration, UUID(token), "verify", cleanup_bridge_id=bridge.pk)
        if bridge.status == "active":
            _progress(bridge.pk, token, {}, transition_name="start_removing_source")
        bridge = _guard(bridge, token)
        if not bridge.evidence.get("bridge_removed"):
            _progress(bridge.pk, token, {"teardown_started": True})
            run_bridge_operation(bridge.migration, UUID(token), "remove", cleanup_bridge_id=bridge.pk)
            _progress(bridge.pk, token, {"bridge_removed": True})
        bridge = _guard(bridge, token)
        if not bridge.evidence.get("source_components_removed"):
            _retire_source(bridge, token)
            _progress(bridge.pk, token, {"source_components_removed": True})
        bridge = _guard(bridge, token)
        if not bridge.evidence.get("origin_removed"):
            run_bridge_operation(bridge.migration, UUID(token), "origin_remove", cleanup_bridge_id=bridge.pk)
            _progress(bridge.pk, token, {"origin_removed": True})
        bridge = _guard(bridge, token)
        if not bridge.evidence.get("target_artifacts_retired"):
            _retire_target_artifacts(bridge, token)
            _progress(bridge.pk, token, {"target_artifacts_retired": True})
        from .migration_artifact_cleanup import _remove_spool  # noqa: PLC0415 -- UUID-owned private controller staging

        _remove_spool(bridge.migration.archive_name)
        _guard(bridge, token)
        _progress(bridge.pk, token, {"last_error": "", "source_services_retained": True}, transition_name="tear_down")
        return {"action": "torn_down"}
    except BridgeOwnershipError as error:
        try:
            _progress(bridge.pk, token, {"last_error": str(error)}, transition_name="fail")
        except BridgeOwnershipError:
            return {"action": "busy"}
        return {"action": "failed"}
    except (ValueError, RuntimeError, OSError, ObjectDoesNotExist) as error:
        _progress(bridge.pk, token, {"last_error": str(error)})
        schedule_bridge_cleanup(bridge.migration_id, timezone.now() + BRIDGE_RETRY)
        return {"action": "retrying"}
