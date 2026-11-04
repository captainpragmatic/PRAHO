"""Lease-bound native target operations for the explicitly selected component contract."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone

from .component_migration_manifest import ComponentManifest
from .component_migration_transport import component_network_current, terminal_artifact_refusal
from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_models import VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity
from .virtualmin_units import quota_parameters

TARGET_PHASES = {
    "target_prepare": frozenset({"restoring"}),
    "target_restore": frozenset({"restoring"}),
    "target_verify": frozenset({"verifying"}),
    "target_seal": frozenset({"verifying"}),
    "target_activate": frozenset({"activating"}),
    "target_policy": frozenset({"activating", "bridging", "repointing", "needs_review"}),
    "target_remove": frozenset({"compensating"}),
    "target_retire_artifacts": frozenset({"failed", "rolled_back"}),
    "target_retire_unprepared_archive": frozenset({"failed", "rolled_back"}),
}
MAX_TARGET_RESULT_BYTES = 4096
FEATURES = ("unix", "dir", "web", "ssl", "mysql", "logrotate")


def target_operation_variables(
    migration: VirtualminMigration, token: UUID, action: str, *, enabled: bool | None = None
) -> dict[str, Any]:
    approval = migration.component_approval
    if action not in TARGET_PHASES or approval is None:
        raise ValueError("An admitted target component action is required")
    review = approval.review
    manifest = ComponentManifest.parse(review.manifest)
    limits = migration.pre_migration_snapshot.get("target_limits")
    if (
        not isinstance(limits, dict)
        or set(limits) != {"disk_quota_mb", "bandwidth_quota_mb"}
        or any(value is not None and type(value) is not int for value in limits.values())
    ):
        raise ValueError("The component target has no immutable reviewed quota snapshot")
    source = manifest.as_json()["source"]
    operation: dict[str, Any] = {
        "operation_id": str(migration.pk),
        "worker_token": str(token),
        "authority_digest": review.authority_digest,
        "target_identity": review.target_identity,
        "archive_sha256": migration.archive_sha256,
        "creation_params": {
            "domain": source["domain"],
            "user": source["owner"],
            "template": "Default Settings",
            "desc": "PRAHO selected website " + source["domain"],
            "no-email": "",
            **dict.fromkeys(FEATURES, ""),
            **quota_parameters(limits["disk_quota_mb"], limits["bandwidth_quota_mb"]),
        },
    }
    if action in {"target_activate", "target_seal"}:
        operation["target_receipt_sha256"] = migration.barrier_state.get("component_target_receipt_sha256")
    if action in {"target_activate", "target_policy"}:
        if type(enabled) is not bool:
            raise ValueError("Component activation needs the current explicit service policy")
        operation.update(
            enabled=enabled,
            target_receipt_sha256=migration.barrier_state.get("component_target_receipt_sha256"),
        )
    elif enabled is not None:
        raise ValueError("Only forward component activation accepts service policy")
    return {"component_action": action, "component_request": manifest.as_json(), "component_operation": operation}


def target_operation_refusal(  # noqa: PLR0911 -- separate current lease, contract, destination and commit boundaries
    server: VirtualminServer, variables: dict[str, Any] | None
) -> str | None:
    values = variables or {}
    action, operation = values.get("component_action"), values.get("component_operation")
    if not isinstance(action, str) or action not in TARGET_PHASES or not isinstance(operation, dict):
        return "An exact admitted target component action is required"
    try:
        operation_id, token = UUID(operation["operation_id"]), UUID(operation["worker_token"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return "The component target operation or worker lease identity is invalid"
    migration = (
        VirtualminMigration.objects.select_related(
            "account", "source_server", "target_server", "component_approval__review", "component_source_obligation"
        )
        .filter(
            pk=operation_id,
            contract=VirtualminMigration.Contract.IMPORTED_WEB,
            lease_token=token,
            worker_lease_expires_at__gt=timezone.now(),
        )
        .first()
    )
    if (
        migration is None
        or migration.status not in TARGET_PHASES[action]
        or migration.target_server_id != server.pk
        or migration.component_approval_id is None
        or migration.component_source_obligation_id is None
    ):
        return "The target component contract, current worker lease or retained source obligation is missing"
    approval, obligation = migration.component_approval, migration.component_source_obligation
    if approval is None or obligation is None:
        return "The component target has no current immutable admission authority"
    review = approval.review
    try:
        manifest = ComponentManifest.parse(review.manifest)
        manifest.assert_ready()
        expected = target_operation_variables(migration, token, action, enabled=operation.get("enabled"))
    except (ValidationError, ValueError, TypeError):
        return "The component target scope or service policy is unqualified"
    if (
        values.get("component_request") != expected["component_request"]
        or operation != expected["component_operation"]
        or review.digest != manifest.digest
        or review.authority_digest != manifest.authority_digest
        or review.source_server_id != migration.source_server_id
        or review.target_server_id != server.pk
        or review.account_id != migration.account_id
        or review.target_identity != connection_identity(migration.target_server)
        or connection_identity(server) != review.target_identity
        or re.fullmatch(r"[0-9a-f]{64}", migration.archive_sha256) is None
        or obligation.source_server_id != migration.source_server_id
        or obligation.source_domain_id != manifest.as_json()["source"]["domain_id"]
        or obligation.domain != manifest.as_json()["source"]["domain"]
        or obligation.owner != manifest.as_json()["source"]["owner"]
        or hasattr(obligation, "release")
    ):
        return "The target connection, selected archive or approved component authority changed"
    if action not in {
        "target_remove",
        "target_retire_artifacts",
        "target_retire_unprepared_archive",
    } and not component_network_current(migration):
        return "The source or target bridge address differs from the admitted component network"
    if (
        action not in {"target_remove", "target_retire_artifacts", "target_retire_unprepared_archive"}
        and destination_refusal(migration.target_server) is not None
    ):
        return "The destination is no longer a currently verified web node"
    return _phase_refusal(migration, action, operation)


def _phase_refusal(  # noqa: PLR0911 -- independent terminal, seal, policy and ownership boundaries
    migration: VirtualminMigration, action: str, operation: dict[str, Any]
) -> str | None:
    if action in {"target_retire_artifacts", "target_retire_unprepared_archive"}:
        return terminal_artifact_refusal(migration, action)
    if (
        action == "target_policy"
        and migration.status == "needs_review"
        and (
            migration.parked_phase not in {"bridging", "repointing"}
            or (migration.barrier_state.get("target_activation") or {}).get("complete") is not True
        )
    ):
        return "Current policy cannot bypass unfinished or uncertain component activation"
    if action == "target_seal" and (
        migration.barrier_state.get("component_source_seal_intent") is not True
        or not isinstance(operation.get("target_receipt_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", operation["target_receipt_sha256"]) is None
    ):
        return "The target seal requires durable forward-only intent and its exact held receipt"
    if action == "target_remove" and (
        migration.barrier_state.get("component_source_seal_intent") is True
        or migration.barrier_state.get("component_source_sealed") is True
    ):
        return "A sealed or uncertain source commit requires preserving the independently verified target"
    if action in {"target_activate", "target_policy"}:
        if (
            migration.cutover_committed_at is None
            or migration.account.server_id != migration.target_server_id
            or migration.barrier_state.get("component_source_sealed") is not True
            or migration.barrier_state.get("component_target_sealed") is not True
            or not isinstance(operation.get("target_receipt_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", operation["target_receipt_sha256"]) is None
        ):
            return "Target activation requires the sealed source, ownership commit and exact held receipt"
    elif migration.cutover_committed_at is not None or migration.account.server_id != migration.source_server_id:
        return "Precommit target restoration cannot run after ownership publication"
    return None


def run_target_operation(
    migration: VirtualminMigration, token: UUID, action: str, *, enabled: bool | None = None
) -> dict[str, Any]:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- cross-app transport boundary

    values = target_operation_variables(migration, token, action, enabled=enabled)
    server = migration.target_server
    if refusal := target_operation_refusal(server, values):
        raise ValueError(refusal)
    identity = connection_identity(server)
    result = AnsibleService().run_server_playbook(
        server,
        "virtualmin_component.yml",
        values,
        timeout_seconds=3600 if action == "target_restore" else 180 if action == "target_policy" else 600,
    )
    if result.is_err() or not result.unwrap().success:
        raise RuntimeError(
            "Target component operation is uncertain; preserve its native ownership and ingress receipts"
        )
    server.refresh_from_db()
    if connection_identity(server) != identity:
        raise RuntimeError("The component target connection changed during its native operation")
    if refusal := target_operation_refusal(server, values):
        raise RuntimeError("Target component authority changed during its native operation: " + refusal)
    matches = re.findall(r"PRAHO_COMPONENT_RESULT=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_TARGET_RESULT_BYTES * 2:
        raise ValueError("Target component operation returned ambiguous or oversized receipt evidence")
    try:
        decoded = base64.b64decode(matches[0], validate=True)
        if len(decoded) > MAX_TARGET_RESULT_BYTES:
            raise ValueError("Target component receipt exceeds its bound")
        receipt = json.loads(decoded)
    except (ValueError, UnicodeError) as error:
        raise ValueError("Target component receipt is malformed") from error
    expected_phase = {
        "target_prepare": "prepared",
        "target_restore": "held",
        "target_verify": "held",
        "target_seal": "sealed",
        "target_activate": "active",
        "target_policy": "active",
        "target_remove": "removed",
        "target_retire_artifacts": "artifacts_retired",
        "target_retire_unprepared_archive": "artifacts_retired",
    }[action]
    keys = {"operation_id", "action", "phase", "target_domain_id"}
    if action == "target_retire_unprepared_archive":
        keys.remove("target_domain_id")
    if expected_phase in {"held", "sealed"}:
        keys.add("target_receipt_sha256")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != keys
        or receipt.get("action") != action
        or receipt.get("phase") != expected_phase
        or receipt.get("operation_id") != str(migration.pk)
        or (
            action != "target_retire_unprepared_archive"
            and (
                not isinstance(receipt.get("target_domain_id"), str)
                or re.fullmatch(r"[0-9]{1,30}", receipt["target_domain_id"]) is None
            )
        )
        or (
            expected_phase in {"held", "sealed"}
            and (
                not isinstance(receipt.get("target_receipt_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", receipt["target_receipt_sha256"]) is None
            )
        )
        or (
            action != "target_retire_unprepared_archive"
            and migration.barrier_state.get("target_domain_id") is not None
            and receipt["target_domain_id"] != migration.barrier_state["target_domain_id"]
        )
        or (
            expected_phase == "sealed"
            and receipt.get("target_receipt_sha256") != migration.barrier_state.get("component_target_receipt_sha256")
        )
    ):
        raise ValueError("Target component receipt does not match its exact operation and native identity")
    return receipt
