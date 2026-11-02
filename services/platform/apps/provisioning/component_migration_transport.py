"""Source mutations require an admitted component contract and its current worker lease."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone

from .component_migration_manifest import ComponentManifest
from .virtualmin_migration_models import MigrationBridge, VirtualminMigration
from .virtualmin_models import VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity

SOURCE_PHASES = {
    "source_hold": frozenset({"quiescing"}),
    "source_verify": frozenset(
        {"quiescing", "backing_up", "fetching", "pushing", "restoring", "verifying", "activating"}
    ),
    "source_export": frozenset({"backing_up"}),
    "source_release": frozenset({"compensating"}),
    "source_commit": frozenset({"verifying", "activating", "bridging", "repointing"}),
    "source_route": frozenset({"repointing"}),
    "source_retire_artifacts": frozenset({"failed", "rolled_back"}),
}
MAX_SOURCE_RESULT_BYTES = 16 * 1024
MAX_COMPONENT_FILES = 200000


def component_network_current(migration: VirtualminMigration) -> bool:
    network = migration.pre_migration_snapshot.get("component_network")
    return (
        isinstance(network, dict)
        and network
        == {
            "source_ipv4": migration.source_server.ipv4_address,
            "target_ipv4": migration.target_server.ipv4_address,
            "source_ipv6": migration.source_server.ipv6_address or "",
            "target_ipv6": migration.target_server.ipv6_address or "",
        }
        and all(isinstance(value, str) for value in network.values())
        and all(network.get(key) for key in ("source_ipv4", "target_ipv4"))
    )


def source_operation_variables(migration: VirtualminMigration, token: UUID, action: str) -> dict[str, Any]:
    approval = migration.component_approval
    if action not in SOURCE_PHASES or approval is None:
        raise ValueError("An admitted component source operation is required")
    review = approval.review
    manifest = ComponentManifest.parse(review.manifest)
    source = manifest.as_json()["source"]
    values: dict[str, Any] = {
        "component_action": action,
        "component_request": {
            **{key: source[key] for key in ("server_uuid", "connection_identity", "domain_id", "domain", "owner")},
            "paths": [{"relative": row["relative"], "purpose": row["purpose"]} for row in manifest.as_json()["paths"]],
            "databases": list(manifest.selected_databases),
        },
        "component_operation": {
            "operation_id": str(migration.pk),
            "worker_token": str(token),
            "authority_digest": review.authority_digest,
        },
    }
    if action == "source_route":
        values["component_operation"]["network"] = migration.pre_migration_snapshot["component_network"]
    return values


def source_operation_refusal(  # noqa: PLR0911 -- distinct fail-closed authority boundaries explain the required recovery
    server: VirtualminServer, variables: dict[str, Any] | None
) -> str | None:
    """Re-read authority immediately before any managed or imported SSH dispatch."""
    values = variables or {}
    action = values.get("component_action")
    operation = values.get("component_operation")
    if not isinstance(action, str) or action not in SOURCE_PHASES or not isinstance(operation, dict):
        return "An exact admitted source component action is required"
    try:
        operation_id, token = UUID(operation["operation_id"]), UUID(operation["worker_token"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return "The component source operation or worker lease identity is invalid"
    migration = (
        VirtualminMigration.objects.select_related(
            "source_server", "target_server", "component_approval__review", "component_source_obligation"
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
        or migration.status not in SOURCE_PHASES[action]
        or migration.source_server_id != server.pk
        or migration.component_approval_id is None
        or migration.component_source_obligation_id is None
    ):
        return "The source component contract, native obligation or current worker lease is missing"
    if action not in {"source_commit", "source_route"} and migration.cutover_committed_at is not None:
        return "Source compensation/export and forward commit require their exact side of the commit boundary"
    if action == "source_release" and (
        migration.barrier_state.get("component_source_seal_intent") is True
        or migration.barrier_state.get("component_source_sealed") is True
    ):
        return "Source seal intent or a committed source requires forward reconciliation; never reopen it"
    source, target = migration.source_server, migration.target_server
    approval = migration.component_approval
    obligation = migration.component_source_obligation
    if approval is None or obligation is None:
        return "The admitted component approval or retained source obligation is missing"
    review = approval.review
    try:
        expected = source_operation_variables(migration, token, action)
        manifest = ComponentManifest.parse(review.manifest)
        manifest.assert_ready()
    except (ValidationError, ValueError):
        return "The approved component source evidence is incomplete or unqualified"
    if (
        values.get("component_request") != expected["component_request"]
        or operation.get("authority_digest") != manifest.authority_digest
        or review.authority_digest != manifest.authority_digest
        or review.digest != manifest.digest
        or review.source_server_id != source.pk
        or review.target_server_id != target.pk
        or review.account_id != migration.account_id
        or review.source_identity != connection_identity(source)
        or connection_identity(server) != connection_identity(source)
        or source.security_state not in {"acknowledged_source_only", "verified_web"}
        or source.security_operation
        or obligation.source_server_id != source.pk
        or obligation.source_domain_id != manifest.as_json()["source"]["domain_id"]
        or obligation.domain != manifest.as_json()["source"]["domain"]
        or obligation.owner != manifest.as_json()["source"]["owner"]
        or hasattr(obligation, "release")
    ):
        return "The source connection, approved component scope or retained service identity changed"
    if action not in {"source_release", "source_retire_artifacts"} and not component_network_current(migration):
        return "The source or target bridge address differs from the admitted component network"
    if action not in {"source_release", "source_retire_artifacts"} and (
        review.target_identity != connection_identity(target) or destination_refusal(target) is not None
    ):
        return "The component migration destination is no longer the reviewed verified web node"
    return _forward_refusal(migration, action, operation, expected["component_operation"])


def _forward_refusal(
    migration: VirtualminMigration, action: str, operation: dict[str, Any], expected: dict[str, Any]
) -> str | None:
    if action == "source_retire_artifacts":
        if operation != expected:
            return "Source staging retirement changed its exact native attempt"
        return terminal_artifact_refusal(migration, action)
    if action == "source_route" and (
        operation != expected
        or migration.cutover_committed_at is None
        or migration.account.server_id != migration.target_server_id
        or migration.barrier_state.get("component_source_sealed") is not True
        or migration.barrier_state.get("component_target_sealed") is not True
        or migration.barrier_state.get("component_target_activation_complete") is not True
        or not MigrationBridge.objects.filter(migration=migration, status="active").exists()
    ):
        return "Component routing requires both native seals, current target ownership and its verified source bridge"
    if action == "source_commit" and (
        migration.barrier_state.get("component_source_seal_intent") is not True
        or migration.barrier_state.get("component_target_sealed") is not True
        or not migration.archive_sha256
        or operation.get("archive_sha256") != migration.archive_sha256
        or not migration.barrier_state.get("component_target_receipt_sha256")
        or operation.get("target_receipt_sha256") != migration.barrier_state["component_target_receipt_sha256"]
    ):
        return "The source seal does not match the migration's selected archive and held-target receipt"
    return None


def terminal_artifact_refusal(migration: VirtualminMigration, action: str) -> str | None:
    state = migration.barrier_state
    if (
        migration.status not in {"failed", "rolled_back"}
        or migration.cutover_committed_at is not None
        or any(
            state.get(key) is True
            for key in ("component_source_seal_intent", "component_source_sealed", "component_target_sealed")
        )
    ):
        return "Private staging retirement requires determinate unsealed terminal compensation"
    if action == "source_retire_artifacts" and (
        state.get("component_source_hold_issued") is not True or state.get("component_source_released") is not True
    ):
        return "Source private staging has no independently released native parent"
    if action == "target_retire_artifacts" and (
        not migration.restore_issued or state.get("component_target_removed") is not True
    ):
        return "Prepared target private staging requires proven native removal"
    if action == "target_retire_unprepared_archive" and (
        migration.restore_issued or state.get("component_target_archive_issued") is not True
    ):
        return "Only a provably never-prepared target archive may use file-only retirement"
    return None


def run_source_operation(migration: VirtualminMigration, token: UUID, action: str) -> dict[str, Any]:
    """Execute through the current enrolled source only; ambiguous responses preserve native holds."""
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- cross-app transport boundary

    values = source_operation_variables(migration, token, action)
    if action == "source_commit":
        values["component_operation"].update(
            archive_sha256=migration.archive_sha256,
            target_receipt_sha256=migration.barrier_state.get("component_target_receipt_sha256"),
        )
    server = migration.source_server
    identity = connection_identity(server)
    if refusal := source_operation_refusal(server, values):
        raise ValueError(refusal)
    result = AnsibleService().run_server_playbook(
        server, "virtualmin_component.yml", values, timeout_seconds=3600 if action == "source_export" else 600
    )
    if result.is_err() or not result.unwrap().success:
        raise RuntimeError(
            "Source component operation is uncertain; preserve native holds and inspect its exact receipt"
        )
    server.refresh_from_db()
    if connection_identity(server) != identity:
        raise RuntimeError("Source connection changed during the component operation; inspect before proceeding")
    if refusal := source_operation_refusal(server, values):
        raise RuntimeError("Source component authority changed during its native operation: " + refusal)
    return _source_receipt(migration, values, action, result.unwrap().stdout)


def _source_receipt(migration: VirtualminMigration, values: dict[str, Any], action: str, stdout: str) -> dict[str, Any]:
    matches = re.findall(r"PRAHO_COMPONENT_RESULT=([A-Za-z0-9+/=]+)", stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_SOURCE_RESULT_BYTES * 2:
        raise ValueError("Source component operation returned ambiguous or oversized receipt evidence")
    try:
        decoded = base64.b64decode(matches[0], validate=True)
        if len(decoded) > MAX_SOURCE_RESULT_BYTES:
            raise ValueError("Source component receipt exceeds its bound")
        receipt = json.loads(decoded)
    except (ValueError, UnicodeError) as error:
        raise ValueError("Source component operation returned malformed receipt evidence") from error
    phase = {
        "source_release": "released",
        "source_commit": "committed",
        "source_route": "routed",
        "source_retire_artifacts": "artifacts_retired",
    }.get(action, "held")
    expected = {"operation_id": str(migration.pk), "action": action, "phase": phase}
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("Source component receipt belongs to another operation or phase")
    if action == "source_route":
        if set(receipt) != {*expected, "routing"} or receipt["routing"] not in {
            "source_dns_updated",
            "operator_dns_required",
        }:
            raise ValueError("Component routing returned unrecognized public evidence")
        return receipt
    if action != "source_export":
        if receipt != expected:
            raise ValueError("Source component receipt includes unrecognized evidence")
        return receipt
    exported = receipt.get("export")
    if (
        set(receipt) != {*expected, "export"}
        or not isinstance(exported, dict)
        or set(exported) != {"path", "sha256", "bytes", "files", "databases"}
        or exported["path"] != f"/var/lib/praho-transfer/components/{migration.pk}/migration_{migration.pk}.tar.gz"
        or not isinstance(exported["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", exported["sha256"]) is None
        or type(exported["bytes"]) is not int
        or not 0 < exported["bytes"] <= 2**63 - 1
        or type(exported["files"]) is not int
        or not 0 < exported["files"] <= MAX_COMPONENT_FILES
        or exported["databases"] != sorted(values["component_request"]["databases"])
    ):
        raise ValueError("Source component export does not match its exact selected archive scope")
    return receipt
