"""Narrow component bridge authority over enrolled imported or managed SSH transports."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any
from uuid import UUID

from django.utils import timezone

from .account_hostname_config import bridge_window_hours
from .component_migration_transport import component_network_current
from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_models import VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity

BRIDGE_PHASES = {
    "prepare": ("source", frozenset({"verifying"})),
    "origin_install": ("target", frozenset({"verifying"})),
    "origin_verify": ("source", frozenset({"verifying"})),
    "install": ("source", frozenset({"bridging"})),
    "verify": ("source", frozenset({"bridging", "repointing"})),
    "remove": ("source", frozenset({"compensating"})),
    "origin_remove": ("target", frozenset({"compensating"})),
}
MAX_BRIDGE_BYTES = 256 * 1024
MAX_BRIDGE_VHOSTS = 4
MANIFEST_FIELDS = frozenset({"identity", "domain", "source", "target", "origin", "account_name", "vhosts"})
VHOST_FIELDS = frozenset(
    {"name", "names", "port", "neutral", "bindings", "verify_names", "certificate", "key", "public_certificate"}
)


def _vhost_values_valid(item: dict[str, Any], names: list[str]) -> bool:
    probes, bindings = item.get("verify_names"), item.get("bindings")
    if (
        not isinstance(probes, list)
        or not probes
        or not all(isinstance(value, str) for value in probes)
        or not set(probes) <= set(names)
        or item["name"] not in probes
        or len(set(probes)) != len(probes)
        or not isinstance(bindings, list)
        or not bindings
        or not all(isinstance(value, str) for value in bindings)
    ):
        return False
    try:
        return bindings == sorted(set(bindings)) and all(
            value == "*" or ("%" not in value and str(ipaddress.ip_address(value)) == value) for value in bindings
        )
    except ValueError:
        return False


def bridge_operation_variables(
    migration: VirtualminMigration,
    token: UUID,
    action: str,
    *,
    manifest: dict[str, Any] | None = None,
    origin_certificate: str | None = None,
) -> dict[str, Any]:
    approval = migration.component_approval
    network = migration.pre_migration_snapshot.get("component_network")
    name = migration.pre_migration_snapshot.get("component_account_name")
    if action not in BRIDGE_PHASES or approval is None or not isinstance(network, dict) or not isinstance(name, str):
        raise ValueError("A frozen component bridge scope and admitted worker are required")
    values: dict[str, Any] = {
        "component_bridge_action": action,
        "component_bridge_operation": {
            "operation_id": str(migration.pk),
            "worker_token": str(token),
            "authority_digest": approval.review.authority_digest,
        },
        "bridge_id": str(migration.pk),
        "bridge_domain": migration.account.domain,
        "bridge_account_name": name,
        "bridge_source_ipv4": network["source_ipv4"],
        "bridge_target_ipv4": network["target_ipv4"],
        "bridge_certificate_min_seconds": (bridge_window_hours() + 1) * 3600,
    }
    if action == "origin_install":
        if not isinstance(manifest, dict) or origin_certificate is not None:
            raise ValueError("Origin installation requires exactly its public source bridge manifest")
        values["bridge_manifest"] = json.loads(json.dumps(manifest, allow_nan=False))
    elif action in {"origin_verify", "install"}:
        if not isinstance(origin_certificate, str) or not origin_certificate or manifest is not None:
            raise ValueError("This bridge action requires exactly its public origin trust")
        values["bridge_origin_certificate"] = origin_certificate
    elif manifest is not None or origin_certificate is not None:
        raise ValueError("This component bridge action does not accept extra source data")
    return values


def _manifest_valid(  # noqa: PLR0911 -- bounded untrusted receipt schema rejects before native dispatch
    migration: VirtualminMigration, manifest: object
) -> bool:
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        return False
    network = migration.pre_migration_snapshot["component_network"]
    name = migration.pre_migration_snapshot["component_account_name"]
    if any(
        manifest.get(key) != value
        for key, value in {
            "identity": str(migration.pk),
            "domain": migration.account.domain,
            "source": network["source_ipv4"],
            "target": network["target_ipv4"],
            "origin": "bridge-" + migration.pk.hex + ".invalid",
            "account_name": name,
        }.items()
    ):
        return False
    vhosts = manifest.get("vhosts")
    if not isinstance(vhosts, list) or not 0 < len(vhosts) <= MAX_BRIDGE_VHOSTS:
        return False
    seen = set()
    for item in vhosts:
        if not isinstance(item, dict) or item.keys() - VHOST_FIELDS:
            return False
        neutral = bool(name and item.get("name") == name)
        names = item.get("names")
        allowed = {name} if neutral else {migration.account.domain, "www." + migration.account.domain}
        host = item.get("name")
        if not isinstance(host, str):
            return False
        identity = host, str(item.get("port"))
        if (
            identity in seen
            or identity[1] not in {"80", "443"}
            or item.get("name") != (name if neutral else migration.account.domain)
            or item.get("neutral") is not neutral
            or not isinstance(names, list)
            or not names
            or not all(isinstance(value, str) for value in names)
            or not set(names) <= allowed
            or item["name"] not in names
            or len(set(names)) != len(names)
            or not _vhost_values_valid(item, names)
        ):
            return False
        seen.add(identity)
    return (migration.account.domain, "80") in seen


def bridge_operation_refusal(  # noqa: PLR0911 -- distinct lease, scope and commit refusals aid recovery
    server: VirtualminServer, variables: dict[str, Any] | None
) -> str | None:
    values = variables or {}
    if "component_bridge_cleanup" in values:
        from .component_bridge_cleanup import bridge_cleanup_refusal  # noqa: PLC0415 -- claimed retention lease

        return bridge_cleanup_refusal(server, values)
    action, operation = values.get("component_bridge_action"), values.get("component_bridge_operation")
    if not isinstance(action, str) or action not in BRIDGE_PHASES or not isinstance(operation, dict):
        return "An explicit component bridge action and current worker lease are required"
    try:
        operation_id, token = UUID(operation["operation_id"]), UUID(operation["worker_token"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return "The component bridge worker identity is invalid"
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
    if migration is None or migration.component_approval_id is None or migration.component_source_obligation_id is None:
        return "The component bridge has no current consumed admission or worker lease"
    side, phases = BRIDGE_PHASES[action]
    expected_server = migration.source_server if side == "source" else migration.target_server
    approval, obligation = migration.component_approval, migration.component_source_obligation
    if approval is None or obligation is None:
        return "The admitted bridge approval or retained source obligation is missing"
    review = approval.review
    if (
        migration.status not in phases
        or server.pk != expected_server.pk
        or connection_identity(server) != connection_identity(expected_server)
        or review.source_identity != connection_identity(migration.source_server)
        or review.target_identity != connection_identity(migration.target_server)
        or migration.source_server.security_state not in {"acknowledged_source_only", "verified_web"}
        or migration.source_server.security_operation
        or migration.target_server.security_operation
        or hasattr(obligation, "release")
        or obligation.source_server_id != migration.source_server_id
        or not component_network_current(migration)
    ):
        return "The component bridge side, current connection, retained source or frozen network changed"
    try:
        expected = bridge_operation_variables(
            migration,
            token,
            action,
            manifest=values.get("bridge_manifest"),
            origin_certificate=values.get("bridge_origin_certificate"),
        )
        encoded = json.dumps(values, allow_nan=False).encode()
    except (ValueError, TypeError, KeyError):
        return "The component bridge action has malformed or substituted inputs"
    if values != expected or len(encoded) > MAX_BRIDGE_BYTES or b"PRIVATE KEY" in encoded:
        return "The component bridge inputs exceed their approved public scope"
    if action == "origin_install" and not _manifest_valid(migration, values["bridge_manifest"]):
        return "The source bridge manifest contains unapproved names or endpoint identities"
    if action not in {"remove", "origin_remove"} and destination_refusal(migration.target_server) is not None:
        return "The component bridge destination is no longer a verified web node"
    return _phase_refusal(migration, action)


def _phase_refusal(migration: VirtualminMigration, action: str) -> str | None:
    state = migration.barrier_state
    if action in {"install", "verify"}:
        if (
            migration.cutover_committed_at is None
            or state.get("component_source_sealed") is not True
            or state.get("component_target_sealed") is not True
            or state.get("component_target_activation_complete") is not True
            or migration.account.server_id != migration.target_server_id
        ):
            return "Source bridge publication requires the sealed source, ownership commit and proven target activation"
    elif migration.cutover_committed_at is not None:
        return "This bridge preparation or compensation cannot run after the ownership commit"
    if action in {"remove", "origin_remove"} and (
        state.get("component_source_seal_intent") is True or state.get("component_source_sealed") is True
    ):
        return "A sealed or uncertain source cannot compensate its verified bridge resources"
    return None


def run_bridge_operation(  # noqa: PLR0913 -- explicit public inputs and alternative claimed cleanup authority
    migration: VirtualminMigration,
    token: UUID,
    action: str,
    *,
    manifest: dict[str, Any] | None = None,
    origin_certificate: str | None = None,
    cleanup_bridge_id: UUID | None = None,
) -> Any:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- app transport boundary

    values = bridge_operation_variables(
        migration, token, action, manifest=manifest, origin_certificate=origin_certificate
    )
    if cleanup_bridge_id is not None:
        from .component_bridge_cleanup import cleanup_variables  # noqa: PLC0415 -- completed migration retention lease

        if manifest is not None or origin_certificate is not None:
            raise ValueError("Completed bridge retirement cannot accept substituted preparation inputs")
        values = cleanup_variables(migration, token, action, cleanup_bridge_id)
    server = migration.source_server if BRIDGE_PHASES[action][0] == "source" else migration.target_server
    if refusal := bridge_operation_refusal(server, values):
        raise ValueError(refusal)
    result = AnsibleService().run_server_playbook(
        server, "virtualmin_component_bridge.yml", values, timeout_seconds=600
    )
    if result.is_err() or not result.unwrap().success:
        raise RuntimeError("The component bridge operation is uncertain; preserve its exact native receipts")
    server.refresh_from_db()
    if refusal := bridge_operation_refusal(server, values):
        raise RuntimeError("Component bridge authority changed during its operation: " + refusal)
    matches = re.findall(r"BRIDGE_RESULT=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_BRIDGE_BYTES * 2:
        raise ValueError("The component bridge returned ambiguous or oversized evidence")
    try:
        decoded = base64.b64decode(matches[0], validate=True)
        if len(decoded) > MAX_BRIDGE_BYTES:
            raise ValueError("The component bridge result exceeds its bound")
        receipt = json.loads(decoded)
    except (ValueError, UnicodeError) as error:
        raise ValueError("The component bridge result is malformed") from error
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"identity", "action", "payload"}
        or receipt["identity"] != str(migration.pk)
        or receipt["action"] != action
        or "PRIVATE KEY" in json.dumps(receipt)
        or (action == "prepare" and not _manifest_valid(migration, receipt["payload"]))
    ):
        raise ValueError("The component bridge result does not match its exact public operation scope")
    return receipt["payload"]
