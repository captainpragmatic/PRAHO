"""The source node's reverse proxy to the target during a cutover (ADR-0061 P2.5).

`virtualmin_bridge.yml` writes a vhost in Apache's conf-enabled (selected before the disabled
Virtualmin vhost), proxies the customer domain to the target over the provider's private network,
and verifies that the source answers. The source terminates TLS with the domain's existing
certificate; the target sees the original Host over HTTP.
"""

from __future__ import annotations

from typing import Any

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .virtualmin_gateway import listing_attribute
from .virtualmin_migration_models import VirtualminMigration

BRIDGE_PLAYBOOK = "virtualmin_bridge.yml"
BRIDGE_TIMEOUT_SECONDS = 600
BRIDGE_TARGET_PORT = 80


def _runner() -> Any:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

    return AnsibleService()


def _variables(migration: VirtualminMigration, action: str) -> Result[dict[str, Any], str]:
    remote = (migration.pre_migration_snapshot or {}).get("remote") or {}
    domain_id = str(listing_attribute(remote.get("attributes") or {}, "ID") or "")
    if not domain_id.isdigit():
        return Err(
            "The migration snapshot has no node domain id; the bridge needs the certificate path",
            retriability=Retriability.NOT_RETRIABLE,
        )
    target = migration.target_server
    if not target.ipv4_address:
        return Err("The target node has no IPv4 address", retriability=Retriability.NOT_RETRIABLE)
    return Ok(
        {
            "bridge_action": action,
            "bridge_domain": migration.account.domain,
            "bridge_domain_id": domain_id,
            "bridge_target_ipv4": target.ipv4_address,
            "bridge_target_port": BRIDGE_TARGET_PORT,
            "bridge_certificate": f"/etc/ssl/virtualmin/{domain_id}/ssl.cert",
            "bridge_certificate_key": f"/etc/ssl/virtualmin/{domain_id}/ssl.key",
        }
    )


def _run(migration: VirtualminMigration, action: str) -> Result[str, str]:
    deployment = getattr(migration.source_server, "node_deployment", None)
    if deployment is None:
        return Err(
            f"Server {migration.source_server.hostname} has no managed node_deployment; no bridge is possible",
            retriability=Retriability.NOT_RETRIABLE,
        )
    variables = _variables(migration, action)
    if variables.is_err():
        return Err(variables.unwrap_err(), retriability=retriability_of(variables))
    result = _runner().run_playbook(
        deployment, BRIDGE_PLAYBOOK, variables.unwrap(), timeout_seconds=BRIDGE_TIMEOUT_SECONDS
    )
    if result.is_err():
        return Err(f"Bridge {action} could not run: {result.unwrap_err()}", retriability=retriability_of(result))
    if not result.unwrap().success:
        return Err(
            f"Bridge {action} failed on {migration.source_server.hostname}; its state is uncertain",
            retriability=Retriability.UNKNOWN,
        )
    return Ok({"install": "installed", "verify": "verified", "remove": "removed"}[action])


def install_bridge(migration: VirtualminMigration) -> Result[str, str]:
    return _run(migration, "install")


def verify_bridge(migration: VirtualminMigration) -> Result[str, str]:
    return _run(migration, "verify")


def remove_bridge(migration: VirtualminMigration) -> Result[str, str]:
    return _run(migration, "remove")
