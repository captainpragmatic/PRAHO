"""A complete native Hetzner inventory backing legacy teardown endpoint observers.

Use the real typed client and immutable planner. DELETE reaches the test's existing
provider endpoint mock; only its successful outcome removes the exact native row.
Subsequent lists and exact reads reflect that removal, including across retries.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from apps.infrastructure.cloud_resource_inventory import CloudResourceClient, ResourceResponse
from apps.infrastructure.models import NodeDeployment


def attach_teardown_provider(
    gateway: Any,
    deployment: NodeDeployment,
    *,
    firewall_ids: tuple[str, ...] = (),
    ssh_key_ids: tuple[str, ...] = (),
    server_id: str | None = None,
) -> CloudResourceClient:
    correlation = str(deployment.correlation_id)
    server_id = deployment.external_node_id if server_id is None else server_id
    rows: dict[str, dict[str, dict[str, object]]] = {
        collection: {}
        for collection in ("servers", "primary_ips", "floating_ips", "firewalls", "ssh_keys", "volumes", "images")
    }
    if server_id:
        rows["servers"][server_id] = {
            "id": server_id,
            "name": deployment.hostname,
            "labels": {"praho-deployment": correlation},
            "status": "running",
        }
    for identifier in firewall_ids:
        rows["firewalls"][identifier] = {
            "id": identifier,
            "labels": {"deployment-id": correlation},
            "applied_to": [{"type": "server", "server": {"id": server_id}}] if server_id else [],
        }
    for identifier in ssh_key_ids:
        rows["ssh_keys"][identifier] = {"id": identifier, "labels": {"praho-deployment": correlation}}

    singular = {"servers": "server", "firewalls": "firewall", "ssh_keys": "ssh_key"}
    endpoints = {"servers": "delete_server", "firewalls": "delete_firewall", "ssh_keys": "delete_ssh_key_by_id"}

    def request(
        method: str,
        path: str,
        *,
        params: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
    ) -> ResourceResponse:
        parts = path.strip("/").split("/")
        collection = parts[0]
        if collection not in rows or body is not None:
            raise AssertionError(f"Unexpected provider request: {method} {path}")
        if method == "GET" and len(parts) == 1:
            if params != {"per_page": 100, "page": 1}:
                raise AssertionError(f"Unexpected provider pagination: {params}")
            return ResourceResponse(
                200, {collection: list(rows[collection].values()), "meta": {"pagination": {"next_page": None}}}
            )
        if len(parts[1:]) != 1 or collection not in singular or method not in {"GET", "DELETE"}:
            raise AssertionError(f"Unexpected provider resource: {method} {path}")
        identifier = unquote(parts[1])
        row = rows[collection].get(identifier)
        if row is None:
            return ResourceResponse(404, {"error": {"code": "not_found"}})
        if method == "GET":
            return ResourceResponse(200, {singular[collection]: row})
        result = getattr(gateway, endpoints[collection])(identifier)
        if result.is_err() or result.unwrap() is not True:
            return ResourceResponse(503, {"error": {"code": "service_unavailable"}})
        del rows[collection][identifier]
        return ResourceResponse(204, None)

    client = CloudResourceClient("hetzner", request, poll_timeout=0)
    gateway.resource_client.return_value = client
    return client
