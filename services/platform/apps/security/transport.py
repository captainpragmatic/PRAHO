"""Capture local identities, then perform the frozen read-only gateway protocol."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.common import crowdsec_transport as gateway
from apps.common.ssh import parse_ssh_host_keys

from .models import SecuritySource

MAX_KEY_BYTES = 65536
MAX_SSH_PORT = 65535


@dataclass(frozen=True)
class SourceConnection:
    source_id: UUID
    transport: str
    installation_id: UUID
    configuration_digest: str
    identity: str
    endpoint: gateway.Endpoint | None


@dataclass(frozen=True)
class Observation:
    health: dict[str, object]
    snapshot: dict[str, object]


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _key() -> tuple[str, str]:
    path = str(getattr(settings, "PRAHO_CROWDSEC_SSH_PRIVATE_KEY_PATH", "") or "")
    try:
        if not path:
            raise ValueError("Missing gateway key")
        with Path(path).open("rb") as key:
            content = key.read(MAX_KEY_BYTES + 1)
        if not content or len(content) > MAX_KEY_BYTES:
            raise ValueError("Invalid gateway key")
    except (ValueError, OSError) as error:
        raise ValidationError(_("The separately enrolled CrowdSec gateway identity is unavailable.")) from error
    return path, _digest({"path": path, "sha256": hashlib.sha256(content).hexdigest()})


def _node_identity(source: SecuritySource) -> str:
    if source.kind != "node":
        if source.virtualmin_server_id is not None:
            raise ValidationError(_("Portal sources cannot use a Virtualmin node binding."))
        return ""
    from apps.provisioning.crowdsec_policy import CROWDSEC_PROFILE  # noqa: PLC0415 -- qualification boundary
    from apps.provisioning.virtualmin_security import (  # noqa: PLC0415 -- qualification boundary
        connection_identity,
        selected_profile,
    )

    server = source.virtualmin_server
    if (
        server is None
        or selected_profile(server) != CROWDSEC_PROFILE
        or server.security_configuration_digest != source.configuration_digest
    ):
        raise ValidationError(_("The node must explicitly select the matching CrowdSec qualification profile."))
    return connection_identity(server)


def _connection(source: SecuritySource, *, enrolling: bool) -> SourceConnection:
    endpoint = None
    node_identity = _node_identity(source)
    if source.transport == "local":
        if not (
            getattr(settings, "PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED", False)
            and getattr(settings, "ENVIRONMENT", "") == "staging"
            and source.kind == "portal"
            and source.hostname == "localhost"
            and source.port == 0
            and not source.host_keys
        ):
            raise ValidationError(
                _("A local CrowdSec source requires the explicitly enabled staging Portal installation.")
            )
        key_identity = ""
    elif source.transport == "ssh":
        try:
            ipaddress.ip_address(source.hostname)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", source.hostname):
                raise ValidationError(_("An enrolled CrowdSec SSH hostname is required.")) from None
        try:
            parse_ssh_host_keys(source.host_keys)
        except ValueError as error:
            raise ValidationError(_("Strict independently enrolled CrowdSec SSH host keys are required.")) from error
        if not 1 <= source.port <= MAX_SSH_PORT:
            raise ValidationError(_("The enrolled CrowdSec SSH port is invalid."))
        key_path, key_identity = _key()
        endpoint = gateway.Endpoint(source.hostname, source.port, source.host_keys, key_path)
    else:
        raise ValidationError(_("The CrowdSec source transport is unsupported."))
    if enrolling:
        source.key_identity, source.virtualmin_identity = key_identity, node_identity
    elif source.key_identity != key_identity or source.virtualmin_identity != node_identity:
        raise ValidationError(_("CrowdSec transport or node qualification changed; explicitly review the enrollment."))
    identity = _digest(
        {
            "source": str(source.pk),
            "kind": source.kind,
            "transport": source.transport,
            "hostname": source.hostname,
            "port": source.port,
            "host_keys": source.host_keys,
            "installation_id": str(source.installation_id),
            "configuration_digest": source.configuration_digest,
            "key_identity": key_identity,
            "virtualmin_identity": node_identity,
        }
    )
    return SourceConnection(
        source.pk, source.transport, source.installation_id, source.configuration_digest, identity, endpoint
    )


def bind_connection(source: SecuritySource) -> SourceConnection:
    return _connection(source, enrolling=True)


def capture_connection(source: SecuritySource) -> SourceConnection:
    return _connection(source, enrolling=False)


def _call(connection: SourceConnection, operation: str, payload: dict[str, object]) -> dict[str, object]:
    request = json.dumps(
        {
            "protocol": 1,
            "request_id": str(uuid4()),
            "installation_id": str(connection.installation_id),
            "configuration_digest": connection.configuration_digest,
            "operation": operation,
            "payload": payload,
        },
        separators=(",", ":"),
    ).encode()
    if connection.transport == "local":
        response = gateway.local_rpc(request)
    elif connection.endpoint is not None:
        response = gateway.remote_rpc(connection.endpoint, request)
    else:
        raise gateway.CrowdSecRPCError("CrowdSec RPC failed")
    # Preserve protocol checks at this adapter boundary as well, including alternate clients.
    checked = gateway.parse_response(json.dumps(response, allow_nan=False).encode(), request)
    return cast("dict[str, object]", checked["result"])


def fetch(connection: SourceConnection, after_alert_id: int) -> Observation:
    return Observation(
        _call(connection, "health", {}), _call(connection, "snapshot", {"after_alert_id": after_alert_id})
    )


def validate_observation(connection: SourceConnection, after_alert_id: int, observation: Observation) -> None:
    """Publication accepts only the same bounded schemas as the actual gateway adapter."""
    for operation, payload, result in (
        ("health", {}, observation.health),
        ("snapshot", {"after_alert_id": after_alert_id}, observation.snapshot),
    ):
        wire = {
            "protocol": 1,
            "request_id": str(uuid4()),
            "installation_id": str(connection.installation_id),
            "configuration_digest": connection.configuration_digest,
            "operation": operation,
        }
        gateway.parse_response(
            json.dumps({**wire, "result": result}, allow_nan=False).encode(),
            json.dumps({**wire, "payload": payload}).encode(),
        )
