"""Only the fixed enrolled gateway accepts action payloads; no request supplies paths or URLs."""

from __future__ import annotations

import hashlib
import json
from typing import cast
from uuid import UUID, uuid4

from apps.common import crowdsec_transport as gateway

from .transport import SourceConnection


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


def payload_digest(operation: str, payload: dict[str, object]) -> str:
    return digest({"operation": operation, "payload": payload})


def call(
    connection: SourceConnection, operation: str, payload: dict[str, object], request_id: UUID | None = None
) -> dict[str, object]:
    request = json.dumps(
        {
            "protocol": 1,
            "request_id": str(request_id or uuid4()),
            "installation_id": str(connection.installation_id),
            "configuration_digest": connection.configuration_digest,
            "operation": operation,
            "payload": payload,
        },
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    if connection.transport == "local":
        response = gateway.local_rpc(request)
    elif connection.endpoint is not None:
        response = gateway.remote_rpc(connection.endpoint, request)
    else:
        raise gateway.CrowdSecRPCError("CrowdSec RPC failed")
    return cast(
        "dict[str, object]", gateway.parse_response(json.dumps(response, allow_nan=False).encode(), request)["result"]
    )
