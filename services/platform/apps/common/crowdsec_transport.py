"""Bounded, read-only CrowdSec RPCs through one enrolled forced-command identity."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import queue
import re
import select
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, cast
from uuid import UUID

import paramiko

from apps.common.ssh import configure_strict_host_key_checking

RPC_TIMEOUT = 30.0
MAX_REQUEST = 65536
MAX_RESPONSE = 8 * 1024 * 1024
MAX_DECISIONS = 10000
MAX_ALERTS = 1000
CHUNK_SIZE = 65536
SHA256_LENGTH = 64
MAX_TIMESTAMP = 64
WIRE_FIELDS = {"protocol", "request_id", "installation_id", "configuration_digest", "operation"}
MAX_PENDING_RPCS = 16
_PENDING = threading.BoundedSemaphore(MAX_PENDING_RPCS)


class CrowdSecRPCError(RuntimeError):
    """No response is committed unless a complete matching success was verified."""


@dataclass(frozen=True)
class Endpoint:
    hostname: str
    port: int
    host_keys: str
    private_key_path: str


def _fail() -> NoReturn:
    raise CrowdSecRPCError("CrowdSec RPC failed")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _decode(raw: bytes, limit: int) -> dict[str, object]:
    if not raw or len(raw) > limit:
        _fail()
    try:
        value: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error
    if not isinstance(value, dict):
        _fail()
    return cast("dict[str, object]", value)


def _request(raw: bytes) -> dict[str, object]:
    request = _decode(raw, MAX_REQUEST)
    if set(request) != WIRE_FIELDS | {"payload"} or type(request["protocol"]) is not int or request["protocol"] != 1:
        _fail()
    try:
        for field in ("request_id", "installation_id"):
            value = request[field]
            if not isinstance(value, str) or str(UUID(value)) != value:
                _fail()
    except ValueError as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error
    digest = request["configuration_digest"]
    if (
        not isinstance(digest, str)
        or len(digest) != SHA256_LENGTH
        or any(value not in "0123456789abcdef" for value in digest)
    ):
        _fail()
    payload = request["payload"]
    if not isinstance(payload, dict):
        _fail()
    _request_payload(request["operation"], payload)
    return request


def _request_payload(operation: object, payload: dict[str, object]) -> None:
    if operation == "snapshot":
        if (
            set(payload) != {"after_alert_id"}
            or type(payload["after_alert_id"]) is not int
            or not 0 <= payload["after_alert_id"] < 2**63
        ):
            _fail()
    elif operation == "health":
        if payload:
            _fail()
    elif operation == "receipt_get":
        if set(payload) != {"request_id"} or not isinstance(payload["request_id"], str):
            _fail()
        try:
            if str(UUID(payload["request_id"])) != payload["request_id"]:
                _fail()
        except ValueError as error:
            raise CrowdSecRPCError("CrowdSec RPC failed") from error
    else:
        _fail()


def _validate_snapshot(result: dict[str, object], request: dict[str, object]) -> None:
    if set(result) != {"decisions", "alerts", "alert_watermark", "has_more", "observed_at"}:
        _fail()
    decisions, alerts = result["decisions"], result["alerts"]
    if (
        not isinstance(decisions, list)
        or not isinstance(alerts, list)
        or len(decisions) > MAX_DECISIONS
        or len(alerts) > MAX_ALERTS
    ):
        _fail()
    if type(result["has_more"]) is not bool or type(result["alert_watermark"]) is not int:
        _fail()
    value = result["observed_at"]
    try:
        if not isinstance(value, str) or datetime.fromisoformat(value).tzinfo is None:
            _fail()
    except ValueError as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error
    last = cast("dict[str, int]", request["payload"])["after_alert_id"]
    _summary_rows(decisions, alerts=False)
    ids = _summary_rows(alerts, alerts=True)
    if ids and ids[0] <= last:
        _fail()
    last = ids[-1] if ids else last
    if not last <= result["alert_watermark"] < 2**63:
        _fail()
    if result["has_more"] and (len(alerts) != MAX_ALERTS or result["alert_watermark"] != last):
        _fail()


def _summary_rows(rows: list[object], *, alerts: bool) -> list[int]:
    fields = (
        {"id", "created_at", "scenario", "event_count", "scope", "value", "simulated"}
        if alerts
        else {"id", "created_at", "expires_at", "scenario", "type", "scope", "value", "origin", "simulated"}
    )
    ids = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields or type(row["id"]) is not int or not 0 < row["id"] < 2**63:
            _fail()
        if type(row["simulated"]) is not bool:
            _fail()
        _timestamp(row["created_at"])
        _label(row["scenario"])
        if not alerts:
            _timestamp(row["expires_at"])
            _label(row["origin"])
            _label(row["type"])
        elif type(row["event_count"]) is not int or not 0 <= row["event_count"] < 2**63:
            _fail()
        _summary_address(row["scope"], row["value"], nullable=alerts)
        ids.append(row["id"])
    if ids != sorted(set(ids)):
        _fail()
    return ids


def _summary_address(scope: object, value: object, *, nullable: bool) -> None:
    if nullable and scope is None and value is None:
        return
    try:
        if scope == "ip":
            if not isinstance(value, str) or str(ipaddress.ip_address(value)) != value:
                _fail()
        elif scope == "range":
            if not isinstance(value, str) or str(ipaddress.ip_network(value, strict=True)) != value:
                _fail()
        else:
            _fail()
    except ValueError as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error


def _label(value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./:+-]{1,200}", value):
        _fail()


def _timestamp(value: object) -> None:
    try:
        if not isinstance(value, str) or len(value) > MAX_TIMESTAMP or datetime.fromisoformat(value).tzinfo is None:
            _fail()
    except ValueError as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error


def _validate_health(result: dict[str, object]) -> None:
    if set(result) != {"observed_at", "simulation", "engine", "bouncer", "firewall", "clock", "configuration"}:
        _fail()
    _timestamp(result["observed_at"])
    if type(result["simulation"]) is not bool:
        _fail()
    for name in ("engine", "bouncer"):
        value = result[name]
        if not isinstance(value, dict) or set(value) != {"active", "version"} or type(value["active"]) is not bool:
            _fail()
        version = value["version"]
        if version is not None and (
            not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[+.-][A-Za-z0-9_.-]+)?", version)
        ):
            _fail()
    firewall = result["firewall"]
    if not isinstance(firewall, dict) or set(firewall) != {"qualified", "ban_sets_empty"}:
        _fail()
    if type(firewall["qualified"]) is not bool or (
        firewall["ban_sets_empty"] is not None and type(firewall["ban_sets_empty"]) is not bool
    ):
        _fail()
    configuration = result["configuration"]
    if (
        not isinstance(configuration, dict)
        or set(configuration) != {"qualified"}
        or type(configuration["qualified"]) is not bool
    ):
        _fail()
    _validate_clock(result["clock"])


def _validate_clock(clock: object) -> None:
    if not isinstance(clock, dict) or set(clock) != {
        "synchronized",
        "qualified",
        "offset_seconds",
        "maximum_error_seconds",
        "estimated_error_seconds",
    }:
        _fail()
    if type(clock["qualified"]) is not bool or type(clock["synchronized"]) is not bool:
        _fail()
    readings = [clock[field] for field in ("offset_seconds", "maximum_error_seconds", "estimated_error_seconds")]
    if any(value is not None and (type(value) not in (int, float) or not math.isfinite(value)) for value in readings):
        _fail()
    if clock["qualified"] and (not clock["synchronized"] or any(value is None or abs(value) > 1 for value in readings)):
        _fail()


def parse_response(raw: bytes, request_raw: bytes) -> dict[str, object]:
    request = _request(request_raw)
    response = _decode(raw, MAX_RESPONSE)
    if set(response) != WIRE_FIELDS | {"result"} or any(response[field] != request[field] for field in WIRE_FIELDS):
        _fail()
    if type(response["protocol"]) is not int:
        _fail()
    result = response["result"]
    if not isinstance(result, dict):
        _fail()
    if request["operation"] == "snapshot":
        _validate_snapshot(result, request)
    elif request["operation"] == "receipt_get":
        if result != {"status": "unknown", "evidence": "no_receipt"}:
            _fail()
    else:
        _validate_health(result)
    return response


def _remote(client: paramiko.SSHClient, endpoint: Endpoint, raw: bytes, deadline: float) -> bytes:
    if not endpoint.host_keys or not endpoint.private_key_path:
        _fail()
    configure_strict_host_key_checking(
        client, host_keys=endpoint.host_keys, hostnames=(endpoint.hostname,), port=endpoint.port
    )
    client.connect(
        hostname=endpoint.hostname,
        port=endpoint.port,
        username="praho-crowdsec",
        key_filename=endpoint.private_key_path,
        allow_agent=False,
        look_for_keys=False,
        timeout=max(0.01, deadline - time.monotonic()),
        auth_timeout=max(0.01, deadline - time.monotonic()),
        banner_timeout=max(0.01, deadline - time.monotonic()),
    )
    transport = client.get_transport()
    if transport is None:
        _fail()
    channel = transport.open_session(timeout=max(0.01, deadline - time.monotonic()))
    try:
        channel.settimeout(max(0.01, deadline - time.monotonic()))
        channel.invoke_shell()  # ForceCommand executes without PTY or an arbitrary exec request.
        channel.sendall(raw)
        channel.shutdown_write()
        output = bytearray()
        error_bytes = 0
        while time.monotonic() < deadline:
            if channel.recv_ready():
                output.extend(channel.recv(min(CHUNK_SIZE, MAX_RESPONSE + 1 - len(output))))
                if len(output) > MAX_RESPONSE:
                    _fail()
                continue
            if channel.recv_stderr_ready():
                error_bytes += len(channel.recv_stderr(CHUNK_SIZE))
                if error_bytes > MAX_REQUEST:
                    _fail()
                continue
            if channel.exit_status_ready() and getattr(channel, "eof_received", False):
                if channel.recv_exit_status() != 0:
                    _fail()
                return bytes(output)
            if channel.closed:
                _fail()
            time.sleep(0.01)
        _fail()
    finally:
        channel.close()


def remote_rpc(endpoint: Endpoint, raw: bytes) -> dict[str, object]:
    """The caller has a wall deadline even if DNS, SSH handshake or a remote stalls."""
    _request(raw)
    if not _PENDING.acquire(blocking=False):
        _fail()
    client = paramiko.SSHClient()
    completed: queue.Queue[bytes | Exception] = queue.Queue(maxsize=1)
    deadline = time.monotonic() + RPC_TIMEOUT

    def run() -> None:
        try:
            completed.put(_remote(client, endpoint, raw, deadline))
        except (OSError, EOFError, ValueError, paramiko.SSHException, CrowdSecRPCError) as error:
            completed.put(error)
        finally:
            client.close()
            _PENDING.release()

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        result = completed.get(timeout=RPC_TIMEOUT)
        if isinstance(result, Exception):
            raise CrowdSecRPCError("CrowdSec RPC failed") from result
        return parse_response(result, raw)
    except queue.Empty as error:
        raise CrowdSecRPCError("CrowdSec RPC deadline exceeded") from error
    finally:
        client.close()


def local_rpc(raw: bytes) -> dict[str, object]:
    """Staging uses the same root-owned helper through one no-argument sudo grant."""
    _request(raw)
    deadline = time.monotonic() + RPC_TIMEOUT
    argv = ["/usr/bin/sudo", "-n", "/usr/local/libexec/praho-crowdsec-gateway"]
    try:
        with subprocess.Popen(  # noqa: S603 -- fixed helper and sudo only
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        ) as child:
            timer = threading.Timer(RPC_TIMEOUT, child.kill)
            timer.daemon = True
            timer.start()
            try:
                assert child.stdin is not None and child.stdout is not None
                child.stdin.write(raw)
                child.stdin.close()
                output = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                        _fail()
                    part = os.read(child.stdout.fileno(), min(CHUNK_SIZE, MAX_RESPONSE + 1 - len(output)))
                    if not part:
                        break
                    output.extend(part)
                    if len(output) > MAX_RESPONSE:
                        _fail()
                if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                    _fail()
                return parse_response(bytes(output), raw)
            finally:
                timer.cancel()
                if child.poll() is None:
                    child.kill()
                    child.wait()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise CrowdSecRPCError("CrowdSec RPC failed") from error
