"""Strict, private read-only RPCs against the qualified CrowdSec SQLite schema."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import paramiko
import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy/ansible/roles/crowdsec/files/gateway.py"
INSTALLATION = "417ebf86-1d99-45ec-91bf-16a1a7878e7f"
MANAGED_PATHS = {
    "/etc/praho-crowdsec/artifacts.lock.json",
    "/etc/crowdsec/config.yaml",
    "/etc/crowdsec/acquis.yaml",
    "/etc/crowdsec/profiles.yaml",
    "/etc/crowdsec/simulation.yaml",
    "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
    "/usr/bin/cscli",
    "/etc/systemd/system/crowdsec.service.d/praho.conf",
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/praho.conf",
    "/etc/systemd/system/crowdsec-hubupdate.service.d/praho.conf",
    "/etc/systemd/system/crowdsec-hubupdate.timer.d/praho.conf",
    "/etc/systemd/system/praho-crowdsec-firewall.service",
    "/usr/local/libexec/praho-crowdsec-firewall",
    "/usr/local/libexec/praho-crowdsec-gateway",
    "/home/praho-crowdsec/.ssh/authorized_keys",
    "/etc/sudoers.d/praho-crowdsec",
}
LEAF_PATH = "/etc/crowdsec/parsers/s00-raw/syslog-logs.yaml"
MANIFEST = {
    "hub": {
        "files": [
            {
                "path": "parsers/s00-raw/crowdsecurity/syslog-logs.yaml",
                "installed_path": LEAF_PATH,
                "sha256": hashlib.sha256(b"managed").hexdigest(),
                "host_kinds": ["node", "portal"],
            }
        ]
    }
}
STOCK_PATHS = {
    "crowdsec.service": "/usr/lib/systemd/system/crowdsec.service",
    "crowdsec-firewall-bouncer.service": "/etc/systemd/system/crowdsec-firewall-bouncer.service",
}
MANIFEST["stock_units"] = {
    unit: {
        "path": path,
        "sha256": hashlib.sha256(b"stock").hexdigest(),
        "fragment_paths": (["/lib/systemd/system/crowdsec.service", path] if unit == "crowdsec.service" else [path]),
        "drop_in_paths": [f"/etc/systemd/system/{unit}.d/praho.conf"],
    }
    for unit, path in STOCK_PATHS.items()
}
MANIFEST_BYTES = json.dumps(MANIFEST).encode()
POLICY = {
    "schema": 1,
    "host_kind": "node",
    "simulation": True,
    "protected_cidrs": ["192.0.2.0/24", "2001:db8::/64"],
    "artifact_lock_sha256": hashlib.sha256(MANIFEST_BYTES).hexdigest(),
    "bouncer_binary_sha256": hashlib.sha256(b"bouncer").hexdigest(),
    "managed_files": {path: hashlib.sha256(b"managed").hexdigest() for path in MANAGED_PATHS | {LEAF_PATH}},
}
POLICY["managed_files"]["/etc/praho-crowdsec/artifacts.lock.json"] = hashlib.sha256(MANIFEST_BYTES).hexdigest()
DIGEST = hashlib.sha256(json.dumps(POLICY, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
# Captured from the actual 1.8.2 arm64 package's SQLite database, created by cscli.
TABLES = {
    "alerts": "id INTEGER PRIMARY KEY NOT NULL,created_at datetime NOT NULL,updated_at datetime NOT NULL,"
    "scenario TEXT NOT NULL,bucket_id TEXT,message TEXT,events_count INTEGER,started_at datetime,stopped_at datetime,"
    "source_ip TEXT,source_range TEXT,source_as_number TEXT,source_as_name TEXT,source_country TEXT,"
    "source_latitude REAL,source_longitude REAL,source_scope TEXT,source_value TEXT,capacity INTEGER,leak_speed TEXT,"
    "scenario_version TEXT,scenario_hash TEXT,simulated bool NOT NULL,uuid TEXT,remediation bool,kind TEXT,machine_alerts INTEGER",
    "decisions": "id INTEGER PRIMARY KEY NOT NULL,created_at datetime NOT NULL,updated_at datetime NOT NULL,"
    '"until" datetime,scenario TEXT NOT NULL,type TEXT NOT NULL,start_ip INTEGER,end_ip INTEGER,start_suffix INTEGER,'
    "end_suffix INTEGER,ip_size INTEGER,scope TEXT NOT NULL,value TEXT NOT NULL,origin TEXT NOT NULL,"
    "simulated bool NOT NULL,uuid TEXT,alert_decisions INTEGER",
    "machines": "id INTEGER PRIMARY KEY NOT NULL,created_at datetime NOT NULL,updated_at datetime NOT NULL,"
    "last_push datetime,last_heartbeat datetime,machine_id TEXT NOT NULL,password TEXT NOT NULL,ip_address TEXT NOT NULL,"
    "scenarios TEXT,version TEXT,is_validated bool NOT NULL,auth_type TEXT NOT NULL,osname TEXT,osfamily TEXT,"
    "osversion TEXT,featureflags TEXT,hubstate json,datasources json,features json",
}


def unit_command(argv: list[str], **_kwargs: object) -> tuple[int, bytes]:
    if argv[:2] != ["/usr/bin/systemctl", "show"]:
        return 1, b""
    unit = argv[2]
    command = (
        "/usr/bin/crowdsec -c /etc/crowdsec/config.yaml"
        if unit == "crowdsec.service"
        else "/usr/local/libexec/praho-crowdsec-bouncer -c /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    )
    properties = {
        "LoadState": "loaded",
        "FragmentPath": STOCK_PATHS[unit],
        "DropInPaths": f"/etc/systemd/system/{unit}.d/praho.conf",
        "NeedDaemonReload": "no",
        "Transient": "no",
        "Environment": "LC_ALL=C LANG=C" if unit == "crowdsec.service" else "",
        "EnvironmentFiles": "",
        "RootDirectory": "",
        "RootImage": "",
    }
    result = [f"{name}={value}" for name, value in properties.items()]
    commands = {
        "ExecStart": [command],
        "ExecStartPre": [command + (" -t -error" if unit == "crowdsec.service" else " -t")],
        "ExecReload": [command + " -t -error", "/bin/kill -HUP $MAINPID"] if unit == "crowdsec.service" else [],
        "ExecStartPost": [] if unit == "crowdsec.service" else ["/bin/sleep 0.1"],
    }
    for name, values in commands.items():
        result.extend(f"{name}={{ path={value.split()[0]} ; argv[]={value} ; ignore_errors=no }}" for value in values)
    return 0, ("\n".join(result) + "\n").encode()


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    assert HELPER.exists(), "CrowdSec read-only gateway does not exist"
    spec = importlib.util.spec_from_file_location("crowdsec_gateway_under_test", HELPER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "DATABASE_PATH", tmp_path / "crowdsec.db")
    monkeypatch.setattr(module, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(module, "RECEIPT_DIRECTORY", tmp_path / "receipts")
    monkeypatch.setattr(module, "MANAGED_ROOT", tmp_path)
    monkeypatch.setattr(module, "TRUSTED_ROOT", tmp_path)
    monkeypatch.setattr(module, "TRUSTED_UID", os.getuid())
    monkeypatch.setattr(module, "TRUSTED_GID", tmp_path.stat().st_gid)
    monkeypatch.setattr(module, "_command", unit_command)
    return module


@pytest.fixture
def enrolled(gateway: ModuleType) -> dict[str, object]:
    for name in set(POLICY["managed_files"]) | {"/usr/local/libexec/praho-crowdsec-bouncer"}:
        path = gateway.MANAGED_ROOT / name.removeprefix("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"bouncer" if name.endswith("/praho-crowdsec-bouncer") else b"managed")
    for name in STOCK_PATHS.values():
        path = gateway.MANAGED_ROOT / name.removeprefix("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"stock")
    (gateway.MANAGED_ROOT / "etc/praho-crowdsec/artifacts.lock.json").write_bytes(MANIFEST_BYTES)
    private = {
        "etc/crowdsec/local_api_credentials.yaml": f"url: http://127.0.0.1:8080\nlogin: praho-installation-{INSTALLATION}\npassword: {'s' * 64}\n",
        "etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local": f'api_key: "{"k" * 64}"\n',
    }
    for name, content in private.items():
        path = gateway.MANAGED_ROOT / name
        path.write_text(content)
        path.chmod(0o600)
    state = gateway.MANAGED_ROOT / "var/lib/praho-crowdsec"
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o700)
    for service in ("engine", "bouncer"):
        path = state / f"{service}-applied.sha256"
        path.write_text(DIGEST + "\n")
        path.chmod(0o600)
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        for table, fields in TABLES.items():
            db.execute(f"CREATE TABLE {table}({fields})")
        db.execute(
            "INSERT INTO machines(id,created_at,updated_at,machine_id,password,ip_address,is_validated,auth_type) "
            "VALUES(1,?,?,?,?,?,1,'password')",
            ("2026-11-03T00:00:00Z", "2026-11-03T00:00:00Z", f"praho-installation-{INSTALLATION}", "NEVER_EXPORT", ""),
        )
    status = gateway.DATABASE_PATH.stat()
    os.chmod(gateway.DATABASE_PATH, 0o600)
    config = {
        "protocol": 1,
        "installation_id": INSTALLATION,
        "configuration_digest": DIGEST,
        "simulation": True,
        "protected_cidrs": ["192.0.2.0/24", "2001:db8::/64"],
        "database_witness": {"device": status.st_dev, "inode": status.st_ino},
        "policy": json.loads(json.dumps(POLICY)),
    }
    gateway.CONFIG_PATH.write_text(json.dumps(config))
    os.chmod(gateway.CONFIG_PATH, 0o600)
    return config


def request(operation: str = "snapshot", payload: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        {
            "protocol": 1,
            "request_id": str(uuid4()),
            "installation_id": INSTALLATION,
            "configuration_digest": DIGEST,
            "operation": operation,
            "payload": payload if payload is not None else {"after_alert_id": 0},
        }
    ).encode()


def seed(db_path: Path, *, alerts: int = 1, decisions: int = 1) -> None:
    current = datetime.now(UTC)
    started, expiry = current.isoformat(), (current + timedelta(hours=4)).isoformat()
    with sqlite3.connect(db_path) as db:
        db.executemany(
            "INSERT INTO alerts(id,created_at,updated_at,scenario,message,events_count,source_scope,source_value,"
            "simulated,remediation) VALUES(?,?,?,'crowdsecurity/ssh-bf','SECRET_RAW_EVENT',7,'Ip',?,0,1)",
            [(n, started, started, f"198.51.100.{n % 250 + 1}") for n in range(1, alerts + 1)],
        )
        db.executemany(
            'INSERT INTO decisions(id,created_at,updated_at,"until",scenario,type,scope,value,origin,simulated) '
            "VALUES(?,?,?,?,'crowdsecurity/ssh-bf','ban','Ip',?,'crowdsec',0)",
            [(n, started, started, expiry, f"198.51.100.{n % 250 + 1}") for n in range(1, decisions + 1)],
        )


def test_complete_snapshot_and_multibatch_catchup(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH, alerts=1201, decisions=102)
    first = gateway.handle(request())
    assert len(first["result"]["decisions"]) == 102
    assert len(first["result"]["alerts"]) == 1000
    assert {
        key: first["result"]["decisions"][0][key]
        for key in ("value", "scope", "origin", "scenario", "type", "simulated")
    } == {
        "value": "198.51.100.2",
        "scope": "ip",
        "origin": "crowdsec",
        "scenario": "crowdsecurity/ssh-bf",
        "type": "ban",
        "simulated": False,
    }
    assert first["result"]["alerts"][0]["event_count"] == 7
    assert first["result"]["alert_watermark"] == 1000
    assert first["result"]["has_more"] is True
    last = gateway.handle(request(payload={"after_alert_id": 1000}))
    assert [row["id"] for row in last["result"]["alerts"]] == list(range(1001, 1202))
    assert last["result"]["has_more"] is False
    assert last["result"]["alert_watermark"] == 1201
    assert last["result"]["decisions"] == first["result"]["decisions"]
    assert "SECRET_RAW_EVENT" not in json.dumps(first)
    assert "NEVER_EXPORT" not in json.dumps(first)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"protocol":1,"protocol":1}',
        b"{}{}",
        b"[]",
        b'{"protocol":NaN}',
        b"\xff",
        b"{}" + b" " * 65536,
    ],
    ids=["duplicate", "trailing", "array", "nonfinite", "utf8", "oversize"],
)
def test_reject_ambiguous_or_excessive_input(gateway: ModuleType, raw: bytes) -> None:
    with pytest.raises(gateway.GatewayError):
        gateway.handle(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol", True),
        ("protocol", 2),
        ("request_id", "../../tmp/x"),
        ("installation_id", str(uuid4())),
        ("configuration_digest", "f" * 64),
        ("operation", "ban_put"),
        ("operation", "id; reboot"),
        ("payload", {"after_alert_id": True}),
        ("payload", {"after_alert_id": -1}),
        ("payload", {"after_alert_id": 0, "url": "http://example.org"}),
        ("unknown", "anything"),
    ],
)
def test_reject_wrong_contract_or_source_identity(
    gateway: ModuleType,
    enrolled: dict[str, object],
    field: str,
    value: object,
) -> None:
    envelope = json.loads(request())
    envelope[field] = value
    with pytest.raises(gateway.GatewayError):
        gateway.handle(json.dumps(envelope).encode())


def test_replacement_and_missing_machine_marker_fail(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    replacement = gateway.DATABASE_PATH.with_suffix(".replacement")
    replacement.write_bytes(gateway.DATABASE_PATH.read_bytes())
    replacement.replace(gateway.DATABASE_PATH)
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())
    status = gateway.DATABASE_PATH.stat()
    enrolled["database_witness"] = {"device": status.st_dev, "inode": status.st_ino}
    gateway.CONFIG_PATH.write_text(json.dumps(enrolled))
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        db.execute("DELETE FROM machines")
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_schema_change_fails(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        db.execute("ALTER TABLE decisions ADD COLUMN unqualified TEXT")
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_too_many_decisions_never_returns_partial_snapshot(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH, decisions=10001)
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_expired_decisions_and_cursor_gaps(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH, alerts=4, decisions=2)
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        db.execute('UPDATE decisions SET "until"=? WHERE id=1', ("2000-01-01T00:00:00Z",))
        db.execute("DELETE FROM alerts WHERE id IN (2,3)")
    result = gateway.handle(request())["result"]
    assert [row["id"] for row in result["decisions"]] == [2]
    assert [row["id"] for row in result["alerts"]] == [1, 4]
    assert result["alert_watermark"] == 4
    assert result["has_more"] is False


def test_invalid_expiry_cannot_silently_drop_a_decision(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH)
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        db.execute('UPDATE decisions SET "until"=?', ("not-a-date",))
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


@pytest.mark.parametrize("target", ["config", "database"])
def test_untrusted_modes_and_symlinks_rejected(
    gateway: ModuleType,
    enrolled: dict[str, object],
    target: str,
) -> None:
    path = gateway.CONFIG_PATH if target == "config" else gateway.DATABASE_PATH
    os.chmod(path, 0o666)  # noqa: S103 -- hostile permission fixture must be rejected
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())
    os.chmod(path, 0o600)
    original = path.with_suffix(".original")
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_absent_receipt_is_unknown(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    result = gateway.handle(request("receipt_get", {"request_id": str(uuid4())}))["result"]
    assert result == {"status": "unknown", "evidence": "no_receipt"}


def test_read_only_queries_preserve_database_bytes(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH)
    before = gateway.DATABASE_PATH.read_bytes()
    gateway.handle(request())
    assert gateway.DATABASE_PATH.read_bytes() == before


@pytest.fixture
def transport() -> ModuleType:
    return importlib.import_module("apps.common.crowdsec_transport")


def response_for(raw: bytes) -> bytes:
    envelope = json.loads(raw)
    envelope.pop("payload")
    envelope["result"] = {
        "decisions": [],
        "alerts": [],
        "alert_watermark": 0,
        "has_more": False,
        "observed_at": datetime.now(UTC).isoformat(),
    }
    return json.dumps(envelope).encode()


@pytest.mark.parametrize("failure", ["truncated", "duplicate", "wrong_source", "unknown", "oversize", "partial"])
def test_transport_discards_invalid_response(transport: ModuleType, failure: str) -> None:
    raw = request()
    response = json.loads(response_for(raw))
    if failure == "truncated":
        output = response_for(raw)[:-1]
    elif failure == "duplicate":
        output = response_for(raw).replace(b'"protocol": 1', b'"protocol": 1, "protocol": 1')
    elif failure == "wrong_source":
        response["installation_id"] = str(uuid4())
        output = json.dumps(response).encode()
    elif failure == "unknown":
        response["remote_path"] = "/etc/shadow"
        output = json.dumps(response).encode()
    elif failure == "partial":
        response["result"].pop("has_more")
        output = json.dumps(response).encode()
    else:
        output = b" " * (8 * 1024 * 1024 + 1)
    with pytest.raises(transport.CrowdSecRPCError):
        transport.parse_response(output, raw)


def test_transport_accepts_complete_matching_snapshot(transport: ModuleType) -> None:
    raw = request()
    parsed = transport.parse_response(response_for(raw), raw)
    assert parsed["result"]["decisions"] == []
    assert parsed["result"]["has_more"] is False


@pytest.mark.parametrize(
    ("table", "field", "value"),
    [
        ("alerts", "value", "raw@example.org"),
        ("alerts", "scope", "username"),
        ("alerts", "event_count", True),
        ("alerts", "event_count", -1),
        ("alerts", "created_at", "no timestamp"),
        ("decisions", "value", "2001:db8::/129"),
        ("decisions", "scope", "unknown"),
        ("decisions", "expires_at", "2026-11-03T01:00:00"),
        ("decisions", "scenario", "raw log payload"),
        ("decisions", "origin", []),
        ("decisions", "type", True),
    ],
)
def test_transport_rejects_invalid_summary_fields(transport: ModuleType, table: str, field: str, value: object) -> None:
    raw = request()
    response = json.loads(response_for(raw))
    stamp = datetime.now(UTC).isoformat()
    response["result"]["alerts"] = [
        {
            "id": 1,
            "created_at": stamp,
            "scenario": "crowdsecurity/ssh-bf",
            "event_count": 2,
            "scope": "ip",
            "value": "198.51.100.1",
            "simulated": False,
        }
    ]
    response["result"]["decisions"] = [
        {
            "id": 1,
            "created_at": stamp,
            "expires_at": stamp,
            "scenario": "crowdsecurity/ssh-bf",
            "type": "ban",
            "scope": "ip",
            "value": "198.51.100.1",
            "origin": "crowdsec",
            "simulated": False,
        }
    ]
    response["result"]["alert_watermark"] = 1
    transport.parse_response(json.dumps(response).encode(), raw)
    response["result"][table][0][field] = value
    with pytest.raises(transport.CrowdSecRPCError):
        transport.parse_response(json.dumps(response).encode(), raw)


class RemoteChannel:
    def __init__(self, output: bytes, status: int = 0) -> None:
        self.output, self.status = output, status
        self.sent = b""
        self.invoked = self.eof = self.closed = False
        self.eof_received = True

    def invoke_shell(self) -> None:
        self.invoked = True

    def sendall(self, raw: bytes) -> None:
        self.sent += raw

    def shutdown_write(self) -> None:
        self.eof = True

    def settimeout(self, seconds: float) -> None:
        assert 0 < seconds <= 30

    def recv_ready(self) -> bool:
        return bool(self.output)

    def recv(self, size: int) -> bytes:
        part, self.output = self.output[:size], self.output[size:]
        return part

    def recv_stderr_ready(self) -> bool:
        return False

    def exit_status_ready(self) -> bool:
        return not self.output

    def recv_exit_status(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


def test_remote_transport_uses_fresh_strict_identity_and_no_exec_or_pty(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = request()
    channel = RemoteChannel(response_for(raw))
    key = paramiko.RSAKey.generate(2048)
    clients = []

    class Client:
        def __init__(self) -> None:
            self._system_host_keys = paramiko.HostKeys()
            self.keys = paramiko.HostKeys()
            self.closed = False
            clients.append(self)

        def get_host_keys(self) -> paramiko.HostKeys:
            return self.keys

        def set_missing_host_key_policy(self, policy: object) -> None:
            assert isinstance(policy, paramiko.RejectPolicy)

        def connect(self, **kwargs: object) -> None:
            assert kwargs["username"] == "praho-crowdsec"
            assert kwargs["allow_agent"] is False and kwargs["look_for_keys"] is False
            assert kwargs["key_filename"] == str(tmp_path / "key")
            assert self.keys.lookup("[node.example]:9876")["ssh-rsa"].get_base64() == key.get_base64()

        def get_transport(self) -> Client:
            return self

        def open_session(self, timeout: float) -> RemoteChannel:
            assert timeout <= 30
            return channel

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(transport.paramiko, "SSHClient", Client)
    endpoint = transport.Endpoint("node.example", 9876, f"ssh-rsa {key.get_base64()}", str(tmp_path / "key"))
    result = transport.remote_rpc(endpoint, raw)
    assert result["result"]["has_more"] is False
    assert channel.invoked is True and channel.eof is True
    assert channel.sent == raw
    assert channel.closed is True and clients[0].closed is True


def test_remote_timeout_returns_without_unbounded_worker(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "RPC_TIMEOUT", 0.05)
    started, release, finished = threading.Event(), threading.Event(), threading.Event()

    def blocked(*_args: object) -> bytes:
        started.set()
        release.wait(2)
        finished.set()
        return b""

    monkeypatch.setattr(transport, "_remote", blocked)
    try:
        with pytest.raises(transport.CrowdSecRPCError, match="deadline"):
            transport.remote_rpc(transport.Endpoint("node.example", 9876, "nonempty", "/fixed/key"), request())
        assert started.is_set() and not finished.is_set()
    finally:
        release.set()


def test_remote_eof_is_reported_as_failure_without_waiting_for_deadline(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "RPC_TIMEOUT", 0.05)

    def disconnected(*_args: object) -> bytes:
        raise EOFError("synthetic disconnect")

    monkeypatch.setattr(transport, "_remote", disconnected)
    with pytest.raises(transport.CrowdSecRPCError, match="RPC failed"):
        transport.remote_rpc(transport.Endpoint("node.example", 9876, "nonempty", "/fixed/key"), request())


def test_exit_status_before_eof_cannot_commit_a_json_prefix(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = request()

    class DelayedChannel(RemoteChannel):
        def __init__(self) -> None:
            super().__init__(response_for(raw))
            self.eof_received = False
            self.polls = 0

        def recv_ready(self) -> bool:
            self.polls += 1
            if self.polls == 3:
                self.output = b"{}"
                self.eof_received = True
            return bool(self.output)

    channel = DelayedChannel()
    client = paramiko.SSHClient()
    monkeypatch.setattr(client, "connect", lambda **_kwargs: None)
    monkeypatch.setattr(client, "get_transport", lambda: SimpleNamespace(open_session=lambda **_kwargs: channel))
    key = paramiko.RSAKey.generate(2048)
    endpoint = transport.Endpoint("node.example", 9876, f"ssh-rsa {key.get_base64()}", "/fixed/key")
    with pytest.raises(transport.CrowdSecRPCError):
        output = transport._remote(client, endpoint, raw, time.monotonic() + 1)
        transport.parse_response(output, raw)


@pytest.mark.parametrize("outcome", ["success", "nonzero", "oversize", "timeout"])
def test_local_rpc_has_fixed_sudo_argv_and_bounded_output(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    raw = request()
    output_expression = repr(response_for(raw)) if outcome != "oversize" else "b' ' * (8 * 1024 * 1024 + 1)"
    actual_popen = subprocess.Popen
    children = []
    monkeypatch.setattr(transport, "RPC_TIMEOUT", 0.1 if outcome == "timeout" else 3)
    script = (
        f"import sys,time; assert sys.stdin.buffer.read()=={raw!r}; "
        + ("time.sleep(1); " if outcome == "timeout" else "")
        + f"sys.stdout.buffer.write({output_expression}); sys.exit({1 if outcome == 'nonzero' else 0})"
    )

    def popen(argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        assert argv == ["/usr/bin/sudo", "-n", "/usr/local/libexec/praho-crowdsec-gateway"]
        child = actual_popen([sys.executable, "-S", "-c", script], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(transport.subprocess, "Popen", popen)
    if outcome == "success":
        assert transport.local_rpc(raw)["result"]["has_more"] is False
    else:
        with pytest.raises(transport.CrowdSecRPCError):
            transport.local_rpc(raw)
    assert len(children) == 1 and children[0].poll() is not None
    if outcome == "nonzero":
        assert children[0].returncode == 1


def nft_table(family: str, protected: str) -> dict[str, object]:
    table = f"praho_crowdsec{4 if family == 'ip' else 6}"
    identity = {"family": family, "table": table}
    return {
        "nftables": [
            {"table": {"family": family, "name": table, "handle": 1}},
            {
                "chain": {
                    **identity,
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": -10,
                    "policy": "accept",
                    "handle": 1,
                }
            },
            {
                "set": {
                    **identity,
                    "name": "protected",
                    "type": "ipv4_addr" if family == "ip" else "ipv6_addr",
                    "flags": ["interval"],
                    "elem": [protected],
                    "handle": 2,
                }
            },
            {
                "set": {
                    **identity,
                    "name": "bans",
                    "type": "ipv4_addr" if family == "ip" else "ipv6_addr",
                    "flags": ["interval", "timeout"],
                    "handle": 3,
                }
            },
            *[
                {
                    "rule": {
                        **identity,
                        "chain": "input",
                        "handle": n + 10,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": family, "field": "saddr"}},
                                    "right": f"@{name}",
                                }
                            },
                            {verdict: None},
                        ],
                    }
                }
                for n, (name, verdict) in enumerate((("protected", "return"), ("bans", "drop")))
            ],
        ]
    }


def test_health_distinguishes_simulation_enforcement_and_qualified_clock(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def command(argv: list[str], **_kwargs: object) -> tuple[int, bytes]:
        if argv[:2] == ["/usr/bin/systemctl", "show"]:
            return unit_command(argv)
        if argv[0] == "/usr/sbin/nft":
            family = argv[-2]
            return 0, json.dumps(nft_table(family, "192.0.2.0/24" if family == "ip" else "2001:db8::/64")).encode()
        if argv[:2] == ["/usr/bin/crowdsec", "-version"]:
            return 0, b"version: v1.8.2-debian-arm64\n"
        if argv[:2] == ["/usr/local/libexec/praho-crowdsec-bouncer", "-V"]:
            return 0, b"version: v0.0.36\n"
        return (0, b"active\n") if argv[-1] == "crowdsec.service" else (3, b"inactive\n")

    monkeypatch.setattr(gateway, "_command", command)
    monkeypatch.setattr(gateway, "_kernel_clock", lambda: (0, 0, 10_000, 100_000, 50_000))
    result = gateway.handle(request("health", {}))["result"]
    assert result["engine"] == {"active": True, "version": "1.8.2"}
    assert result["bouncer"] == {"active": False, "version": "0.0.36"}
    assert result["firewall"] == {"qualified": True, "ban_sets_empty": True}
    assert result["clock"]["qualified"] is True and result["clock"]["offset_seconds"] == 0.01


def test_unqualified_clock_and_foreign_rule_cannot_report_healthy(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = nft_table("ip", "192.0.2.0/24")
    table["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
    monkeypatch.setattr(gateway, "_command", lambda *_args, **_kwargs: (0, json.dumps(table).encode()))
    monkeypatch.setattr(gateway, "_kernel_clock", lambda: (0, 64, 0, 0, 0))
    result = gateway.handle(request("health", {}))["result"]
    assert result["firewall"]["qualified"] is False
    assert result["clock"]["qualified"] is False


def test_firewall_physical_elements_can_exceed_decision_count(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def command(argv: list[str], **_kwargs: object) -> tuple[int, bytes]:
        if argv[0] != "/usr/sbin/nft":
            return 1, b""
        family = argv[-2]
        table = nft_table(family, "192.0.2.0/24" if family == "ip" else "2001:db8::/64")
        if family == "ip":
            table["nftables"][3]["set"]["elem"] = [f"198.18.{n // 256}.{n % 256}" for n in range(10001)]
        return 0, json.dumps(table).encode()

    monkeypatch.setattr(gateway, "_command", command)
    result = gateway.handle(request("health", {}))["result"]
    assert result["firewall"] == {"qualified": True, "ban_sets_empty": False}


def test_declared_digest_does_not_hide_policy_tampering(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    enrolled["policy"]["host_kind"] = "portal"
    gateway.CONFIG_PATH.write_text(json.dumps(enrolled))
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_health_rechecks_managed_config_bytes(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway, "_command", unit_command)
    monkeypatch.setattr(gateway, "_kernel_clock", lambda: None)
    clean = gateway.handle(request("health", {}))["result"]
    assert clean["configuration"]["qualified"] is True
    (gateway.MANAGED_ROOT / "etc/crowdsec/config.yaml").write_text("changed")
    drifted = gateway.handle(request("health", {}))["result"]
    assert drifted["configuration"]["qualified"] is False


def test_snapshot_refuses_actual_managed_config_drift(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    gateway.handle(request())
    (gateway.MANAGED_ROOT / "etc/crowdsec/config.yaml").write_text("changed")
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


@pytest.mark.parametrize("service", ["engine", "bouncer"])
@pytest.mark.parametrize("case", ["missing", "stale", "trailing", "unsafe", "symlink"])
def test_unapplied_runtime_policy_degrades_health_and_refuses_mirror_reads(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    service: str,
    case: str,
) -> None:
    monkeypatch.setattr(gateway, "_kernel_clock", lambda: None)
    assert gateway.handle(request("health", {}))["result"]["configuration"]["qualified"] is True
    path = gateway.MANAGED_ROOT / f"var/lib/praho-crowdsec/{service}-applied.sha256"
    if case == "missing":
        path.unlink()
    elif case == "stale":
        path.write_text("0" * 64 + "\n")
    elif case == "trailing":
        path.write_text(DIGEST + "\nextra\n")
    elif case == "unsafe":
        path.chmod(0o644)
    else:
        actual = path.with_suffix(".original")
        path.rename(actual)
        path.symlink_to(actual)
    assert gateway.handle(request("health", {}))["result"]["configuration"]["qualified"] is False
    for operation, payload in (("snapshot", {"after_alert_id": 0}), ("receipt_get", {"request_id": str(uuid4())})):
        with pytest.raises(gateway.GatewayError):
            gateway.handle(request(operation, payload))


def test_matching_new_disk_policy_requires_successful_service_application(
    gateway: ModuleType, enrolled: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway, "_kernel_clock", lambda: None)
    acquisition = "/etc/crowdsec/acquis.yaml"
    content = b"# changed acquisition awaiting daemon restart\n"
    (gateway.MANAGED_ROOT / acquisition.removeprefix("/")).write_bytes(content)
    enrolled["policy"]["managed_files"][acquisition] = hashlib.sha256(content).hexdigest()
    digest = hashlib.sha256(
        json.dumps(enrolled["policy"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    enrolled["configuration_digest"] = digest
    gateway.CONFIG_PATH.write_text(json.dumps(enrolled))
    health = json.loads(request("health", {}))
    health["configuration_digest"] = digest
    assert gateway.handle(json.dumps(health).encode())["result"]["configuration"]["qualified"] is False
    snapshot = {**health, "operation": "snapshot", "payload": {"after_alert_id": 0}}
    with pytest.raises(gateway.GatewayError):
        gateway.handle(json.dumps(snapshot).encode())
    for service in ("engine", "bouncer"):
        (gateway.MANAGED_ROOT / f"var/lib/praho-crowdsec/{service}-applied.sha256").write_text(digest + "\n")
    assert gateway.handle(json.dumps(health).encode())["result"]["configuration"]["qualified"] is True
    assert gateway.handle(json.dumps(snapshot).encode())["result"]["decisions"] == []


def test_symlink_above_managed_parent_is_refused(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    ancestor = gateway.MANAGED_ROOT / "etc"
    original = ancestor.with_name("etc-real")
    ancestor.rename(original)
    ancestor.symlink_to(original, target_is_directory=True)
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


@pytest.mark.parametrize("case", ["external_api", "extra_local", "extra_bouncer_field"])
def test_credential_files_cannot_override_policy(
    gateway: ModuleType,
    enrolled: dict[str, object],
    case: str,
) -> None:
    gateway.handle(request())
    root = gateway.MANAGED_ROOT / "etc/crowdsec"
    if case == "external_api":
        path = root / "local_api_credentials.yaml"
        path.write_text(path.read_text().replace("http://127.0.0.1:8080", "https://external.example"))
    elif case == "extra_local":
        (root / "config.yaml.local").write_text("api: {server: {online_client: {}}}\n")
    else:
        path = root / "bouncers/crowdsec-firewall-bouncer.yaml.local"
        path.write_text(path.read_text() + "api_url: https://external.example\n")
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_unapproved_active_leaf_is_refused(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    path = gateway.MANAGED_ROOT / "etc/crowdsec/scenarios/unapproved.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("type: trigger\n")
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())


def test_cli_pipe_failure_is_a_sanitized_nonzero_result(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ClosedOutput:
        def write(self, _value: bytes) -> int:
            raise BrokenPipeError("native output detail must stay private")

    errors = io.StringIO()
    monkeypatch.setattr(sys, "argv", ["gateway"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request())))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=ClosedOutput()))
    monkeypatch.setattr(sys, "stderr", errors)
    monkeypatch.setattr(gateway.os, "isatty", lambda _: False)
    monkeypatch.setattr(gateway.signal, "signal", lambda *_: None)
    monkeypatch.setattr(gateway.signal, "alarm", lambda *_: 0)
    monkeypatch.delenv("SSH_ORIGINAL_COMMAND", raising=False)
    assert gateway.main() == 1
    assert errors.getvalue() == "CrowdSec request refused\n"


def test_retention_does_not_regress_alert_watermark(gateway: ModuleType, enrolled: dict[str, object]) -> None:
    seed(gateway.DATABASE_PATH, alerts=4)
    first = gateway.handle(request())["result"]
    with sqlite3.connect(gateway.DATABASE_PATH) as db:
        db.execute("DELETE FROM alerts")
    result = gateway.handle(request(payload={"after_alert_id": first["alert_watermark"]}))["result"]
    assert result["alerts"] == [] and result["has_more"] is False
    assert result["alert_watermark"] == 4
    assert result["decisions"] == first["decisions"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("path", "parsers/s00-raw/crowdsecurity/../../passwd.yaml"),
        ("installed_path", "/etc/passwd"),
        ("sha256", "invalid"),
        ("host_kinds", ["node", "node"]),
    ],
)
def test_manifest_cannot_select_arbitrary_paths(gateway: ModuleType, field: str, value: object) -> None:
    entry = dict(MANIFEST["hub"]["files"][0])
    assert gateway._manifest_leaf(entry)[0] == LEAF_PATH
    entry[field] = value
    with pytest.raises(gateway.GatewayError):
        gateway._manifest_leaf(entry)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("FragmentPath", "/etc/systemd/system/foreign.service"),
        (
            "DropInPaths",
            "/etc/systemd/system/crowdsec.service.d/praho.conf /run/systemd/system/crowdsec.service.d/foreign.conf",
        ),
        ("NeedDaemonReload", "yes"),
        ("Environment", "LC_ALL=C LANG=C EXTRA=unsafe"),
        ("ExecStart", "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no }"),
    ],
)
def test_effective_service_changes_refuse_snapshots(
    gateway: ModuleType,
    enrolled: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    gateway.handle(request())

    def altered(argv: list[str], **_kwargs: object) -> tuple[int, bytes]:
        status, raw = unit_command(argv)
        lines = raw.decode().splitlines()
        return status, (
            "\n".join(f"{field}={value}" if line.startswith(field + "=") else line for line in lines) + "\n"
        ).encode()

    monkeypatch.setattr(gateway, "_command", altered)
    with pytest.raises(gateway.GatewayError):
        gateway.handle(request())
