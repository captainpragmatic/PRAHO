#!/usr/bin/python3
"""Private CrowdSec protocol v1 endpoint. No remote-selected command or SQL exists."""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import os
import re
import select
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn
from uuid import UUID

CONFIG_PATH = Path("/etc/praho-crowdsec/config.json")
DATABASE_PATH = Path("/var/lib/crowdsec/data/crowdsec.db")
RECEIPT_DIRECTORY = Path("/var/lib/praho-crowdsec/receipts")
MANAGED_ROOT = Path("/")
TRUSTED_ROOT = Path("/")
BOUNCER_PATH = "/usr/local/libexec/praho-crowdsec-bouncer"
MANAGED_PATHS = frozenset(
    {
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
)
TRUSTED_UID = TRUSTED_GID = 0
PRIVATE_MODE = 0o600
MAX_REQUEST = 65536
MAX_RESPONSE = 8 * 1024 * 1024
MAX_DECISIONS = 10000
MAX_BAN_ELEMENTS = 4 * MAX_DECISIONS + 2
MAX_ALERTS = 1000
DEADLINE = 30
MAX_ID = 2**63 - 1
MAX_NETWORKS = 1024
MAX_TIMESTAMP = 64
NATIVE_LONG_BYTES = 8
CLOCK_MAX_ERROR_SECONDS = 1.0
STA_UNSYNC = 0x40
STA_NANO = 0x2000
REQUEST_FIELDS = {"protocol", "request_id", "installation_id", "configuration_digest", "operation", "payload"}
CONFIG_FIELDS = {
    "protocol",
    "installation_id",
    "configuration_digest",
    "simulation",
    "protected_cidrs",
    "database_witness",
    "policy",
}
POLICY_FIELDS = {
    "schema",
    "host_kind",
    "simulation",
    "protected_cidrs",
    "artifact_lock_sha256",
    "bouncer_binary_sha256",
    "managed_files",
}
MAX_MANAGED_BYTES = 128 * 1024 * 1024
MAX_HUB_LEAVES = 64
STOCK_UNIT_PATHS = {
    "crowdsec.service": "/usr/lib/systemd/system/crowdsec.service",
    "crowdsec-firewall-bouncer.service": "/etc/systemd/system/crowdsec-firewall-bouncer.service",
}
UNIT_SCALARS = {
    "LoadState",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "Transient",
    "Environment",
    "EnvironmentFiles",
    "RootDirectory",
    "RootImage",
}
UNIT_COMMANDS = {"ExecStart", "ExecStartPre", "ExecReload", "ExecStartPost"}
SCHEMA = {
    "alerts": (
        ("id", "integer"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
        ("scenario", "text"),
        ("bucket_id", "text"),
        ("message", "text"),
        ("events_count", "integer"),
        ("started_at", "datetime"),
        ("stopped_at", "datetime"),
        ("source_ip", "text"),
        ("source_range", "text"),
        ("source_as_number", "text"),
        ("source_as_name", "text"),
        ("source_country", "text"),
        ("source_latitude", "real"),
        ("source_longitude", "real"),
        ("source_scope", "text"),
        ("source_value", "text"),
        ("capacity", "integer"),
        ("leak_speed", "text"),
        ("scenario_version", "text"),
        ("scenario_hash", "text"),
        ("simulated", "bool"),
        ("uuid", "text"),
        ("remediation", "bool"),
        ("kind", "text"),
        ("machine_alerts", "integer"),
    ),
    "decisions": (
        ("id", "integer"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
        ("until", "datetime"),
        ("scenario", "text"),
        ("type", "text"),
        ("start_ip", "integer"),
        ("end_ip", "integer"),
        ("start_suffix", "integer"),
        ("end_suffix", "integer"),
        ("ip_size", "integer"),
        ("scope", "text"),
        ("value", "text"),
        ("origin", "text"),
        ("simulated", "bool"),
        ("uuid", "text"),
        ("alert_decisions", "integer"),
    ),
    "machines": (
        ("id", "integer"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
        ("last_push", "datetime"),
        ("last_heartbeat", "datetime"),
        ("machine_id", "text"),
        ("password", "text"),
        ("ip_address", "text"),
        ("scenarios", "text"),
        ("version", "text"),
        ("is_validated", "bool"),
        ("auth_type", "text"),
        ("osname", "text"),
        ("osfamily", "text"),
        ("osversion", "text"),
        ("featureflags", "text"),
        ("hubstate", "json"),
        ("datasources", "json"),
        ("features", "json"),
    ),
}


class GatewayError(Exception):
    """A bounded public failure, deliberately without native exception details."""


def fail() -> NoReturn:
    raise GatewayError("CrowdSec request refused")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def _json(raw: bytes, maximum: int) -> dict[str, object]:
    if not raw or len(raw) > maximum:
        fail()
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: fail())
    except (ValueError, UnicodeError, RecursionError) as error:
        raise GatewayError("CrowdSec request refused") from error
    if not isinstance(result, dict):
        fail()
    return result


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        fail()
    return value


def _integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_ID:
        fail()
    return value


def _status(path: Path, *, private: bool = False) -> os.stat_result:
    if not path.is_relative_to(TRUSTED_ROOT):
        fail()
    for parent_path in path.parents:
        parent = parent_path.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != TRUSTED_UID
            or parent.st_gid != TRUSTED_GID
            or parent.st_mode & 0o022
        ):
            fail()
        if parent_path == TRUSTED_ROOT:
            break
    status = path.lstat()
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != TRUSTED_UID
        or status.st_gid != TRUSTED_GID
        or status.st_mode & (0o077 if private else 0o022)
    ):
        fail()
    return status


def _read_private(path: Path, maximum: int) -> bytes:
    return _read_owned(path, maximum, private=True)


def _read_owned(path: Path, maximum: int, *, private: bool = False) -> bytes:
    expected = _status(path, private=private)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        actual = os.fstat(descriptor)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            fail()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read(maximum + 1)
    finally:
        os.close(descriptor)


def _configuration() -> dict[str, object]:
    config = _json(_read_private(CONFIG_PATH, MAX_REQUEST), MAX_REQUEST)
    if set(config) != CONFIG_FIELDS or type(config["protocol"]) is not int or config["protocol"] != 1:
        fail()
    _uuid(config["installation_id"])
    if not isinstance(config["configuration_digest"], str) or not re.fullmatch(
        "[a-f0-9]{64}", config["configuration_digest"]
    ):
        fail()
    if type(config["simulation"]) is not bool:
        fail()
    networks = config["protected_cidrs"]
    if not isinstance(networks, list) or not 1 <= len(networks) <= MAX_NETWORKS:
        fail()
    if any(not isinstance(value, str) or str(ipaddress.ip_network(value, strict=True)) != value for value in networks):
        fail()
    if any(ipaddress.ip_network(value).prefixlen == 0 for value in networks) or len(set(networks)) != len(networks):
        fail()
    witness = config["database_witness"]
    if not isinstance(witness, dict) or set(witness) != {"device", "inode"}:
        fail()
    _integer(witness["device"])
    _integer(witness["inode"], minimum=1)
    _validate_policy(config, networks)
    return config


def _validate_policy(config: dict[str, object], networks: list[str]) -> None:
    policy = config["policy"]
    if (
        not isinstance(policy, dict)
        or set(policy) != POLICY_FIELDS
        or type(policy["schema"]) is not int
        or policy["schema"] != 1
    ):
        fail()
    if policy["host_kind"] not in {"node", "portal"} or type(policy["simulation"]) is not bool:
        fail()
    if policy["simulation"] != config["simulation"] or policy["protected_cidrs"] != sorted(networks):
        fail()
    for field in ("artifact_lock_sha256", "bouncer_binary_sha256"):
        if not isinstance(policy[field], str) or not re.fullmatch("[a-f0-9]{64}", policy[field]):
            fail()
    files = policy["managed_files"]
    leaves = _manifest_files(policy)
    if not isinstance(files, dict) or set(files) != MANAGED_PATHS | set(leaves):
        fail()
    if any(not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value) for value in files.values()):
        fail()
    digest = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    if digest != config["configuration_digest"]:
        fail()
    if files["/etc/praho-crowdsec/artifacts.lock.json"] != policy["artifact_lock_sha256"]:
        fail()
    if any(files[name] != digest for name, digest in leaves.items()):
        fail()


def _manifest_files(policy: dict[str, object]) -> dict[str, str]:
    manifest = _manifest(policy)
    hub = manifest.get("hub")
    if (
        not isinstance(hub, dict)
        or not isinstance(hub.get("files"), list)
        or not 1 <= len(hub["files"]) <= MAX_HUB_LEAVES
    ):
        fail()
    selected, seen = {}, set()
    for entry in hub["files"]:
        if not isinstance(entry, dict):
            fail()
        installed, digest, kinds = _manifest_leaf(entry)
        if installed in seen:
            fail()
        seen.add(installed)
        if policy["host_kind"] in kinds:
            selected[installed] = digest
    if not selected:
        fail()
    return selected


def _manifest(policy: dict[str, object]) -> dict[str, object]:
    path = MANAGED_ROOT / "etc/praho-crowdsec/artifacts.lock.json"
    raw = _read_owned(path, MAX_RESPONSE)
    if hashlib.sha256(raw).hexdigest() != policy["artifact_lock_sha256"]:
        fail()
    return _json(raw, MAX_RESPONSE)


def _manifest_leaf(entry: dict[str, object]) -> tuple[str, str, list[str]]:
    source, installed, digest, kinds = (entry.get(name) for name in ("path", "installed_path", "sha256", "host_kinds"))
    if not isinstance(source, str) or not re.fullmatch(
        r"(?:parsers/(?:s00-raw|s01-parse|s02-enrich)|scenarios)/(?:crowdsecurity|andreasbrett)/[a-zA-Z0-9_.-]+\.yaml",
        source,
    ):
        fail()
    parts = source.split("/")
    expected = (
        f"/etc/crowdsec/parsers/{parts[1]}/{parts[-1]}"
        if parts[0] == "parsers"
        else f"/etc/crowdsec/scenarios/{parts[-1]}"
    )
    if installed != expected or not isinstance(digest, str) or not re.fullmatch("[a-f0-9]{64}", digest):
        fail()
    if not isinstance(kinds, list) or not kinds or any(value not in {"node", "portal"} for value in kinds):
        fail()
    if len(kinds) != len(set(kinds)):
        fail()
    return installed, digest, kinds


def _identity(config: dict[str, object]) -> None:
    status = _status(DATABASE_PATH)
    if config["database_witness"] != {"device": status.st_dev, "inode": status.st_ino}:
        fail()


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_TIMESTAMP:
        fail()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        fail()
    return parsed.astimezone(UTC).isoformat()


def _label(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./:+-]{1,200}", value):
        fail()
    return value


def _address(scope: object, value: object) -> tuple[str, str]:
    if not isinstance(scope, str) or not isinstance(value, str) or scope.lower() not in {"ip", "range"}:
        fail()
    if scope.lower() == "ip":
        return "ip", str(ipaddress.ip_address(value))
    return "range", str(ipaddress.ip_network(value, strict=True))


def _boolean(value: object) -> bool:
    if type(value) is not int or value not in (0, 1):
        fail()
    return bool(value)


def _snapshot(config: dict[str, object], after: int) -> dict[str, object]:
    _identity(config)
    deadline = time.monotonic() + DEADLINE - 1
    current = datetime.now(UTC).isoformat()
    with closing(sqlite3.connect(f"file:{DATABASE_PATH}?mode=ro", uri=True, timeout=1)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        db.execute("BEGIN")
        for table, expected in SCHEMA.items():
            native = db.execute("SELECT type FROM sqlite_schema WHERE name=?", (table,)).fetchall()
            actual = db.execute(f"PRAGMA table_info({table})").fetchall()
            if native != [("table",)] or tuple((row[1], row[2].lower()) for row in actual) != expected:
                fail()
        marker = db.execute(
            "SELECT machine_id FROM machines WHERE machine_id=?", (f"praho-installation-{config['installation_id']}",)
        ).fetchall()
        if marker != [(f"praho-installation-{config['installation_id']}",)]:
            fail()
        if db.execute(
            'SELECT id FROM decisions WHERE "until" IS NOT NULL AND julianday("until") IS NULL LIMIT 1'
        ).fetchone():
            fail()
        rows = db.execute(
            'SELECT id,created_at,"until",scenario,type,scope,value,origin,simulated FROM decisions '
            'WHERE julianday("until") > julianday(?) ORDER BY id LIMIT ?',
            (current, MAX_DECISIONS + 1),
        ).fetchall()
        if len(rows) > MAX_DECISIONS:
            fail()
        decisions = []
        for row in rows:
            scope, address = _address(row[5], row[6])
            decisions.append(
                {
                    "id": _integer(row[0], minimum=1),
                    "created_at": _timestamp(row[1]),
                    "expires_at": _timestamp(row[2]),
                    "scenario": "cscli/manual" if row[7] == "cscli" else _label(row[3]),
                    "type": _label(row[4]),
                    "scope": scope,
                    "value": address,
                    "origin": _label(row[7]),
                    "simulated": _boolean(row[8]),
                }
            )
        rows = db.execute(
            "SELECT id,created_at,scenario,events_count,source_scope,source_value,simulated,kind FROM alerts "
            "WHERE id>? ORDER BY id LIMIT ?",
            (after, MAX_ALERTS + 1),
        ).fetchall()
        has_more = len(rows) > MAX_ALERTS
        alerts = []
        for row in rows[:MAX_ALERTS]:
            # cscli batch imports intentionally create aggregate alerts with an empty source.
            scope, address = (None, None) if row[4] in (None, "") and row[5] in (None, "") else _address(row[4], row[5])
            alerts.append(
                {
                    "id": _integer(row[0], minimum=1),
                    "created_at": _timestamp(row[1]),
                    "scenario": ("cscli/import" if scope is None else "cscli/manual")
                    if row[7] == "cscli"
                    else _label(row[2]),
                    "event_count": _integer(0 if row[3] is None else row[3]),
                    "scope": scope,
                    "value": address,
                    "simulated": _boolean(row[6]),
                }
            )
        maximum = db.execute("SELECT COALESCE(MAX(id),0) FROM alerts").fetchone()[0]
        watermark = alerts[-1]["id"] if has_more else max(after, maximum)
        result = {
            "decisions": decisions,
            "alerts": alerts,
            "alert_watermark": watermark,
            "has_more": has_more,
            "observed_at": current,
        }
        _identity(config)
        db.rollback()
    return result


def _command(argv: list[str], *, maximum: int = MAX_REQUEST) -> tuple[int, bytes]:
    deadline = time.monotonic() + 3
    with subprocess.Popen(  # noqa: S603 -- all callers pass literal read-only commands
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    ) as child:
        assert child.stdout is not None
        output = bytearray()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail()
                if not select.select([child.stdout], [], [], remaining)[0]:
                    fail()
                chunk = os.read(child.stdout.fileno(), min(65536, maximum + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > maximum:
                    fail()
            return child.wait(timeout=max(0.01, deadline - time.monotonic())), bytes(output)
        except (GatewayError, subprocess.TimeoutExpired):
            child.kill()
            child.wait()
            raise


def _observed(argv: list[str]) -> str | None:
    try:
        status, raw = _command(argv)
        return raw.decode("utf-8").strip() if status == 0 else None
    except (OSError, UnicodeError, GatewayError, subprocess.TimeoutExpired):
        return None


def _kernel_clock() -> tuple[int, int, int, int, int] | None:
    if sys.platform != "linux" or ctypes.sizeof(ctypes.c_long) != NATIVE_LONG_BYTES:
        return None

    class TimexHead(ctypes.Structure):
        # Linux 64-bit timex prefix. Tail storage exceeds the complete kernel structure.
        _fields_ = [
            ("modes", ctypes.c_uint),
            ("offset", ctypes.c_long),
            ("frequency", ctypes.c_long),
            ("maximum_error", ctypes.c_long),
            ("estimated_error", ctypes.c_long),
            ("status", ctypes.c_int),
            ("reserved", ctypes.c_byte * 512),
        ]

    try:
        library = ctypes.CDLL(None, use_errno=True)
        read_clock = library.adjtimex
        read_clock.argtypes = [ctypes.POINTER(TimexHead)]
        read_clock.restype = ctypes.c_int
        observation = TimexHead()
        observation.modes = 0  # Read-only kernel query; never request a clock adjustment.
        state = read_clock(ctypes.byref(observation))
        if state < 0:
            return None
        return state, observation.status, observation.offset, observation.maximum_error, observation.estimated_error
    except (AttributeError, OSError):
        return None


def _clock() -> dict[str, object]:
    reading = _kernel_clock()
    if reading is None:
        return {
            "synchronized": False,
            "qualified": False,
            "offset_seconds": None,
            "maximum_error_seconds": None,
            "estimated_error_seconds": None,
        }
    state, status, offset, maximum, estimated = reading
    synchronized = state == 0 and not status & STA_UNSYNC
    seconds = offset / (1_000_000_000 if status & STA_NANO else 1_000_000)
    maximum_seconds, estimated_seconds = maximum / 1_000_000, estimated / 1_000_000
    qualified = synchronized and max(abs(seconds), maximum_seconds, estimated_seconds) <= CLOCK_MAX_ERROR_SECONDS
    qualified = qualified and maximum >= 0 and estimated >= 0
    return {
        "synchronized": synchronized,
        "qualified": qualified,
        "offset_seconds": seconds,
        "maximum_error_seconds": maximum_seconds,
        "estimated_error_seconds": estimated_seconds,
    }


def _set_networks(elements: object) -> list[str]:
    if not isinstance(elements, list) or len(elements) > MAX_NETWORKS:
        fail()
    result = []
    for element in elements:
        if isinstance(element, str):
            result.append(str(ipaddress.ip_network(element, strict=True)))
        elif isinstance(element, dict) and set(element) == {"prefix"}:
            prefix = element["prefix"]
            if not isinstance(prefix, dict) or set(prefix) != {"addr", "len"} or type(prefix["len"]) is not int:
                fail()
            result.append(str(ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=True)))
        else:
            fail()
    return sorted(str(value) for value in ipaddress.collapse_addresses(ipaddress.ip_network(value) for value in result))


def _native_entries(parsed: dict[str, object], family: str, table: str) -> tuple[dict[str, object], list[object]]:
    if set(parsed) != {"nftables"} or not isinstance(parsed["nftables"], list):
        fail()
    sets, rules, chain, tables = {}, [], None, 0
    for entry in parsed["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            fail()
        kind, native = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        data = _native_data(native)
        if kind == "table":
            if data != {"family": family, "name": table}:
                fail()
            tables += 1
        elif data.pop("family", None) != family or data.pop("table", None) != table:
            fail()
        elif kind == "chain" and chain is None:
            chain = data
        elif kind == "set" and data.get("name") not in sets:
            sets[data.get("name")] = data
        elif kind == "rule":
            rules.append(data)
        else:
            fail()
    if tables != 1 or chain != {"name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}:
        fail()
    return sets, rules


def _native_data(native: object) -> dict[str, object]:
    if not isinstance(native, dict):
        fail()
    return {key: value for key, value in native.items() if key != "handle"}


def _native_sets(sets: dict[str, object], config: dict[str, object], family: str) -> bool:
    if set(sets) != {"protected", "bans"}:
        fail()
    empty = True
    for name, native in sets.items():
        elements = native.pop("elem", [])
        expected = {
            "name": name,
            "type": "ipv4_addr" if family == "ip" else "ipv6_addr",
            "flags": ["interval"] if name == "protected" else ["interval", "timeout"],
        }
        if native != expected:
            fail()
        if name == "protected":
            protected = [value for value in config["protected_cidrs"] if (":" in value) == (family == "ip6")]
            expected_networks = sorted(
                str(value) for value in ipaddress.collapse_addresses(ipaddress.ip_network(value) for value in protected)
            )
            if _set_networks(elements) != expected_networks:
                fail()
        elif not isinstance(elements, list) or len(elements) > MAX_BAN_ELEMENTS:
            fail()
        else:
            empty = empty and not elements
    return empty


def _firewall(config: dict[str, object]) -> dict[str, object]:
    empty = True
    try:
        for family, suffix in (("ip", "4"), ("ip6", "6")):
            table = "praho_crowdsec" + suffix
            code, raw = _command(["/usr/sbin/nft", "--json", "list", "table", family, table], maximum=MAX_RESPONSE)
            if code != 0:
                fail()
            sets, rules = _native_entries(_json(raw, MAX_RESPONSE), family, table)
            empty = _native_sets(sets, config, family) and empty
            expected_rules = [
                {
                    "chain": "input",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": family, "field": "saddr"}},
                                "right": "@" + name,
                            }
                        },
                        {verdict: None},
                    ],
                }
                for name, verdict in (("protected", "return"), ("bans", "drop"))
            ]
            if rules != expected_rules:
                fail()
        return {"qualified": True, "ban_sets_empty": empty}
    except (GatewayError, OSError, ValueError, TypeError, KeyError):
        return {"qualified": False, "ban_sets_empty": None}


def _managed_configuration(config: dict[str, object]) -> dict[str, object]:
    try:
        _applied_configuration(config)
        _credential_overrides(config)
        policy = config["policy"]
        expected_leaves = set(_manifest_files(policy))
        if _active_yaml("etc/crowdsec/parsers") | _active_yaml("etc/crowdsec/scenarios") != expected_leaves:
            fail()
        if _active_yaml("etc/crowdsec/acquis.d"):
            fail()
        files = {**policy["managed_files"], BOUNCER_PATH: policy["bouncer_binary_sha256"]}
        for name, expected in files.items():
            _verify_digest(name, expected)
        _service_configuration(policy)
        return {"qualified": True}
    except (GatewayError, OSError, ValueError, TypeError, KeyError):
        return {"qualified": False}


def _applied_configuration(config: dict[str, object]) -> None:
    expected = (config["configuration_digest"] + "\n").encode("ascii")
    for service in ("engine", "bouncer"):
        path = MANAGED_ROOT / f"var/lib/praho-crowdsec/{service}-applied.sha256"
        if stat.S_IMODE(_status(path, private=True).st_mode) != PRIVATE_MODE:
            fail()
        if _read_private(path, len(expected)) != expected:
            fail()


def _verify_digest(name: str, expected: str) -> None:
    path = MANAGED_ROOT / name.removeprefix("/")
    status = _status(path)
    if status.st_size > MAX_MANAGED_BYTES:
        fail()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        actual = os.fstat(descriptor)
        if (status.st_dev, status.st_ino) != (actual.st_dev, actual.st_ino):
            fail()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != expected:
                fail()
    finally:
        os.close(descriptor)


def _service_configuration(policy: dict[str, object]) -> None:
    units = _manifest(policy).get("stock_units")
    if not isinstance(units, dict) or set(units) != set(STOCK_UNIT_PATHS):
        fail()
    for name, canonical in STOCK_UNIT_PATHS.items():
        metadata = units[name]
        expected_fragments = (
            ["/lib/systemd/system/crowdsec.service", canonical] if name == "crowdsec.service" else [canonical]
        )
        expected_dropins = [f"/etc/systemd/system/{name}.d/praho.conf"]
        if not isinstance(metadata, dict) or set(metadata) != {"path", "sha256", "fragment_paths", "drop_in_paths"}:
            fail()
        if (
            metadata["path"] != canonical
            or metadata["fragment_paths"] != expected_fragments
            or metadata["drop_in_paths"] != expected_dropins
        ):
            fail()
        if not isinstance(metadata["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", metadata["sha256"]):
            fail()
        _verify_digest(canonical, metadata["sha256"])
        properties = _unit_properties(name)
        fragment = properties["FragmentPath"]
        if fragment not in expected_fragments or shlex.split(properties["DropInPaths"]) != expected_dropins:
            fail()
        # Resolve only this exact reviewed merged-/usr alias, never a request-selected path.
        if (MANAGED_ROOT / fragment.removeprefix("/")).resolve() != MANAGED_ROOT / canonical.removeprefix("/"):
            fail()
        if (
            properties["LoadState"] != "loaded"
            or properties["NeedDaemonReload"] != "no"
            or properties["Transient"] != "no"
        ):
            fail()
        if any(properties[field] for field in ("EnvironmentFiles", "RootDirectory", "RootImage")):
            fail()
        environment = ["LC_ALL=C", "LANG=C"] if name == "crowdsec.service" else []
        if sorted(shlex.split(properties["Environment"])) != sorted(environment):
            fail()
        _unit_commands(properties, name)


def _unit_properties(name: str) -> dict[str, object]:
    code, raw = _command(
        [
            "/usr/bin/systemctl",
            "show",
            name,
            "--all",
            "--no-pager",
            *["--property=" + key for key in sorted(UNIT_SCALARS | UNIT_COMMANDS)],
        ]
    )
    if code != 0:
        fail()
    values = {key: [] for key in UNIT_COMMANDS}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in UNIT_SCALARS | UNIT_COMMANDS:
            fail()
        if key in UNIT_COMMANDS:
            if value:
                values[key].append(value)
        elif key in values:
            fail()
        else:
            values[key] = value
    # systemctl omits empty array properties even with --all; a nonempty value is rejected below.
    values.setdefault("EnvironmentFiles", "")
    if set(values) != UNIT_SCALARS | UNIT_COMMANDS:
        fail()
    return values


def _unit_commands(properties: dict[str, object], name: str) -> None:
    command = (
        ["/usr/bin/crowdsec", "-c", "/etc/crowdsec/config.yaml"]
        if name == "crowdsec.service"
        else [BOUNCER_PATH, "-c", "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"]
    )
    expected = {
        "ExecStart": [command],
        "ExecStartPre": [command + (["-t", "-error"] if name == "crowdsec.service" else ["-t"])],
        "ExecReload": [[*command, "-t", "-error"], ["/bin/kill", "-HUP", "$MAINPID"]]
        if name == "crowdsec.service"
        else [],
        "ExecStartPost": [] if name == "crowdsec.service" else [["/bin/sleep", "0.1"]],
    }
    for key, commands in expected.items():
        if [_unit_argv(value) for value in properties[key]] != commands:
            fail()


def _unit_argv(value: str) -> list[str]:
    if not value.startswith("{ ") or not value.endswith(" }"):
        fail()
    parts = {}
    for item in value[2:-2].split(" ; "):
        key, separator, data = item.partition("=")
        if (
            not separator
            or key in parts
            or key not in {"path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status"}
        ):
            fail()
        parts[key] = data
    if not {"path", "argv[]", "ignore_errors"} <= set(parts) or parts["ignore_errors"] != "no":
        fail()
    arguments = shlex.split(parts["argv[]"])
    if not arguments or parts["path"] != arguments[0]:
        fail()
    return arguments


def _active_yaml(relative: str) -> set[str]:
    base = MANAGED_ROOT / relative
    if not base.exists():
        return set()
    pending, found, visited = [base], set(), 0
    while pending:
        directory = pending.pop()
        status = directory.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != TRUSTED_UID
            or status.st_gid != TRUSTED_GID
            or status.st_mode & 0o022
        ):
            fail()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_HUB_LEAVES * 4 or entry.is_symlink():
                    fail()
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.name.endswith((".yaml", ".yml")):
                    _status(Path(entry.path))
                    found.add("/" + str(Path(entry.path).relative_to(MANAGED_ROOT)))
    return found


def _credential_overrides(config: dict[str, object]) -> None:
    directory = MANAGED_ROOT / "etc/crowdsec"
    local = directory / "bouncers/crowdsec-firewall-bouncer.yaml.local"
    if list(directory.glob("*.yaml.local")) or list(local.parent.glob("*.yaml.local")) != [local]:
        fail()
    text = _read_private(local, MAX_REQUEST).decode("utf-8")
    match = re.fullmatch(r'api_key: ("[^"\n]+")\n', text)
    if match is None:
        fail()
    token = json.loads(match[1])
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_+./=-]{16,512}", token):
        fail()
    credentials = _read_private(directory / "local_api_credentials.yaml", MAX_REQUEST).decode("utf-8")
    values = {}
    for line in credentials.splitlines():
        name, separator, value = line.partition(": ")
        if not separator or name in values:
            fail()
        values[name] = json.loads(value) if value.startswith('"') else value
    if set(values) != {"url", "login", "password"}:
        fail()
    if values["url"] not in {"http://127.0.0.1:8080", "http://127.0.0.1:8080/"}:
        fail()
    if values["login"] != f"praho-installation-{config['installation_id']}":
        fail()
    if not isinstance(values["password"], str) or not re.fullmatch("[A-Za-z0-9]{64}", values["password"]):
        fail()


def _health(config: dict[str, object]) -> dict[str, object]:
    # Snapshot also validates the physical database, native schema and marker.
    _snapshot(config, 0)
    engine = _observed(["/usr/bin/crowdsec", "-version"])
    engine_version = "1.8.2" if engine and re.search(r"\bv1\.8\.2\b", engine) else None
    engine_active = _observed(["/usr/bin/systemctl", "is-active", "crowdsec.service"]) == "active"
    bouncer_active = _observed(["/usr/bin/systemctl", "is-active", "crowdsec-firewall-bouncer.service"]) == "active"
    bouncer = _observed([BOUNCER_PATH, "-V"])
    bouncer_match = re.search(r"\b(?:v)?(\d+\.\d+\.\d+(?:[+.-][A-Za-z0-9_.-]+)?)\b", bouncer) if bouncer else None
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "simulation": config["simulation"],
        "engine": {"active": engine_active, "version": engine_version},
        "bouncer": {"active": bouncer_active, "version": bouncer_match[1] if bouncer_match else None},
        "firewall": _firewall(config),
        "clock": _clock(),
        "configuration": _managed_configuration(config),
    }


def handle(raw: bytes) -> dict[str, object]:
    """Validate, read, buffer and return one complete response, with no output side effects."""
    try:
        request = _json(raw, MAX_REQUEST)
        if set(request) != REQUEST_FIELDS or type(request["protocol"]) is not int or request["protocol"] != 1:
            fail()
        _uuid(request["request_id"])
        _uuid(request["installation_id"])
        config = _configuration()
        if any(request[field] != config[field] for field in ("installation_id", "configuration_digest")):
            fail()
        payload = request["payload"]
        if not isinstance(payload, dict):
            fail()
        operation = request["operation"]
        if operation != "health" and not _managed_configuration(config)["qualified"]:
            fail()
        if operation == "snapshot" and set(payload) == {"after_alert_id"}:
            result = _snapshot(config, _integer(payload["after_alert_id"]))
        elif operation == "health" and not payload:
            result = _health(config)
        elif operation == "receipt_get" and set(payload) == {"request_id"}:
            identifier = _uuid(payload["request_id"])
            _snapshot(config, 0)
            if (RECEIPT_DIRECTORY / f"{identifier}.json").exists():
                fail()  # Audited mutation receipts require their qualified writer/reader schema together.
            result = {"status": "unknown", "evidence": "no_receipt"}
        else:
            fail()
        response = {field: request[field] for field in REQUEST_FIELDS - {"payload"}}
        response["result"] = result
        if len(json.dumps(response, separators=(",", ":"), allow_nan=False).encode()) > MAX_RESPONSE:
            fail()
        return response
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, sqlite3.Error) as error:
        raise GatewayError("CrowdSec request refused") from error


def _timeout(_number: int, _frame: object) -> NoReturn:
    fail()


def main() -> int:
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(DEADLINE)
    try:
        if len(sys.argv) != 1 or os.environ.get("SSH_ORIGINAL_COMMAND") or os.isatty(0) or os.isatty(1):
            fail()
        response = handle(sys.stdin.buffer.read(MAX_REQUEST + 1))
        output = json.dumps(response, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(output) > MAX_RESPONSE:
            fail()
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return 0
    except (GatewayError, OSError):
        sys.stderr.write("CrowdSec request refused\n")
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
