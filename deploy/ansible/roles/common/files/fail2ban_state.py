#!/usr/bin/python3 -I
"""A private installation-bound retirement intent prevents legacy protection revival."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import closing
from pathlib import Path
from typing import cast

MARKER = Path("/var/lib/praho-crowdsec/fail2ban-retired.json")
CONFIG = Path("/etc/praho-crowdsec/config.json")
INSTALLATION = Path("/var/lib/praho-crowdsec/installation.json")
DATABASE = Path("/var/lib/crowdsec/data/crowdsec.db")
JAIL = Path("/etc/fail2ban/jail.local")
GATEWAY = "/usr/local/libexec/praho-crowdsec-gateway"
ROOT_UID = 0
ROOT_GID = 0
PRIVATE = 0o600
DIRECTORY = 0o700
LIMIT = 65536
MAIN_ARG_COUNT = 2
REQUEST_ID = "da0fad02-c166-46bf-9b39-c3068af582cc"


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("Duplicate state field")
        value[key] = item
    return value


def _private_parent(path: Path) -> None:
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != ROOT_UID
        or parent.st_gid != ROOT_GID
        or stat.S_IMODE(parent.st_mode) != DIRECTORY
    ):
        raise ValueError("Unsafe retirement parent")


def _private_json(path: Path) -> dict[str, object]:
    _private_parent(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_gid != ROOT_GID
        or stat.S_IMODE(info.st_mode) != PRIVATE
        or info.st_nlink != 1
        or info.st_size > LIMIT
    ):
        raise ValueError("Unsafe retirement state")
    with path.open("rb") as source:
        raw = source.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Oversized retirement state")
    value = json.loads(raw, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError("Invalid retirement state")
    return cast("dict[str, object]", value)


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid installation identity")
    return value


def _digest(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("Invalid policy identity")


def _identity() -> dict[str, object]:
    config, installation = _private_json(CONFIG), _private_json(INSTALLATION)
    identifier = _uuid(config["installation_id"])
    _digest(config["configuration_digest"])
    if installation["installation_id"] != identifier or type(config["protocol"]) is not int or config["protocol"] != 1:
        raise ValueError("Installation identity changed")
    _private_parent(DATABASE)
    info = DATABASE.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_gid != ROOT_GID
        or info.st_mode & 0o022
        or info.st_nlink != 1
    ):
        raise ValueError("Unsafe installation database")
    witness = {"device": info.st_dev, "inode": info.st_ino}
    if config["database_witness"] != witness or installation["database_witness"] != witness:
        raise ValueError("Installation database changed")
    with closing(sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT machine_id FROM machines WHERE machine_id=?", ["praho-installation-" + identifier]
        ).fetchall()
    if rows != [("praho-installation-" + identifier,)]:
        raise ValueError("Installation marker changed")
    return config


def inspect_state() -> dict[str, object]:
    try:
        MARKER.lstat()
    except FileNotFoundError:
        return {"state": "absent"}
    value = _private_json(MARKER)
    if (
        set(value) != {"schema", "installation_id", "configuration_digest", "state"}
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or value["state"] not in {"pending", "complete"}
    ):
        raise ValueError("Invalid retirement marker")
    _uuid(value["installation_id"])
    _digest(value["configuration_digest"])
    if value["installation_id"] != _identity()["installation_id"]:
        raise ValueError("Retirement belongs to another installation")
    return value


def _health(config: dict[str, object]) -> dict[str, object]:
    request = {
        "protocol": 1,
        "request_id": REQUEST_ID,
        "installation_id": config["installation_id"],
        "configuration_digest": config["configuration_digest"],
        "operation": "health",
        "payload": {},
    }
    result = subprocess.run(  # noqa: S603  # Fixed root-owned gateway and read-only request.
        [GATEWAY],
        input=json.dumps(request).encode(),
        capture_output=True,
        check=True,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if len(result.stdout) > LIMIT:
        raise ValueError("Oversized qualification evidence")
    reply = json.loads(result.stdout, object_pairs_hook=_pairs)
    if (
        not isinstance(reply, dict)
        or set(reply) != (set(request) - {"payload"}) | {"result"}
        or any(reply[field] != value for field, value in request.items() if field != "payload")
    ):
        raise ValueError("Qualification identity changed")
    return _mapping(reply["result"])


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Invalid qualification evidence")
    return cast("dict[str, object]", value)


def _qualified(config: dict[str, object]) -> None:
    health = _health(config)
    if (
        config["simulation"] is not False
        or health["simulation"] is not False
        or _mapping(health["engine"])["active"] is not True
        or _mapping(health["engine"])["version"] != "1.8.2"
        or _mapping(health["bouncer"])["active"] is not True
        or not _mapping(health["bouncer"])["version"]
        or _mapping(health["configuration"])["qualified"] is not True
        or _mapping(health["firewall"])["qualified"] is not True
    ):
        raise ValueError("Qualified enforcing replacement required")


def _write(value: dict[str, object]) -> bool:
    content = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if MARKER.exists() and MARKER.read_bytes() == content:
        return False
    with tempfile.NamedTemporaryFile(dir=MARKER.parent, prefix=".retirement-", delete=False) as temporary:
        path = Path(temporary.name)
        try:
            os.fchmod(temporary.fileno(), PRIVATE)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            path.replace(MARKER)
            directory = os.open(MARKER.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            path.unlink(missing_ok=True)
    return True


def begin() -> dict[str, object]:
    current = inspect_state()
    config = _identity()
    _qualified(config)
    if current["state"] != "absent":
        return {**current, "changed": False}
    value = {
        "schema": 1,
        "installation_id": config["installation_id"],
        "configuration_digest": config["configuration_digest"],
        "state": "pending",
    }
    return {**value, "changed": _write(value)}


def complete() -> dict[str, object]:
    current = inspect_state()
    if current["state"] == "absent":
        raise ValueError("Missing retirement intent")
    _qualified(_identity())
    package = subprocess.run(
        ["/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Status}", "fail2ban"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    service = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "fail2ban.service"], capture_output=True, text=True, timeout=15, check=False
    )
    if (
        package.returncode not in {0, 1}
        or package.stdout.strip() not in {"", "not-installed"}
        or service.returncode not in {3, 4}
    ):
        raise ValueError("Legacy protection has not been retired")
    try:
        JAIL.lstat()
    except FileNotFoundError:
        value = {**current, "state": "complete"}
        return {**value, "changed": _write(value)}
    raise ValueError("Legacy jail remains configured")


if __name__ == "__main__":
    try:
        if os.geteuid() != 0 or len(sys.argv) != MAIN_ARG_COUNT or sys.argv[1] not in {"inspect", "begin", "complete"}:
            raise ValueError("Explicit root retirement operation required")
        operation = {"inspect": inspect_state, "begin": begin, "complete": complete}[sys.argv[1]]
        print(json.dumps(operation(), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, sqlite3.Error, subprocess.SubprocessError):
        print(
            "Fail2ban replacement state refused; repair local enrollment or finish qualified retirement",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
