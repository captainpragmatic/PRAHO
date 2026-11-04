#!/usr/bin/python3 -I
"""Bind one local database incarnation; convergence never repairs identity loss."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

STATE = Path("/var/lib/praho-crowdsec/installation.json")
CONFIG = Path("/etc/praho-crowdsec/config.json")
DATABASE = Path("/var/lib/crowdsec/data/crowdsec.db")
PRIVATE_MODE = 0o600
MAIN_ARG_COUNT = 2


def _atomic_json(path: Path, value: dict[str, object]) -> bool:
    content = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if path.exists() and path.read_bytes() == content:
        return False
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".praho-", delete=False) as destination:
        temporary = Path(destination.name)
        try:
            os.fchmod(destination.fileno(), PRIVATE_MODE)
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return True


def _witness() -> dict[str, int]:
    info = DATABASE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError("Database ownership changed; explicit reenrollment is required")
    return {"device": info.st_dev, "inode": info.st_ino}


def _verify(state: dict[str, object]) -> None:
    try:
        installation = str(uuid.UUID(state["installation_id"]))
        if state["database_witness"] != _witness():
            raise ValueError("Database incarnation changed")
        with closing(sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
            connection.execute("PRAGMA query_only=ON")
            markers = connection.execute(
                "SELECT machine_id FROM machines WHERE machine_id=?", ["praho-installation-" + installation]
            ).fetchall()
        if markers != [("praho-installation-" + installation,)]:
            raise ValueError("Installation marker disappeared")
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
        raise ValueError("Database identity is unresolved; explicit reenrollment is required") from error


def check_existing() -> dict[str, object] | None:
    if not STATE.exists():
        if DATABASE.exists():
            raise ValueError("An unenrolled database already exists; explicit reenrollment is required")
        return None
    info = STATE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != PRIVATE_MODE:
        raise ValueError("Installation state ownership changed; explicit reenrollment is required")
    state = json.loads(STATE.read_text())
    _verify(state)
    return state


def ensure_installation(policy: dict[str, object], register_marker: Callable[[str], None]) -> dict[str, object]:
    state = check_existing()
    created = state is None
    if state is None:
        installation = str(uuid.uuid4())
        register_marker("praho-installation-" + installation)
        state = {"installation_id": installation, "database_witness": _witness()}
        _verify(state)
        _atomic_json(STATE, state)
    digest = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    config = {
        "protocol": 1,
        **state,
        "configuration_digest": digest,
        "simulation": policy["simulation"],
        "protected_cidrs": policy["protected_cidrs"],
        "policy": policy,
    }
    changed = _atomic_json(CONFIG, config)
    return {"installation_id": state["installation_id"], "configuration_digest": digest, "changed": created or changed}


def _register_marker(name: str) -> None:
    try:
        subprocess.run(  # noqa: S603 -- fixed CLI and locally generated installation marker
            ["/usr/bin/cscli", "machines", "add", name, "--auto", "--file", "/etc/crowdsec/local_api_credentials.yaml"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except subprocess.SubprocessError as error:
        raise ValueError("Local machine registration failed; inspect the fixed local CLI configuration") from error


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != MAIN_ARG_COUNT:
        raise ValueError("Root and one explicit enrollment operation are required")
    if sys.argv[1] == "check":
        check_existing()
        print('{"changed":false}')
    else:
        policy = json.loads(base64.b64decode(sys.argv[1], validate=True))
        print(json.dumps(ensure_installation(policy, _register_marker)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print("CrowdSec installation refused: " + str(error)[:256], file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, sqlite3.Error, subprocess.SubprocessError):
        print(
            "CrowdSec installation identity is unresolved; explicit reenrollment or configuration repair is required",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
