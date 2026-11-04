#!/usr/bin/python3 -I
"""Refuse unreviewed effective configuration before persistent adoption changes."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path("/")
UNITS = (
    "crowdsec.service",
    "crowdsec-firewall-bouncer.service",
    "crowdsec-hubupdate.service",
    "crowdsec-hubupdate.timer",
)
PACKAGED_BOUNCER_UNIT_SHA256 = "1c459fdc032edf948d2e97eae4ca1160c093f234898c1fb14dcf641fe9fb26f5"
MAIN_ARG_COUNT = 2
APPLIED_STAMP_BYTES = 65
PRIVATE_MODE = 0o600
TRUSTED_UID = 0
TRUSTED_GID = 0


def check_configuration(allowed_leaves: list[str]) -> None:
    allowed = {ROOT / value.lstrip("/") for value in allowed_leaves}
    directory = ROOT / "etc/crowdsec"
    secret_override = directory / "bouncers/crowdsec-firewall-bouncer.yaml.local"
    if directory.exists():
        for path in directory.rglob("*.local"):
            if path != secret_override:
                raise ValueError("An unreviewed CrowdSec configuration override exists")
        for tree in ("parsers", "scenarios", "postoverflows", "collections", "acquis.d"):
            for suffix in ("*.yaml", "*.yml"):
                for path in (directory / tree).rglob(suffix):
                    if path not in allowed or path.is_symlink():
                        raise ValueError("An unreviewed acquisition or Hub leaf exists")
    _check_service_fragments()
    _check_owned_roots()


def _check_service_fragments() -> None:
    for unit in UNITS:
        system = ROOT / "etc/systemd/system"
        fragment = system / unit
        if fragment.exists() or fragment.is_symlink():
            maintained_mask = (
                unit == "crowdsec-hubupdate.timer" and fragment.is_symlink() and os.readlink(fragment) == "/dev/null"
            )
            packaged = (
                unit == "crowdsec-firewall-bouncer.service"
                and not fragment.is_symlink()
                and fragment.is_file()
                and hashlib.sha256(fragment.read_bytes()).hexdigest() == PACKAGED_BOUNCER_UNIT_SHA256
            )
            if not packaged and not maintained_mask:
                raise ValueError("An unreviewed native service fragment exists")
        for path in (system / f"{unit}.d").glob("*"):
            if path.name != "praho.conf" or path.is_symlink():
                raise ValueError("An unreviewed native service drop-in exists")


def _check_owned_roots() -> None:
    owned_roots = (
        "etc/crowdsec",
        "etc/praho-crowdsec",
        "var/lib/praho-crowdsec",
        "var/lib/crowdsec/data",
        "home/praho-crowdsec",
        "home/praho-crowdsec/.ssh",
    )
    for relative in owned_roots:
        path = ROOT / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("An unreviewed owned directory or symlink exists")


def read_service_stamps() -> dict[str, str]:
    """Read bounded runtime witnesses; malformed private bytes force reapplication."""
    result = {"engine": "", "bouncer": ""}
    for service in result:
        path = ROOT / f"var/lib/praho-crowdsec/{service}-applied.sha256"
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != TRUSTED_UID
            or info.st_gid != TRUSTED_GID
            or stat.S_IMODE(info.st_mode) != PRIVATE_MODE
            or info.st_nlink != 1
            or info.st_size > APPLIED_STAMP_BYTES
        ):
            raise ValueError("Unsafe applied service witness")
        content = path.read_bytes()
        if re.fullmatch(rb"[0-9a-f]{64}\n", content):
            result[service] = content.decode("ascii")
    return result


if __name__ == "__main__":
    if os.geteuid() != 0 or len(sys.argv) != MAIN_ARG_COUNT:
        raise SystemExit("Root and explicit locked leaf paths are required")
    check_configuration(json.loads(base64.b64decode(sys.argv[1], validate=True)))
    print(json.dumps({"changed": False, "applied_stamps": read_service_stamps()}))
