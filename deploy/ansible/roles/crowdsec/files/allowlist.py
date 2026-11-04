#!/usr/bin/python3 -I
"""Reconcile only the inventory-owned allowlist through supported local cscli."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import subprocess
import sys
from collections.abc import Callable

NAME = "praho-inventory"
MAIN_ARG_COUNT = 2
ZERO_EXPIRATIONS = frozenset({None, "", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z"})


def sync_inventory(desired: list[str], execute: Callable[[list[str]], str]) -> bool:
    wanted = {str(ipaddress.ip_network(value, strict=True)) for value in desired}
    response = json.loads(execute(["-o", "json", "allowlists", "list"]))
    if not isinstance(response, list):
        raise ValueError("Allowlist inspection is incompatible")
    candidates = [entry for entry in response if entry.get("name") == NAME]
    if len(candidates) > 1 or any(entry.get("console_managed") for entry in candidates):
        raise ValueError("Inventory allowlist ownership is incompatible")
    changed = not candidates
    if not candidates:
        execute(["allowlists", "create", NAME, "--description", "PRAHO immutable inventory protections"])
        current = set()
    else:
        entries = candidates[0].get("items", [])
        if any(entry.get("expiration") not in ZERO_EXPIRATIONS for entry in entries):
            raise ValueError("Inventory protections cannot have an expiry")
        current = {str(ipaddress.ip_network(entry["value"], strict=True)) for entry in entries}
    missing, extra = sorted(wanted - current), sorted(current - wanted)
    if missing:
        execute(["allowlists", "add", NAME, *missing])
    if extra:
        execute(["allowlists", "remove", NAME, *extra])
    return changed or bool(missing or extra)


def _execute(arguments: list[str]) -> str:
    return subprocess.run(["/usr/bin/cscli", *arguments], capture_output=True, text=True, check=True, timeout=30).stdout  # noqa: S603 -- fixed local CLI with validated inventory CIDRs


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != MAIN_ARG_COUNT:
        raise ValueError("Root and an explicit inventory are required")
    desired = json.loads(base64.b64decode(sys.argv[1], validate=True))
    print(json.dumps({"changed": sync_inventory(desired, _execute)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("CrowdSec inventory allowlist reconciliation failed", file=sys.stderr)
        raise SystemExit(1) from None
