"""Fixed root-only expiry checks for a disposable mail test node; never an application command API.

Like node_checks, failures print only a fixed code and stage. No argv, output, key material or
traceback leaves the clone.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROPERTIES = (
    "Type",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "LoadState",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "ExecStartPre",
    "ExecStartPreEx",
    "Wants",
    "Requires",
    "PartOf",
)
UNITS = ("postfix.service", "postfix@-.service", "dovecot.service")
GUARD = ("/usr/bin/python3", "/usr/lib/praho/mail/praho-mail-boot.py")
GUARD_SAMPLES = 5


class CheckError(RuntimeError):
    pass


def command(argv: list[str], *, data: str | None = None, timeout: int = 180, check: bool = True) -> str:
    try:
        result = subprocess.run(argv, input=data, text=True, capture_output=True, check=False, timeout=timeout)  # noqa: S603 -- fixed dispatcher commands
    except (subprocess.SubprocessError, OSError):
        raise CheckError("fixed_command_failed") from None
    if check and result.returncode:
        raise CheckError("fixed_command_refused")
    return result.stdout


def unit_properties(unit: str) -> dict[str, str]:
    output = command(["systemctl", "show", unit, "--property=" + ",".join(PROPERTIES)], timeout=30)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def guard_seconds() -> list[float]:
    samples = []
    for _ in range(GUARD_SAMPLES):
        started = time.monotonic()
        command(list(GUARD), timeout=120)
        samples.append(round(time.monotonic() - started, 3))
    return samples


def topology(_request: dict[str, Any], _directory: Path) -> dict[str, Any]:
    """Record the installed units' loaded systemd state and the ready guard's cost on this profile."""
    if json.loads(Path("/var/lib/praho/mail/node.json").read_text()).get("status") != "ready":
        raise CheckError("mail_journal_not_ready")
    dropins = {
        directory: sorted(path.name for path in Path(directory).iterdir())
        for directory in (
            "/usr/lib/systemd/system/service.d",
            "/lib/systemd/system/service.d",
            "/etc/systemd/system/service.d",
            "/run/systemd/system/service.d",
        )
        if Path(directory).is_dir()
    }
    return {
        "units": {unit: unit_properties(unit) for unit in UNITS},
        "toplevel_dropins": dropins,
        "guard_seconds": guard_seconds(),
    }


def main() -> int:
    actions: dict[str, Callable[[dict[str, Any], Path], dict[str, Any]]] = {"topology": topology}
    action = "invalid"
    try:
        request = json.loads(sys.stdin.read(65537))
        run_id = request["run_id"]
        if os.geteuid() != 0 or not isinstance(run_id, str) or re.fullmatch(r"[a-f0-9]{32}", run_id) is None:
            raise CheckError("invalid_test_identity")
        directory = Path("/var/lib/praho-mail-lab", run_id)
        if directory.resolve() != Path(__file__).resolve().parent or directory.stat().st_mode & 0o077:
            raise CheckError("invalid_private_test_directory")
        if request.get("action") not in actions:
            raise CheckError("unknown_fixed_action")
        action = request["action"]
        print(json.dumps({"ok": True, **actions[action](request, directory)}))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "code": "mail_lab_expiry_check_failed", "stage": action}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
