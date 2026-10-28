"""Fixed root-only expiry checks for a disposable mail test node; never an application command API.

Like node_checks, failures print only a fixed code and stage. No argv, output, key material or
traceback leaves the clone. ``forge_expired`` is test-only: production cannot install an expired
leaf, because setup and rotation refuse any candidate within seven days of expiry.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import signal
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
JOURNAL = Path("/var/lib/praho/mail/node.json")
INSTALLED = Path("/usr/lib/praho/mail")
WATCH_SECONDS = 900
# Fixed so a previous bundle, which predates BUNDLE_PATHS, can be read the same way.
BUNDLE_PATHS = (
    *(
        "/usr/lib/praho/mail/" + name
        for name in (
            "praho-mail.py",
            "praho_mail_setup.py",
            "praho-mail-native.pl",
            "praho-mail-boot.py",
            "praho_mail_submitters.py",
        )
    ),
    *(
        "/etc/systemd/system/" + name + ".d/praho-mail.conf"
        for name in ("postfix.service", "postfix@.service", "dovecot.service")
    ),
)


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


def refused(argv: list[str]) -> bool:
    """True when a real systemd start is refused (the unit's guard exits non-zero)."""
    try:
        return subprocess.run(argv, capture_output=True, check=False, timeout=120).returncode != 0  # noqa: S603 -- fixed dispatcher commands
    except (subprocess.SubprocessError, OSError):
        raise CheckError("fixed_command_failed") from None


def save(path: Path, content: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name("." + path.name + ".lab")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def protocol() -> Any:
    """The installed setup module: the same topology and fence checker the guard uses."""
    specification = importlib.util.spec_from_file_location("installed_mail_setup", INSTALLED / "praho_mail_setup.py")
    if specification is None or specification.loader is None:
        raise CheckError("installed_protocol_missing")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def journal() -> dict[str, Any]:
    return json.loads(JOURNAL.read_text())


def eligible() -> list[str]:
    return [unit["unit"] for unit in protocol().UNIT_TOPOLOGY[journal()["profile"]] if unit["start"]]


def active(unit: str) -> bool:
    return command(["systemctl", "is-active", unit], timeout=30, check=False).strip() == "active"


def fences() -> dict[str, str]:
    module = protocol()
    return {
        program: module.certificate_fence(command([program + "-save", "-t", "filter"], timeout=30), rejection)
        for program, rejection in module.FENCE_FAMILIES.items()
    }


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
    if journal().get("status") != "ready":
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


def forge_expired(request: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Install a trusted, correctly named, expired leaf with its manifest digests; then stop mail."""
    material = request["material"]
    record = journal()
    if record.get("status") != "ready":
        raise CheckError("mail_journal_not_ready")
    ca_digest = hashlib.sha256(material["ca"].encode()).hexdigest()
    save(
        Path("/usr/local/share/ca-certificates/praho-mail-lab-" + directory.name + "-expired-" + ca_digest + ".crt"),
        material["ca"].encode(),
        0o644,
    )
    command(["update-ca-certificates"], timeout=180)
    for name, content in (("node.pem", material["leaf"]), ("node.key", material["key"])):
        save(Path("/etc/praho-mail") / name, content.encode())
        record["files"]["/etc/praho-mail/" + name] = hashlib.sha256(content.encode()).hexdigest()
    save(JOURNAL, json.dumps(record).encode())
    # A real start under systemd: the installed guard must refuse the expired leaf.
    restart_refused = refused(["systemctl", "restart", "dovecot.service"])
    command(["systemctl", "stop", *UNITS], timeout=120)
    if not restart_refused or any(active(unit) for unit in UNITS):
        raise CheckError("expired_leaf_started")
    return {"expired_leaf_installed": True, "real_restart_refused": True, "units_stopped": True}


def arm_kill(request: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Start a detached watcher that SIGKILLs the certificate worker at a fixed point."""
    if request.get("trigger") not in {"first_start", "starting"}:
        raise CheckError("unknown_kill_trigger")
    (directory / "kill.json").unlink(missing_ok=True)
    watcher = subprocess.Popen(  # noqa: S603 -- this fixed dispatcher, detached
        [sys.executable, str(Path(__file__).resolve())],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    if watcher.stdin is None:
        raise CheckError("watcher_not_started")
    watcher.stdin.write(json.dumps({**request, "action": "watch"}).encode())
    watcher.stdin.close()
    return {"armed": request["trigger"]}


def watch(request: dict[str, Any], directory: Path) -> dict[str, Any]:
    deadline = time.monotonic() + WATCH_SECONDS
    while time.monotonic() < deadline:
        try:
            record = journal()
        except (OSError, ValueError):
            record = {}
        if record.get("status") == "certificate_starting":
            first = eligible()[0]
            if request["trigger"] == "starting" or active(first):
                os.kill(record["start"]["pid"], signal.SIGKILL)
                save(
                    directory / "kill.json",
                    json.dumps({"killed": True, "pid": record["start"]["pid"], "unit": first}).encode(),
                )
                return {"killed": True}
        time.sleep(0.02)
    save(directory / "kill.json", json.dumps({"killed": False}).encode())
    return {"killed": False}


def owner_killed(_request: dict[str, Any], directory: Path) -> dict[str, Any]:
    """After guard approval the owner died: admitted daemons stay fenced; later starts are refused."""
    kill = json.loads((directory / "kill.json").read_text())
    record = journal()
    if kill.get("killed") is not True or record.get("status") != "certificate_starting":
        raise CheckError("owner_not_killed_after_approval")
    if Path("/proc", str(kill["pid"])).exists() or not active(kill["unit"]):
        raise CheckError("admitted_daemon_not_running")
    if set(fences().values()) != {"exact"}:
        raise CheckError("admitted_daemon_not_fenced")
    later = next(unit for unit in eligible() if not active(unit))
    if not refused(["systemctl", "start", later]):
        raise CheckError("later_start_approved_without_owner")
    return {"admitted_daemon": kill["unit"], "fence_exact": True, "later_start_refused": later}


def after_restart(_request: dict[str, Any], _directory: Path) -> dict[str, Any]:
    """A container restart: the tmpfs lock and live fence are gone, and the guard still refuses."""
    if Path("/run/praho-mail/operation.lock").exists() or journal().get("status") != "certificate_starting":
        raise CheckError("restart_did_not_drop_runtime_state")
    if set(fences().values()) != {"absent"}:
        raise CheckError("fence_survived_restart")
    units = eligible()
    if any(active(unit) for unit in units) or not refused(["systemctl", "start", units[-1]]):
        raise CheckError("start_approved_after_restart")
    return {"runtime_lock_gone": True, "fence_gone": True, "start_refused": units[-1]}


def start_timing(_request: dict[str, Any], _directory: Path) -> dict[str, Any]:
    """Seconds from leaving inactive to active per eligible unit: an upper bound on the guard's cost
    under a permit (it includes the daemon's own start). ExecMainStart is not refreshed for every type."""
    seconds = {}
    for unit in eligible():
        values = dict(
            line.split("=", 1)
            for line in command(
                [
                    "systemctl",
                    "show",
                    unit,
                    "--property=InactiveExitTimestampMonotonic,ActiveEnterTimestampMonotonic",
                ],
                timeout=30,
            ).splitlines()
            if "=" in line
        )
        entered, active_at = int(values["InactiveExitTimestampMonotonic"]), int(values["ActiveEnterTimestampMonotonic"])
        seconds[unit] = round((active_at - entered) / 1_000_000, 3)
    return {"guard_start_seconds": seconds}


def installed_bundle(_request: dict[str, Any], _directory: Path) -> dict[str, Any]:
    return {
        "digests": {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in BUNDLE_PATHS},
        "journal_status": journal()["status"],
    }


def main() -> int:
    actions: dict[str, Callable[[dict[str, Any], Path], dict[str, Any]]] = {
        "topology": topology,
        "forge_expired": forge_expired,
        "arm_kill": arm_kill,
        "watch": watch,
        "owner_killed": owner_killed,
        "after_restart": after_restart,
        "start_timing": start_timing,
        "installed_bundle": installed_bundle,
    }
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
