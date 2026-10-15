"""Decode native deployment configuration as data; never source it as shell code."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
CONNECTION_KEYS = ("PRAHO_SERVER_IP", "PRAHO_DEV_IP", "PRAHO_SSH_USER", "PRAHO_SSH_KEY")


def read_env(path: Path) -> dict[str, str]:
    """One assignment per line, last wins; single quotes preserve literal dollars/backticks."""
    values: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        key = match.group(1) if match else "assignment"
        try:
            if not match or "\x00" in line:
                raise ValueError
            raw = match.group(2).strip()
            if raw and raw[0] in "\"'" and raw[-1] != raw[0]:
                raise ValueError
            if not raw.startswith("'") and any(char in raw for char in ("$", "`")):
                raise ValueError
            if raw.startswith("#") or (not raw.startswith(("'", '"')) and re.search(r"\s+#", raw)):
                raise ValueError
            parts = shlex.split(raw, comments=False, posix=True)
            if len(parts) > 1:
                raise ValueError
            values[key] = parts[0] if parts else ""
        except ValueError:
            raise ValueError(
                f"line {number}:{key}: unsupported env syntax; quote values and use one assignment per line"
            ) from None
    return values


def systemd_env(values: dict[str, str]) -> str:
    """Quote for EnvironmentFile and the legacy maintenance cron's POSIX shell reader."""
    lines = []
    for key, value in values.items():
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        lines.append(f'{key}="{escaped}"\n')
    return "".join(lines)


def pgpass(values: dict[str, str]) -> str:
    """Escape libpq's colon/backslash separators without evaluating the credential."""
    fields = [
        values.get(key) or default
        for key, default in (
            ("DB_HOST", "localhost"),
            ("DB_PORT", "5432"),
            ("DB_NAME", "praho"),
            ("DB_USER", "praho"),
            ("DB_PASSWORD", ""),
        )
    ]
    return ":".join(field.replace("\\", "\\\\").replace(":", "\\:") for field in fields) + "\n"


def run_native(values: dict[str, str], path: Path, environment: str, *, fetch_backup: str | None, version: str) -> int:
    """Export inventory connection values, never application credentials, to Ansible."""
    inventory = "dev.yml" if environment == "dev" else "native-single-server.yml"
    local_controller = Path(sys.executable).with_name("ansible-playbook")
    controller = (
        str(local_controller)
        if local_controller.is_file()
        else (shutil.which("ansible-playbook") or "ansible-playbook")
    )
    command = [
        controller,
        "-i",
        f"inventory/{inventory}",
        f"playbooks/{'backup' if fetch_backup is not None else 'native-single-server'}.yml",
        "-e",
        f"praho_env={environment}",
        "-e",
        f"env_file_path={path}",
    ]
    if fetch_backup is not None:
        command += ["-e", f"fetch_backup={fetch_backup}"]
    if version:
        command += ["-e", f"cli_version={version}"]
    child_env = {**os.environ, **{key: values[key] for key in CONNECTION_KEYS if key in values}}
    return subprocess.run(command, cwd=ROOT / "deploy/ansible", env=child_env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run",))
    parser.add_argument("--env", choices=("prod", "staging", "dev"), default="prod")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--backup", action="store_true")
    parser.add_argument("--fetch", choices=("true", "false"), default="false")
    parser.add_argument("--version", default="")
    args = parser.parse_args()
    path = (args.env_file or ROOT / f".env.{args.env}").resolve()
    try:
        values = read_env(path)
    except (OSError, UnicodeError, ValueError) as error:
        message = (
            str(error)
            if isinstance(error, ValueError) and not isinstance(error, UnicodeError)
            else "cannot read UTF-8 env file"
        )
        print(message, file=sys.stderr)
        return 1
    try:
        return run_native(
            values, path, args.env, fetch_backup=args.fetch if args.backup else None, version=args.version
        )
    except OSError:
        print("cannot start ansible-playbook; install the project dependencies", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
