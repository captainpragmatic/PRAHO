#!/usr/bin/python3 -I
"""Keep Debian bootstrap and future operators on the locked local-only policy."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

REAL_CLI = "/usr/bin/cscli.praho-real"
CONFIG = Path("/etc/praho-crowdsec/config.json")
MAINTAINER_GUARD = Path("/run/praho-crowdsec-maintainer")
AUDIT_LOG = "/var/log/praho-crowdsec-install.log"
MAINTAINER_COMMANDS = (("hub", "update"), ("hub", "upgrade"), ("setup", "unattended"))
PRIVATE_MODE = 0o600
COMMAND_DEPTH = 2
SHORT_OPTION_LENGTH = 2
HUB_GROUPS = {"collections", "parsers", "scenarios", "postoverflows", "contexts", "appsec-configs", "appsec-rules"}
COMMAND_ALIASES = {
    "decision": "decisions",
    "collection": "collections",
    "parser": "parsers",
    "scenario": "scenarios",
    "postoverflow": "postoverflows",
    "context": "contexts",
    "appsec-config": "appsec-configs",
    "waf-configs": "appsec-configs",
    "appsec-rule": "appsec-rules",
    "waf-rules": "appsec-rules",
}


def _command_pair(arguments: list[str]) -> tuple[str, str] | None:
    """Resolve Cobra's first two command words, consuming only pinned global flags."""
    values = {"--config", "--output", "--color", "--branch", "-c", "-o"}
    switches = {"--debug", "--info", "--warning", "--error", "--trace", "--help", "-h", "--version"}
    commands = []
    index = 0
    while index < len(arguments) and len(commands) < COMMAND_DEPTH:
        token = arguments[index]
        name, equals, _value = token.partition("=")
        if name in values:
            if not equals:
                index += 1
                if index >= len(arguments):
                    return None
        elif name in switches:
            pass
        elif token.startswith(("-c", "-o")) and len(token) > SHORT_OPTION_LENGTH:
            pass  # Cobra accepts an attached short-option value, e.g. -ojson.
        elif token.startswith("-"):
            return None  # Never guess how an unreviewed flag consumes argv.
        else:
            commands.append(token)
            canonical = COMMAND_ALIASES.get(token, token)
            if len(commands) == 1 and canonical not in HUB_GROUPS | {
                "hub",
                "setup",
                "capi",
                "console",
                "simulation",
                "decisions",
            }:
                return token, ""  # Unprotected CLI groups keep their native local options.
        index += 1
    commands += [""] * (COMMAND_DEPTH - len(commands))
    return commands[0], commands[1]


def forbidden_operation(arguments: list[str], *, simulation: bool) -> str | None:
    """Apply the same policy to pinned aliases and interposed persistent flags."""
    pair = _command_pair(arguments)
    if pair is None:
        return "unrecognized CLI syntax"
    command, operation = pair
    command = COMMAND_ALIASES.get(command, command)
    blocked = (
        (command == "hub" and operation in {"update", "upgrade"})
        or (command in HUB_GROUPS and operation not in {"list", "inspect"})
        or command == "setup"
        or (command in {"capi", "console"} and operation not in {"status", "inspect"})
        or (command == "simulation" and operation not in {"", "status"})
        or (simulation and command == "decisions" and operation in {"add", "import"})
    )
    return f"{command} {operation}" if blocked else None


def maintainer_skip(arguments: list[str], *, package: str, guard_present: bool) -> bool:
    return package == "crowdsec" and guard_present and tuple(arguments) in MAINTAINER_COMMANDS


def _private_regular(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return info.st_uid == 0 and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == PRIVATE_MODE


def main() -> int:
    if os.geteuid() != 0:
        print("PRAHO's local security CLI requires root.", file=sys.stderr)
        return 1
    simulation = True
    if CONFIG.exists():
        try:
            value = json.loads(CONFIG.read_text())["simulation"]
            if type(value) is bool:
                simulation = value
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Unknown protection state keeps manual creates disabled.
    arguments = sys.argv[1:]
    operation = forbidden_operation(arguments, simulation=simulation)
    if operation is not None:
        if maintainer_skip(
            arguments,
            package=os.environ.get("DPKG_MAINTSCRIPT_PACKAGE", ""),
            guard_present=_private_regular(MAINTAINER_GUARD),
        ):
            descriptor = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "a") as log:
                info = os.fstat(log.fileno())
                if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise ValueError("CrowdSec bootstrap audit must be private and root-owned")
                log.write("Skipped pinned-policy bootstrap operation: " + operation + "\n")
            return 0
        print("PRAHO pins Hub content and local protection policy; operation refused: " + operation, file=sys.stderr)
        return 1
    os.execv(REAL_CLI, [REAL_CLI, *arguments])  # noqa: S606 -- fixed diverted CLI, original argv, no shell
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
