#!/usr/bin/env python3
"""Report, before anything on the host changes, what the real staging deploy would refuse.

promote_staging.sh runs this for both a dry run and a real run:

    python3 scripts/promote_preflight.py <release checkout> <env file>

It loads the RELEASE's own deploy/scripts/native_env.py, so the checks are the ones that release
enforces:

- the release's application configuration validation (a missing required deploy input, such as
  PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS since #863);
- when the release's playbook refuses an older edge, a read-only probe over the deploy's own SSH
  options that every target host already has the maintenance-aware Caddy edge
  (docs/deployment/NATIVE_TOPOLOGY.md: apply it first with `make deploy-caddy ENV=…`).

An older release that does not enforce a check is not held to it. Exit 1 lists every problem found.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import os
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

EDGE_GUARD_TASK = "Require maintenance-aware Caddy before coordinating an existing origin"
EDGE_PROBE = "test ! -e /etc/caddy/Caddyfile || grep -q /etc/praho-native /etc/caddy/Caddyfile"
ENVIRONMENT = "staging"


def _native_env(release: Path) -> ModuleType:
    path = release / "deploy" / "scripts" / "native_env.py"
    spec = importlib.util.spec_from_file_location("release_native_env", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve their module through sys.modules while the class is created.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _edge_enforced(release: Path) -> bool:
    playbook = release / "deploy" / "ansible" / "playbooks" / "native.yml"
    return playbook.is_file() and EDGE_GUARD_TASK in playbook.read_text(encoding="utf-8")


def _ssh_argv(connection: dict[str, Any]) -> list[str]:
    argv = ["ssh", *shlex.split(str(connection["ansible_ssh_common_args"])), "-p", str(connection["ansible_port"])]
    if connection.get("ansible_ssh_private_key_file"):
        argv += ["-i", str(connection["ansible_ssh_private_key_file"])]
    return [*argv, f"{connection['ansible_user']}@{connection['ansible_host']}", EDGE_PROBE]


def preflight(
    release: Path, env_file: Path, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
) -> list[str]:
    native_env = _native_env(release)
    values = native_env.read_env(env_file)
    problems: list[str] = []
    validate = getattr(native_env, "validate_application_configuration", None)
    if validate is not None:
        try:
            validate(values, ENVIRONMENT)
        except ValueError as error:
            problems.append(f"configuration: {error}")
    if not _edge_enforced(release):
        return problems
    # Resolve targets exactly as the release's run_native does: shell connection settings merged under the
    # env file, then each target's SSH port recovered with its pinned identity.
    connection_keys = getattr(native_env, "CONNECTION_KEYS", set())
    connection_values = {
        key: value
        for key, value in os.environ.items()
        if key in connection_keys or key.startswith(("PRAHO_PLATFORM_", "PRAHO_PORTAL_"))
    }
    connection_values.update(values)
    try:
        topology = native_env.normalize_topology(connection_values, ENVIRONMENT)
        targets = []
        for target in dict.fromkeys([topology.platform] + ([topology.portal] if topology.mode == "split" else [])):
            recover = getattr(native_env, "recover_ssh_port", None)
            if recover is not None:
                connection = {
                    "PRAHO_SERVER_IP": target.server,
                    "PRAHO_DEV_IP": target.server,
                    "PRAHO_SSH_USER": target.user,
                    "PRAHO_SSH_PORT": str(target.port),
                    "PRAHO_SSH_KEY": target.identity,
                    "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": target.known_hosts,
                }
                recover(connection, ENVIRONMENT)
                target = dataclasses.replace(target, port=int(connection["PRAHO_SSH_PORT"]))
            targets.append(target)
    except ValueError as error:
        return [*problems, f"topology: {error}"]
    except subprocess.TimeoutExpired:
        return [*problems, "topology: SSH port recovery timed out"]
    for target in targets:
        try:
            result = run(_ssh_argv(target.connection()), capture_output=True, text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            problems.append(f"{target.server}: the edge check over SSH timed out")
            continue
        if result.returncode == 1:
            problems.append(
                f"{target.server}: the existing Caddy edge is not maintenance-aware, and this release refuses it. "
                "Apply it first with `make deploy-caddy ENV=staging` from a checkout of the release "
                "(docs/deployment/NATIVE_TOPOLOGY.md)."
            )
        elif result.returncode != 0:
            problems.append(f"{target.server}: could not check the edge over SSH (exit {result.returncode})")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <release checkout> <env file>", file=sys.stderr)
        return 2
    try:
        problems = preflight(Path(argv[1]), Path(argv[2]))
    except (OSError, ValueError, ImportError) as error:
        problems = [f"preflight could not run: {error}"]
    for problem in problems:
        print(f"❌ {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
