"""The promote preflight reports, before anything on the host changes, what the real deploy would refuse.

A dry run said "every check passed" while the real run then failed twice: once on a required deploy input
the release validates, once on the release's maintenance-aware edge guard. The preflight runs the
release's own checks and a read-only edge probe, so both surface in the dry run.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.promote_preflight import EDGE_PROBE, preflight

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
GUARD_TASK = "    - name: Require maintenance-aware Caddy before coordinating an existing origin\n"

NATIVE_ENV_STUB = """
from dataclasses import dataclass

def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)

{validate}

CONNECTION_KEYS = {{"PRAHO_SSH_KEY", "PRAHO_SSH_PORT"}}
ALLOWLIST_KEYS = ("PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS",)

@dataclass(frozen=True)
class Target:
    server: str
    port: int = 9876
    identity: str = "/keys/operator.pub"
    user: str = "root"
    known_hosts: str = "/keys/known_hosts"
    def connection(self):
        return {{
            "ansible_host": self.server,
            "ansible_user": self.user,
            "ansible_port": self.port,
            "ansible_ssh_private_key_file": self.identity,
            "ansible_ssh_common_args": "-F /dev/null -o BatchMode=yes -o HostKeyAlias=" + self.server,
        }}

def recover_ssh_port(connection, environment):
    # The real one probes the pinned identity on 9876 after hardening moved SSH off 22.
    if connection["PRAHO_SSH_PORT"] == "22":
        connection["PRAHO_SSH_PORT"] = "9876"

@dataclass(frozen=True)
class Topology:
    mode: str
    platform: Target
    portal: Target

def normalize_topology(values, environment):
    mode = values.get("PRAHO_NATIVE_TOPOLOGY", "combined")
    port = int(values.get("PRAHO_SSH_PORT", "9876"))
    key = values.get("PRAHO_SSH_KEY", "/keys/operator.pub")
    platform = Target("192.0.2.10", port, key)
    return Topology(mode, platform, Target("192.0.2.20", port, key) if mode == "split" else platform)
"""
VALIDATE = """
def validate_application_configuration(values, environment):
    if not values.get("PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS"):
        raise ValueError("Native HTTPS callbacks require explicit Platform egress CIDRs")
"""


def release(tmp_path: Path, *, guard: bool = True, validate: bool = True) -> Path:
    root = tmp_path / "release"
    (root / "deploy/scripts").mkdir(parents=True)
    (root / "deploy/scripts/native_env.py").write_text(NATIVE_ENV_STUB.format(validate=VALIDATE if validate else ""))
    (root / "deploy/ansible/playbooks").mkdir(parents=True)
    (root / "deploy/ansible/playbooks/native.yml").write_text(
        "- hosts: praho\n  tasks:\n" + (GUARD_TASK if guard else "")
    )
    return root


def env_file(tmp_path: Path, **values: str) -> Path:
    path = tmp_path / ".env.staging"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return path


class FakeSSH:
    def __init__(self, returncodes: dict[str, int] | None = None) -> None:
        self.returncodes = returncodes or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        host = argv[-2].split("@", 1)[1]
        return subprocess.CompletedProcess(argv, self.returncodes.get(host, 0), "", "")


GOOD = {"PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": "192.0.2.10/32"}


def test_a_ready_release_and_host_pass(tmp_path: Path) -> None:
    ssh = FakeSSH()
    assert preflight(release(tmp_path), env_file(tmp_path, **GOOD), run=ssh) == []
    (call,) = ssh.calls
    assert call[0] == "ssh" and call[-1] == EDGE_PROBE and call[-2] == "root@192.0.2.10"
    assert call[call.index("-p") : call.index("-p") + 2] == ["-p", "9876"]
    assert "BatchMode=yes" in " ".join(call), "the deploy's own non-interactive SSH options are reused"


def test_the_releases_own_configuration_check_is_reported(tmp_path: Path) -> None:
    problems = preflight(release(tmp_path), env_file(tmp_path), run=FakeSSH())
    assert problems == ["configuration: Native HTTPS callbacks require explicit Platform egress CIDRs"]


def test_an_old_edge_is_reported_before_the_deploy(tmp_path: Path) -> None:
    problems = preflight(release(tmp_path), env_file(tmp_path, **GOOD), run=FakeSSH({"192.0.2.10": 1}))
    assert len(problems) == 1 and "192.0.2.10" in problems[0] and "make deploy-caddy ENV=staging" in problems[0]


def test_an_unreachable_host_is_reported_not_ignored(tmp_path: Path) -> None:
    problems = preflight(release(tmp_path), env_file(tmp_path, **GOOD), run=FakeSSH({"192.0.2.10": 255}))
    assert len(problems) == 1 and "could not check" in problems[0]


def test_a_split_topology_checks_both_hosts(tmp_path: Path) -> None:
    ssh = FakeSSH({"192.0.2.20": 1})
    problems = preflight(release(tmp_path), env_file(tmp_path, PRAHO_NATIVE_TOPOLOGY="split", **GOOD), run=ssh)
    assert {call[-2] for call in ssh.calls} == {"root@192.0.2.10", "root@192.0.2.20"}
    assert len(problems) == 1 and "192.0.2.20" in problems[0]


def test_an_older_release_without_the_guard_or_validation_is_not_held_to_them(tmp_path: Path) -> None:
    ssh = FakeSSH({"192.0.2.10": 1})
    assert preflight(release(tmp_path, guard=False, validate=False), env_file(tmp_path), run=ssh) == []
    assert ssh.calls == [], "no edge probe when the release does not enforce the edge"


def test_every_problem_is_kept_when_the_topology_also_fails(tmp_path: Path) -> None:
    root = release(tmp_path)
    stub = root / "deploy/scripts/native_env.py"
    stub.write_text(
        stub.read_text()
        + "\n\ndef normalize_topology(values, environment):\n    raise ValueError('split requires stable egress CIDRs')\n"
    )
    problems = preflight(root, env_file(tmp_path), run=FakeSSH())
    assert problems[0].startswith("configuration: ") and "topology: split requires stable egress CIDRs" in problems[1]


def test_a_stalled_host_is_reported_not_raised(tmp_path: Path) -> None:
    def stall(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 60))

    problems = preflight(release(tmp_path), env_file(tmp_path, **GOOD), run=stall)
    assert len(problems) == 1 and "timed out" in problems[0]


def test_shell_connection_settings_reach_the_probe_as_they_reach_the_deploy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PRAHO_SSH_KEY", "/keys/from-shell.pub")
    ssh = FakeSSH()
    assert preflight(release(tmp_path), env_file(tmp_path, **GOOD), run=ssh) == []
    (call,) = ssh.calls
    assert call[call.index("-i") + 1] == "/keys/from-shell.pub"


def test_a_legacy_ssh_port_is_recovered_before_the_probe(tmp_path: Path) -> None:
    ssh = FakeSSH()
    assert preflight(release(tmp_path), env_file(tmp_path, PRAHO_SSH_PORT="22", **GOOD), run=ssh) == []
    (call,) = ssh.calls
    assert call[call.index("-p") + 1] == "9876"


def test_a_shell_supplied_allowlist_satisfies_validation_as_in_the_deploy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS", "192.0.2.10/32")
    assert preflight(release(tmp_path), env_file(tmp_path), run=FakeSSH()) == []


def test_the_edge_probe_only_reads() -> None:
    assert EDGE_PROBE == "test ! -e /etc/caddy/Caddyfile || grep -q /etc/praho-native /etc/caddy/Caddyfile"


def test_the_promote_runs_the_preflight_before_its_dry_run_ends() -> None:
    script = (REPO / "scripts/promote_staging.sh").read_text(encoding="utf-8")
    assert "scripts/promote_preflight.py" in script
    assert script.index("scripts/promote_preflight.py") < script.index('if [ "$dry_run" -eq 1 ]; then')
