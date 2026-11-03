"""Install the shared role through real Debian scripts, systemd and restricted SSH."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import urllib.request
from pathlib import Path

import pytest
import yaml
from test_crowdsec_qualification_docker import assert_native_role_profile
from test_ssh_hardening_docker import ROOT, docker, harden, ssh_target

__all__ = ["ssh_target"]
pytestmark = pytest.mark.docker


def _package(lock: dict[str, object], architecture: str, name: str, temporary: Path) -> Path:
    artifact = lock["packages"][architecture][name]
    filename = f"{name}_{artifact['version']}_{architecture}.deb"
    cache = os.environ.get("CROWDSEC_ARTIFACT_DIR")
    path = Path(cache) / filename if cache else temporary / filename
    if not cache:
        assert artifact["url"].startswith("https://packagecloud.io/crowdsec/crowdsec/")
        with urllib.request.urlopen(artifact["url"], timeout=120) as source, path.open("wb") as destination:  # noqa: S310 -- pinned public package URL, size and SHA-256 verified before execution
            shutil.copyfileobj(source, destination)
    assert path.stat().st_size == artifact["size"]
    with path.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == artifact["sha256"]
    return path


def _wait_for_alerts(target: str, address: str) -> list[list[int]]:
    script = (
        "import sqlite3,json,sys; from contextlib import closing; "
        "\nwith closing(sqlite3.connect('file:/var/lib/crowdsec/data/crowdsec.db?mode=ro',uri=True,timeout=1)) as c: "
        "print(json.dumps(c.execute(\"SELECT simulated FROM alerts WHERE scenario LIKE 'crowdsecurity/ssh-bf%' AND source_value=?\", (sys.argv[1],)).fetchall()))"
    )
    deadline = time.monotonic() + 25
    rows = []
    while time.monotonic() < deadline:
        rows = json.loads(docker("exec", target, "python3", "-I", "-c", script, address).stdout)
        if rows:
            break
        time.sleep(0.1)
    return rows


@pytest.mark.parametrize("ssh_target", ["26.04"], indirect=True)
def test_shared_role_install_convergence_acquisition_and_simulation_transitions(  # noqa: PLR0915 -- one real adoption and mode-transition trajectory
    ssh_target: str, tmp_path: Path
) -> None:
    target = ssh_target
    lock = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    architecture = docker("exec", target, "dpkg", "--print-architecture").stdout.strip()
    docker("cp", str(ROOT / "deploy/crowdsec"), f"{target}:/work/crowdsec")
    docker("exec", target, "mkdir", "-p", "/work/packages", "/work/repository/build/crowdsec-patched")
    for name in ("crowdsec", "crowdsec-firewall-bouncer-nftables"):
        package = _package(lock, architecture, name, tmp_path)
        docker("cp", str(package), f"{target}:/work/packages/{package.name}")
    selected = lock["bouncer_build"]["binaries"][architecture]
    candidate = ROOT / selected["file"]
    with candidate.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == selected["sha256"]
    docker("cp", str(candidate), f"{target}:/work/repository/{selected['file']}")
    docker(
        "cp",
        str(ROOT / "build/crowdsec-patched/license-notices.tar.gz"),
        f"{target}:/work/repository/build/crowdsec-patched/license-notices.tar.gz",
    )
    docker("exec", target, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/root/crowdsec-controller")
    public_key = docker("exec", target, "cat", "/root/crowdsec-controller.pub").stdout.strip()
    ssh_result = harden(target, extra={"ssh_crowdsec_gateway_enabled": True})
    assert ssh_result.returncode == 0, ssh_result.stdout[-7000:] + ssh_result.stderr[-1000:]
    docker("exec", target, "apt-get", "update")
    docker("exec", target, "apt-get", "install", "-y", "--no-install-recommends", "gnupg")
    docker("exec", target, "touch", "/var/log/auth.log")
    variables = {
        "crowdsec_enabled": True,
        "crowdsec_simulation": True,
        "crowdsec_host_kind": "node",
        "crowdsec_protected_cidrs": ["127.0.0.1/32", "::1/128"],
        "crowdsec_gateway_public_key": public_key,
        "crowdsec_ssh_acquisition": "file",
        "crowdsec_artifact_lock_path": "/work/crowdsec/artifacts.lock.json",
        "crowdsec_repository_root": "/work/repository",
        "crowdsec_package_cache": "/work/packages",
    }
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": True,
            "become": True,
            "vars": variables,
            "roles": ["crowdsec"],
        }
    ]

    def apply():
        docker("exec", "-i", target, "tee", "/work/crowdsec-role.yml", input_text=yaml.safe_dump(play))
        return docker(
            "exec",
            "-w",
            "/work",
            target,
            "/opt/controller/bin/ansible-playbook",
            "-i",
            "localhost,",
            "crowdsec-role.yml",
            check=False,
        )

    variables["crowdsec_policy_preview"] = True
    preview = apply()
    assert preview.returncode == 0 and "PRAHO_CROWDSEC_CONFIGURATION_DIGEST=" in preview.stdout, preview.stdout[-5000:]
    for untouched in ("/etc/crowdsec", "/etc/praho-crowdsec", "/var/lib/praho-crowdsec", "/usr/bin/cscli"):
        assert docker("exec", target, "test", "-e", untouched, check=False).returncode != 0
    assert docker("exec", target, "id", "praho-crowdsec", check=False).returncode != 0
    variables["crowdsec_policy_preview"] = False
    installed = apply()
    if installed.returncode != 0 and os.environ.get("CROWDSEC_DEBUG_INSTALL") == "1":
        docker("commit", target, "praho-crowdsec-role-debug:failed-install")
    assert installed.returncode == 0, installed.stdout[-15000:] + installed.stderr[-2000:]
    first = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    assert first["simulation"] is True
    assert "PRAHO_CROWDSEC_INSTALLATION_ID=" + first["installation_id"] in installed.stdout
    assert docker("exec", target, "systemctl", "is-active", "crowdsec").stdout.strip() == "active"
    unauthenticated = docker(
        "exec",
        target,
        "runuser",
        "-u",
        "praho-crowdsec",
        "--",
        "python3",
        "-I",
        "-c",
        "import urllib.request,urllib.error; "
        "\ntry: urllib.request.urlopen('http://127.0.0.1:8080/v1/decisions',timeout=2)"
        "\nexcept urllib.error.HTTPError as error: print(error.code)",
    )
    assert unauthenticated.stdout.strip() in {"401", "403"}
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer", check=False).returncode != 0
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-hubupdate.timer", check=False).returncode != 0
    audit = docker("exec", target, "cat", "/var/log/praho-crowdsec-install.log").stdout
    assert "hub update" in audit and "hub upgrade" in audit and "setup unattended" in audit
    assert docker("exec", target, "stat", "-c", "%s", "/etc/crowdsec/online_api_credentials.yaml").stdout.strip() == "0"
    assert "nil" in docker("exec", target, "cscli", "config", "show", "--key", "Config.API.Server.OnlineClient").stdout
    refused = docker("exec", target, "cscli", "hub", "update", check=False)
    assert refused.returncode != 0 and "operation refused" in refused.stderr
    for arguments in (
        ("decision", "add", "--ip", "198.51.100.77"),
        ("decisions", "--debug", "add", "--ip", "198.51.100.77"),
        ("parser", "install", "crowdsecurity/sshd-logs"),
        ("hub", "--debug", "update"),
        ("contexts", "install", "--help"),
        ("waf-rules", "--debug", "install", "--help"),
        ("simulation", "disable", "--global"),
    ):
        blocked_alias = docker("exec", target, "cscli", *arguments, check=False)
        assert blocked_alias.returncode != 0 and "operation refused" in blocked_alias.stderr
    assert docker("exec", target, "cscli", "decision", "--output", "json", "list").returncode == 0
    again = apply()
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout[-15000:] + again.stderr[-1000:]
    second = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    assert second["installation_id"] == first["installation_id"]
    assert_native_role_profile(target, expected_configuration_digest=second["configuration_digest"])
    gateway_request = json.dumps(
        {
            "protocol": 1,
            "request_id": "5677bcca-c5a6-4afd-937f-d78817e76ad2",
            "installation_id": second["installation_id"],
            "configuration_digest": second["configuration_digest"],
            "operation": "health",
            "payload": {},
        }
    )
    ssh_arguments = (
        "exec",
        "-i",
        target,
        "ssh",
        "-F",
        "/dev/null",
        "-T",
        "-p",
        "9876",
        "-o",
        "HostKeyAlias=127.0.0.1",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=/root/known_hosts",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=3",
        "-i",
        "/root/crowdsec-controller",
        "praho-crowdsec@127.0.0.1",
    )
    gateway = docker(*ssh_arguments, input_text=gateway_request, check=False)
    assert gateway.returncode == 0, gateway.stderr
    assert json.loads(gateway.stdout)["result"]["configuration"]["qualified"] is True
    assert docker(*ssh_arguments, "id", input_text=gateway_request, check=False).returncode != 0
    before_override = docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout
    docker("exec", "-i", target, "tee", "/etc/crowdsec/config.yaml.local", input_text="unreviewed: true\n")
    rejected_override = apply()
    assert rejected_override.returncode != 0
    assert docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout == before_override
    assert docker("exec", target, "cat", "/etc/crowdsec/config.yaml.local").stdout == "unreviewed: true\n"
    docker("exec", target, "rm", "/etc/crowdsec/config.yaml.local")
    timestamp = docker("exec", target, "date", "+%b %e %H:%M:%S").stdout.strip()
    lines = "".join(
        f"{timestamp} node sshd[{9000 + index}]: Failed password for invalid user fixture-user from 198.51.100.9 port 4444 ssh2\n"
        for index in range(12)
    )
    docker("exec", "-i", target, "tee", "-a", "/var/log/auth.log", input_text=lines)
    detected = _wait_for_alerts(target, "198.51.100.9")
    assert detected and all(row == [1] for row in detected), docker(
        "exec", target, "journalctl", "-u", "crowdsec", "--no-pager", "-n", "50"
    ).stdout
    variables["crowdsec_simulation"] = False
    refused_enforcement = apply()
    assert refused_enforcement.returncode != 0
    assert json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)["simulation"] is True
    variables["crowdsec_enforcement_qualified"] = (
        True  # Explicit qualification-only gate inside this disposable fixture.
    )
    without_reviewed_digest = apply()
    assert without_reviewed_digest.returncode != 0
    assert json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)["simulation"] is True
    variables["crowdsec_policy_preview"] = True
    enforcement_preview = apply()
    assert enforcement_preview.returncode == 0, enforcement_preview.stdout[-8000:]
    marker = "PRAHO_CROWDSEC_CONFIGURATION_DIGEST="
    variables["crowdsec_expected_configuration_digest"] = (
        enforcement_preview.stdout.split(marker)[1].split('"')[0].strip()
    )
    assert json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)["simulation"] is True
    variables["crowdsec_policy_preview"] = False
    enforcing = apply()
    assert enforcing.returncode == 0, enforcing.stdout[-15000:] + enforcing.stderr[-1500:]
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer").stdout.strip() == "active"
    enforcing_config = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    assert_native_role_profile(target, expected_configuration_digest=enforcing_config["configuration_digest"])
    docker("exec", target, "cscli", "decisions", "add", "--ip", "198.51.100.77", "--duration", "5m")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        bans = docker("exec", target, "nft", "list", "set", "ip", "praho_crowdsec4", "bans").stdout
        if "198.51.100.77" in bans:
            break
        time.sleep(0.1)
    assert "198.51.100.77" in bans
    previous_pid = docker(
        "exec", target, "systemctl", "show", "crowdsec-firewall-bouncer", "--property=MainPID", "--value"
    ).stdout.strip()
    unchanged = apply()
    assert unchanged.returncode == 0 and "changed=0" in unchanged.stdout, unchanged.stdout[-10000:]
    assert (
        docker(
            "exec", target, "systemctl", "show", "crowdsec-firewall-bouncer", "--property=MainPID", "--value"
        ).stdout.strip()
        == previous_pid
    )
    variables["crowdsec_ssh_acquisition"] = "journalctl"
    variables["crowdsec_policy_preview"] = True
    changed_preview = apply()
    assert changed_preview.returncode == 0, changed_preview.stdout[-8000:]
    variables["crowdsec_expected_configuration_digest"] = changed_preview.stdout.split(marker)[1].split('"')[0].strip()
    variables["crowdsec_policy_preview"] = False
    changed_config = apply()
    assert changed_config.returncode == 0, changed_config.stdout[-12000:]
    assert (
        docker(
            "exec", target, "systemctl", "show", "crowdsec-firewall-bouncer", "--property=MainPID", "--value"
        ).stdout.strip()
        != previous_pid
    )
    assert "198.51.100.77" in docker("exec", target, "nft", "list", "set", "ip", "praho_crowdsec4", "bans").stdout
    docker("exec", target, "ufw", "reload")
    docker("exec", target, "systemctl", "restart", "praho-crowdsec-firewall")
    assert "198.51.100.77" in docker("exec", target, "nft", "list", "set", "ip", "praho_crowdsec4", "bans").stdout
    docker("restart", target)
    docker("exec", target, "systemctl", "is-system-running", "--wait", check=False)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        restored = docker("exec", target, "nft", "list", "set", "ip", "praho_crowdsec4", "bans", check=False)
        readiness = docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer", check=False)
        if restored.returncode == 0 and "198.51.100.77" in restored.stdout and readiness.stdout.strip() == "active":
            break
        time.sleep(0.1)
    assert restored.returncode == 0 and "198.51.100.77" in restored.stdout
    assert readiness.stdout.strip() == "active", (
        readiness.stdout
        + docker("exec", target, "journalctl", "-u", "crowdsec-firewall-bouncer", "--no-pager", "-n", "30").stdout
    )
    variables["crowdsec_ssh_acquisition"] = "file"
    variables["crowdsec_policy_preview"] = True
    file_preview = apply()
    assert file_preview.returncode == 0, file_preview.stdout[-8000:]
    variables["crowdsec_expected_configuration_digest"] = file_preview.stdout.split(marker)[1].split('"')[0].strip()
    variables["crowdsec_policy_preview"] = False
    file_mode = apply()
    assert file_mode.returncode == 0, file_mode.stdout[-10000:]
    before_failed_engine = docker(
        "exec", target, "systemctl", "show", "crowdsec", "--property=MainPID", "--value"
    ).stdout.strip()
    variables["crowdsec_simulation"] = True
    variables["crowdsec_expected_configuration_digest"] = ""
    variables["crowdsec_package_cache"] = "/work/missing-package-cache"
    interrupted_transition = apply()
    assert interrupted_transition.returncode != 0
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer", check=False).returncode != 0
    interrupted_config = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    degraded_request = {
        "protocol": 1,
        "request_id": "5677bcca-c5a6-4afd-937f-d78817e76ad2",
        "installation_id": interrupted_config["installation_id"],
        "configuration_digest": interrupted_config["configuration_digest"],
        "operation": "health",
        "payload": {},
    }
    degraded_health = docker(
        "exec", "-i", target, "/usr/local/libexec/praho-crowdsec-gateway", input_text=json.dumps(degraded_request)
    )
    assert json.loads(degraded_health.stdout)["result"]["configuration"]["qualified"] is False
    degraded_request.update(operation="snapshot", payload={"after_alert_id": 0})
    assert (
        docker(
            "exec",
            "-i",
            target,
            "/usr/local/libexec/praho-crowdsec-gateway",
            input_text=json.dumps(degraded_request),
            check=False,
        ).returncode
        != 0
    )
    variables["crowdsec_package_cache"] = "/work/packages"
    simulated = apply()
    assert simulated.returncode == 0, simulated.stdout[-15000:] + simulated.stderr[-1500:]
    assert "198.51.100.77" not in docker("exec", target, "nft", "list", "set", "ip", "praho_crowdsec4", "bans").stdout
    assert docker("exec", target, "cscli", "decisions", "add", "--ip", "198.51.100.77", check=False).returncode != 0
    docker("exec", target, "cscli", "decisions", "delete", "--ip", "198.51.100.77")
    assert (
        json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)["installation_id"]
        == first["installation_id"]
    )

    timestamp = docker("exec", target, "date", "+%b %e %H:%M:%S").stdout.strip()
    restored_attack = "".join(
        f"{timestamp} node sshd[{10000 + index}]: Failed password for invalid user fixture-restored from 198.51.100.88 port 5555 ssh2\n"
        for index in range(12)
    )
    docker("exec", "-i", target, "tee", "-a", "/var/log/auth.log", input_text=restored_attack)
    fresh_alerts = _wait_for_alerts(target, "198.51.100.88")
    after_repair_engine = docker(
        "exec", target, "systemctl", "show", "crowdsec", "--property=MainPID", "--value"
    ).stdout.strip()
    assert fresh_alerts and all(row == [1] for row in fresh_alerts), (
        f"repaired simulation still used old runtime: enginePID {before_failed_engine}->{after_repair_engine}, alerts={fresh_alerts}"
    )
    assert after_repair_engine != before_failed_engine

    # Crash after B successfully starts but before it receives an applied stamp.
    # Then an A rollback fails after restoring files, so the A retry sees no file
    # changes. Its missing stamp must still force the B runtime back to A.
    task_path = "/work/roles/crowdsec/tasks/install.yml"
    original_tasks = docker("exec", target, "cat", task_path).stdout
    tasks = yaml.safe_load(original_tasks)
    stamp_index = next(
        index
        for index, task in enumerate(tasks)
        if task.get("name") == "Record the successfully applied engine configuration"
    )
    tasks.insert(
        stamp_index,
        {
            "name": "Fixture interruption after runtime restart",
            "ansible.builtin.fail": {"msg": "fixture interruption before applied stamp"},
        },
    )
    docker("exec", "-i", target, "tee", task_path, input_text=yaml.safe_dump(tasks))
    variables["crowdsec_ssh_acquisition"] = "journalctl"
    variables["crowdsec_simulation"] = False
    variables["crowdsec_policy_preview"] = True
    rollback_preview = apply()
    assert rollback_preview.returncode == 0, rollback_preview.stdout[-8000:]
    variables["crowdsec_expected_configuration_digest"] = rollback_preview.stdout.split(marker)[1].split('"')[0].strip()
    variables["crowdsec_policy_preview"] = False
    try:
        interrupted_restart = apply()
        assert (
            interrupted_restart.returncode != 0
            and "fixture interruption before applied stamp" in interrupted_restart.stdout
        )
        assert (
            docker(
                "exec", target, "test", "-e", "/var/lib/praho-crowdsec/engine-applied.sha256", check=False
            ).returncode
            != 0
        )
    finally:
        docker("exec", "-i", target, "tee", task_path, input_text=original_tasks)
    running_b = docker("exec", target, "systemctl", "show", "crowdsec", "--property=MainPID", "--value").stdout.strip()
    variables["crowdsec_ssh_acquisition"] = "file"
    variables["crowdsec_simulation"] = True
    variables["crowdsec_expected_configuration_digest"] = ""
    variables["crowdsec_package_cache"] = "/work/missing-package-cache"
    interrupted_rollback = apply()
    assert interrupted_rollback.returncode != 0
    assert (
        docker("exec", target, "systemctl", "show", "crowdsec", "--property=MainPID", "--value").stdout.strip()
        == running_b
    )
    variables["crowdsec_package_cache"] = "/work/packages"
    repaired_rollback = apply()
    assert repaired_rollback.returncode == 0, repaired_rollback.stdout[-10000:]
    assert (
        docker("exec", target, "systemctl", "show", "crowdsec", "--property=MainPID", "--value").stdout.strip()
        != running_b
    )
    final_config = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    for service in ("engine", "bouncer"):
        assert (
            docker("exec", target, "cat", f"/var/lib/praho-crowdsec/{service}-applied.sha256").stdout
            == final_config["configuration_digest"] + "\n"
        )
    assert_native_role_profile(target, expected_configuration_digest=final_config["configuration_digest"])
