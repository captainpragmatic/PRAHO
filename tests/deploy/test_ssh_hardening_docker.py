"""Real Ubuntu/systemd/sshd cutovers, isolated inside disposable containers."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKER = shutil.which("docker") or "docker"
pytestmark = pytest.mark.docker


def docker(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- Docker args are fixed test setup or the generated container ID
        [DOCKER, *args], input=input_text, capture_output=True, text=True, check=check, timeout=300
    )


@pytest.fixture(params=["24.04", "26.04"])
def ssh_target(request: pytest.FixtureRequest) -> Iterator[str]:
    version = str(request.param)
    image = f"praho-ssh-test:{version}"
    built = docker("build", "--build-arg", f"UBUNTU_VERSION={version}", "-t", image,
                   "-f", str(ROOT / "tests/deploy/ssh/Dockerfile"), str(ROOT / "tests/deploy/ssh"), check=False)
    assert built.returncode == 0, built.stderr[-4000:]
    container = docker("run", "-d", "--privileged", "--cgroupns=private", "--tmpfs", "/run",
                       "--tmpfs", "/run/lock", image).stdout.strip()
    try:
        docker("cp", str(ROOT / "deploy/ansible"), f"{container}:/work")
        docker("exec", container, "systemctl", "is-system-running", "--wait", check=False)
        docker("exec", container, "mkdir", "-p", "/root/.ssh")
        for name in ("controller", "operator", "disabled"):
            docker("exec", container, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"/root/{name}")
        public = docker("exec", container, "cat", "/root/controller.pub").stdout
        docker("exec", "-i", container, "tee", "/root/.ssh/authorized_keys", input_text=public)
        docker("exec", container, "chmod", "700", "/root/.ssh")
        docker("exec", container, "chmod", "600", "/root/.ssh/authorized_keys")
        disabled = docker("exec", container, "cat", "/root/disabled.pub").stdout
        docker("exec", "-i", container, "tee", "/root/.ssh/authorized_keys2", input_text=disabled)
        docker("exec", "-i", container, "tee", "-a", "/etc/ssh/sshd_config", input_text="\nAuthorizedKeysFile .ssh/authorized_keys\n")
        docker("exec", container, "systemctl", "restart", "ssh.socket", "ssh.service")
        host_key = docker("exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout
        docker("exec", "-i", container, "tee", "/root/known_hosts", input_text="127.0.0.1 " + host_key)
        docker("exec", container, "useradd", "--create-home", "--shell", "/bin/bash", "ssh-test-user")
        docker("exec", "-i", container, "chpasswd", input_text=f"root:{secrets.token_urlsafe(24)}\nssh-test-user:{secrets.token_urlsafe(24)}\n")
        inventory = {"all": {"children": {"praho": {"hosts": {"target": {
            "ansible_host": "127.0.0.1", "ansible_user": "root", "ansible_port": 22,
            "ansible_ssh_private_key_file": "/root/controller",
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=yes -o HostKeyAlias=127.0.0.1 -o UserKnownHostsFile=/root/known_hosts",
        }}}}}}
        docker("exec", "-i", container, "tee", "/work/test-inventory.json", input_text=json.dumps(inventory))
        yield container
    finally:
        docker("rm", "-f", container)


def harden(
    container: str, port: int = 22, extra: dict[str, str | int] | None = None, sources: str = "127.0.0.1/32"
) -> subprocess.CompletedProcess[str]:
    # Host vars are changed rather than extra-vars, so set_fact can perform the handoff.
    docker("exec", container, "/opt/controller/bin/python", "-c",
           "import json; p='/work/test-inventory.json'; v=json.load(open(p)); "
           f"v['all']['children']['praho']['hosts']['target']['ansible_port']={port}; "
           "open(p,'w').write(json.dumps(v))")
    docker("exec", "-i", container, "tee", "/work/test-vars.json", input_text=json.dumps(extra or {}))
    return docker("exec", "-w", "/work", "-e", "PRAHO_SSH_PUBLIC_KEYS_FILE=/root/operator.pub",
                  "-e", "PRAHO_DEPLOY_KNOWN_HOSTS_FILE=/root/known_hosts",
                  "-e", f"PRAHO_SSH_ALLOWED_CIDRS={sources}", container,
                  "/opt/controller/bin/ansible-playbook", "-i", "test-inventory.json", "-e", "@/work/test-vars.json",
                  "playbooks/ssh-hardening.yml", check=False)


def ssh(container: str, port: int, key: str = "controller", user: str = "root") -> subprocess.CompletedProcess[str]:
    return docker("exec", container, "ssh", "-F", "/dev/null", "-p", str(port), "-o", "BatchMode=yes",
                  "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/root/known_hosts",
                  "-o", "HostKeyAlias=127.0.0.1", "-o", "IdentitiesOnly=yes",
                  "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=3",
                  "-i", f"/root/{key}", f"{user}@127.0.0.1", "id -u", check=False)


def test_socket_cutover_rejection_and_repeat(ssh_target: str) -> None:
    container = ssh_target
    original = docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout
    restriction = "/etc/ssh/sshd_config.d/90-custom.conf"
    docker("exec", "-i", container, "tee", restriction, input_text="Match User ssh-test-user\n    ForceCommand internal-sftp\n")
    rejected = harden(container)
    assert rejected.returncode != 0
    assert "custom SSH policy" in rejected.stdout, rejected.stdout[-4000:]
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original
    assert ssh(container, 22).stdout.strip() == "0"
    docker("exec", container, "rm", restriction)

    # A provider/host firewall that blocks the target port must leave SSH untouched.
    rule = ["INPUT", "-p", "tcp", "--dport", "9876", "-j", "REJECT"]
    docker("exec", container, "iptables", "-I", *rule)
    blocked = harden(container)
    assert blocked.returncode != 0
    assert "Require the exact probe" in blocked.stdout, blocked.stdout[-4000:]
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original
    assert ssh(container, 22).stdout.strip() == "0"
    docker("exec", container, "iptables", "-D", *rule)
    # The bounded preflight listener exits after 20s even if its controller failed.
    docker("exec", container, "timeout", "25", "sh", "-c", "while ss -lnt 'sport = :9876' | grep -q LISTEN; do sleep 1; done")

    # Fail after the dual listener is active, so this exercises actual rollback.
    failed_handoff = harden(container, extra={
        "ssh_probe_identity_file": "{{ '/root/controller' if ssh_proof_port | int == 22 else '/root/disabled' }}",
    })
    assert failed_handoff.returncode != 0
    assert "Restore the last verified configuration" in failed_handoff.stdout
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original
    assert ssh(container, 22).stdout.strip() == "0"
    assert ssh(container, 9876).returncode != 0

    result = harden(container)
    assert result.returncode == 0, result.stdout[-7000:] + result.stderr[-1000:]
    for key in ("controller", "operator"):
        assert ssh(container, 9876, key).stdout.strip() == "0"
    assert ssh(container, 9876, "disabled").returncode != 0
    assert ssh(container, 22).returncode != 0
    for user in ("root", "ssh-test-user"):
        policy = docker("exec", container, "sshd", "-T", "-C", f"user={user},host=localhost,addr=127.0.0.1").stdout.splitlines()
        assert "authenticationmethods publickey" in policy
        assert "passwordauthentication no" in policy
        assert "kbdinteractiveauthentication no" in policy
    keys_before = docker("exec", container, "cat", "/root/.ssh/authorized_keys").stdout
    again = harden(container, 9876)
    assert again.returncode == 0, again.stdout[-7000:] + again.stderr[-1000:]
    assert docker("exec", container, "cat", "/root/.ssh/authorized_keys").stdout == keys_before
    assert ssh(container, 9876).stdout.strip() == "0"
    assert ssh(container, 22).returncode != 0


def test_ssh_is_admitted_only_from_the_allowlist(ssh_target: str) -> None:
    container = ssh_target
    original = docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout
    unset = harden(container, sources="")
    assert unset.returncode != 0
    assert "Set PRAHO_SSH_ALLOWED_CIDRS" in unset.stdout, unset.stdout[-4000:]
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original
    world = harden(container, sources="127.0.0.1/32 0.0.0.0/0.0.0.0")
    assert world.returncode != 0
    assert "Refuse an SSH allowlist that admits the whole Internet" in world.stdout, world.stdout[-4000:]
    outside = harden(container, sources="192.0.2.0/24")
    assert outside.returncode != 0
    assert "Verify controller is within the SSH source allowlist" in outside.stdout, outside.stdout[-4000:]
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original

    assert harden(container).returncode == 0
    # A server an earlier deploy left open to everyone, as every deploy did before the allowlist was fed.
    docker("exec", container, "ufw", "allow", "9876/tcp")
    docker("exec", container, "ufw", "allow", "9876")
    added = docker("exec", container, "ufw", "show", "added").stdout
    assert "ufw allow 9876/tcp" in added
    assert "ufw allow 9876\n" in added
    again = harden(container, 9876, sources="127.0.0.1/32 198.51.100.7/32")
    assert again.returncode == 0, again.stdout[-7000:] + again.stderr[-1000:]
    rules = [line for line in docker("exec", container, "ufw", "show", "added").stdout.splitlines() if "9876" in line]
    assert sorted(rules) == [
        "ufw allow from 127.0.0.1 to any port 9876 proto tcp",
        "ufw allow from 198.51.100.7 to any port 9876 proto tcp",
    ]
    assert ssh(container, 9876).stdout.strip() == "0"

    # Dropping a source from the list revokes its rule on the next run.
    shrunk = harden(container, 9876)
    assert shrunk.returncode == 0, shrunk.stdout[-7000:] + shrunk.stderr[-1000:]
    rules = [line for line in docker("exec", container, "ufw", "show", "added").stdout.splitlines() if "9876" in line]
    assert rules == ["ufw allow from 127.0.0.1 to any port 9876 proto tcp"]
    assert ssh(container, 9876).stdout.strip() == "0"


@pytest.mark.parametrize("before_activation", [False, True])
def test_rollback_timer_recovers_a_delayed_controller(ssh_target: str, before_activation: bool) -> None:
    container = ssh_target
    phase = ROOT / "deploy/ansible/roles/ssh-hardening/tasks/phase.yml"
    tasks = yaml.safe_load(phase.read_text())
    activation = next(index for index, task in enumerate(tasks) if task["name"].startswith("Activate staged"))
    # Start the exact transient rollback service synchronously, avoiding timer jitter.
    # In the before case the stale Ansible run then resumes its original activation task.
    tasks.insert(activation if before_activation else activation + 1, {
        "name": "Simulate rollback firing while controller is stalled",
        "ansible.builtin.command": {"argv": ["systemctl", "start", "praho-ssh-{{ ssh_snapshot.path | basename }}.service"]},
    })
    docker("exec", "-i", container, "tee", "/work/roles/ssh-hardening/tasks/phase.yml", input_text=yaml.safe_dump(tasks))
    original = docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout
    result = harden(container, extra={"ssh_rollback_seconds": 60})
    assert result.returncode != 0
    assert "Simulate rollback firing" in result.stdout, result.stdout[-6000:]
    if before_activation:
        assert "refusing activation" in result.stdout, result.stdout[-6000:]
    assert docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout == original
    assert ssh(container, 22).stdout.strip() == "0"
    assert ssh(container, 9876).returncode != 0
    states = docker("exec", container, "sh", "-c", "cat /var/lib/praho-ssh/rollback-*/state").stdout
    assert "rolled-back" in states


def test_application_python_and_postgresql_on_supported_ubuntu(ssh_target: str) -> None:
    container = ssh_target
    # A freshly cleaned image can retain a recent APT timestamp with no indexes.
    # Keep that state deterministic even when the local Docker image is old.
    docker("exec", container, "test", "-d", "/var/lib/apt/lists")
    docker("exec", container, "find", "/var/lib/apt/lists", "-mindepth", "1", "-delete")
    assert not docker("exec", container, "find", "/var/lib/apt/lists", "-mindepth", "1", "-print").stdout.strip()
    docker("exec", container, "mkdir", "-p", "/var/lib/apt/periodic")
    docker("exec", container, "touch", "/var/lib/apt/lists", "/var/lib/apt/periodic/update-success-stamp")
    native = ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml"
    package_names = {
        "Create keyrings directory", "Download PostgreSQL GPG key",
        "Add PostgreSQL APT repository", "Install PostgreSQL 16",
    }
    package_tasks = [task for task in yaml.safe_load(native.read_text()) if task.get("name") in package_names]
    assert len(package_tasks) == len(package_names)
    playbook = [{"hosts": "localhost", "connection": "local", "gather_facts": True,
                 "tasks": [{"ansible.builtin.include_role": {"name": "praho-native", "tasks_from": "runtime"}},
                           *package_tasks]}]
    docker("exec", "-i", container, "tee", "/work/runtime-test.yml", input_text=yaml.safe_dump(playbook))
    installed = docker("exec", "-w", "/work", container, "/opt/controller/bin/ansible-playbook",
                       "-i", "localhost,", "runtime-test.yml", check=False)
    assert installed.returncode == 0, installed.stdout[-7000:] + installed.stderr[-1500:]
    postgres = docker("exec", container, "/usr/lib/postgresql/16/bin/postgres", "--version")
    assert "PostgreSQL) 16." in postgres.stdout
    python = docker("exec", container, "/opt/praho-python/bin/python3.13", "--version")
    assert python.stdout.startswith("Python 3.13.")
    # The Portal's separate identity must read the base interpreter outside /root.
    portal = docker("exec", container, "runuser", "-u", "ssh-test-user", "--",
                    "/opt/praho-python/bin/python3.13", "-c", "import ssl, sqlite3; print('runtime-readable')")
    assert portal.stdout.strip() == "runtime-readable"


def test_swap_preparation_recovers_and_never_formats_existing_data(ssh_target: str) -> None:
    container = ssh_target
    script = "/work/roles/common/files/prepare-swap.sh"
    docker("exec", container, "mkdir", "-p", "/work/test-bin")
    # Overlayfs is deliberately unsupported. Stub that external filesystem query
    # to exercise allocation/format/recovery on disposable files, without swapon.
    fake_findmnt = "/work/test-bin/findmnt"
    docker("exec", "-i", container, "tee", fake_findmnt, input_text="#!/bin/sh\nprintf 'ext4\\n'\n")
    docker("exec", container, "chmod", "700", fake_findmnt)
    path = "/work/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def prepare() -> subprocess.CompletedProcess[str]:
        return docker("exec", "-e", f"PATH={path}", container, "bash", script, "32", check=False)

    docker("exec", "-i", container, "tee", "/work/victim", input_text="preserve me")
    docker("exec", container, "ln", "-s", "/work/victim", "/swapfile")
    assert prepare().returncode != 0
    assert docker("exec", container, "cat", "/work/victim").stdout == "preserve me"
    docker("exec", container, "rm", "/swapfile")
    docker("exec", "-i", container, "tee", "/swapfile", input_text="unrelated file")
    docker("exec", container, "chmod", "600", "/swapfile")
    assert prepare().returncode != 0
    assert docker("exec", container, "cat", "/swapfile").stdout == "unrelated file"
    docker("exec", container, "rm", "/swapfile")

    # Interrupted/failed formatting leaves one bounded file, which a retry resumes.
    docker("exec", "-i", container, "tee", "/work/test-bin/mkswap", input_text="#!/bin/sh\nexit 99\n")
    docker("exec", container, "chmod", "700", "/work/test-bin/mkswap")
    assert prepare().returncode == 99
    assert docker("exec", container, "stat", "-c", "%s", "/var/lib/praho-swap/pending").stdout.strip() == str(32 * 1024**2)
    assert docker("exec", container, "test", "-e", "/swapfile", check=False).returncode != 0
    docker("exec", container, "rm", "/work/test-bin/mkswap")
    created = prepare()
    assert created.returncode == 0, created.stderr
    assert created.stdout.strip() == "created"
    uuid = docker("exec", container, "blkid", "-p", "-s", "UUID", "-o", "value", "/swapfile").stdout
    repeated = prepare()
    assert repeated.returncode == 0 and repeated.stdout.strip() == "existing"
    assert docker("exec", container, "blkid", "-p", "-s", "UUID", "-o", "value", "/swapfile").stdout == uuid
    assert docker("exec", container, "test", "-e", "/var/lib/praho-swap/pending", check=False).returncode != 0

    # A failed kernel activation must not put a broken swap entry into fstab.
    fstab = docker("exec", container, "cat", "/etc/fstab").stdout
    docker("exec", "-i", container, "tee", "/work/test-bin/swapon", input_text=(
        '#!/bin/sh\nif [ "$1" = "--show=NAME" ]; then exit 0; fi\nexit 77\n'
    ))
    docker("exec", container, "chmod", "700", "/work/test-bin/swapon")
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars": {"swap_size_mb": 32}, "environment": {"PATH": path},
             "tasks": [{"ansible.builtin.include_role": {"name": "common", "tasks_from": "swap"}}]}]
    docker("exec", "-i", container, "tee", "/work/swap-test.yml", input_text=yaml.safe_dump(play))
    activation = docker("exec", "-w", "/work", container, "/opt/controller/bin/ansible-playbook",
                        "-i", "localhost,", "swap-test.yml", check=False)
    assert activation.returncode != 0
    assert "Activate the swap file before making it persistent" in activation.stdout
    assert docker("exec", container, "cat", "/etc/fstab").stdout == fstab


def test_swap_retry_counts_only_unallocated_bytes(ssh_target: str) -> None:
    container = ssh_target
    docker("exec", container, "mkdir", "-p", "/work/test-bin", "/var/lib/praho-swap")
    docker("exec", container, "chmod", "700", "/var/lib/praho-swap")
    docker("exec", "-i", container, "tee", "/work/test-bin/findmnt", input_text="#!/bin/sh\nprintf 'ext4\\n'\n")
    docker("exec", container, "chmod", "700", "/work/test-bin/findmnt")
    path = "/work/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    # Already allocated extents are reflected in df's remaining free bytes.
    # Sparse logical bytes must not receive credit for unallocated physical space.
    cases = ((16, 16, 1048, True), (32, 32, 1040, True), (0, 0, 1040, False), (16, 16, 1032, False), (0, 32, 1040, False))
    for allocated_mb, logical_mb, available_mb, succeeds in cases:
        docker("exec", container, "touch", "/var/lib/praho-swap/pending")
        docker("exec", container, "chmod", "600", "/var/lib/praho-swap/pending")
        if allocated_mb:
            docker("exec", container, "fallocate", "-l", str(allocated_mb * 1024**2), "/var/lib/praho-swap/pending")
        if logical_mb > allocated_mb:
            docker("exec", container, "truncate", "-s", str(logical_mb * 1024**2), "/var/lib/praho-swap/pending")
        docker("exec", "-i", container, "tee", "/work/test-bin/df", input_text=(
            f"#!/bin/sh\nprintf 'Avail\\n{available_mb * 1024**2}\\n'\n"
        ))
        docker("exec", container, "chmod", "700", "/work/test-bin/df")
        prepared = docker("exec", "-e", f"PATH={path}", container, "bash",
                          "/work/roles/common/files/prepare-swap.sh", "32", check=False)
        if succeeds:
            assert prepared.returncode == 0, prepared.stdout + prepared.stderr
            assert docker("exec", container, "stat", "-c", "%s", "/swapfile").stdout.strip() == str(32 * 1024**2)
            assert docker("exec", container, "blkid", "-p", "-s", "TYPE", "-o", "value", "/swapfile").stdout.strip() == "swap"
            docker("exec", container, "rm", "/swapfile")
        else:
            assert prepared.returncode != 0
            assert "leave at least 1 GiB free" in prepared.stderr
            assert docker("exec", container, "test", "-e", "/swapfile", check=False).returncode != 0
            assert docker("exec", container, "stat", "-c", "%s", "/var/lib/praho-swap/pending").stdout.strip() == str(logical_mb * 1024**2)
            docker("exec", container, "rm", "/var/lib/praho-swap/pending")
