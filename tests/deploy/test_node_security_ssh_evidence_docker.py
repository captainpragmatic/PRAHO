"""Native effective SSH evidence is bound to the reviewed restricted operator keys."""

from __future__ import annotations

import json

import pytest
from django.core.exceptions import ValidationError
from test_ssh_hardening_docker import ROOT, docker, harden, ssh_target

from apps.provisioning.virtualmin_security_policy import verify_ssh_policy

__all__ = ["ssh_target"]
pytestmark = pytest.mark.docker


def test_native_ssh_evidence_requires_effective_auth_and_exact_restricted_keys(ssh_target: str) -> None:
    container = ssh_target
    docker(
        "exec",
        container,
        "python3",
        "-c",
        "from pathlib import Path; p=Path('/etc/ssh/sshd_config'); p.write_text(p.read_text().replace('AuthorizedKeysFile .ssh/authorized_keys'+chr(10), 'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2'+chr(10)))",
    )
    applied = harden(container, extra={"ssh_webmin_tunnel_enabled": True})
    assert applied.returncode == 0, applied.stdout[-6000:] + applied.stderr[-1000:]
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"
    docker("cp", str(source), container + ":/root/inspect-security.py")
    expected = docker("exec", container, "ssh-keygen", "-lf", "/root/operator.pub", "-E", "sha256").stdout.split()[1]
    program = (
        "import importlib.util,json; spec=importlib.util.spec_from_file_location('node_inspector','/root/inspect-security.py'); "
        "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); print(json.dumps(module.inspect_ssh()))"
    )

    def inspect():
        result = docker(
            "exec", "-e", "SSH_CONNECTION=127.0.0.1 50000 127.0.0.1 9876", container, "python3", "-c", program
        )
        return json.loads(result.stdout)

    files = ("/etc/ssh/sshd_config", "/home/praho-webmin-tunnel/.ssh/authorized_keys")
    before = docker("exec", container, "sha256sum", *files).stdout
    evidence = inspect()
    tunnel = next(json.loads(row.split(" ", 1)[1]) for row in evidence if row.startswith("PRAHO_SSH_TUNNEL "))
    assert tunnel["authorizedkeysfile"] == [".ssh/authorized_keys .ssh/authorized_keys2"]
    verify_ssh_policy(evidence, [expected])
    assert docker("exec", container, "sha256sum", *files).stdout == before
    public = docker("exec", container, "cat", "/root/operator.pub").stdout.split()[1]
    assert public not in json.dumps(evidence), "raw public key material escaped the bounded projection"

    # A root-only Match override must be checked in its own context, not hidden by global sshd -T.
    original = docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout
    docker(
        "exec",
        "-i",
        container,
        "tee",
        "-a",
        "/etc/ssh/sshd_config",
        input_text="\nMatch User root\n    AllowTcpForwarding yes\n",
    )
    with pytest.raises(ValidationError):
        verify_ssh_policy(inspect(), [expected])
    docker("exec", "-i", container, "tee", "/etc/ssh/sshd_config", input_text=original)

    # Another peer's Match block leaves this controller's -T contexts unchanged.
    docker(
        "exec",
        "-i",
        container,
        "tee",
        "-a",
        "/etc/ssh/sshd_config",
        input_text="\nMatch Address 198.51.100.1\n    PasswordAuthentication yes\n",
    )
    with pytest.raises(ValidationError):
        verify_ssh_policy(inspect(), [expected])
    docker("exec", "-i", container, "tee", "/etc/ssh/sshd_config", input_text=original)

    # The secondary configured key file is authoritative too, even with the approved primary intact.
    operator_key = docker("exec", container, "cat", "/root/operator.pub").stdout
    docker("exec", "-i", container, "tee", "/home/praho-webmin-tunnel/.ssh/authorized_keys2", input_text=operator_key)
    with pytest.raises(ValidationError):
        verify_ssh_policy(inspect(), [expected])
    docker("exec", container, "rm", "/home/praho-webmin-tunnel/.ssh/authorized_keys2")
    verify_ssh_policy(inspect(), [expected])

    # Startup overrides are rejected without exposing arbitrary environment/command material.
    docker("exec", container, "mkdir", "-p", "/run/systemd/system/ssh.service.d")
    docker(
        "exec",
        "-i",
        container,
        "tee",
        "/run/systemd/system/ssh.service.d/99-unreviewed.conf",
        input_text="[Service]\nEnvironment=UNREVIEWED_TOKEN=PRIVATE_STARTUP_VALUE\n",
    )
    docker("exec", container, "systemctl", "daemon-reload")
    unreviewed = inspect()
    assert 'PRAHO_SSH_STARTUP {"canonical":false}' in unreviewed
    assert "PRIVATE_STARTUP_VALUE" not in json.dumps(unreviewed)
    with pytest.raises(ValidationError):
        verify_ssh_policy(unreviewed, [expected])
