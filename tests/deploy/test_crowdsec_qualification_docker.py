"""The optional profile observes effective SSH restrictions on real native hosts."""

from __future__ import annotations

import hashlib
import json

import pytest
from django.core.exceptions import ValidationError
from test_ssh_hardening_docker import ROOT, docker, harden, ssh_target

from apps.provisioning.crowdsec_policy import CROWDSEC_PROFILE, verify_configuration, verify_owned_firewall
from apps.provisioning.virtualmin_security_policy import verify_ssh_policy

__all__ = ["ssh_target"]
pytestmark = pytest.mark.docker


def test_gateway_qualification_requires_exact_principal_key_and_effective_force_command(ssh_target: str) -> None:
    container = ssh_target
    docker("exec", container, "useradd", "--create-home", "--shell", "/bin/sh", "praho-crowdsec")
    docker("exec", container, "chown", "root:root", "/home/praho-crowdsec")
    docker("exec", container, "mkdir", "-p", "/home/praho-crowdsec/.ssh")
    public = docker("exec", container, "cat", "/root/controller.pub").stdout
    key_path = "/home/praho-crowdsec/.ssh/authorized_keys"
    docker("exec", "-i", container, "tee", key_path, input_text="restrict " + public)
    docker("exec", container, "chmod", "600", key_path)
    applied = harden(container, extra={"ssh_webmin_tunnel_enabled": True, "ssh_crowdsec_gateway_enabled": True})
    assert applied.returncode == 0, applied.stdout[-6000:] + applied.stderr[-1000:]
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"
    docker("cp", str(source), container + ":/root/inspect-security.py")
    expected_operator = docker(
        "exec", container, "ssh-keygen", "-lf", "/root/operator.pub", "-E", "sha256"
    ).stdout.split()[1]
    expected_gateway = docker(
        "exec", container, "ssh-keygen", "-lf", "/root/controller.pub", "-E", "sha256"
    ).stdout.split()[1]
    program = (
        "import importlib.util,json; spec=importlib.util.spec_from_file_location('node_inspector','/root/inspect-security.py'); "
        "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
        "print(json.dumps(module.inspect_ssh(module.CROWDSEC_PROFILE)))"
    )

    def inspect() -> list[str]:
        observed = docker(
            "exec", "-e", "SSH_CONNECTION=127.0.0.1 50000 127.0.0.1 9876", container, "python3", "-c", program
        )
        return json.loads(observed.stdout)

    def qualify(rows: list[str]) -> None:
        verify_ssh_policy(
            rows, [expected_operator], policy_version=CROWDSEC_PROFILE, expected_gateway_fingerprint=expected_gateway
        )

    before = docker("exec", container, "sha256sum", key_path, "/etc/ssh/sshd_config").stdout
    evidence = inspect()
    qualify(evidence)
    assert docker("exec", container, "sha256sum", key_path, "/etc/ssh/sshd_config").stdout == before
    assert public.split()[1] not in json.dumps(evidence)
    with pytest.raises(ValidationError):
        verify_ssh_policy(evidence, [expected_operator])

    docker("exec", "-i", container, "tee", key_path, input_text=public)
    with pytest.raises(ValidationError):
        qualify(inspect())
    docker("exec", "-i", container, "tee", key_path, input_text="restrict " + public)
    docker("exec", container, "usermod", "--shell", "/usr/sbin/nologin", "praho-crowdsec")
    with pytest.raises(ValidationError):
        qualify(inspect())
    docker("exec", container, "usermod", "--shell", "/bin/sh", "praho-crowdsec")
    qualify(inspect())

    docker("exec", container, "chown", "praho-crowdsec", key_path)
    with pytest.raises(ValidationError):
        qualify(inspect())
    docker("exec", container, "chown", "root:root", key_path)
    original = docker("exec", container, "cat", "/etc/ssh/sshd_config").stdout
    docker(
        "exec",
        "-i",
        container,
        "tee",
        "/etc/ssh/sshd_config",
        input_text=original.replace("DisableForwarding yes", "DisableForwarding no"),
    )
    with pytest.raises(ValidationError):
        qualify(inspect())
    docker("exec", "-i", container, "tee", "/etc/ssh/sshd_config", input_text=original)
    qualify(inspect())


def assert_native_role_profile(container: str, expected_configuration_digest: str | None = None) -> None:
    """Reuse the real role fixture to prove configuration and firewall evidence without a Virtualmin rebuild."""
    inspector_source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"
    helper_source = ROOT / "deploy/ansible/roles/crowdsec/files/gateway.py"
    lock_source = ROOT / "deploy/crowdsec/artifacts.lock.json"
    helper_digest = hashlib.sha256(helper_source.read_bytes()).hexdigest()
    lock_digest = hashlib.sha256(lock_source.read_bytes()).hexdigest()
    docker("cp", str(inspector_source), container + ":/root/inspect-crowdsec.py")
    configuration = json.loads(docker("exec", container, "cat", "/etc/praho-crowdsec/config.json").stdout)
    expected = expected_configuration_digest or configuration["configuration_digest"]
    program = (
        "import importlib.util,json,sys; spec=importlib.util.spec_from_file_location('inspector','/root/inspect-crowdsec.py'); "
        "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
        "print(json.dumps({'services':module.inspect_crowdsec(sys.argv[1],sys.argv[2]),'firewall':module.inspect_firewall(module.CROWDSEC_PROFILE)}))"
    )

    def facts() -> tuple[list[str], list[dict[str, object]]]:
        result = json.loads(docker("exec", container, "python3", "-c", program, helper_digest, lock_digest).stdout)
        owned = [
            json.loads(row.removeprefix("PRAHO_CROWDSEC_NFT "))
            for row in result["firewall"]
            if row.startswith("PRAHO_CROWDSEC_NFT ")
        ]
        return result["services"], owned

    services, owned = facts()
    protected = verify_configuration(services, expected, ["127.0.0.1/32", "::1/128"])
    verify_owned_firewall(owned, protected)
    assert len(owned) == 12, "The native projection must include every owned table, chain, set and rule"
    if not configuration["simulation"]:
        # The enforcement set changes independently of the attested policy.
        docker(
            "exec",
            "-i",
            container,
            "nft",
            "-f",
            "-",
            input_text="add element ip praho_crowdsec4 bans { 203.0.113.222 timeout 1m }\n",
        )
        try:
            later_services, later_owned = facts()
            assert later_owned == owned
            assert later_services == services
        finally:
            docker(
                "exec",
                "-i",
                container,
                "nft",
                "-f",
                "-",
                input_text="delete element ip praho_crowdsec4 bans { 203.0.113.222 }\n",
                check=False,
            )
    docker(
        "exec",
        "-i",
        container,
        "nft",
        "-f",
        "-",
        input_text="add element ip praho_crowdsec4 protected { 203.0.113.223 }\n",
    )
    try:
        _, changed = facts()
        with pytest.raises(ValidationError):
            verify_owned_firewall(changed, protected)
    finally:
        docker(
            "exec",
            "-i",
            container,
            "nft",
            "-f",
            "-",
            input_text="delete element ip praho_crowdsec4 protected { 203.0.113.223 }\n",
        )
