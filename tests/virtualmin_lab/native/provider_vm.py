#!/usr/bin/env python3
"""Disposable Ubuntu VM owner. No Docker kernel substitutes and no fleet targets.

Create/run/destroy accept one private manifest. Provider labels and exact IDs are
rechecked before SSH, reboot or cleanup; uncertain creation leaves the manifest.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any
from uuid import UUID, uuid4

OWNER = "praho-quota-776"
ROOT = Path(__file__).resolve().parents[3]
MAX_MANIFEST = 65536
SSH_DEADLINE = 300


def read_manifest(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
        or info.st_size > MAX_MANIFEST
    ):
        raise ValueError("An exact private bounded native VM manifest is required")
    value = json.loads(path.read_text())
    if (
        value.get("schema") != 1
        or value.get("owner") != OWNER
        or value.get("provider") != "hetzner"
        or str(UUID(value.get("run", ""))) != value["run"]
        or datetime.fromisoformat(value["expires_at"]).tzinfo is None
    ):
        raise ValueError("Manifest is not owned by the disposable quota lab")
    for key in ("server_id", "ssh_key_id", "firewall_id"):
        if value.get(key) is not None and (type(value[key]) is not int or value[key] <= 0):
            raise ValueError("Manifest resource identities must be exact")
    if value.get("ipv4") is not None:
        ipaddress.IPv4Address(value["ipv4"])
    return value


def owned_resource(manifest: dict[str, Any], labels: dict[str, str]) -> bool:
    return labels.get("praho-native-run") == manifest["run"] and labels.get("praho-native-owner") == OWNER


def validate_fresh_deployment_proof(_manifest: dict[str, Any]) -> None:
    """Manifest fields are resource hints, never evidence that a workflow ran."""
    raise ValueError(
        "Manifest self-attestation cannot certify a fresh deployment. "
        "The real NodeDeploymentService.deploy_node producer and database/runtime verification are required."
    )


def fresh_deployment_proof(path: Path) -> None:
    manifest, _server = owned_server(path)
    validate_fresh_deployment_proof(manifest)


def admin_cidr(value: str) -> str:
    network = ipaddress.ip_network(value, strict=True)
    if network.prefixlen == 0 or network.num_addresses > 256:
        raise ValueError("An explicit narrow operator CIDR is required; world-open SSH is refused")
    return str(network)


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".native-vm-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(manifest, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def client() -> Any:
    from hcloud import Client  # noqa: PLC0415 -- provider dependency only for explicit native actions

    token = os.environ.get("HCLOUD_TOKEN")
    if not token:
        raise ValueError("HCLOUD_TOKEN must reference the approved disposable lab project")
    result = Client(token=token, timeout=20)
    result._client._retry_max_retries = 0
    return result


def paths(path: Path, manifest: dict[str, Any]) -> tuple[Path, Path]:
    return path.parent / (manifest["run"] + ".key"), path.parent / (manifest["run"] + ".known_hosts")


def fresh_intent(path: Path) -> None:
    """Create private local authority before the public Platform deployment owns any VM."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    if path.exists() or path.is_symlink():
        raise ValueError("Manifest already exists; retain its original authority and reconcile it first")
    cidr = admin_cidr(os.environ.get("PRAHO_NATIVE_ADMIN_CIDR", ""))
    location, size = os.environ.get("PRAHO_NATIVE_LOCATION"), os.environ.get("PRAHO_NATIVE_SERVER_TYPE")
    if not location or not size:
        raise ValueError("Set the approved disposable location and server type explicitly")
    manifest = {
        "schema": 1,
        "owner": OWNER,
        "provider": "hetzner",
        "origin": "platform_fresh",
        "run": str(uuid4()),
        "phase": "fresh-intent",
        "expires_at": (datetime.now(UTC) + timedelta(hours=6)).isoformat(),
        "server_id": None,
        "ssh_key_id": None,
        "firewall_id": None,
        "ipv4": None,
        "ssh_port": 22,
        "host_public_key": None,
        "admin_cidr": cidr,
        "location": location,
        "server_type": size,
    }
    write_manifest(path, manifest)
    key_path, trust_path = paths(path, manifest)
    private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    for target, contents in ((key_path, private_key), (trust_path, b"")):
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
    print("Private fresh-deployment intent recorded; no provider resource has been created")


def create(path: Path) -> None:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    from hcloud.firewalls.domain import FirewallRule  # noqa: PLC0415
    from hcloud.images.domain import Image  # noqa: PLC0415
    from hcloud.locations.domain import Location  # noqa: PLC0415
    from hcloud.server_types.domain import ServerType  # noqa: PLC0415

    if path.exists():
        raise ValueError("Manifest already exists; inspect or destroy its exact resources first")
    cidr = admin_cidr(os.environ.get("PRAHO_NATIVE_ADMIN_CIDR", ""))
    location, size = os.environ.get("PRAHO_NATIVE_LOCATION"), os.environ.get("PRAHO_NATIVE_SERVER_TYPE")
    if not location or not size:
        raise ValueError("Set the approved disposable location and server type explicitly")
    cloud = client()
    manifest = {
        "schema": 1,
        "owner": OWNER,
        "provider": "hetzner",
        "run": str(uuid4()),
        "phase": "creating",
        "expires_at": (datetime.now(UTC) + timedelta(hours=6)).isoformat(),
        "server_id": None,
        "ssh_key_id": None,
        "firewall_id": None,
        "ipv4": None,
        "ssh_port": 22,
        "admin_cidr": cidr,
    }
    write_manifest(path, manifest)
    labels = {"praho-native-run": manifest["run"], "praho-native-owner": OWNER}
    key_path, trust_path = paths(path, manifest)
    key, host_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    def private(item: Any) -> str:
        return item.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        ).decode()

    def public(item: Any) -> str:
        return (
            item.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        )

    key_path.write_text(private(key))
    key_path.chmod(0o600)
    manifest["host_public_key"] = public(host_key)
    write_manifest(path, manifest)
    ssh_key = cloud.ssh_keys.create(name="quota-lab-" + manifest["run"], public_key=public(key), labels=labels)
    manifest["ssh_key_id"] = ssh_key.id
    write_manifest(path, manifest)
    firewall = cloud.firewalls.create(
        name="quota-lab-" + manifest["run"],
        labels=labels,
        rules=[
            FirewallRule(direction="in", protocol="tcp", port="22", source_ips=[cidr]),
            FirewallRule(direction="in", protocol="tcp", port="9876", source_ips=[cidr]),
        ],
    ).firewall
    manifest["firewall_id"] = firewall.id
    write_manifest(path, manifest)
    userdata = "#cloud-config\n" + json.dumps(
        {
            "ssh_pwauth": False,
            "disable_root": False,
            "ssh_deletekeys": False,
            "ssh_authorized_keys": [public(key)],
            "ssh_keys": {"ed25519_private": private(host_key), "ed25519_public": public(host_key)},
        }
    )
    response = cloud.servers.create(
        name="quota-lab-" + manifest["run"],
        server_type=ServerType(name=size),
        image=Image(name="ubuntu-26.04"),
        location=Location(name=location),
        ssh_keys=[ssh_key],
        firewalls=[firewall],
        labels=labels,
        user_data=userdata,
    )
    manifest["server_id"], manifest["ipv4"], manifest["phase"] = (
        response.server.id,
        response.server.public_net.ipv4.ip,
        "created",
    )
    write_manifest(path, manifest)
    trust_path.write_text(
        manifest["ipv4"]
        + " "
        + manifest["host_public_key"]
        + "\n["
        + manifest["ipv4"]
        + "]:9876 "
        + manifest["host_public_key"]
        + "\n"
    )
    trust_path.chmod(0o600)
    # API credentials and generated private keys never enter stdout.
    print("Owned disposable Ubuntu 26.04 VM recorded in the private manifest")


def owned_server(path: Path, *, allow_expired: bool = False) -> tuple[dict[str, Any], Any]:
    manifest = read_manifest(path)
    if not allow_expired and datetime.now(UTC) >= datetime.fromisoformat(manifest["expires_at"]):
        raise ValueError("Native VM run has expired; only exact cleanup is allowed")
    if manifest.get("server_id") is None:
        raise ValueError("Creation is uncertain; reconcile labeled provider inventory before SSH or cleanup")
    server = client().servers.get_by_id(manifest["server_id"])
    if server is None or not owned_resource(manifest, server.labels) or server.public_net.ipv4.ip != manifest["ipv4"]:
        raise ValueError("Provider resource no longer matches the private manifest")
    return manifest, server


def ssh(path: Path, *, timeout: int = SSH_DEADLINE) -> Any:
    import paramiko  # noqa: PLC0415 -- exact enrolled SSH boundary

    manifest, _server = owned_server(path)
    key, trust = paths(path, manifest)
    deadline = monotonic() + timeout
    poll = Event()
    while True:
        connection = paramiko.SSHClient()
        connection.load_host_keys(str(trust))
        connection.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            connection.connect(
                manifest["ipv4"],
                port=manifest["ssh_port"],
                username="root",
                key_filename=str(key),
                allow_agent=False,
                look_for_keys=False,
                timeout=10,
                auth_timeout=10,
                banner_timeout=10,
            )
            return connection
        except (OSError, paramiko.SSHException):
            connection.close()
            if monotonic() >= deadline:
                raise
            poll.wait(2)


def remote(path: Path, command: str, *, payload: str = "", timeout: int = 300) -> str:
    connection = ssh(path)
    try:
        stdin, stdout, stderr = connection.exec_command(command, timeout=timeout)
        stdin.write(payload)
        stdin.channel.shutdown_write()
        result, error = stdout.read(MAX_MANIFEST + 1).decode(), stderr.read(MAX_MANIFEST + 1).decode()
        if stdout.channel.recv_exit_status() or len(result.encode()) > MAX_MANIFEST:
            raise AssertionError("Native VM operation failed: " + error[-2000:])
        return result.strip()
    finally:
        connection.close()


def provision(  # noqa: PLR0913 -- Exact persisted deployment/credential binding and its production API proof callback.
    path: Path,
    *,
    deployment_id: int | None = None,
    fqdn: str = "",
    api_username: str = "",
    api_password: str = "",
    before_harden: Callable[[], None] | None = None,
) -> None:
    manifest, _server = owned_server(path)
    binding = manifest.get("platform_fixture")
    if (
        not isinstance(binding, dict)
        or type(deployment_id) is not int
        or deployment_id <= 0
        or binding.get("deployment_id") != deployment_id
        or binding.get("fqdn") != fqdn
        or not fqdn
        or not api_username
        or api_username == "root"
        or not api_password
        or before_harden is None
    ):
        raise ValueError(
            "Platform-bound fixture and encrypted vault credentials are required; use make native-vm-prepare"
        )
    remote(path, "cloud-init status --wait", timeout=600)
    key, trust = paths(path, manifest)
    public_key = manifest["host_public_key"]  # Trust is independently generated before provider creation.
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    operator = (
        serialization.load_ssh_private_key(key.read_bytes(), password=None)
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    ansible = shutil.which("ansible-playbook")
    if ansible is None or not public_key:
        raise ValueError("The repository Ansible runtime and enrolled trust are required")
    root = ROOT / "services/platform/infrastructure/ansible"
    with tempfile.TemporaryDirectory(prefix="praho-native-ansible-") as directory:
        inventory, variables = Path(directory) / "inventory.json", Path(directory) / "vars.json"
        inventory.write_text(
            json.dumps(
                {
                    "all": {
                        "hosts": {
                            "quota-lab": {
                                "ansible_host": manifest["ipv4"],
                                "ansible_user": "root",
                                "ansible_port": manifest["ssh_port"],
                                "ansible_python_interpreter": "/usr/bin/python3",
                            }
                        }
                    }
                }
            )
        )
        variables.write_text(
            json.dumps(
                {
                    "deployment_id": str(deployment_id),
                    "node_fqdn": fqdn,
                    "praho_generated_node": True,
                    "praho_api_user": api_username,
                    "node_admin_allowed_cidrs": [manifest["admin_cidr"]],
                    "ssh_operator_public_keys": [operator],
                    "ssh_allowed_cidrs": [manifest["admin_cidr"]],
                    "ssh_probe_known_hosts_file": str(trust),
                    "ssh_probe_identity_file": str(key),
                    "ssh_provisioning_public_key": operator,
                    "ssh_port": 9876,
                    "backup_enabled": False,
                    "backup_storage": "platform",
                    "virtualmin_force_hostname": False,
                }
            )
        )
        inventory.chmod(0o600)
        variables.chmod(0o600)
        environment = {
            **os.environ,
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_SSH_ARGS": "-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o UserKnownHostsFile="
            + str(trust),
            "ANSIBLE_SSH_EXTRA_ARGS": "",
            "ANSIBLE_SCP_EXTRA_ARGS": "",
            "ANSIBLE_SFTP_EXTRA_ARGS": "",
        }
        # All playbooks use the same repository roles as production. No unsigned alternate installer.
        for playbook in (
            "ssh-hardening.yml",
            "common_base.yml",
            "virtualmin.yml",
            "virtualmin_harden.yml",
            "virtualmin_usage.yml",
        ):
            if playbook == "virtualmin_harden.yml":
                before_harden()
            stage_values = json.loads(variables.read_text())
            if playbook == "virtualmin.yml":
                stage_values["praho_api_password"] = api_password
            else:
                stage_values.pop("praho_api_password", None)
            variables.write_text(json.dumps(stage_values))
            result = subprocess.run(  # noqa: S603 -- Fixed Ansible argv, exact owned host and private generated inputs.
                [
                    ansible,
                    "-i",
                    str(inventory),
                    "--private-key",
                    str(key),
                    "-e",
                    "@" + str(root / "group_vars/all.yml"),
                    "-e",
                    "@" + str(variables),
                    str(root / "playbooks" / playbook),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=2400,
                check=False,
            )
            log = path.parent / (manifest["run"] + "-" + playbook + ".log")
            log.write_text(result.stdout + result.stderr)
            log.chmod(0o600)
            if result.returncode:
                raise AssertionError("Native node preparation failed; private diagnostics and owned VM retained")
            if playbook == "ssh-hardening.yml":
                manifest["ssh_port"] = 9876
                write_manifest(path, manifest)
                inventory.write_text(inventory.read_text().replace('"ansible_port": 22', '"ansible_port": 9876'))
        manifest["phase"] = "prepared"
        write_manifest(path, manifest)


def destroy(path: Path) -> None:
    manifest = read_manifest(path)
    if manifest.get("origin") == "platform_fresh":
        raise ValueError("Fresh Platform deployments require public teardown; use make native-vm-fresh-destroy")
    cloud = client()
    for key, collection in (
        ("server_id", cloud.servers),
        ("firewall_id", cloud.firewalls),
        ("ssh_key_id", cloud.ssh_keys),
    ):
        identifier = manifest.get(key)
        if identifier is None:
            # Reconcile an ambiguous create using the exact run labels, never a broad project listing.
            matches = collection.get_all(
                label_selector="praho-native-run=" + manifest["run"] + ",praho-native-owner=" + OWNER
            )
            if len(matches) > 1 or any(not owned_resource(manifest, item.labels) for item in matches):
                raise ValueError("Creation has ambiguous owned resources; inspect the retained private manifest")
            if not matches:
                continue
            identifier = matches[0].id
        try:
            resource = collection.get_by_id(identifier)
        except Exception as error:
            if getattr(error, "code", None) != "not_found":
                raise
            resource = None
        if resource is not None:
            if not owned_resource(manifest, resource.labels):
                raise ValueError("Cleanup refused an unowned provider resource")
            resource.delete()
        manifest[key] = None
        write_manifest(path, manifest)
    manifest["phase"] = "destroyed"
    write_manifest(path, manifest)


def reboot_and_wait(path: Path, previous_boot: str) -> None:
    import paramiko  # noqa: PLC0415 -- native enrolled SSH error boundary

    _manifest, server = owned_server(path)
    server.reboot()
    poll, deadline = Event(), monotonic() + SSH_DEADLINE
    while True:
        try:
            if remote(path, "/usr/bin/cat /proc/sys/kernel/random/boot_id", timeout=10) != previous_boot:
                return
        except (OSError, AssertionError, paramiko.SSHException):
            pass
        if monotonic() >= deadline:
            raise AssertionError("Owned native VM did not complete its observed reboot")
        poll.wait(2)


def verify(path: Path) -> None:
    manifest, _server = owned_server(path)
    if manifest["phase"] not in {"prepared", "verifying", "verified"}:
        raise ValueError("Prepare the exact owned Ubuntu VM before native acceptance")
    manifest["phase"] = "verifying"
    write_manifest(path, manifest)
    connection = ssh(path)
    try:
        sftp = connection.open_sftp()
        with sftp.file("/root/praho-native-lab-owner", "w") as owner:
            owner.write(manifest["run"])
        sftp.chmod("/root/praho-native-lab-owner", 0o600)
        sftp.put(str(Path(__file__).with_name("quota_acceptance.py")), "/root/praho-quota-acceptance.py")
        sftp.chmod("/root/praho-quota-acceptance.py", 0o700)
        sftp.close()
    finally:
        connection.close()
    prefix = "/usr/bin/python3 /root/praho-quota-acceptance.py " + str(UUID(manifest["run"])) + " "
    initial = json.loads(remote(path, prefix + "initial", timeout=600))
    # The exact provider resource is rechecked before issuing a reboot.
    reboot_and_wait(path, initial["boot_id"])
    reboot = json.loads(remote(path, prefix + "reboot", timeout=600))
    updated = json.loads(remote(path, prefix + "upgrade", timeout=1500))
    if updated["reboot_required"]:
        reboot_and_wait(path, reboot["boot_id"])
    final = json.loads(remote(path, prefix + "update", timeout=600))
    if final.get("verified") is not True:
        raise AssertionError("Native acceptance did not publish its complete verified proof")
    reboot_and_wait(path, final["boot_id"])
    recovery = json.loads(remote(path, prefix + "requalify", timeout=600))
    if recovery.get("isolated_requalification") is not True:
        raise AssertionError("Explicit same-node reboot requalification and cleanup are still unverified")
    final["requalification"] = recovery
    manifest["phase"], manifest["quota_acceptance"] = "verified", final
    write_manifest(path, manifest)
    print("UID, PHP, MariaDB, neighbor, reboot and update quota acceptance passed on the owned Ubuntu VM")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "fresh-intent", "prepare", "verify", "fresh-proof", "destroy"))
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.action == "prepare":
        parser.error("Use make native-vm-prepare to bind the exact Platform deployment and encrypted credential")
    {"create": create, "fresh-intent": fresh_intent, "verify": verify, "fresh-proof": fresh_deployment_proof, "destroy": destroy}[arguments.action](
        arguments.manifest.absolute()
    )


if __name__ == "__main__":
    main()
