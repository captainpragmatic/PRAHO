"""Pinned-engine schema and real restricted SSH, including hostile channel requests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import paramiko
import pytest
from test_ssh_hardening_docker import ROOT, docker

from apps.common.crowdsec_transport import CrowdSecRPCError, Endpoint, remote_rpc

pytestmark = pytest.mark.docker
INSTALLATION = "417ebf86-1d99-45ec-91bf-16a1a7878e7f"


@dataclass(frozen=True)
class NativeGateway:
    endpoint: Endpoint
    container: str
    digest: str


SETUP = r"""from pathlib import Path
import json,os,shutil
package=Path('/opt/crowdsec-package')
shutil.copytree(package/'etc/crowdsec','/etc/crowdsec')
for name in ('cscli','crowdsec'):
 shutil.copy2(package/'usr/bin'/name,Path('/usr/bin')/name)
Path('/var/lib/crowdsec/data').mkdir(parents=True)
Path('/var/lib/praho-crowdsec').mkdir(mode=0o700)
Path('/etc/praho-crowdsec').mkdir(mode=0o700)
config=Path('/etc/crowdsec/config.yaml')
text=config.read_text().replace('    online_client: # Central API credentials (to push signals and receive bad IPs)\n      credentials_path: /etc/crowdsec/online_api_credentials.yaml','    online_client: null')
config.write_text(text)
Path('/etc/systemd/system/crowdsec.service').write_text('[Service]\nExecStart=/usr/bin/crowdsec -no-cs -c /etc/crowdsec/config.yaml\nRestart=no\n')
"""

ENROLL = r"""from pathlib import Path
import hashlib,json,os,runpy
module=runpy.run_path('/usr/local/libexec/praho-crowdsec-gateway')
manifest=Path('/etc/praho-crowdsec/artifacts.lock.json');manifest.write_bytes(Path('/root/artifacts.lock.json').read_bytes())
selected={item['installed_path'] for item in json.loads(manifest.read_text())['hub']['files'] if 'node' in item['host_kinds']}
for name in module['MANAGED_PATHS']|selected|{module['BOUNCER_PATH']}:
 p=Path(name);p.parent.mkdir(parents=True,exist_ok=True)
 if not p.exists():p.write_text('# isolated gateway qualification fixture\n')
local=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local');local.write_text('api_key: "'+'k'*64+'"\n');local.chmod(0o600)
policy={'schema':1,'host_kind':'node','simulation':True,'protected_cidrs':['192.0.2.0/24','2001:db8::/64'],'artifact_lock_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'bouncer_binary_sha256':hashlib.sha256(Path(module['BOUNCER_PATH']).read_bytes()).hexdigest(),'managed_files':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in module['MANAGED_PATHS']|selected}}
status=Path('/var/lib/crowdsec/data/crowdsec.db').stat()
config={'protocol':1,'installation_id':'417ebf86-1d99-45ec-91bf-16a1a7878e7f','configuration_digest':hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),'simulation':True,'protected_cidrs':['192.0.2.0/24','2001:db8::/64'],'database_witness':{'device':status.st_dev,'inode':status.st_ino},'policy':policy}
p=Path('/etc/praho-crowdsec/config.json'); p.write_text(json.dumps(config)); p.chmod(0o600)
for service in ('engine','bouncer'):
 p=Path('/var/lib/praho-crowdsec')/(service+'-applied.sha256');p.write_text(config['configuration_digest']+'\n');p.chmod(0o600)
"""


def request(target: NativeGateway, operation: str = "snapshot", after: int = 0) -> bytes:
    return json.dumps(
        {
            "protocol": 1,
            "request_id": "5677bcca-c5a6-4afd-937f-d78817e76ad2",
            "installation_id": INSTALLATION,
            "configuration_digest": target.digest,
            "operation": operation,
            "payload": {"after_alert_id": after} if operation == "snapshot" else {},
        }
    ).encode()


def package_archive(image: str, directory: Path, name: str = "crowdsec") -> Path:
    architecture = docker("image", "inspect", image, "--format", "{{.Architecture}}").stdout.strip()
    assert architecture in {"amd64", "arm64"}
    package = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())["packages"][architecture][name]
    if cache := os.environ.get("CROWDSEC_ARTIFACT_DIR"):
        archive = Path(cache) / f"{name}_{package['version']}_{architecture}.deb"
    else:
        archive = directory / f"{name}.deb"
        assert package["url"].startswith("https://packagecloud.io/crowdsec/crowdsec/")
        with urllib.request.urlopen(package["url"], timeout=60) as response, archive.open("wb") as output:  # noqa: S310 -- pinned HTTPS URL, size and SHA256
            shutil.copyfileobj(response, output)
    assert archive.stat().st_size == package["size"]
    with archive.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == package["sha256"]
    return archive


def install_engine(container: str, archive: Path) -> None:
    docker("exec", container, "systemctl", "is-system-running", "--wait", check=False)
    docker("cp", str(archive), f"{container}:/root/crowdsec.deb")
    docker("exec", container, "dpkg-deb", "-x", "/root/crowdsec.deb", "/opt/crowdsec-package")
    docker("exec", container, "python3", "-c", SETUP)
    docker(
        "exec",
        container,
        "cscli",
        "machines",
        "add",
        f"praho-installation-{INSTALLATION}",
        "--auto",
        "-f",
        "/etc/crowdsec/local_api_credentials.yaml",
    )
    docker("exec", container, "systemctl", "daemon-reload")
    docker("exec", container, "systemctl", "start", "crowdsec.service")
    ready = "import socket,time; deadline=time.monotonic()+10\nwhile time.monotonic()<deadline:\n try:\n  socket.create_connection(('127.0.0.1',8080),timeout=.2).close();break\n except OSError:time.sleep(.05)\nelse:raise RuntimeError('LAPI unavailable')"
    docker("exec", container, "python3", "-c", ready)
    imports = [
        {
            "scope": "ip",
            "value": f"198.18.{n // 250}.{n % 250 + 1}",
            "duration": "4h",
            "reason": "crowdsecurity/ssh-bf",
            "type": "ban",
        }
        for n in range(1201)
    ]
    docker(
        "exec",
        "-i",
        container,
        "cscli",
        "decisions",
        "import",
        "--format",
        "json",
        "--input",
        "-",
        "--batch",
        "1",
        input_text=json.dumps(imports),
    )


def restore_stock_units(container: str, archive: Path) -> None:
    # Import test data through LAPI, then qualify the actual package units while stopped.
    # Active-agent acquisition is proved independently by the role's native suite.
    docker("exec", container, "systemctl", "stop", "crowdsec.service")
    docker("cp", str(archive), f"{container}:/root/bouncer.deb")
    docker("exec", container, "dpkg-deb", "-x", "/root/bouncer.deb", "/opt/bouncer-package")
    script = """from pathlib import Path
import shutil
Path('/etc/systemd/system/crowdsec.service').unlink()
shutil.copyfile('/opt/crowdsec-package/lib/systemd/system/crowdsec.service','/usr/lib/systemd/system/crowdsec.service')
shutil.copyfile('/opt/bouncer-package/etc/systemd/system/crowdsec-firewall-bouncer.service','/etc/systemd/system/crowdsec-firewall-bouncer.service')
"""
    docker("exec", container, "python3", "-c", script)
    for unit, template in (
        ("crowdsec.service", "engine-guard.conf.j2"),
        ("crowdsec-firewall-bouncer.service", "bouncer-guard.conf.j2"),
    ):
        path = f"/etc/systemd/system/{unit}.d"
        docker("exec", container, "mkdir", "-p", path)
        content = (ROOT / "deploy/ansible/roles/crowdsec/templates" / template).read_text()
        docker("exec", "-i", container, "tee", path + "/praho.conf", input_text=content)
    docker("exec", container, "systemctl", "daemon-reload")


def install_ssh(container: str, directory: Path) -> Endpoint:
    docker("exec", container, "useradd", "--system", "--create-home", "--shell", "/bin/sh", "praho-crowdsec")
    docker("exec", container, "usermod", "--password", "*", "praho-crowdsec")
    docker("exec", container, "mkdir", "-p", "/usr/local/libexec", "/home/praho-crowdsec/.ssh")
    docker(
        "cp",
        str(ROOT / "deploy/ansible/roles/crowdsec/files/gateway.py"),
        f"{container}:/usr/local/libexec/praho-crowdsec-gateway",
    )
    docker("exec", container, "chown", "root:root", "/usr/local/libexec/praho-crowdsec-gateway")
    docker("exec", container, "chmod", "755", "/usr/local/libexec/praho-crowdsec-gateway")
    docker("exec", container, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/root/gateway-client")
    public = docker("exec", container, "cat", "/root/gateway-client.pub").stdout.strip()
    docker(
        "exec",
        "-i",
        container,
        "tee",
        "/home/praho-crowdsec/.ssh/authorized_keys",
        input_text="restrict " + public + "\n",
    )
    docker("exec", container, "chown", "-R", "root:root", "/home/praho-crowdsec")
    docker("exec", container, "chmod", "755", "/home/praho-crowdsec", "/home/praho-crowdsec/.ssh")
    docker("exec", container, "chmod", "644", "/home/praho-crowdsec/.ssh/authorized_keys")
    sudoers = (
        'Defaults:praho-crowdsec env_reset\nDefaults:praho-crowdsec env_keep += "SSH_ORIGINAL_COMMAND"\n'
        'Defaults:praho-crowdsec secure_path="/usr/sbin:/usr/bin:/sbin:/bin"\n'
        'praho-crowdsec ALL=(root) NOPASSWD: /usr/local/libexec/praho-crowdsec-gateway ""\n'
    )
    docker("exec", "-i", container, "tee", "/etc/sudoers.d/praho-crowdsec", input_text=sudoers)
    docker("exec", container, "chmod", "440", "/etc/sudoers.d/praho-crowdsec")
    docker("exec", container, "visudo", "-cf", "/etc/sudoers.d/praho-crowdsec")
    ssh_config = (
        "Port 22\nListenAddress 0.0.0.0\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
        "PubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nStrictModes yes\n"
        "AuthorizedKeysFile .ssh/authorized_keys\nAllowTcpForwarding no\nAllowAgentForwarding no\n"
        "AllowStreamLocalForwarding no\nX11Forwarding no\nPermitTunnel no\n"
        "Match User praho-crowdsec\n ForceCommand sudo -n /usr/local/libexec/praho-crowdsec-gateway\n"
        " PermitTTY no\n DisableForwarding yes\n"
    )
    docker("exec", "-i", container, "tee", "/etc/ssh/sshd_config", input_text=ssh_config)
    docker("exec", container, "sshd", "-t")
    docker("exec", container, "systemctl", "restart", "ssh.socket", "ssh.service")
    port = int(docker("port", container, "22/tcp").stdout.strip().rsplit(":", 1)[1])
    key_path = directory / "client"
    docker("cp", f"{container}:/root/gateway-client", str(key_path))
    key_path.chmod(0o600)
    host_key = " ".join(docker("exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout.split()[:2])
    return Endpoint("127.0.0.1", port, host_key, str(key_path))


def install_hub(container: str, directory: Path) -> None:
    manifest = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    for item in manifest["hub"]["files"]:
        if "node" not in item["host_kinds"]:
            continue
        source = directory / Path(item["path"]).name
        if cache := os.environ.get("CROWDSEC_HUB_DIR"):
            source.write_bytes((Path(cache) / item["path"]).read_bytes())
        else:
            assert item["url"].startswith("https://raw.githubusercontent.com/crowdsecurity/hub/")
            with urllib.request.urlopen(item["url"], timeout=30) as response:  # noqa: S310 -- pinned HTTPS URL and digest
                source.write_bytes(response.read(65537))
        assert hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
        target = Path(item["installed_path"])
        docker("exec", container, "mkdir", "-p", str(target.parent))
        docker("cp", str(source), f"{container}:{target}")
        docker("exec", container, "chown", "root:root", str(target))


@pytest.fixture(scope="module")
def native_gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[NativeGateway]:
    image = "praho-ssh-test:26.04"
    docker(
        "build",
        "--build-arg",
        "UBUNTU_VERSION=26.04",
        "-t",
        image,
        "-f",
        str(ROOT / "tests/deploy/ssh/Dockerfile"),
        str(ROOT / "tests/deploy/ssh"),
    )
    directory = tmp_path_factory.mktemp("crowdsec-native-gateway")
    archive = package_archive(image, directory)
    bouncer_archive = package_archive(image, directory, "crowdsec-firewall-bouncer-nftables")
    container = docker(
        "run",
        "--rm",
        "-d",
        "--privileged",
        "--cgroupns=private",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "-p",
        "127.0.0.1::22",
        image,
    ).stdout.strip()
    try:
        install_engine(container, archive)
        restore_stock_units(container, bouncer_archive)
        endpoint = install_ssh(container, directory)
        install_hub(container, directory)
        docker("cp", str(ROOT / "deploy/crowdsec/artifacts.lock.json"), f"{container}:/root/artifacts.lock.json")
        docker("exec", container, "python3", "-c", ENROLL)
        digest = json.loads(docker("exec", container, "cat", "/etc/praho-crowdsec/config.json").stdout)[
            "configuration_digest"
        ]
        yield NativeGateway(endpoint, container, digest)
    finally:
        docker("rm", "-f", container, check=False)


def test_native_pinned_schema_and_multibatch_snapshot(native_gateway: NativeGateway) -> None:
    first = remote_rpc(native_gateway.endpoint, request(native_gateway))
    result = first["result"]
    assert len(result["decisions"]) == 1201
    assert len(result["alerts"]) == 1000 and result["has_more"] is True
    second = remote_rpc(native_gateway.endpoint, request(native_gateway, after=result["alert_watermark"]))["result"]
    assert len(second["alerts"]) == 201 and second["has_more"] is False
    assert second["alert_watermark"] == 1201
    assert "password" not in json.dumps(first).lower()


def connect(endpoint: Endpoint) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    key_type, encoded = endpoint.host_keys.split()
    key = paramiko.PKey.from_type_string(key_type, base64.b64decode(encoded))
    client.get_host_keys().add(f"[{endpoint.hostname}]:{endpoint.port}", key_type, key)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=endpoint.hostname,
        port=endpoint.port,
        username="praho-crowdsec",
        key_filename=endpoint.private_key_path,
        look_for_keys=False,
        allow_agent=False,
        timeout=5,
    )
    return client


@pytest.mark.parametrize("command", ["id", "sh -c id", "sudo id", "PATH=/tmp id"])
def test_native_exec_requests_refused(native_gateway: NativeGateway, command: str) -> None:
    with connect(native_gateway.endpoint) as client:
        stdin, stdout, _stderr = client.exec_command(command, timeout=5)
        stdin.write(request(native_gateway))
        stdin.channel.shutdown_write()
        assert stdout.read() == b""
        assert stdout.channel.recv_exit_status() != 0


def test_native_pty_and_forwarding_refused(native_gateway: NativeGateway) -> None:
    with connect(native_gateway.endpoint) as client:
        transport = client.get_transport()
        assert transport is not None
        channel = transport.open_session(timeout=5)
        with pytest.raises(paramiko.SSHException):
            channel.get_pty()
        channel.close()
        with pytest.raises(paramiko.SSHException):
            transport.open_channel("direct-tcpip", ("127.0.0.1", 8080), ("127.0.0.1", 12345), timeout=5)
        with pytest.raises(paramiko.SSHException):
            transport.request_port_forward("127.0.0.1", 0)


def test_native_health_and_narrow_local_sudo(native_gateway: NativeGateway) -> None:
    health = remote_rpc(native_gateway.endpoint, request(native_gateway, "health"))["result"]
    assert health["engine"] == {"active": False, "version": "1.8.2"}
    assert health["configuration"]["qualified"] is True
    assert health["bouncer"]["active"] is False
    assert health["firewall"]["qualified"] is False  # This isolated gateway fixture installs no firewall.
    assert type(health["clock"]["qualified"]) is bool
    local = docker(
        "exec",
        "-i",
        native_gateway.container,
        "sudo",
        "-u",
        "praho-crowdsec",
        "--",
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/praho-crowdsec-gateway",
        input_text=request(native_gateway).decode(),
    )
    assert len(json.loads(local.stdout)["result"]["decisions"]) == 1201
    denied = docker(
        "exec",
        native_gateway.container,
        "sudo",
        "-u",
        "praho-crowdsec",
        "--",
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/praho-crowdsec-gateway",
        "extra",
        check=False,
    )
    assert denied.returncode != 0
    arbitrary = docker(
        "exec",
        native_gateway.container,
        "sudo",
        "-u",
        "praho-crowdsec",
        "--",
        "/usr/bin/sudo",
        "-n",
        "/bin/sh",
        "-c",
        "id",
        check=False,
    )
    assert arbitrary.returncode != 0


@pytest.mark.parametrize("service", ["engine", "bouncer"])
def test_native_unapplied_runtime_policy_refuses_snapshot(native_gateway: NativeGateway, service: str) -> None:
    stamp = f"/var/lib/praho-crowdsec/{service}-applied.sha256"
    docker("exec", "-i", native_gateway.container, "tee", stamp, input_text="0" * 64 + "\n")
    try:
        health = remote_rpc(native_gateway.endpoint, request(native_gateway, "health"))["result"]
        assert health["configuration"]["qualified"] is False
        with pytest.raises(CrowdSecRPCError):
            remote_rpc(native_gateway.endpoint, request(native_gateway))
    finally:
        docker("exec", "-i", native_gateway.container, "tee", stamp, input_text=native_gateway.digest + "\n")
    assert (
        remote_rpc(native_gateway.endpoint, request(native_gateway, "health"))["result"]["configuration"]["qualified"]
        is True
    )


@pytest.mark.parametrize(
    "raw", [b"{}{}", b'{"protocol":1,"protocol":1}', b"{}" + b" " * 65536], ids=["trailing", "duplicate", "oversize"]
)
def test_native_malformed_requests_have_no_partial_stdout(native_gateway: NativeGateway, raw: bytes) -> None:
    with connect(native_gateway.endpoint) as client:
        transport = client.get_transport()
        assert transport is not None
        channel = transport.open_session(timeout=5)
        channel.settimeout(5)
        channel.invoke_shell()
        channel.sendall(raw)
        channel.shutdown_write()
        assert channel.makefile("rb").read() == b""
        assert channel.recv_exit_status() != 0
        channel.close()


def test_native_slow_stdin_deadline(native_gateway: NativeGateway) -> None:
    with connect(native_gateway.endpoint) as client:
        transport = client.get_transport()
        assert transport is not None
        channel = transport.open_session(timeout=5)
        channel.settimeout(35)
        channel.invoke_shell()
        channel.sendall(b"{")
        before = time.monotonic()
        assert channel.makefile("rb").read() == b""
        assert channel.recv_exit_status() != 0
        assert time.monotonic() - before < 35
        channel.close()


def test_native_enrollment_and_schema_changes_refused(native_gateway: NativeGateway) -> None:
    wrong_key = paramiko.RSAKey.generate(2048)
    endpoint = native_gateway.endpoint
    bad = Endpoint(endpoint.hostname, endpoint.port, f"ssh-rsa {wrong_key.get_base64()}", endpoint.private_key_path)
    with pytest.raises(CrowdSecRPCError):
        remote_rpc(bad, request(native_gateway))
    container = native_gateway.container
    docker(
        "exec",
        container,
        "python3",
        "-c",
        "from pathlib import Path; import shutil; p=Path('/var/lib/crowdsec/data/crowdsec.db'); shutil.copyfile(p,str(p)+'.new'); p.rename(str(p)+'.original'); Path(str(p)+'.new').replace(p)",
    )
    try:
        with pytest.raises(CrowdSecRPCError):
            remote_rpc(endpoint, request(native_gateway))
    finally:
        docker(
            "exec",
            container,
            "python3",
            "-c",
            "from pathlib import Path; p=Path('/var/lib/crowdsec/data/crowdsec.db'); Path(str(p)+'.original').replace(p)",
        )
