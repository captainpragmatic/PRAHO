"""Qualify pinned package bytes using real dual-stack HTTPS and nftables packets."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker
TABLES = {"ip": "praho_crowdsec4", "ip6": "praho_crowdsec6"}

SERVER = """import http.server,json,socket,ssl,threading
from pathlib import Path
class API(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path.startswith('/v1/decisions/stream'):
   body=json.dumps({'new':json.loads(Path('/root/decisions.json').read_text()),'deleted':[]}).encode()
  else: body=b'{}'
  self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
class Web(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'crowdsec-https-control'; self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
class Web6(http.server.ThreadingHTTPServer): address_family=socket.AF_INET6
api=http.server.ThreadingHTTPServer(('127.0.0.1',8080),API)
threading.Thread(target=api.serve_forever,daemon=True).start()
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain('/root/cert.pem','/root/key.pem')
for cls,addr in ((http.server.ThreadingHTTPServer,'192.0.2.1'),(Web6,'fd00:767::1')):
 server=cls((addr,443),Web); server.socket=context.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
"""

FETCH = """import http.client,json,ssl,sys
try:
 connection=http.client.HTTPSConnection(sys.argv[1],443,timeout=.6,source_address=(sys.argv[2],0),context=ssl._create_unverified_context())
 connection.request('GET','/'); response=connection.getresponse(); body=response.read().decode(); print(json.dumps({'status':response.status,'body':body}))
except OSError:
 sys.exit(2)
"""


def put(container: str, path: str, content: str) -> None:
    docker("exec", "-i", container, "tee", path, input_text=content)


@pytest.fixture(scope="module")
def bouncer_image() -> str:
    base = "praho-ssh-test:26.04"
    docker(
        "build", "--build-arg", "UBUNTU_VERSION=26.04", "-t", base,
        "-f", str(ROOT / "tests/deploy/ssh/Dockerfile"), str(ROOT / "tests/deploy/ssh"),
    )
    image = "praho-crowdsec-bouncer-test:26.04"
    docker(
        "build", "-t", image, "-f", "-", str(ROOT / "tests/deploy/ssh"),
        input_text=(f"FROM {base}\nRUN apt-get update && apt-get install -y --no-install-recommends nftables openssl && apt-get clean && rm -rf /var/lib/apt/lists/*\n"),
    )
    return image


@pytest.fixture(scope="module")
def bouncer_package(bouncer_image: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    architecture = docker("image", "inspect", bouncer_image, "--format", "{{.Architecture}}").stdout.strip()
    assert architecture in {"amd64", "arm64"}
    lock = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    package = lock["packages"][architecture]["crowdsec-firewall-bouncer-nftables"]
    assert package["version"] == "0.0.36"
    name = f"crowdsec-firewall-bouncer-nftables_0.0.36_{architecture}.deb"
    cache = os.environ.get("CROWDSEC_ARTIFACT_DIR")
    if cache:
        path = Path(cache) / name
    else:
        path = tmp_path_factory.mktemp("crowdsec-packages") / name
        assert package["url"].startswith("https://packagecloud.io/crowdsec/crowdsec/")
        with urllib.request.urlopen(package["url"], timeout=60) as response, path.open("wb") as destination:  # noqa: S310 -- pinned HTTPS package URL and digest
            shutil.copyfileobj(response, destination)
    assert path.stat().st_size == package["size"]
    with path.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == package["sha256"]
    return path


@pytest.fixture
def bouncer_target(bouncer_image: str, bouncer_package: Path) -> Iterator[str]:
    container = docker(
        "run", "--rm", "-d", "--privileged", "--network", "none", "--entrypoint", "/bin/sleep",
        bouncer_image, "600",
    ).stdout.strip()
    try:
        docker("cp", str(bouncer_package), f"{container}:/root/bouncer.deb")
        assert docker("exec", container, "dpkg-deb", "-f", "/root/bouncer.deb", "Version").stdout.strip() == "0.0.36"
        docker("exec", container, "dpkg-deb", "-x", "/root/bouncer.deb", "/root/package")
        docker(
            "exec", "-i", container, "sh", "-s", input_text="""set -eu
ip link set lo up
sysctl -w net.ipv6.conf.all.disable_ipv6=0
ip netns add outside
ip link add wan type veth peer name peer
ip link set peer netns outside
ip address add 192.0.2.1/24 dev wan
ip -6 address add fd00:767::1/64 dev wan nodad
ip link set wan up
ip netns exec outside ip link set lo up
ip netns exec outside ip address add 192.0.2.2/24 dev peer
ip netns exec outside ip -6 address add fd00:767::2/64 dev peer nodad
ip netns exec outside ip address add 198.51.100.8/32 dev peer
ip netns exec outside ip address add 198.51.100.9/32 dev peer
ip netns exec outside ip -6 address add fd00:767::8/128 dev peer nodad
ip netns exec outside ip -6 address add fd00:767::9/128 dev peer nodad
ip netns exec outside ip link set peer up
ip route add 198.51.100.8/30 via 192.0.2.2
openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/key.pem -out /root/cert.pem -days 1 -subj /CN=crowdsec-test
""",
        )
        put(container, "/root/decisions.json", "[]")
        docker("exec", "-d", container, "python3", "-c", SERVER)
        yield container
    finally:
        docker("rm", "-f", container)


def fetch(container: str, destination: str, source: str) -> subprocess.CompletedProcess[str]:
    return docker(
        "exec", container, "ip", "netns", "exec", "outside", "python3", "-c", FETCH,
        destination, source, check=False,
    )


def assert_reachable(container: str, destination: str, source: str) -> None:
    deadline = time.monotonic() + 5
    while True:
        result = fetch(container, destination, source)
        if result.returncode == 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": 200, "body": "crowdsec-https-control"}


def start_bouncer(container: str, family: str, value: str, protected: str) -> None:
    address_type = "ipv4_addr" if family == "ip" else "ipv6_addr"
    table = TABLES[family]
    docker(
        "exec", "-i", container, "nft", "-f", "-", input_text=f"""table {family} {table} {{
set protected {{ type {address_type}; flags interval; elements = {{ {protected} }}; }}
set bans {{ type {address_type}; flags timeout; }}
chain input {{ type filter hook input priority -10; policy accept;
{family} saddr @protected return
{family} saddr @bans drop
}}
}}
""",
    )
    decisions = [
        {"id": index, "duration": "5m", "origin": "cscli", "scenario": "qualification", "scope": scope,
         "type": "ban", "value": address}
        for index, (scope, address) in enumerate((("Range" if "/" in value else "Ip", value), ("Ip", protected)), 1)
    ]
    put(container, "/root/decisions.json", json.dumps(decisions))
    config = {
        "mode": "nftables", "update_frequency": "100ms", "log_mode": "stdout", "log_level": "debug",
        "api_url": "http://127.0.0.1:8080/", "api_key": "qualification-only", "disable_ipv6": family != "ip6",
        "deny_action": "DROP", "supported_decisions_types": ["ban"],
        "blacklists_ipv4": "bans", "blacklists_ipv6": "bans", "nftables_hooks": ["input"],
        "nftables": {
            "ipv4": {"enabled": family == "ip", "set-only": True, "table": TABLES["ip"], "chain": "input", "priority": -10},
            "ipv6": {"enabled": family == "ip6", "set-only": True, "table": TABLES["ip6"], "chain": "input", "priority": -10},
        },
        "prometheus": {"enabled": False},
    }
    put(container, "/root/bouncer.yaml", yaml.safe_dump(config))
    binaries = docker("exec", container, "find", "/root/package", "-type", "f", "-name", "crowdsec-firewall-bouncer").stdout.splitlines()
    assert len(binaries) == 1, binaries
    docker(
        "exec", container, "python3", "-c",
        "import subprocess,sys; subprocess.Popen([sys.argv[1],'-c','/root/bouncer.yaml'],stdout=open('/root/bouncer.log','w'),stderr=subprocess.STDOUT)",
        binaries[0],
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        observed = docker("exec", container, "nft", "-j", "list", "set", family, table, "bans").stdout
        if value.split("/", 1)[0] in observed and protected in observed:
            return
        time.sleep(0.1)
    pytest.fail("Bouncer did not apply the test decisions: " + docker("exec", container, "cat", "/root/bouncer.log").stdout[-5000:])


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("cidr", [False, True], ids=["host", "cidr"])
def test_pinned_bouncer_enforces_https_and_preserves_protected_addresses(
    bouncer_target: str, ipv6: bool, cidr: bool,
) -> None:
    destination = "fd00:767::1" if ipv6 else "192.0.2.1"
    protected = "fd00:767::2" if ipv6 else "192.0.2.2"
    first = "fd00:767::8" if ipv6 else "198.51.100.8"
    neighbor = "fd00:767::9" if ipv6 else "198.51.100.9"
    family = "ip6" if ipv6 else "ip"
    value = first + ("/126" if ipv6 else "/30") if cidr else first
    for address in (protected, first, neighbor):
        assert_reachable(bouncer_target, destination, address)
    start_bouncer(bouncer_target, family, value, protected)
    assert fetch(bouncer_target, destination, first).returncode == 2, "Banned first address still reached HTTPS"
    assert_reachable(bouncer_target, destination, protected)
    if cidr:
        observed = fetch(bouncer_target, destination, neighbor)
        assert observed.returncode == 2, (
            f"Pinned bouncer 0.0.36 failed {family} CIDR enforcement: {value} was admitted but "
            f"in-range source {neighbor} still reached HTTPS: {observed.stdout}; "
            + docker("exec", bouncer_target, "nft", "list", "set", family, TABLES[family], "bans").stdout
        )
    else:
        assert_reachable(bouncer_target, destination, neighbor)
