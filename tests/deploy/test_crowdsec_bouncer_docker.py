"""Qualify pinned package bytes using real dual-stack HTTPS and nftables packets."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker
TABLES = {"ip": "praho_crowdsec4", "ip6": "praho_crowdsec6"}


@dataclass(frozen=True)
class BouncerOptions:
    interval: bool | None = None
    experimental_ranges: bool | None = None
    set_only_intervals: bool | None = None
    initial_decisions: list[dict[str, object]] | None = None
    dual_stack: bool = False


SERVER = """import http.server,json,re,socket,ssl,threading,time,urllib.parse
from pathlib import Path
lock=threading.Lock()
last_generation=None
active={}
def frame(startup):
 global last_generation
 with lock:
  state=json.loads(Path('/root/decisions.json').read_text())
  new,deleted=[],[]
  pause=False
  if state['generation'] != last_generation:
   last_generation=state['generation']
   for item in state['deleted']:
    previous=active.pop(item['id'],None)
    if previous is not None:
     deleted.append({k:v for k,v in previous.items() if k!='_expires'} | {'duration':str(int((previous['_expires']-time.monotonic())*1000))+'ms'})
   for item in state['new']:
    match=re.fullmatch(r'(-?\\d+)(ms|s|m|h)',item['duration'])
    assert match,item
    duration=int(match[1])*{'ms':.001,'s':1,'m':60,'h':3600}[match[2]]
    active[item['id']]={**item,'_expires':time.monotonic()+duration}
   new=state['new']
   pause=state.get('pause',False)
  if startup:
   new=[]
   for item in active.values():
    remaining=item['_expires']-time.monotonic()
    if remaining>0:
     new.append({k:v for k,v in item.items() if k!='_expires'} | {'duration':str(max(1,int(remaining*1000)))+'ms'})
   deleted=[]
  if pause:
   Path('/root/stream-paused').write_text(str(state['generation']))
   while Path('/root/stream-pause').exists(): time.sleep(.01)
  return {'new':new,'deleted':deleted}
class API(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path.startswith('/v1/decisions/stream'):
   startup=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('startup')==['true']
   body=json.dumps(frame(startup)).encode()
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


def write_decisions(
    container: str,
    new: list[dict[str, object]],
    deleted: list[dict[str, object]] | None = None,
    *,
    pause: bool = False,
) -> int:
    generation = time.time_ns()
    frame = {"generation": generation, "new": new, "deleted": deleted or [], "pause": pause}
    if pause:
        put(container, "/root/stream-pause", "hold")
    put(container, "/root/decisions.new", json.dumps(frame))
    docker("exec", container, "mv", "/root/decisions.new", "/root/decisions.json")
    return generation


@pytest.fixture(scope="module")
def bouncer_image() -> str:
    base = "praho-ssh-test:26.04"
    docker(
        "build",
        "--build-arg",
        "UBUNTU_VERSION=26.04",
        "-t",
        base,
        "-f",
        str(ROOT / "tests/deploy/ssh/Dockerfile"),
        str(ROOT / "tests/deploy/ssh"),
    )
    image = "praho-crowdsec-bouncer-test:26.04"
    docker(
        "build",
        "-t",
        image,
        "-f",
        "-",
        str(ROOT / "tests/deploy/ssh"),
        input_text=(
            f"FROM {base}\nRUN apt-get update && apt-get install -y --no-install-recommends nftables openssl && apt-get clean && rm -rf /var/lib/apt/lists/*\n"
        ),
    )
    return image


@pytest.fixture(scope="module")
def bouncer_package(bouncer_image: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    architecture = docker("image", "inspect", bouncer_image, "--format", "{{.Architecture}}").stdout.strip()
    assert architecture in {"amd64", "arm64"}
    if candidate := os.environ.get("CROWDSEC_BOUNCER_BINARY"):
        expected_hash = os.environ.get("CROWDSEC_BOUNCER_SHA256", "")
        assert re.fullmatch(r"[0-9a-f]{64}", expected_hash), "Candidate requires explicit SHA256"
        path = Path(candidate)
        with path.open("rb") as source:
            assert hashlib.file_digest(source, "sha256").hexdigest() == expected_hash
        return path
    lock = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    if os.environ.get("CROWDSEC_BOUNCER_REJECTED_PACKAGE") != "1":
        artifact = lock["bouncer_build"]["binaries"][architecture]
        path = ROOT / artifact["file"]
        assert path.stat().st_size == artifact["size"]
        with path.open("rb") as source:
            assert hashlib.file_digest(source, "sha256").hexdigest() == artifact["sha256"]
        return path
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
        "run",
        "--rm",
        "-d",
        "--privileged",
        "--network",
        "none",
        "--entrypoint",
        "/bin/sleep",
        bouncer_image,
        "600",
    ).stdout.strip()
    try:
        if os.environ.get("CROWDSEC_BOUNCER_BINARY") or os.environ.get("CROWDSEC_BOUNCER_REJECTED_PACKAGE") != "1":
            docker("exec", container, "mkdir", "-p", "/root/package/usr/local/bin")
            binary = "/root/package/usr/local/bin/crowdsec-firewall-bouncer"
            docker("cp", str(bouncer_package), f"{container}:{binary}")
            docker("exec", container, "chmod", "755", binary)
        else:
            docker("cp", str(bouncer_package), f"{container}:/root/bouncer.deb")
            assert (
                docker("exec", container, "dpkg-deb", "-f", "/root/bouncer.deb", "Version").stdout.strip() == "0.0.36"
            )
            docker("exec", container, "dpkg-deb", "-x", "/root/bouncer.deb", "/root/package")
        docker(
            "exec",
            "-i",
            container,
            "sh",
            "-s",
            input_text="""set -eu
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
for address in 7 8 9 10 11 12; do
 ip netns exec outside ip address add "198.51.100.$address/32" dev peer
done
for address in 7 8 9 a b c; do
 ip netns exec outside ip -6 address add "fd00:767::$address/128" dev peer nodad
done
ip netns exec outside ip link set peer up
ip route add 198.51.100.0/24 via 192.0.2.2
openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/key.pem -out /root/cert.pem -days 1 -subj /CN=crowdsec-test
""",
        )
        write_decisions(container, [])
        docker("exec", "-d", container, "python3", "-c", SERVER)
        yield container
    finally:
        docker("rm", "-f", container)


def fetch(container: str, destination: str, source: str) -> subprocess.CompletedProcess[str]:
    return docker(
        "exec",
        container,
        "ip",
        "netns",
        "exec",
        "outside",
        "python3",
        "-c",
        FETCH,
        destination,
        source,
        check=False,
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


def start_bouncer(
    container: str,
    family: str,
    value: str,
    protected: str,
    options: BouncerOptions | None = None,
) -> None:
    options = options or BouncerOptions()
    interval, experimental_ranges, set_only_intervals = (
        options.interval,
        options.experimental_ranges,
        options.set_only_intervals,
    )
    selected = (
        not os.environ.get("CROWDSEC_BOUNCER_BINARY") and os.environ.get("CROWDSEC_BOUNCER_REJECTED_PACKAGE") != "1"
    )
    if interval is None:
        interval = selected or os.environ.get("CROWDSEC_NFT_INTERVAL") == "1"
    if experimental_ranges is None:
        experimental_ranges = os.environ.get("CROWDSEC_NFT_EXPERIMENTAL_RANGES") == "1"
    if set_only_intervals is None:
        set_only_intervals = selected or os.environ.get("CROWDSEC_NFT_SET_ONLY_INTERVALS") == "1"
    flags = "interval,timeout" if interval else "timeout"
    families = ("ip", "ip6") if options.dual_stack else (family,)
    for enabled_family in families:
        address_type = "ipv4_addr" if enabled_family == "ip" else "ipv6_addr"
        table = TABLES[enabled_family]
        family_protected = (
            ("192.0.2.2" if enabled_family == "ip" else "fd00:767::2") if options.dual_stack else protected
        )
        docker(
            "exec",
            "-i",
            container,
            "nft",
            "-f",
            "-",
            input_text=f"""table {enabled_family} {table} {{
set protected {{ type {address_type}; flags interval; elements = {{ {family_protected} }}; }}
set bans {{ type {address_type}; flags {flags}; }}
chain input {{ type filter hook input priority -10; policy accept;
{enabled_family} saddr @protected return
{enabled_family} saddr @bans drop
}}
}}
""",
        )
    decisions = (
        options.initial_decisions
        if options.initial_decisions is not None
        else [
            {
                "id": index,
                "duration": "5m",
                "origin": "cscli",
                "scenario": "qualification",
                "scope": scope,
                "type": "ban",
                "value": address,
            }
            for index, (scope, address) in enumerate((("Range" if "/" in value else "Ip", value), ("Ip", protected)), 1)
        ]
    )
    write_decisions(container, decisions)
    config = {
        "mode": "nftables",
        "update_frequency": "100ms",
        "log_mode": "stdout",
        "log_level": "debug",
        "api_url": "http://127.0.0.1:8080/",
        "api_key": "qualification-only",
        "disable_ipv6": "ip6" not in families,
        "deny_action": "DROP",
        "supported_decisions_types": ["ban"],
        "blacklists_ipv4": "bans",
        "blacklists_ipv6": "bans",
        "nftables_hooks": ["input"],
        "nftables": {
            "ipv4": {
                "enabled": "ip" in families,
                "set-only": True,
                "table": TABLES["ip"],
                "chain": "input",
                "priority": -10,
            },
            "ipv6": {
                "enabled": "ip6" in families,
                "set-only": True,
                "table": TABLES["ip6"],
                "chain": "input",
                "priority": -10,
            },
        },
        "prometheus": {"enabled": False},
    }
    if experimental_ranges:
        config["nftables"]["enable_experimental_ranges"] = True
    if set_only_intervals:
        config["nftables"]["set_only_intervals"] = True
    put(container, "/root/bouncer.yaml", yaml.safe_dump(config))
    launch_bouncer(container)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        observed = docker("exec", container, "nft", "-j", "list", "set", family, TABLES[family], "bans").stdout
        if value.split("/", 1)[0] in observed and protected in observed:
            return
        time.sleep(0.1)
    pytest.fail(
        "Bouncer did not apply the test decisions: "
        + docker("exec", container, "cat", "/root/bouncer.log").stdout[-5000:]
    )


def launch_bouncer(container: str) -> None:
    binaries = docker(
        "exec", container, "find", "/root/package", "-type", "f", "-name", "crowdsec-firewall-bouncer"
    ).stdout.splitlines()
    assert len(binaries) == 1, binaries
    docker(
        "exec",
        container,
        "python3",
        "-c",
        "import subprocess,sys; from pathlib import Path; p=subprocess.Popen([sys.argv[1],'-c','/root/bouncer.yaml'],stdout=open('/root/bouncer.log','w'),stderr=subprocess.STDOUT); Path('/root/bouncer.pid').write_text(str(p.pid))",
        binaries[0],
    )


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("cidr", [False, True], ids=["host", "cidr"])
def test_pinned_bouncer_enforces_https_and_preserves_protected_addresses(
    bouncer_target: str,
    ipv6: bool,
    cidr: bool,
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
