"""Read-only qualification catches forwarded ingress without damaging private/outbound routing."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

import pytest
from django.core.exceptions import ValidationError
from fixture_images import fixture_image
from test_ssh_hardening_docker import ROOT, docker

from apps.provisioning.virtualmin_security_policy import verify_network_ingress

pytestmark = pytest.mark.docker


@pytest.fixture(params=["24.04", "26.04"])
def network_target(request: pytest.FixtureRequest) -> Iterator[str]:
    version = str(request.param)
    base = fixture_image(f"praho-ssh-test:{version}")
    built = docker(
        "build",
        "--build-arg",
        f"UBUNTU_VERSION={version}",
        "-t",
        base,
        "-f",
        str(ROOT / "tests/deploy/ssh/Dockerfile"),
        str(ROOT / "tests/deploy/ssh"),
        check=False,
    )
    assert built.returncode == 0, built.stderr[-3000:]
    image = fixture_image(f"praho-network-proof:{version}")
    nft = docker(
        "build",
        "-t",
        image,
        "-f",
        "-",
        str(ROOT / "tests/deploy/ssh"),
        input_text=f"FROM {base}\nRUN apt-get update && apt-get install -y --no-install-recommends nftables && apt-get clean && rm -rf /var/lib/apt/lists/*\n",
        check=False,
    )
    assert nft.returncode == 0, nft.stderr[-3000:]
    container = docker(
        "run", "--rm", "-d", "--privileged", "--network", "none", "--entrypoint", "/bin/sleep", image, "900"
    ).stdout.strip()
    try:
        docker(
            "cp",
            str(ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"),
            f"{container}:/tmp/inspect.py",
        )
        yield container
    finally:
        docker("rm", "-f", container)


def test_live_qualification_covers_all_node_addresses_and_routed_ipv6(network_target: str) -> None:
    target = network_target

    def shell(source: str) -> None:
        result = docker("exec", "-i", target, "sh", "-s", input_text="set -eu\n" + source, check=False)
        assert result.returncode == 0, result.stderr[-3000:]

    shell("""ip link set lo up
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.disable_ipv6=0
ip netns add outside
ip netns add backend
ip link add wan type veth peer name peer
ip link set peer netns outside
ip address add 192.0.2.1/30 dev wan
ip address add 198.51.100.9/32 dev wan
ip -6 address add fd00:178::1/64 dev wan nodad
ip link set wan up
ip netns exec outside ip address add 192.0.2.2/30 dev peer
ip netns exec outside ip -6 address add fd00:178::2/64 dev peer nodad
ip netns exec outside ip link set peer up
ip netns exec outside ip link set lo up
ip netns exec outside ip route add default via 192.0.2.1
ip netns exec outside ip -6 route add fd00:177::/64 via fd00:178::1
ip route add default via 192.0.2.2
ip -6 route add default via fd00:178::2
ip link add lan type bridge
ip address add 10.177.0.1/30 dev lan
ip -6 address add fd00:177::1/64 dev lan nodad
ip link set lan up
ip link add private type veth peer name back
ip link set private master lan
ip link set private up
ip link set back netns backend
ip netns exec backend ip address add 10.177.0.2/30 dev back
ip netns exec backend ip -6 address add fd00:177::2/64 dev back nodad
ip netns exec backend ip link set back up
ip netns exec backend ip link set lo up
ip netns exec backend ip route add default via 10.177.0.1
ip netns exec backend ip -6 route add default via fd00:177::1
sysctl -w net.ipv6.conf.all.forwarding=1
for name in before.rules before6.rules after.rules after6.rules; do
    sed '/--dport 5353\\|--dport 1900/d' /usr/share/ufw/iptables/$name > /etc/ufw/$name
done
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
iptables -t nat -A POSTROUTING -s 10.177.0.0/30 -o wan -j MASQUERADE
for tool in iptables ip6tables; do
    "$tool" -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    "$tool" -I FORWARD 2 -i lan -o wan -j ACCEPT
done
""")
    server = """import socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((sys.argv[1],int(sys.argv[2]))); s.listen()
while True:
 c,a=s.accept(); c.recv(4096); body=sys.argv[3].encode(); c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body); c.close()
"""
    for namespace, address, port, body in (
        (None, "192.0.2.1", 80, "public-web"),
        (None, "fd00:178::1", 80, "public-web6"),
        ("backend", "10.177.0.2", 8080, "private-app"),
        ("backend", "fd00:177::2", 8080, "private-app6"),
        ("outside", "192.0.2.2", 8081, "outbound-peer"),
        ("outside", "fd00:178::2", 8081, "outbound-peer6"),
    ):
        command = ["ip", "netns", "exec", namespace] if namespace else []
        docker("exec", "-d", target, *command, "python3", "-c", server, address, str(port), body)
    fetch = """import http.client,sys,time
for attempt in range(20):
 try:
  c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=.2); c.request('GET','/'); print(c.getresponse().read().decode()); break
 except OSError:
  if attempt==19: raise
  time.sleep(.03)
"""

    def get(namespace: str, address: str, port: int) -> str:
        result = docker(
            "exec", target, "ip", "netns", "exec", namespace, "python3", "-c", fetch, address, str(port), check=False
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    inspect = "import importlib.util,json; s=importlib.util.spec_from_file_location('inspect','/tmp/inspect.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps(m.inspect_firewall()))"

    def evidence() -> list[str]:
        return json.loads(docker("exec", target, "python3", "-c", inspect).stdout)

    def saved_rules() -> list[str]:
        return [
            re.sub(r"\[\d+:\d+\]", "[0:0]", row)
            for tool in ("iptables-save", "ip6tables-save")
            for row in docker("exec", target, tool).stdout.splitlines()
            if not row.startswith("#")
        ]

    original = saved_rules()
    verify_network_ingress(evidence())
    assert saved_rules() == original
    assert get("outside", "192.0.2.1", 80) == "public-web"
    assert get("outside", "fd00:178::1", 80) == "public-web6"
    assert get("backend", "192.0.2.2", 8081) == "outbound-peer"
    assert get("backend", "fd00:178::2", 8081) == "outbound-peer6"
    shell("""iptables -t nat -A PREROUTING -i wan -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080
iptables -I FORWARD 1 -i wan -o lan -p tcp -d 10.177.0.2 --dport 8080 -j ACCEPT
""")
    assert get("outside", "192.0.2.1", 2525) == "private-app"
    assert get("outside", "198.51.100.9", 2525) == "private-app"
    assert docker("exec", target, "ss", "-H", "-lnt", "sport = :2525").stdout == ""
    unsafe = evidence()
    assert any("198.51.100.9/32" in row for row in unsafe)
    with pytest.raises(ValidationError, match="2525"):
        verify_network_ingress(unsafe)
    shell("iptables -t nat -D PREROUTING -i wan -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080\n")
    with pytest.raises(ValidationError, match="8080"):
        verify_network_ingress(evidence())
    shell("""iptables -D FORWARD -i wan -o lan -p tcp -d 10.177.0.2 --dport 8080 -j ACCEPT
ip6tables -I FORWARD 1 -i wan -o lan -p tcp -d fd00:177::2 --dport 8080 -j ACCEPT
""")
    assert get("outside", "fd00:177::2", 8080) == "private-app6"
    with pytest.raises(ValidationError, match="8080"):
        verify_network_ingress(evidence())
    shell("ip6tables -D FORWARD -i wan -o lan -p tcp -d fd00:177::2 --dport 8080 -j ACCEPT\n")
    verify_network_ingress(evidence())
    assert saved_rules() == original
    assert get("backend", "192.0.2.2", 8081) == "outbound-peer"
    assert get("backend", "fd00:178::2", 8081) == "outbound-peer6"
