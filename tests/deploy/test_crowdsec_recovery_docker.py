"""Real kernel continuity across bouncer termination, failed commits and full resync."""

from __future__ import annotations

import ipaddress
import json
import time

import pytest
from test_crowdsec_bouncer_docker import (
    TABLES,
    BouncerOptions,
    bouncer_image,
    bouncer_package,
    bouncer_target,
    launch_bouncer,
    start_bouncer,
    write_decisions,
)
from test_crowdsec_lifecycle_docker import addresses, decision
from test_ssh_hardening_docker import docker

pytestmark = pytest.mark.docker
__all__ = ["bouncer_image", "bouncer_package", "bouncer_target"]

PROBE = """import concurrent.futures,http.client,json,ssl,sys
def request(pair):
 destination,source=pair
 try:
  client=http.client.HTTPSConnection(destination,443,timeout=.45,source_address=(source,0),context=ssl._create_unverified_context())
  client.request('GET','/'); response=client.getresponse(); body=response.read().decode();client.close()
  return source,{'status':response.status,'body':body}
 except OSError:return source,{'status':'dropped'}
pairs=json.loads(sys.argv[1])
with concurrent.futures.ThreadPoolExecutor(max_workers=len(pairs)) as pool:
 print(json.dumps(dict(pool.map(request,pairs))))
"""

RUNNING = """from pathlib import Path
import sys
p=Path('/proc')/sys.argv[1]/'stat'
sys.exit(0 if p.exists() and p.read_text().split()[2]!='Z' else 1)
"""


def targets() -> list[tuple[str, str]]:
    result = []
    for ipv6 in (False, True):
        _family, destination, protected, first, middle, last, outside = addresses(ipv6)
        before, other = ("fd00:767::7", "fd00:767::a") if ipv6 else ("198.51.100.7", "198.51.100.10")
        result.extend((destination, source) for source in (protected, before, first, middle, other, last, outside))
    return result


def expect_packets(container: str, banned: set[str], *, timeout: float = 5) -> None:
    deadline, observed = time.monotonic() + timeout, {}
    expected = {
        source: ({"status": "dropped"} if source in banned else {"status": 200, "body": "crowdsec-https-control"})
        for _destination, source in targets()
    }
    while time.monotonic() < deadline:
        result = docker(
            "exec", container, "ip", "netns", "exec", "outside", "python3", "-c", PROBE, json.dumps(targets())
        )
        observed = json.loads(result.stdout)
        if observed == expected:
            return
        time.sleep(0.05)
    pytest.fail(
        "HTTPS packet state differs: "
        + repr({source: value for source, value in observed.items() if value != expected[source]})
    )


def process_id(container: str) -> str:
    pid = docker("exec", container, "cat", "/root/bouncer.pid").stdout.strip()
    assert pid.isdecimal()
    return pid


def wait_exited(container: str, pid: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if docker("exec", container, "python3", "-c", RUNNING, pid, check=False).returncode != 0:
            return
        time.sleep(0.05)
    pytest.fail(
        "Bouncer remained alive after terminal event: "
        + docker("exec", container, "cat", "/root/bouncer.log").stdout[-4000:]
    )


def dual_stack(initial: list[dict[str, object]]) -> BouncerOptions:
    return BouncerOptions(interval=True, set_only_intervals=True, initial_decisions=initial, dual_stack=True)


def test_stopped_bouncer_keeps_kernel_ttls_and_overlapping_host_bans(bouncer_target: str) -> None:
    expect_packets(bouncer_target, set())
    initial = []
    range_hosts, long_hosts = set(), set()
    for index, ipv6 in enumerate((False, True)):
        _family, _destination, protected, first, middle, last, _outside = addresses(ipv6)
        value = first + ("/126" if ipv6 else "/30")
        initial.extend(
            [decision(index * 3 + 1, value, "12s"), decision(index * 3 + 2, protected), decision(index * 3 + 3, middle)]
        )
        other = "fd00:767::a" if ipv6 else "198.51.100.10"
        range_hosts.update((first, middle, other, last))
        long_hosts.add(middle)
    start_bouncer(bouncer_target, "ip", "198.51.100.8/30", "192.0.2.2", dual_stack(initial))
    expect_packets(bouncer_target, range_hosts)
    pid = process_id(bouncer_target)
    docker("exec", bouncer_target, "kill", "-TERM", pid)
    wait_exited(bouncer_target, pid)
    expect_packets(bouncer_target, range_hosts, timeout=2)
    expect_packets(bouncer_target, long_hosts, timeout=16)
    assert docker("exec", bouncer_target, "python3", "-c", RUNNING, pid, check=False).returncode != 0
    launch_bouncer(bouncer_target)
    expect_packets(bouncer_target, long_hosts)


def test_failed_ipv4_commit_exits_and_startup_recovers_consumed_ipv6_frame(bouncer_target: str) -> None:
    expect_packets(bouncer_target, set())
    initial = [
        decision(1, "198.51.100.8"),
        decision(2, "192.0.2.2"),
        decision(3, "fd00:767::8"),
        decision(4, "fd00:767::2"),
    ]
    start_bouncer(bouncer_target, "ip", "198.51.100.8", "192.0.2.2", dual_stack(initial))
    expect_packets(bouncer_target, {"198.51.100.8", "fd00:767::8"})
    generation = write_decisions(bouncer_target, [decision(5, "fd00:767::c")], pause=True)
    acknowledgement = """from pathlib import Path
import sys,time
p=Path('/root/stream-paused');deadline=time.monotonic()+5
while time.monotonic()<deadline:
 if p.exists() and p.read_text().strip()==sys.argv[1]:break
 time.sleep(.02)
else:raise RuntimeError('stream generation was not paused')
"""
    docker("exec", bouncer_target, "python3", "-c", acknowledgement, str(generation))
    pid = process_id(bouncer_target)
    try:
        docker("exec", bouncer_target, "nft", "delete", "table", "ip", TABLES["ip"])
    finally:
        docker("exec", bouncer_target, "rm", "/root/stream-pause")
    wait_exited(bouncer_target, pid)
    # The removed table is an injected fault. The unaffected family must keep its old ban.
    expect_packets(bouncer_target, {"fd00:767::8"})
    docker(
        "exec",
        "-i",
        bouncer_target,
        "nft",
        "-f",
        "-",
        input_text="""table ip praho_crowdsec4 {
set protected { type ipv4_addr; flags interval; elements = { 192.0.2.2 }; }
set bans { type ipv4_addr; flags interval,timeout; }
chain input { type filter hook input priority -10; policy accept;
ip saddr @protected return
ip saddr @bans drop
}
}
""",
    )
    launch_bouncer(bouncer_target)
    expect_packets(bouncer_target, {"198.51.100.8", "fd00:767::8", "fd00:767::c"})


def element_cardinality(value: object) -> int:
    if isinstance(value, str):
        ipaddress.ip_address(value)
        return 1
    assert isinstance(value, dict), value
    if "elem" in value:
        return element_cardinality(value["elem"]["val"])
    if "prefix" in value:
        prefix = value["prefix"]
        return ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=True).num_addresses
    assert set(value) == {"range"}, value
    first, last = (int(ipaddress.ip_address(address)) for address in value["range"])
    assert first <= last
    return last - first + 1


def test_ten_thousand_disjoint_decisions_fit_one_atomic_kernel_update(bouncer_target: str) -> None:
    """Check live enforcement, then count the unchanged kernel state with its writer stopped."""
    expect_packets(bouncer_target, set())
    initial = [
        decision(1, "198.51.100.8"),
        decision(2, "192.0.2.2"),
        decision(3, "fd00:767::8"),
        decision(4, "fd00:767::2"),
    ]
    base = int(ipaddress.ip_address("198.18.0.0"))
    initial.extend(decision(index + 5, str(ipaddress.ip_address(base + index * 2))) for index in range(9996))
    assert len(initial) == 10000 and len({item["id"] for item in initial}) == 10000
    assert len(json.dumps(initial).encode()) < 8 * 1024 * 1024
    try:
        start_bouncer(bouncer_target, "ip", "198.51.100.8", "192.0.2.2", dual_stack(initial))
    except pytest.fail.Exception:
        diagnostics = """from collections import deque
from pathlib import Path
with Path('/root/bouncer.log').open() as source:
 print(''.join(deque((line[:2000] for line in source if 'level=error' in line or 'level=fatal' in line),maxlen=10)))
for name in ('wmem_max','wmem_default'):
 p=Path('/proc/sys/net/core')/name
 print(name+': '+(p.read_text().strip() if p.exists() else 'unavailable'))
"""
        pytest.fail(
            "10,000-decision capacity failed: " + docker("exec", bouncer_target, "python3", "-c", diagnostics).stdout
        )
    expect_packets(bouncer_target, {"198.51.100.8", "fd00:767::8"})
    # Large nft dumps are multipart: concurrent replacements can produce an inconsistent
    # listing, including inverted ranges, despite valid point lookups and packet enforcement.
    # The qualified TERM path preserves kernel elements and their original timeouts. Quiesce
    # that writer before the strict full-cardinality snapshot; never accept malformed ranges.
    pid = process_id(bouncer_target)
    docker("exec", bouncer_target, "kill", "-TERM", pid)
    wait_exited(bouncer_target, pid)
    for family, expected in (("ip", 9998), ("ip6", 2)):
        observed = json.loads(
            docker("exec", bouncer_target, "nft", "--json", "list", "set", family, TABLES[family], "bans").stdout
        )
        sets = [item["set"] for item in observed["nftables"] if "set" in item]
        assert len(sets) == 1
        assert sum(element_cardinality(item) for item in sets[0].get("elem", [])) == expected
    for address in (str(ipaddress.ip_address(base)), str(ipaddress.ip_address(base + 9995 * 2))):
        assert (
            docker(
                "exec",
                bouncer_target,
                "nft",
                "get",
                "element",
                "ip",
                TABLES["ip"],
                "bans",
                "{",
                address,
                "}",
                check=False,
            ).returncode
            == 0
        )
    assert (
        docker(
            "exec",
            bouncer_target,
            "nft",
            "get",
            "element",
            "ip",
            TABLES["ip"],
            "bans",
            "{",
            str(ipaddress.ip_address(base + 1)),
            "}",
            check=False,
        ).returncode
        != 0
    )
    expect_packets(bouncer_target, {"198.51.100.8", "fd00:767::8"})
