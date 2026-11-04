"""Range boundaries and decision lifecycles against the candidate's real binary."""

from __future__ import annotations

import json
import time

import pytest
from test_crowdsec_bouncer_docker import (
    TABLES,
    BouncerOptions,
    assert_reachable,
    bouncer_image,
    bouncer_package,
    bouncer_target,
    fetch,
    launch_bouncer,
    start_bouncer,
    write_decisions,
)
from test_ssh_hardening_docker import docker

pytestmark = pytest.mark.docker
# Pytest registers these imported fixtures and their dependencies in this module.
__all__ = ["bouncer_image", "bouncer_package", "bouncer_target"]


def decision(identifier: int, value: str, duration: str = "5m") -> dict[str, object]:
    return {
        "id": identifier,
        "duration": duration,
        "origin": "cscli",
        "scenario": "qualification",
        "scope": "Range" if "/" in value else "Ip",
        "type": "ban",
        "value": value,
    }


def addresses(ipv6: bool) -> tuple[str, str, str, str, str, str, str]:
    if ipv6:
        return "ip6", "fd00:767::1", "fd00:767::2", "fd00:767::8", "fd00:767::9", "fd00:767::b", "fd00:767::c"
    return "ip", "192.0.2.1", "192.0.2.2", "198.51.100.8", "198.51.100.9", "198.51.100.11", "198.51.100.12"


def expect_policy(
    container: str, destination: str, *, reachable: tuple[str, ...], banned: tuple[str, ...], timeout: float = 8
) -> None:
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        last = {address: fetch(container, destination, address) for address in (*reachable, *banned)}
        if all(last[address].returncode == 0 for address in reachable) and all(
            last[address].returncode == 2 for address in banned
        ):
            for address in reachable:
                assert json.loads(last[address].stdout) == {"status": 200, "body": "crowdsec-https-control"}
            return
        time.sleep(0.05)
    pytest.fail(
        "Packet policy did not converge: "
        + repr({key: (value.returncode, value.stdout, value.stderr) for key, value in last.items()})
    )


@pytest.mark.parametrize("ipv6", [False, True])
def test_cidr_has_exact_first_last_and_outside_boundaries(bouncer_target: str, ipv6: bool) -> None:
    family, destination, protected, first, middle, last, outside = addresses(ipv6)
    before = "fd00:767::7" if ipv6 else "198.51.100.7"
    for source in (protected, before, first, middle, last, outside):
        assert_reachable(bouncer_target, destination, source)
    start_bouncer(bouncer_target, family, first + ("/126" if ipv6 else "/30"), protected)
    expect_policy(bouncer_target, destination, reachable=(protected, before, outside), banned=(first, middle, last))


@pytest.mark.parametrize("ipv6", [False, True])
def test_revoke_range_preserves_overlapping_host_then_delete(bouncer_target: str, ipv6: bool) -> None:
    family, destination, protected, first, middle, last, outside = addresses(ipv6)
    for source in (protected, first, middle, last, outside):
        assert_reachable(bouncer_target, destination, source)
    start_bouncer(bouncer_target, family, first + ("/126" if ipv6 else "/30"), protected)
    expect_policy(bouncer_target, destination, reachable=(protected, outside), banned=(first, middle, last))
    write_decisions(bouncer_target, [decision(3, middle)], [{"id": 1}])
    expect_policy(bouncer_target, destination, reachable=(protected, first, last, outside), banned=(middle,))
    write_decisions(bouncer_target, [], [{"id": 3}])
    expect_policy(bouncer_target, destination, reachable=(protected, first, middle, last, outside), banned=())


@pytest.mark.parametrize("ipv6", [False, True])
def test_range_expiry_preserves_later_independent_ban(bouncer_target: str, ipv6: bool) -> None:
    family, destination, protected, first, middle, last, outside = addresses(ipv6)
    for source in (protected, first, middle, last, outside):
        assert_reachable(bouncer_target, destination, source)
    value = first + ("/126" if ipv6 else "/30")
    start_bouncer(
        bouncer_target,
        family,
        value,
        protected,
        BouncerOptions(initial_decisions=[decision(1, value, "8s"), decision(2, protected)]),
    )
    expect_policy(bouncer_target, destination, reachable=(protected, outside), banned=(first, middle, last))
    write_decisions(bouncer_target, [decision(3, outside)])
    expect_policy(bouncer_target, destination, reachable=(protected,), banned=(first, middle, outside))
    expect_policy(
        bouncer_target, destination, reachable=(protected, first, middle, last), banned=(outside,), timeout=12
    )


@pytest.mark.parametrize("ipv6", [False, True])
def test_restart_uses_current_source_snapshot_without_reviving_revoke(bouncer_target: str, ipv6: bool) -> None:
    family, destination, protected, first, middle, last, outside = addresses(ipv6)
    for source in (protected, first, middle, last, outside):
        assert_reachable(bouncer_target, destination, source)
    start_bouncer(bouncer_target, family, first + ("/126" if ipv6 else "/30"), protected)
    expect_policy(bouncer_target, destination, reachable=(protected, outside), banned=(first, middle, last))
    write_decisions(bouncer_target, [decision(3, middle, "10s")], [{"id": 1}])
    expect_policy(bouncer_target, destination, reachable=(protected, first, last, outside), banned=(middle,))
    pid = docker("exec", bouncer_target, "cat", "/root/bouncer.pid").stdout.strip()
    assert pid.isdecimal()
    docker("exec", bouncer_target, "kill", "-TERM", pid)
    deadline = time.monotonic() + 5
    running = "from pathlib import Path; import sys; p=Path('/proc')/sys.argv[1]/'stat'; sys.exit(0 if p.exists() and p.read_text().split()[2] != 'Z' else 1)"
    while docker("exec", bouncer_target, "python3", "-c", running, pid, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            pytest.fail("Bouncer did not stop cleanly")
        time.sleep(0.05)
    launch_bouncer(bouncer_target)
    expect_policy(bouncer_target, destination, reachable=(protected, first, last, outside), banned=(middle,))
    expect_policy(
        bouncer_target, destination, reachable=(protected, first, middle, last, outside), banned=(), timeout=12
    )


def test_both_address_families_coexist_and_preserve_unrelated_policy(bouncer_target: str) -> None:
    controls = [addresses(False), addresses(True)]
    for _, destination, protected, first, middle, last, outside in controls:
        for source in (protected, first, middle, last, outside):
            assert_reachable(bouncer_target, destination, source)
    docker(
        "exec",
        "-i",
        bouncer_target,
        "nft",
        "-f",
        "-",
        input_text="table inet unrelated {\n set sentinel { type ipv4_addr; elements = { 203.0.113.17 }; }\n}\n",
    )
    original = docker("exec", bouncer_target, "nft", "-s", "list", "table", "inet", "unrelated").stdout
    initial = [
        decision(1, "198.51.100.8/30"),
        decision(2, "192.0.2.2"),
        decision(3, "fd00:767::8/126"),
        decision(4, "fd00:767::2"),
    ]
    start_bouncer(
        bouncer_target, "ip", "198.51.100.8/30", "192.0.2.2", BouncerOptions(initial_decisions=initial, dual_stack=True)
    )
    for _, destination, protected, first, middle, last, outside in controls:
        expect_policy(bouncer_target, destination, reachable=(protected, outside), banned=(first, middle, last))
    write_decisions(bouncer_target, [], [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}])
    for family, destination, protected, first, middle, last, outside in controls:
        expect_policy(bouncer_target, destination, reachable=(protected, first, middle, last, outside), banned=())
        observed = json.loads(
            docker("exec", bouncer_target, "nft", "-j", "list", "set", family, TABLES[family], "bans").stdout
        )
        assert all(not item.get("set", {}).get("elem") for item in observed["nftables"])
    assert docker("exec", bouncer_target, "nft", "-s", "list", "table", "inet", "unrelated").stdout == original


def test_elapsed_stream_durations_do_not_discard_valid_bans_or_become_permanent(bouncer_target: str) -> None:
    """LAPI rounds remaining TTL to seconds after selecting rows at stream start."""
    controls = [addresses(False), addresses(True)]
    for _, destination, protected, first, middle, last, outside in controls:
        for source in (protected, first, middle, last, outside):
            assert_reachable(bouncer_target, destination, source)
    initial = [
        decision(1, "198.51.100.8"),
        decision(2, "192.0.2.2"),
        decision(3, "fd00:767::8"),
        decision(4, "fd00:767::2"),
    ]
    start_bouncer(
        bouncer_target, "ip", "198.51.100.8", "192.0.2.2", BouncerOptions(initial_decisions=initial, dual_stack=True)
    )
    for _, destination, protected, first, middle, last, outside in controls:
        expect_policy(bouncer_target, destination, reachable=(protected, middle, last, outside), banned=(first,))
    write_decisions(
        bouncer_target,
        [
            decision(5, "198.51.100.12", "0s"),
            decision(6, "fd00:767::c", "-1s"),
            decision(7, "198.51.100.8/30"),
            decision(8, "fd00:767::8/126"),
        ],
    )
    for _, destination, protected, first, middle, last, outside in controls:
        expect_policy(bouncer_target, destination, reachable=(protected, outside), banned=(first, middle, last))
