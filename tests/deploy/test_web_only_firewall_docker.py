"""Native web-only firewall access and recovery across the supported SSH handoff."""

from __future__ import annotations

import json
import select
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
import yaml
from test_ssh_hardening_docker import DOCKER, ROOT, docker, harden, ssh, ssh_target

from apps.provisioning.virtualmin_security_policy import verify_filter

__all__ = ["ssh_target"]  # Register the shared parametrized fixture with pytest.

pytestmark = pytest.mark.docker


@contextmanager
def denied_panel_probe(container: str) -> Iterator[None]:
    """Catch even brief ACCEPT windows against the real dual-stack panel listener."""
    script = """import json,select,socket,sys,threading,time
stop=threading.Event()
exposed=[]
attempts={'ipv4':0,'ipv6':0}
def probe(label,address):
    while not stop.is_set():
        attempts[label]+=1
        try:
            with socket.create_connection((address,10000),timeout=0.03):
                exposed.append(label)
                stop.set()
        except OSError:
            pass
        time.sleep(0.001)
threads=[threading.Thread(target=probe,args=item) for item in
         (('ipv4','172.31.176.1'),('ipv6','fd00:176::1'))]
for thread in threads:
    thread.start()
print('ready',flush=True)
while not stop.is_set() and not select.select([sys.stdin],[],[],0.01)[0]:
    pass
stop.set()
for thread in threads:
    thread.join()
print(json.dumps({'attempts':attempts,'exposed':exposed}),flush=True)
sys.exit(bool(exposed))
"""
    with subprocess.Popen(  # noqa: S603 -- disposable fixture container and fixed native probe
        [DOCKER, "exec", "-i", container, "ip", "netns", "exec", "outside", "python3", "-u", "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        assert process.stdout is not None
        assert select.select([process.stdout], [], [], 10)[0], "Denied-peer probe did not start"
        assert process.stdout.readline().strip() == "ready"
        try:
            yield
        finally:
            output, error = process.communicate(input="stop\n", timeout=10)
            verdict = json.loads(output)
            assert process.returncode == 0, (verdict, error)
            assert verdict["exposed"] == [], verdict
            assert all(count > 0 for count in verdict["attempts"].values()), verdict


def test_web_only_firewall_converges_across_the_real_ssh_handoff(ssh_target: str) -> None:  # noqa: C901, PLR0915 -- one real access/recovery trajectory shares the isolated node
    container = ssh_target
    play = {
        "name": "Prove web-only policy",
        "hosts": "all",
        "gather_facts": False,
        "become": True,
        "roles": ["virtualmin-web-only"],
        "vars": {
            "node_admin_allowed_cidrs": ["127.0.0.1/32"],
            "ssh_probe_identity_file": "/root/controller",
            "ssh_probe_known_hosts_file": "/root/known_hosts",
        },
    }
    docker("exec", "-i", container, "tee", "/work/firewall-test.yml", input_text=yaml.safe_dump([play]))
    # Saved broad allows exist while the firewall is inactive: numbered status cannot discover them.
    for port in ("22/tcp", "25/tcp", "53/udp", "20000/tcp"):
        docker("exec", container, "ufw", "allow", port)
    docker("exec", container, "ufw", "route", "allow", "in", "on", "eth0", "to", "any", "port", "25", "proto", "tcp")

    def apply_firewall():
        return docker(
            "exec",
            "-w",
            "/work",
            container,
            "/opt/controller/bin/ansible-playbook",
            "-i",
            "test-inventory.json",
            "firewall-test.yml",
            check=False,
        )

    early = apply_firewall()
    assert early.returncode == 0, early.stdout[-9000:] + early.stderr[-1000:]
    assert ssh(container, 22).stdout.strip() == "0"
    first_rules = docker("exec", container, "ufw", "show", "added").stdout
    assert "ufw allow 25/tcp" not in first_rules
    assert "ufw allow 53/udp" not in first_rules
    assert "ufw allow 22/tcp\n" not in first_rules
    assert "ufw route allow" not in first_rules
    moved = harden(container)
    assert moved.returncode == 0, moved.stdout[-9000:] + moved.stderr[-1000:]
    docker(
        "exec",
        container,
        "/opt/controller/bin/python",
        "-c",
        "import json; p='/work/test-inventory.json'; v=json.load(open(p)); v['all']['children']['praho']['hosts']['target']['ansible_port']=9876; open(p,'w').write(json.dumps(v))",
    )
    # Imported UFW defaults must not flush another owner's routing/NAT chains.
    docker("exec", container, "sed", "-i", "s/^MANAGE_BUILTINS=.*/MANAGE_BUILTINS=yes/", "/etc/default/ufw")
    for executable in ("iptables", "ip6tables"):
        docker("exec", container, executable, "-N", "other-router")
        docker("exec", container, executable, "-A", "FORWARD", "-j", "other-router")
        docker("exec", container, executable, "-t", "nat", "-N", "other-nat")
        docker("exec", container, executable, "-t", "nat", "-A", "PREROUTING", "-j", "other-nat")
    final = apply_firewall()
    assert final.returncode == 0, final.stdout[-9000:] + final.stderr[-1000:]
    again = apply_firewall()
    assert again.returncode == 0, again.stdout[-9000:] + again.stderr[-1000:]
    assert "changed=0" in again.stdout, again.stdout[-3000:]
    rules = docker("exec", container, "ufw", "show", "added").stdout
    assert "port 22 " not in rules
    assert "port 9876 proto tcp" in rules
    assert "port 10000 proto tcp" in rules
    before = docker("exec", container, "cat", "/etc/ufw/before.rules").stdout
    before6 = docker("exec", container, "cat", "/etc/ufw/before6.rules").stdout
    assert "--dport 5353" not in before + before6
    assert "--sport 67 --dport 68" in before
    assert "--sport 547" in before6 and "--dport 546" in before6
    for executable, ipv6 in (("iptables-save", False), ("ip6tables-save", True)):
        verify_filter(docker("exec", container, executable, "-t", "filter").stdout, ["127.0.0.1/32"], ipv6=ipv6)

    def verify_packet_policy():
        # Actual packets traverse a separate network namespace, not loopback's unconditional exception.
        docker("exec", container, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
        docker("exec", container, "ip", "netns", "add", "outside")
        docker("exec", container, "ip", "link", "add", "p768-host", "type", "veth", "peer", "name", "p768-peer")
        docker("exec", container, "ip", "link", "set", "p768-peer", "netns", "outside")
        for family, host_address, peer_address in (
            ("-4", "172.31.176.1/30", "172.31.176.2/30"),
            ("-6", "fd00:176::1/64", "fd00:176::2/64"),
        ):
            address_flags = ("nodad",) if family == "-6" else ()
            docker(
                "exec",
                container,
                "ip",
                family,
                "address",
                "add",
                host_address,
                "dev",
                "p768-host",
                *address_flags,
            )
            docker(
                "exec",
                container,
                "ip",
                "netns",
                "exec",
                "outside",
                "ip",
                family,
                "address",
                "add",
                peer_address,
                "dev",
                "p768-peer",
                *address_flags,
            )
        docker("exec", container, "ip", "link", "set", "p768-host", "up")
        docker("exec", container, "ip", "netns", "exec", "outside", "ip", "link", "set", "lo", "up")
        docker("exec", container, "ip", "netns", "exec", "outside", "ip", "link", "set", "p768-peer", "up")
        listeners = """import socket, threading, time
def serve(family, port):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
    listener.listen()
    while True:
        connection, _ = listener.accept()
        connection.close()
for family in (socket.AF_INET, socket.AF_INET6):
    for port in (80, 443, 10000, 25):
        threading.Thread(target=serve, args=(family, port), daemon=True).start()
time.sleep(600)
"""
        docker("exec", "-d", container, "python3", "-c", listeners)
        ready = """import socket,time
deadline=time.monotonic()+10
for address in ('127.0.0.1','::1'):
    for port in (80,443,10000,25):
        while True:
            try:
                connection=socket.create_connection((address,port),timeout=0.2)
                connection.close()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
"""
        docker("exec", container, "python3", "-c", ready)
        probe = "import socket,sys; connection=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1); connection.close()"

        def outside(address: str, port: int) -> subprocess.CompletedProcess[str]:
            return docker(
                "exec",
                container,
                "ip",
                "netns",
                "exec",
                "outside",
                "python3",
                "-c",
                probe,
                address,
                str(port),
                check=False,
            )

        for address in ("172.31.176.1", "fd00:176::1"):
            for public_port in (80, 443):
                assert outside(address, public_port).returncode == 0
            assert outside(address, 10000).returncode != 0
            assert outside(address, 25).returncode != 0
        # Positive control: the blocked administrative/mail sockets really are listening.
        for local in ("127.0.0.1", "::1"):
            for port in (10000, 25):
                assert docker("exec", container, "python3", "-c", probe, local, str(port)).returncode == 0
        play["vars"]["node_admin_allowed_cidrs"] = ["127.0.0.1/32", "172.31.176.2/32", "fd00:176::2/128"]
        docker("exec", "-i", container, "tee", "/work/firewall-test.yml", input_text=yaml.safe_dump([play]))
        admitted = apply_firewall()
        assert admitted.returncode == 0, admitted.stdout[-7000:]
        for address in ("172.31.176.1", "fd00:176::1"):
            assert outside(address, 10000).returncode == 0
            assert outside(address, 25).returncode != 0
        play["vars"]["node_admin_allowed_cidrs"] = ["127.0.0.1/32"]
        docker("exec", "-i", container, "tee", "/work/firewall-test.yml", input_text=yaml.safe_dump([play]))
        revoked = apply_firewall()
        assert revoked.returncode == 0, revoked.stdout[-7000:]
        for address in ("172.31.176.1", "fd00:176::1"):
            assert outside(address, 10000).returncode != 0
            assert outside(address, 80).returncode == 0

        # Final-only probes missed UFW's stop/start default-policy and reload windows.
        with denied_panel_probe(container):
            for _ in range(2):
                converged = apply_firewall()
                assert converged.returncode == 0, converged.stdout[-7000:]
                assert "changed=0" in converged.stdout, converged.stdout[-3000:]

        # A pre-user ACCEPT bypass is removed by the vendor-baseline convergence.
        docker(
            "exec",
            container,
            "python3",
            "-c",
            "from pathlib import Path; p=Path('/etc/ufw/before.rules'); lines=p.read_text().splitlines(); lines.insert(lines.index('COMMIT'), '-A ufw-before-input -p tcp --dport 25 -j ACCEPT'); p.write_text(chr(10).join(lines)+chr(10))",
        )
        docker("exec", container, "ufw", "reload")
        assert outside("172.31.176.1", 25).returncode == 0
        repaired = apply_firewall()
        assert repaired.returncode == 0, repaired.stdout[-7000:]
        assert outside("172.31.176.1", 25).returncode != 0
        return outside

    outside = verify_packet_policy()

    def verify_hook_and_recovery():
        # UFW reload cannot safely take ownership of an unrelated direct INPUT rule.
        docker("exec", container, "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "25", "-j", "ACCEPT")
        assert outside("172.31.176.1", 25).returncode == 0
        foreign_rule = apply_firewall()
        assert foreign_rule.returncode != 0
        assert "Foreign INPUT rules require manual reviewed preparation" in foreign_rule.stdout
        assert outside("172.31.176.1", 25).returncode == 0
        docker("exec", container, "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "25", "-j", "ACCEPT")
        assert outside("172.31.176.1", 25).returncode != 0

        # Rejecting a newly found hook must not execute it as part of rescue rollback.
        hook = "/etc/ufw/after.init"
        docker(
            "exec",
            "-i",
            container,
            "tee",
            hook,
            input_text="#!/bin/sh\niptables -I INPUT -p tcp --dport 25 -j ACCEPT\n",
        )
        docker("exec", container, "chmod", "700", hook)
        rejected_hook = apply_firewall()
        assert rejected_hook.returncode != 0
        assert "hooks require explicit review" in rejected_hook.stdout
        assert outside("172.31.176.1", 25).returncode != 0
        docker("exec", container, "rm", hook)

        # A failed immediate rollback retains the timer, whose real service can finish recovery.
        role_tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/virtualmin-web-only/tasks/main.yml").read_text())
        guarded = next(task for task in role_tasks if task.get("name") == "Converge and prove administrative access")
        applied_index = next(
            index
            for index, task in enumerate(guarded["block"])
            if task["name"] == "Apply the complete reviewed firewall policy"
        )
        guarded["block"].insert(
            applied_index + 1,
            {"name": "Inject controller verification failure", "ansible.builtin.command": {"argv": ["false"]}},
        )
        guarded["rescue"][0]["ansible.builtin.command"]["argv"] = ["false"]
        docker(
            "exec",
            "-i",
            container,
            "tee",
            "/work/roles/virtualmin-web-only/tasks/main.yml",
            input_text=yaml.safe_dump(role_tasks),
        )
        play["vars"]["node_admin_allowed_cidrs"] = ["127.0.0.1/32", "192.0.2.77/32"]
        docker("exec", "-i", container, "tee", "/work/firewall-test.yml", input_text=yaml.safe_dump([play]))
        docker("exec", container, "sed", "-i", "s/^MANAGE_BUILTINS=.*/MANAGE_BUILTINS=yes/", "/etc/default/ufw")
        original_defaults = docker("exec", container, "cat", "/etc/default/ufw").stdout
        interrupted = apply_firewall()
        assert interrupted.returncode != 0
        token = docker("exec", container, "cat", "/run/praho-ssh-transition.lock/owner").stdout.strip()
        timer = f"praho-firewall-{token}.timer"
        assert docker("exec", container, "systemctl", "is-active", timer).stdout.strip() == "active"
        assert "192.0.2.77" in docker("exec", container, "ufw", "show", "added").stdout
        docker("exec", container, "systemctl", "start", f"praho-firewall-{token}.service")
        recovery_finished = """from pathlib import Path
import sys,time
state=Path(sys.argv[1])
deadline=time.monotonic()+45
while state.read_text() == 'pending' and time.monotonic() < deadline:
    time.sleep(0.1)
assert state.read_text() == 'rolled-back', state.read_text()
"""
        docker("exec", container, "python3", "-c", recovery_finished, f"/var/lib/praho-firewall/{token}/state")
        assert docker("exec", container, "cat", f"/var/lib/praho-firewall/{token}/state").stdout == "rolled-back"
        assert "192.0.2.77" not in docker("exec", container, "ufw", "show", "added").stdout
        assert ssh(container, 9876).stdout.strip() == "0"
        assert docker("exec", container, "cat", "/etc/default/ufw").stdout == original_defaults
        for executable in ("iptables", "ip6tables"):
            assert "-A FORWARD -j other-router" in docker("exec", container, executable, "-S", "FORWARD").stdout
            assert (
                "-A PREROUTING -j other-nat"
                in docker("exec", container, executable, "-t", "nat", "-S", "PREROUTING").stdout
            )
            assert "praho-" not in docker("exec", container, executable, "-S", "INPUT").stdout

    with denied_panel_probe(container):
        verify_hook_and_recovery()
