"""Actual Portal events traverse the shared role, engine, LAPI and packet filter."""

from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from test_crowdsec_bouncer_docker import assert_reachable, fetch, put
from test_crowdsec_role_docker import _package
from test_ssh_hardening_docker import ROOT, docker, harden, ssh, ssh_target

__all__ = ["ssh_target"]
pytestmark = pytest.mark.docker
EVENT_PATH = "/var/log/praho/portal/portal-auth.jsonl"
PSEUDONYM = "e" * 64
READ_ALERTS = """import json,sqlite3
from contextlib import closing
with closing(sqlite3.connect('file:/var/lib/crowdsec/data/crowdsec.db?mode=ro',uri=True)) as c:
 rows=c.execute("SELECT scenario,source_value,simulated FROM alerts WHERE scenario LIKE 'praho/portal-%'").fetchall()
 assert 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' not in '\\n'.join(c.iterdump()), 'Account pseudonym was stored in LAPI event metadata'
 print(json.dumps(rows))
"""
HTTPS = """import http.server,socket,ssl,threading
class Web(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'crowdsec-https-control')
 def log_message(self,*args): pass
class Web6(http.server.ThreadingHTTPServer): address_family=socket.AF_INET6
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/root/portal-cert.pem','/root/portal-key.pem')
for cls,host in ((http.server.ThreadingHTTPServer,'192.0.2.1'),(Web6,'fd00:767::1')):
 server=cls((host,443),Web);server.socket=context.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
"""


def _emit(target: str, address: str, event: str, reason: str, count: int) -> None:
    timestamp = docker("exec", target, "date", "-u", "+%Y-%m-%dT%H:%M:%SZ").stdout.strip()
    payload = {
        "schema": 1,
        "timestamp": timestamp,
        "event": event,
        "ip": address,
        "account": PSEUDONYM,
        "reason": reason,
    }
    docker("exec", "-i", target, "tee", "-a", EVENT_PATH, input_text=(json.dumps(payload) + "\n") * count)


def _alerts(target: str, required: set[tuple[str, str, int]]) -> list[list[object]]:
    deadline = time.monotonic() + 30
    while True:
        rows = json.loads(docker("exec", target, "python3", "-I", "-c", READ_ALERTS).stdout)
        if required <= {tuple(row) for row in rows}:
            return rows
        if time.monotonic() >= deadline:
            explanation = docker(
                "exec",
                target,
                "cscli",
                "-o",
                "json",
                "explain",
                "--file",
                EVENT_PATH,
                "--type",
                "praho_portal_auth",
                check=False,
            )
            logs = docker("exec", target, "tail", "-n", "80", "/var/log/crowdsec.log", check=False)
            pytest.fail(
                f"Missing Portal alerts: {rows!r}\n{explanation.stdout[-12000:]}\n{explanation.stderr[-2000:]}\n{logs.stdout[-8000:]}"
            )
        time.sleep(0.1)


@pytest.mark.parametrize("ssh_target", ["26.04"], indirect=True)
def test_portal_role_detects_throttles_locally_and_enforces_five_minute_bans(  # noqa: PLR0915 -- one native Portal adoption, simulation and enforcement trajectory
    ssh_target: str, tmp_path: Path
) -> None:
    target = ssh_target
    lock = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    architecture = docker("exec", target, "dpkg", "--print-architecture").stdout.strip()
    docker("cp", str(ROOT / "deploy/crowdsec"), f"{target}:/work/crowdsec")
    docker("exec", target, "mkdir", "-p", "/work/packages", "/work/repository/build/crowdsec-patched")
    for name in ("crowdsec", "crowdsec-firewall-bouncer-nftables"):
        package = _package(lock, architecture, name, tmp_path)
        docker("cp", str(package), f"{target}:/work/packages/{package.name}")
    for filename in (lock["bouncer_build"]["binaries"][architecture]["file"], lock["bouncer_build"]["notices"]["file"]):
        docker("cp", str(ROOT / filename), f"{target}:/work/repository/{filename}")
    docker("exec", target, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/root/crowdsec-controller")
    public_key = docker("exec", target, "cat", "/root/crowdsec-controller.pub").stdout.strip()
    hardened = harden(target, extra={"ssh_crowdsec_gateway_enabled": True})
    assert hardened.returncode == 0, hardened.stdout[-7000:] + hardened.stderr[-1000:]
    docker("exec", target, "apt-get", "update")
    docker("exec", target, "apt-get", "install", "-y", "--no-install-recommends", "gnupg", "openssl")
    docker("exec", target, "useradd", "--system", "--no-create-home", "praho-portal")
    docker("exec", target, "mkdir", "-p", "/var/log/praho/portal", "/var/log/caddy")
    docker("exec", target, "chown", "praho-portal:praho-portal", "/var/log/praho/portal")
    docker("exec", target, "chmod", "0700", "/var/log/praho/portal")
    docker("exec", target, "touch", "/var/log/caddy/portal-access.log")
    variables = {
        "crowdsec_enabled": True,
        "crowdsec_simulation": True,
        "crowdsec_host_kind": "portal",
        "crowdsec_protected_cidrs": ["198.51.100.7/32", "fd00:767::7/128"],
        "crowdsec_gateway_public_key": public_key,
        "crowdsec_local_reader_user": "ssh-test-user",
        "crowdsec_staging_local_source": True,
        "crowdsec_artifact_lock_path": "/work/crowdsec/artifacts.lock.json",
        "crowdsec_repository_root": "/work/repository",
        "crowdsec_package_cache": "/work/packages",
    }
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": True,
            "become": True,
            "vars": variables,
            "roles": ["crowdsec"],
        }
    ]

    def apply() -> str:
        put(target, "/work/portal-crowdsec.yml", yaml.safe_dump(play))
        result = docker(
            "exec",
            "-w",
            "/work",
            target,
            "/opt/controller/bin/ansible-playbook",
            "-i",
            "localhost,",
            "portal-crowdsec.yml",
            check=False,
        )
        assert result.returncode == 0, result.stdout[-12000:] + result.stderr[-2000:]
        return result.stdout

    apply()
    assert ssh(target, 9876, "operator").stdout.strip() == "0"
    assert docker("exec", target, "stat", "-c", "%U:%a", EVENT_PATH).stdout.strip() == "praho-portal:600"
    assert "changed=0" in apply()
    _emit(target, "198.51.100.9", "auth_failure", "credentials", 6)
    _emit(target, "fd00:767::9", "throttle_refusal", "mfa", 3)
    _alerts(target, {("praho/portal-auth-bf", "198.51.100.9", 1), ("praho/portal-auth-throttle", "fd00:767::9", 1)})
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer", check=False).returncode != 0
    simulated_alerts = json.loads(docker("exec", target, "cscli", "-o", "json", "decisions", "list").stdout)
    assert simulated_alerts and all(alert["simulated"] is True for alert in simulated_alerts)
    for family, table in (("ip", "praho_crowdsec4"), ("ip6", "praho_crowdsec6")):
        rules = json.loads(docker("exec", target, "nft", "-j", "list", "set", family, table, "bans").stdout)
        assert all(not row.get("set", {}).get("elem") for row in rules["nftables"])

    variables["crowdsec_simulation"] = False
    variables["crowdsec_policy_preview"] = True
    preview = apply()
    digest = preview.split("PRAHO_CROWDSEC_CONFIGURATION_DIGEST=", 1)[1].split('"', 1)[0].strip()
    variables.update(
        crowdsec_policy_preview=False,
        crowdsec_enforcement_qualified=True,
        crowdsec_expected_configuration_digest=digest,
    )
    apply()
    assert docker("exec", target, "systemctl", "is-active", "crowdsec-firewall-bouncer").stdout.strip() == "active"
    config = json.loads(docker("exec", target, "cat", "/etc/praho-crowdsec/config.json").stdout)
    request = {
        "protocol": 1,
        "request_id": str(uuid4()),
        "installation_id": config["installation_id"],
        "configuration_digest": config["configuration_digest"],
        "operation": "health",
        "payload": {},
    }
    response = docker(
        "exec",
        "-i",
        target,
        "runuser",
        "-u",
        "ssh-test-user",
        "--",
        "sudo",
        "-n",
        "/usr/local/libexec/praho-crowdsec-gateway",
        input_text=json.dumps(request),
        check=False,
    )
    assert response.returncode == 0, response.stderr
    assert json.loads(response.stdout)["result"]["configuration"]["qualified"] is True

    docker("exec", target, "ufw", "allow", "443/tcp")
    docker(
        "exec",
        "-i",
        target,
        "bash",
        "-euo",
        "pipefail",
        "-s",
        input_text="""ip netns add outside
ip link add wan type veth peer name peer
ip link set peer netns outside
ip address add 192.0.2.1/24 dev wan
ip -6 address add fd00:767::1/64 dev wan nodad
ip link set wan up
ip netns exec outside ip link set lo up
ip netns exec outside ip address add 192.0.2.2/24 dev peer
ip netns exec outside ip -6 address add fd00:767::2/64 dev peer nodad
for address in 7 8 9; do
 ip netns exec outside ip address add "198.51.100.$address/32" dev peer
 ip netns exec outside ip -6 address add "fd00:767::$address/128" dev peer nodad
done
ip netns exec outside ip link set peer up
ip route add 198.51.100.0/24 via 192.0.2.2
openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/portal-key.pem -out /root/portal-cert.pem -days 1 -subj /CN=portal-control
""",
    )
    docker("exec", "-d", target, "python3", "-I", "-c", HTTPS)
    for destination, source in (
        ("192.0.2.1", "198.51.100.8"),
        ("fd00:767::1", "fd00:767::8"),
        ("192.0.2.1", "198.51.100.7"),
        ("fd00:767::1", "fd00:767::7"),
    ):
        assert_reachable(target, destination, source)
    for event, reason in (
        ("protection_degraded", "upstream_unavailable"),
        ("protection_degraded", "policy_refusal"),
        ("password_reset_request", "password_reset"),
    ):
        _emit(target, "198.51.100.11", event, reason, 8)
    _emit(target, "198.51.100.8", "auth_failure", "credentials", 6)
    _emit(target, "fd00:767::8", "mfa_failure", "second_factor", 6)
    _emit(target, "198.51.100.7", "auth_failure", "credentials", 6)
    _emit(target, "fd00:767::7", "throttle_refusal", "reset", 3)
    rows = _alerts(target, {("praho/portal-auth-bf", "198.51.100.8", 0), ("praho/portal-auth-bf", "fd00:767::8", 0)})
    assert not any(row[1] == "198.51.100.11" for row in rows), rows
    verify_expiry = """import datetime,json,sqlite3
from contextlib import closing
now=datetime.datetime.now(datetime.UTC)
with closing(sqlite3.connect('file:/var/lib/crowdsec/data/crowdsec.db?mode=ro',uri=True)) as c:
 rows=c.execute("SELECT value,until FROM decisions WHERE scenario LIKE 'praho/portal-%' AND simulated=0 AND julianday(until) > julianday(?)",(now.isoformat(),)).fetchall()
 assert {row[0] for row in rows} == {'198.51.100.8','fd00:767::8'}, rows
 for _,until in rows:
  remaining=(datetime.datetime.fromisoformat(until.replace('Z','+00:00'))-now).total_seconds()
  assert 240 < remaining <= 300, remaining
 print(json.dumps({'active':len(rows)}))
"""
    docker("exec", target, "python3", "-I", "-c", verify_expiry)
    deadline = time.monotonic() + 20
    while fetch(target, "192.0.2.1", "198.51.100.8").returncode == 0:
        assert time.monotonic() < deadline, "IPv4 Portal authentication ban did not reach the packet filter"
        time.sleep(0.1)
    assert fetch(target, "fd00:767::1", "fd00:767::8").returncode == 2
    assert_reachable(target, "192.0.2.1", "198.51.100.7")
    assert_reachable(target, "fd00:767::1", "fd00:767::7")
    assert_reachable(target, "192.0.2.1", "198.51.100.9")
    assert_reachable(target, "fd00:767::1", "fd00:767::9")
    assert ssh(target, 9876, "operator").stdout.strip() == "0"
