"""Pinned local API behavior and audited gateway actions over restricted SSH."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from test_crowdsec_gateway_docker import INSTALLATION, NativeGateway, native_gateway
from test_ssh_hardening_docker import docker

from apps.common.crowdsec_transport import CrowdSecRPCError, remote_rpc

__all__ = ["native_gateway"]
pytestmark = pytest.mark.docker

LAPI_POST = """import json,sys,urllib.request
from pathlib import Path
credentials={}
for line in Path('/etc/crowdsec/local_api_credentials.yaml').read_text().splitlines():
 name,value=line.split(': ',1)
 credentials[name]=json.loads(value) if value.startswith('"') else value
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
auth=json.dumps({'machine_id':credentials['login'],'password':credentials['password'],'scenarios':[]}).encode()
with opener.open(urllib.request.Request('http://127.0.0.1:8080/v1/watchers/login',data=auth,headers={'Content-Type':'application/json'}),timeout=5) as response:
 token=json.load(response)['token']
with opener.open(urllib.request.Request('http://127.0.0.1:8080/v1/alerts',data=sys.stdin.buffer.read(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token}),timeout=5) as response:
 print(response.status)
"""
READ_DECISIONS = """import json,sqlite3,sys
with sqlite3.connect('file:/var/lib/crowdsec/data/crowdsec.db?mode=ro',uri=True) as connection:
 connection.execute('PRAGMA query_only=ON')
 rows=connection.execute('SELECT value,uuid,"until" FROM decisions WHERE scenario=? ORDER BY value',(sys.argv[1],)).fetchall()
 print(json.dumps(rows))
"""

REFRESH_POLICY = r"""import hashlib,json,sys
from pathlib import Path
path=Path('/etc/praho-crowdsec/config.json')
config=json.loads(path.read_text())
config['simulation']=json.loads(sys.argv[1])
config['policy']['simulation']=config['simulation']
config['policy']['managed_files']={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in config['policy']['managed_files']}
config['configuration_digest']=hashlib.sha256(json.dumps(config['policy'],sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
path.write_text(json.dumps(config));path.chmod(0o600)
for service in ('engine','bouncer'):
 stamp=Path('/var/lib/praho-crowdsec')/(service+'-applied.sha256')
 stamp.write_text(config['configuration_digest']+'\n');stamp.chmod(0o600)
print(config['configuration_digest'])
"""
PROXY = """from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from http.client import HTTPConnection
from pathlib import Path
import json,time
class Proxy(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def forward(self):
  size=int(self.headers.get('Content-Length','0'))
  if size>65536: self.send_error(413);return
  body=self.rfile.read(size)
  gate=Path('/root/crowdsec-pause-post')
  if self.command=='POST' and self.path=='/v1/alerts' and gate.exists():
   marker=json.loads(body)[0]['scenario']
   Path('/root/crowdsec-post-paused').write_text(marker)
   deadline=time.monotonic()+20
   while gate.exists() and time.monotonic()<deadline:time.sleep(.01)
   if gate.exists():self.send_error(504);return
  connection=HTTPConnection('127.0.0.1',8081,timeout=5)
  try:
   headers={key:self.headers[key] for key in ('Content-Type','Authorization','User-Agent') if key in self.headers}
   connection.request(self.command,self.path,body=body,headers=headers)
   response=connection.getresponse();payload=response.read(8388609)
   if len(payload)>8388608:self.send_error(502);return
   self.send_response(response.status)
   self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)))
   self.end_headers()
   try:self.wfile.write(payload)
   except (BrokenPipeError,ConnectionResetError):pass
  finally:connection.close()
 do_GET=forward
 do_POST=forward
 do_DELETE=forward
ThreadingHTTPServer(('127.0.0.1',8080),Proxy).serve_forever()
"""
KILL_HELPER = r"""from pathlib import Path
import os,signal
found=[]
for entry in Path('/proc').iterdir():
 if not entry.name.isdigit():continue
 try:arguments=(entry/'cmdline').read_bytes().split(b'\0')
 except (FileNotFoundError,ProcessLookupError,PermissionError):continue
 if arguments[:2]==[b'/usr/bin/python3',b'/usr/local/libexec/praho-crowdsec-gateway']:found.append(int(entry.name))
assert len(found)==1,'Expected one dispatched helper'
os.kill(found[0],signal.SIGKILL)
"""


def action_request(
    target: NativeGateway, operation: str, payload: dict[str, object], identifier: str | None = None
) -> bytes:
    return json.dumps(
        {
            "protocol": 1,
            "request_id": identifier or str(uuid4()),
            "installation_id": INSTALLATION,
            "configuration_digest": target.digest,
            "operation": operation,
            "payload": payload,
        }
    ).encode()


def native_ban(value: str = "198.51.200.9", **changes: object) -> dict[str, object]:
    return {
        "provenance_id": str(uuid4()),
        "revision": 1,
        "kind": "manual",
        "scope": "range" if "/" in value else "ip",
        "value": value,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        "source": None,
        **changes,
    }


def refresh_policy(target: NativeGateway, *, simulation: bool = False) -> NativeGateway:
    digest = docker(
        "exec", target.container, "python3", "-I", "-c", REFRESH_POLICY, json.dumps(simulation)
    ).stdout.strip()
    return NativeGateway(target.endpoint, target.container, digest)


def wait_file(target: NativeGateway, path: str, expected: str) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        result = docker("exec", target.container, "cat", path, check=False)
        if result.returncode == 0 and result.stdout.strip() == expected:
            return
        time.sleep(0.03)
    raise AssertionError("Native fault boundary was not reached")


@pytest.fixture(scope="module")
def action_gateway(active_lapi: NativeGateway) -> Iterator[NativeGateway]:
    # The proxy holds the original request once; all actual mutation semantics remain real LAPI.
    target = active_lapi
    docker("exec", target.container, "systemctl", "stop", "crowdsec-action-contract")
    prepare = """from pathlib import Path
source=Path('/etc/crowdsec/config.yaml').read_text()
assert '127.0.0.1:8080' in source
Path('/root/crowdsec-actions-api.yaml').write_text(source.replace('127.0.0.1:8080','127.0.0.1:8081'))
"""
    docker("exec", target.container, "python3", "-I", "-c", prepare)
    docker("exec", "-i", target.container, "tee", "/root/crowdsec-actions-proxy.py", input_text=PROXY)
    docker(
        "exec",
        target.container,
        "systemd-run",
        "--unit=crowdsec-actions-api",
        "/usr/bin/crowdsec",
        "-no-cs",
        "-c",
        "/root/crowdsec-actions-api.yaml",
    )
    docker(
        "exec",
        target.container,
        "systemd-run",
        "--unit=crowdsec-actions-proxy",
        "/usr/bin/python3",
        "-I",
        "/root/crowdsec-actions-proxy.py",
    )
    ready = """import socket,time
deadline=time.monotonic()+10
while time.monotonic()<deadline:
 try:
  for port in (8080,8081):socket.create_connection(('127.0.0.1',port),timeout=.2).close()
  break
 except OSError:time.sleep(.05)
else:raise RuntimeError('Native action API and proxy did not become ready')
"""
    docker("exec", target.container, "python3", "-I", "-c", ready)
    target = refresh_policy(target)
    try:
        yield target
    finally:
        docker("exec", target.container, "rm", "-f", "/root/crowdsec-pause-post")
        docker(
            "exec", target.container, "systemctl", "stop", "crowdsec-actions-proxy", "crowdsec-actions-api", check=False
        )


def test_native_gateway_create_receipt_idempotency_and_revoke(action_gateway: NativeGateway) -> None:
    target = action_gateway
    payload = native_ban()
    identifier = str(uuid4())
    raw = action_request(target, "ban_put", payload, identifier)
    first = remote_rpc(target.endpoint, raw)["result"]
    assert first["status"] == "succeeded" and first["evidence"] == "decision_present"
    assert datetime.fromisoformat(first["expires_at"]) <= datetime.fromisoformat(payload["expires_at"])
    again = remote_rpc(target.endpoint, raw)["result"]
    assert again["decision_ids"] == first["decision_ids"] and again["expires_at"] == first["expires_at"]
    native = json.loads(
        docker(
            "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
        ).stdout
    )
    assert len(native) == 1
    receipt = remote_rpc(target.endpoint, action_request(target, "receipt_get", {"request_id": identifier}))["result"]
    assert receipt["status"] == "succeeded" and receipt["payload_digest"] == first["payload_digest"]
    revoked = remote_rpc(
        target.endpoint,
        action_request(target, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None}),
    )["result"]
    assert revoked["status"] == "succeeded" and revoked["decision_ids"] == first["decision_ids"]
    assert remote_rpc(target.endpoint, raw)["result"]["evidence"] == "revoked"


def test_native_gateway_pending_create_tombstone_and_late_completion(action_gateway: NativeGateway) -> None:
    target = action_gateway
    payload = native_ban("198.51.200.10")
    identifier = str(uuid4())
    docker("exec", target.container, "touch", "/root/crowdsec-pause-post")
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(remote_rpc, target.endpoint, action_request(target, "ban_put", payload, identifier))
        try:
            wait_file(target, "/root/crowdsec-post-paused", "praho/" + payload["provenance_id"])
            docker("exec", target.container, "python3", "-I", "-c", KILL_HELPER)
            with pytest.raises(CrowdSecRPCError):
                pending.result(timeout=5)
            unknown = remote_rpc(target.endpoint, action_request(target, "receipt_get", {"request_id": identifier}))[
                "result"
            ]
            assert unknown["status"] == "unknown" and unknown["evidence"] == "pending_create"
            revoke_raw = action_request(
                target, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None}
            )
            tombstone = remote_rpc(target.endpoint, revoke_raw)["result"]
            assert tombstone["status"] == "unknown" and tombstone["evidence"] == "pending_create"
        finally:
            docker("exec", target.container, "rm", "-f", "/root/crowdsec-pause-post")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            native = json.loads(
                docker(
                    "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
                ).stdout
            )
            if native:
                break
            time.sleep(0.03)
        assert len(native) == 1, "The original delayed LAPI request must actually commit"
        observed = remote_rpc(
            target.endpoint, action_request(target, "receipt_get", {"request_id": json.loads(revoke_raw)["request_id"]})
        )["result"]
        assert observed["status"] == "unknown"
        finished = remote_rpc(target.endpoint, revoke_raw)["result"]
        assert finished["status"] == "succeeded" and finished["evidence"] == "decision_absent"
        rows = json.loads(
            docker(
                "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
            ).stdout
        )
        assert len(rows) == 1 and datetime.fromisoformat(rows[0][2]) <= datetime.now(UTC)


def test_native_gateway_crash_after_commit_and_receipt_across_configuration_upgrade(
    action_gateway: NativeGateway,
) -> None:
    target = action_gateway
    helper = "/usr/local/libexec/praho-crowdsec-gateway"
    original = docker("exec", target.container, "cat", helper).stdout
    boundary = "    if status != HTTPStatus.CREATED:\n"
    assert original.count(boundary) == 1
    injected = original.replace(boundary, "    os._exit(91)  # fixture crash after the real LAPI reply\n" + boundary)
    docker("exec", "-i", target.container, "tee", helper, input_text=injected)
    changed = refresh_policy(target)
    payload, identifier = native_ban("198.51.200.11"), str(uuid4())
    try:
        with pytest.raises(CrowdSecRPCError):
            remote_rpc(changed.endpoint, action_request(changed, "ban_put", payload, identifier))
        rows = json.loads(
            docker(
                "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
            ).stdout
        )
        assert len(rows) == 1, "The real native application must precede the injected crash"
    finally:
        docker("exec", "-i", target.container, "tee", helper, input_text=original)
        restored = refresh_policy(target)
    assert restored.digest != changed.digest and restored.digest == target.digest
    receipt = remote_rpc(restored.endpoint, action_request(restored, "receipt_get", {"request_id": identifier}))[
        "result"
    ]
    assert receipt["status"] == "succeeded"
    replayed = remote_rpc(restored.endpoint, action_request(restored, "ban_put", payload, identifier))["result"]
    assert replayed["decision_ids"] == receipt["decision_ids"]
    rows = json.loads(
        docker(
            "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
        ).stdout
    )
    assert len(rows) == 1


def test_native_gateway_protected_overlap_simulation_and_staff_allowlist_repair(action_gateway: NativeGateway) -> None:
    target = action_gateway
    for value in ("192.0.2.9", "192.0.0.0/16", "2001:db8::9", "2001:db8::/32"):
        result = remote_rpc(target.endpoint, action_request(target, "ban_put", native_ban(value)))["result"]
        assert result["status"] == "rejected" and result["evidence"] == "protected_overlap"
    for value in ("::ffff:127.0.0.1", "fe80::1%eth0"):
        with pytest.raises(CrowdSecRPCError):
            remote_rpc(target.endpoint, action_request(target, "ban_put", native_ban(value)))
    broad_payload = native_ban("198.51.203.0/24")
    broad = remote_rpc(target.endpoint, action_request(target, "ban_put", broad_payload))["result"]
    assert broad["status"] == "succeeded"
    simulated = refresh_policy(target, simulation=True)
    try:
        denied = remote_rpc(simulated.endpoint, action_request(simulated, "ban_put", native_ban("198.51.204.9")))[
            "result"
        ]
        assert denied["status"] == "rejected" and denied["evidence"] == "simulation"
        result = remote_rpc(
            simulated.endpoint,
            action_request(simulated, "allowlist_replace", {"revision": 10, "cidrs": ["198.51.203.9/32"]}),
        )["result"]
        assert result["status"] == "succeeded" and broad["decision_ids"][0] in result["decision_ids"]
        revoked = remote_rpc(
            simulated.endpoint,
            action_request(
                simulated, "revoke", {"provenance_id": broad_payload["provenance_id"], "revision": 2, "decision": None}
            ),
        )["result"]
        assert revoked["status"] == "succeeded"
        # Native cscli cannot update an existing item's expiry; complete replacement must repair it.
        docker("exec", target.container, "cscli", "allowlists", "remove", "praho-staff", "198.51.203.9/32")
        docker(
            "exec",
            target.container,
            "cscli",
            "allowlists",
            "add",
            "praho-staff",
            "198.51.203.9/32",
            "--expiration",
            "1h",
        )
        repaired = remote_rpc(
            simulated.endpoint,
            action_request(simulated, "allowlist_replace", {"revision": 11, "cidrs": ["198.51.203.9/32"]}),
        )["result"]
        assert repaired["status"] == "succeeded"
    finally:
        assert refresh_policy(target).digest == target.digest


def test_native_orphan_cli_retains_mutation_fence_after_helper_death(action_gateway: NativeGateway) -> None:
    target = action_gateway
    cli = "/usr/bin/cscli"
    real = "/usr/bin/cscli.praho-action-native"
    wrapper = r"""#!/usr/bin/python3 -I
import os,sys,time
from pathlib import Path
if 'allowlists' in sys.argv and 'add' in sys.argv:
 Path('/root/crowdsec-cli-paused').write_text('paused')
 Path('/root/crowdsec-cli-pid').write_text(str(os.getpid()))
 deadline=time.monotonic()+15
 while Path('/root/crowdsec-pause-cli').exists() and time.monotonic()<deadline:time.sleep(.01)
 if Path('/root/crowdsec-pause-cli').exists():raise SystemExit(1)
os.execv('/usr/bin/cscli.praho-action-native',['/usr/bin/cscli.praho-action-native',*sys.argv[1:]])
"""
    docker("exec", target.container, "mv", cli, real)
    docker("exec", "-i", target.container, "tee", cli, input_text=wrapper)
    docker("exec", target.container, "chmod", "755", cli)
    changed = refresh_policy(target)
    identifier = str(uuid4())
    raw = action_request(
        changed, "allowlist_replace", {"revision": 12, "cidrs": ["198.51.203.9/32", "198.51.205.9/32"]}, identifier
    )
    docker("exec", target.container, "touch", "/root/crowdsec-pause-cli")
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = executor.submit(remote_rpc, changed.endpoint, raw)
            wait_file(target, "/root/crowdsec-cli-paused", "paused")
            docker("exec", target.container, "python3", "-I", "-c", KILL_HELPER)
            with pytest.raises(CrowdSecRPCError):
                pending.result(timeout=5)
            held = remote_rpc(changed.endpoint, action_request(changed, "receipt_get", {"request_id": identifier}))[
                "result"
            ]
            assert held["status"] == "unknown" and held["evidence"] == "operation_pending"
            blocker = r"""import sqlite3,time
from pathlib import Path
connection=sqlite3.connect('/var/lib/crowdsec/data/crowdsec.db',timeout=5)
connection.execute('BEGIN IMMEDIATE')
Path('/root/crowdsec-db-held').write_text('held')
deadline=time.monotonic()+15
while Path('/root/crowdsec-hold-db').exists() and time.monotonic()<deadline:time.sleep(.01)
connection.rollback();connection.close()
"""
            docker("exec", "-i", target.container, "tee", "/root/crowdsec-hold-db.py", input_text=blocker)
            docker("exec", target.container, "touch", "/root/crowdsec-hold-db")
            docker(
                "exec",
                target.container,
                "systemd-run",
                "--unit=crowdsec-action-db-lock",
                "/usr/bin/python3",
                "-I",
                "/root/crowdsec-hold-db.py",
            )
            wait_file(target, "/root/crowdsec-db-held", "held")
            docker("exec", target.container, "rm", "/root/crowdsec-pause-cli")
            reached_go = r"""from pathlib import Path
import time
pid=int(Path('/root/crowdsec-cli-pid').read_text())
deadline=time.monotonic()+5
while time.monotonic()<deadline:
 try:arguments=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
 except FileNotFoundError:raise RuntimeError('Native CLI exited before the locked write') from None
 if arguments[0]==b'/usr/bin/cscli.praho-action-native':break
 time.sleep(.01)
else:raise RuntimeError('The real Go CLI was not execed')
"""
            docker("exec", target.container, "python3", "-I", "-c", reached_go)
            go_held = remote_rpc(changed.endpoint, action_request(changed, "receipt_get", {"request_id": identifier}))[
                "result"
            ]
            assert go_held["status"] == "unknown" and go_held["evidence"] == "operation_pending"
            other = executor.submit(
                remote_rpc, changed.endpoint, action_request(changed, "ban_put", native_ban("198.51.206.9"))
            )
            assert not other.done()
            docker("exec", target.container, "rm", "/root/crowdsec-hold-db")
            assert other.result(timeout=8)["result"]["status"] == "succeeded"
        settled = remote_rpc(changed.endpoint, action_request(changed, "receipt_get", {"request_id": identifier}))[
            "result"
        ]
        assert settled["status"] == "succeeded" and settled["evidence"] == "allowlist_matches"
    finally:
        docker("exec", target.container, "rm", "-f", "/root/crowdsec-pause-cli", "/root/crowdsec-hold-db")
        docker("exec", target.container, "systemctl", "stop", "crowdsec-action-db-lock", check=False)
        docker("exec", target.container, "mv", real, cli)
        assert refresh_policy(target).digest == target.digest


def test_native_fingerprint_provenance_and_private_legacy_manual_revocation(action_gateway: NativeGateway) -> None:
    target = action_gateway
    payload = native_ban("198.51.207.9")
    created = remote_rpc(target.endpoint, action_request(target, "ban_put", payload))["result"]
    observed = remote_rpc(target.endpoint, action_request(target, "snapshot", {"after_alert_id": 0}))["result"][
        "decisions"
    ]
    fingerprint = next(item for item in observed if item["id"] == created["decision_ids"][0])
    wrong = {"provenance_id": str(uuid4()), "revision": 2, "decision": fingerprint}
    denied = remote_rpc(target.endpoint, action_request(target, "revoke", wrong))["result"]
    assert denied["status"] == "rejected" and denied["evidence"] == "immutable_conflict"
    correct = {**wrong, "provenance_id": payload["provenance_id"]}
    for value in ("198.51.208.9", "::ffff:198.51.208.10"):
        before = {
            item["id"]
            for item in remote_rpc(target.endpoint, action_request(target, "snapshot", {"after_alert_id": 0}))[
                "result"
            ]["decisions"]
        }
        docker("exec", target.container, "cscli", "decisions", "add", "--ip", value, "--duration", "10m")
        after = remote_rpc(target.endpoint, action_request(target, "snapshot", {"after_alert_id": 0}))["result"][
            "decisions"
        ]
        introduced = [item for item in after if item["id"] not in before]
        assert len(introduced) == 1 and introduced[0]["scenario"] == "cscli/manual"
        mixed = {**correct, "decision": introduced[0]}
        denied = remote_rpc(target.endpoint, action_request(target, "revoke", mixed))["result"]
        assert denied["status"] == "rejected" and denied["evidence"] == "immutable_conflict"
        request = action_request(
            target, "revoke", {"provenance_id": str(uuid4()), "revision": 1, "decision": introduced[0]}
        )
        response = remote_rpc(target.endpoint, request)
        assert response["result"]["status"] == "succeeded"
        assert "manual 'ban'" not in json.dumps(response)
    assert remote_rpc(target.endpoint, action_request(target, "revoke", correct))["result"]["status"] == "succeeded"


def test_native_staff_allowlist_barrier_covers_an_earlier_late_ban_post(action_gateway: NativeGateway) -> None:
    target = action_gateway
    payload = native_ban("198.51.209.9")
    identifier = str(uuid4())
    docker("exec", target.container, "touch", "/root/crowdsec-pause-post")
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(remote_rpc, target.endpoint, action_request(target, "ban_put", payload, identifier))
        try:
            wait_file(target, "/root/crowdsec-post-paused", "praho/" + payload["provenance_id"])
            docker("exec", target.container, "python3", "-I", "-c", KILL_HELPER)
            with pytest.raises(CrowdSecRPCError):
                pending.result(timeout=5)
            raw = action_request(
                target,
                "allowlist_replace",
                {"revision": 13, "cidrs": ["198.51.203.9/32", "198.51.205.9/32", "198.51.209.9/32"]},
            )
            configured = remote_rpc(target.endpoint, raw)["result"]
            assert configured["status"] == "unknown" and configured["evidence"] == "pending_create"
        finally:
            docker("exec", target.container, "rm", "-f", "/root/crowdsec-pause-post")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            native = json.loads(
                docker(
                    "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
                ).stdout
            )
            if native:
                break
            time.sleep(0.03)
        assert len(native) == 1 and datetime.fromisoformat(native[0][2]) > datetime.now(UTC)
        # Manual LAPI alerts trust their caller's allowlist check, so this original POST can still commit.
        observed = remote_rpc(
            target.endpoint, action_request(target, "receipt_get", {"request_id": json.loads(raw)["request_id"]})
        )["result"]
        assert observed["status"] == "unknown" and observed["evidence"] == "mutation_uncertain"
        repaired = remote_rpc(target.endpoint, raw)["result"]
        assert repaired["status"] == "succeeded" and repaired["evidence"] == "allowlist_matches"
        assert len(repaired["decision_ids"]) == 1
        final = json.loads(
            docker(
                "exec", target.container, "python3", "-I", "-c", READ_DECISIONS, "praho/" + payload["provenance_id"]
            ).stdout
        )
        assert len(final) == 1 and datetime.fromisoformat(final[0][2]) <= datetime.now(UTC)


@pytest.fixture(scope="module")
def active_lapi(native_gateway: NativeGateway) -> Iterator[NativeGateway]:
    # The gateway fixture deliberately leaves the actual stock units stopped.
    # This separate process qualifies upstream mutation semantics, not service admission.
    target = native_gateway.container
    docker(
        "exec",
        target,
        "systemd-run",
        "--unit=crowdsec-action-contract",
        "/usr/bin/crowdsec",
        "-no-cs",
        "-c",
        "/etc/crowdsec/config.yaml",
    )
    ready = """import socket,time
deadline=time.monotonic()+10
while time.monotonic()<deadline:
 try:
  socket.create_connection(('127.0.0.1',8080),timeout=.2).close()
  break
 except OSError:
  time.sleep(.05)
else:
 raise RuntimeError('Pinned local API did not become ready')
"""
    docker("exec", target, "python3", "-I", "-c", ready)
    try:
        yield native_gateway
    finally:
        docker("exec", target, "systemctl", "stop", "crowdsec-action-contract", check=False)


def test_pinned_local_api_fixed_expiry_uuid_and_allowlist_side_effects(active_lapi: NativeGateway) -> None:
    target = active_lapi.container
    now = datetime.now(UTC).replace(microsecond=0)
    reference = now - timedelta(days=1)
    expiry = now + timedelta(minutes=2)
    marker = "praho/upstream-contract"
    supplied_uuid = str(uuid4())
    values = ["198.51.100.0/24", "198.51.101.9", "198.51.102.9", "2001:db8:1::/64", "2001:db8:2::9", "2001:db8:3::9"]
    decisions = [
        {
            "scope": "Range" if "/" in value else "Ip",
            "value": value,
            "duration": "86520s",
            "type": "ban",
            "origin": "cscli",
            "scenario": marker,
            "uuid": supplied_uuid,
        }
        for value in values
    ]
    alert = {
        "capacity": 0,
        "decisions": decisions,
        "events": [],
        "events_count": 1,
        "leakspeed": "0",
        "message": marker,
        "scenario": marker,
        "scenario_hash": "",
        "scenario_version": "",
        "simulated": False,
        "source": {"scope": "Ip", "value": "198.51.102.9", "ip": "198.51.102.9"},
        "start_at": reference.isoformat(),
        "stop_at": reference.isoformat(),
        "created_at": now.isoformat(),
        "remediation": True,
        "kind": "cscli",
        "uuid": supplied_uuid,
    }
    created = docker("exec", "-i", target, "python3", "-I", "-c", LAPI_POST, input_text=json.dumps([alert]))
    assert created.stdout.strip() == "201"
    before = json.loads(docker("exec", target, "python3", "-I", "-c", READ_DECISIONS, marker).stdout)
    assert {row[0] for row in before} == set(values)
    assert all(row[1] != supplied_uuid for row in before)
    assert all(datetime.fromisoformat(row[2]) == expiry for row in before)
    docker(
        "exec",
        target,
        "cscli",
        "allowlists",
        "create",
        "praho-upstream-contract",
        "--description",
        "Pinned upstream allowlist contract",
    )
    docker(
        "exec",
        target,
        "cscli",
        "allowlists",
        "add",
        "praho-upstream-contract",
        "198.51.100.9",
        "198.51.101.0/24",
        "2001:db8:1::9",
        "2001:db8:2::/64",
    )
    after = json.loads(docker("exec", target, "python3", "-I", "-c", READ_DECISIONS, marker).stdout)
    active = {row[0] for row in after if datetime.fromisoformat(row[2]) > datetime.now(UTC)}
    assert active == {"198.51.102.9", "2001:db8:3::9"}
