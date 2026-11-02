"""Real SSH tunnel authorization, independent of a configured Match block's appearance."""

from __future__ import annotations

import pytest
from test_ssh_hardening_docker import docker, harden, ssh, ssh_target

__all__ = ["ssh_target"]
pytestmark = pytest.mark.docker


def test_operator_tunnel_allows_only_the_loopback_panel(ssh_target: str) -> None:
    container = ssh_target
    policy = {"ssh_webmin_tunnel_enabled": True}
    applied = harden(container, extra=policy)
    assert applied.returncode == 0, applied.stdout[-5000:] + applied.stderr[-1000:]
    assert ssh(container, 9876).stdout.strip() == "0"

    listener = """import socket,threading,time
def serve(port):
    listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('127.0.0.1',port)); listener.listen()
    while True:
        client,_=listener.accept()
        client.recv(4096)
        body=('panel-ok' if port==10000 else 'other-target').encode()
        client.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body)
        client.close()
for port in (10000,10001): threading.Thread(target=serve,args=(port,),daemon=True).start()
time.sleep(600)
"""
    docker("exec", "-i", container, "tee", "/root/tunnel-listeners.py", input_text=listener)
    docker(
        "exec",
        container,
        "systemd-run",
        "--unit=p768-tunnel-listeners",
        "/usr/bin/python3",
        "/root/tunnel-listeners.py",
    )

    fetch = """import http.client,sys,time
for attempt in range(int(sys.argv[2])):
    try:
        connection=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=3)
        connection.request('GET','/')
        sys.stdout.buffer.write(connection.getresponse().read())
        break
    except OSError:
        if attempt+1 == int(sys.argv[2]): raise
        time.sleep(0.1)
"""

    def get(port, *, attempts=1):
        return docker("exec", container, "/usr/bin/python3", "-c", fetch, str(port), str(attempts), check=False)

    # Positive control proves both destinations are healthy before testing access denial.
    ready = get(10000, attempts=30)
    assert ready.returncode == 0 and ready.stdout == "panel-ok"
    assert get(10001).stdout == "other-target"

    def forward(user, key, local_port, target_port, *, remote=False):
        return docker(
            "exec",
            container,
            "ssh",
            "-F",
            "/dev/null",
            "-p",
            "9876",
            "-i",
            f"/root/{key}",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=/root/known_hosts",
            "-o",
            "HostKeyAlias=127.0.0.1",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ConnectTimeout=3",
            "-N",
            "-f",
            "-R" if remote else "-L",
            f"127.0.0.1:{local_port}:127.0.0.1:{target_port}",
            f"{user}@127.0.0.1",
            check=False,
        )

    tunnel = forward("praho-webmin-tunnel", "operator", 18443, 10000)
    assert tunnel.returncode == 0, tunnel.stderr
    assert get(18443).stdout == "panel-ok"
    forbidden = forward("praho-webmin-tunnel", "operator", 18444, 10001)
    assert forbidden.returncode == 0, forbidden.stderr
    assert get(18444).returncode != 0, "the tunnel reached an unapproved destination"
    assert forward("praho-webmin-tunnel", "operator", 18445, 10000, remote=True).returncode != 0
    command = ssh(container, 9876, key="operator", user="praho-webmin-tunnel")
    assert command.returncode != 0 and "uid=" not in command.stdout, "the tunnel account executed a command"
    assert ssh(container, 9876, key="controller", user="praho-webmin-tunnel").returncode != 0
    root_forward = forward("root", "controller", 18446, 10000)
    assert root_forward.returncode == 0, root_forward.stderr
    assert get(18446).returncode != 0, "root inherited the dedicated account's forwarding permission"

    before = docker(
        "exec", container, "sha256sum", "/etc/ssh/sshd_config", "/home/praho-webmin-tunnel/.ssh/authorized_keys"
    ).stdout
    repeated = harden(container, port=9876, extra=policy)
    assert repeated.returncode == 0, repeated.stdout[-5000:] + repeated.stderr[-1000:]
    after = docker(
        "exec", container, "sha256sum", "/etc/ssh/sshd_config", "/home/praho-webmin-tunnel/.ssh/authorized_keys"
    ).stdout
    assert after == before, "a repeated handoff changed the verified tunnel policy"
