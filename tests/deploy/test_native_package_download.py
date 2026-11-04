"""Run the real signing-key task against a verified HTTPS origin with handshake timeouts."""

from __future__ import annotations

import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

from tests.native_role_helpers import native_tasks

ROOT = Path(__file__).resolve().parents[2]
KEY = b"native signing-key transport fixture\n"


@pytest.mark.parametrize("persistent", [False, True])
def test_signing_key_handshake_timeouts_retry_then_fail_closed(tmp_path: Path, persistent: bool) -> None:
    certificate, private_key = tmp_path / "ca.crt", tmp_path / "server.key"
    subprocess.run(  # noqa: S603 -- creates a disposable fixture CA, without network access.
        [
            shutil.which("openssl") or "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    attempts: list[int] = []
    lock = threading.Lock()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            with lock:
                attempts.append(1)
                fail = persistent or len(attempts) == 1
            if fail:
                # Accept TCP but withhold ServerHello beyond the module's test timeout.
                threading.Event().wait(2)
                return
            with context.wrap_socket(self.request, server_side=True) as connection:
                connection.recv(8192)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + str(len(KEY)).encode()
                    + b"\r\n\r\n"
                    + KEY
                )

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            task = next(
                task
                for task in native_tasks(ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml")
                if task["name"] == "Download PostgreSQL GPG key"
            )
            destination = tmp_path / "postgresql.asc"
            task["get_url"].update(
                url=f"https://127.0.0.1:{server.server_address[1]}/key", dest=str(destination), timeout=1
            )
            task["environment"] = {"SSL_CERT_FILE": str(certificate)}
            playbook = tmp_path / "play.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "hosts": "localhost",
                            "gather_facts": False,
                            "vars": {"ansible_python_interpreter": sys.executable},
                            "tasks": [task],
                        }
                    ]
                )
            )
            executable = Path(sys.executable).with_name("ansible-playbook")
            result = subprocess.run(  # noqa: S603 -- extracted real task, loopback HTTPS, disposable destination.
                [
                    str(executable)
                    if executable.is_file()
                    else (shutil.which("ansible-playbook") or "ansible-playbook"),
                    "-i",
                    "localhost,",
                    "-c",
                    "local",
                    str(playbook),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=45,
                env={
                    **os.environ,
                    "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
                    "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
                },
            )
        finally:
            server.shutdown()
            worker.join(timeout=5)
    output = result.stdout + result.stderr
    if persistent:
        assert result.returncode != 0, output
        assert len(attempts) == 4, output
        assert not destination.exists()
        assert "handshake operation timed out" in output, output
    else:
        assert result.returncode == 0, output
        assert len(attempts) == 2, output
        assert destination.read_bytes() == KEY


def test_signing_key_download_allows_slow_tls_without_disabling_verification() -> None:
    task = next(
        task
        for task in native_tasks(ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml")
        if task["name"] == "Download PostgreSQL GPG key"
    )
    assert task["get_url"].get("timeout", 10) >= 60
    assert task["get_url"].get("validate_certs", True) is True
