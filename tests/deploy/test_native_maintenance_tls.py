"""Probe actual trusted TLS: readiness retries may never accept a bad certificate or HTTP 200."""

import http.server
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest
import yaml

from tests.deploy.test_native_review_regressions import ansible

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("failure", ["temporary", "untrusted", "wrong-status"])
def test_maintenance_probe_retries_readiness_but_keeps_tls_and_status_validation(tmp_path: Path, failure: str) -> None:
    certificate, key = tmp_path / "certificate.pem", tmp_path / "key.pem"
    subprocess.run(  # noqa: S603 -- disposable fixture certificate generated without network access
        [
            shutil.which("openssl") or "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
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
    attempts = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            attempts.append(self.path)
            if failure == "temporary" and len(attempts) == 1:
                self.connection.close()
                return
            self.send_response(200 if failure == "wrong-status" else 503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_arguments: object) -> None:
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            task = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native/hold.yml").read_text())[-1]
            arguments = task["command"]["argv"]
            index = arguments.index("--resolve")
            del arguments[index : index + 2]
            arguments[-1] = f"https://127.0.0.1:{server.server_port}/"
            task.update(loop=["127.0.0.1"], no_log=False, delay=0)
            if failure != "untrusted":
                task["environment"] = {"CURL_CA_BUNDLE": str(certificate)}
            result = ansible(tmp_path, [task], {})
        finally:
            server.shutdown()
            thread.join(timeout=5)
    output = result.stdout + result.stderr
    if failure == "temporary":
        assert result.returncode == 0 and len(attempts) == 2, output
    else:
        assert result.returncode != 0, output
        assert len(attempts) == (0 if failure == "untrusted" else task.get("retries", 0) + 1), output
    assert "--insecure" not in arguments and "-k" not in arguments
