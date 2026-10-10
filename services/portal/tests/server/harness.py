"""Run the real portal under real gunicorn against a stub Platform whose logins can be held open.

Used by the ``server`` acceptance tests (``make test-portal-server``). Each portal is started with the
production settings and the shipped gunicorn.conf.py, on a free port, in its own process group, so
a failing test can always stop it and every worker it forked.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import requests

PORTAL = Path(__file__).resolve().parents[2]
READY_TIMEOUT = 60.0
LOCALISATION = {
    "success": True,
    "localisation": {
        "default_language": "en",
        "default_country": "RO",
        "timezone": "Europe/Bucharest",
        "customer_date_format": "%d.%m.%Y",
    },
    "company": {
        "legal_name": "PragmaticHost SRL",
        "email_support": "support@pragmatichost.com",
        "email_privacy": "privacy@pragmatichost.com",
        "email_finance": "",
        "phone": "",
    },
}


class StubPlatform:
    """A Platform that answers instantly, except logins, which wait until released."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self._lock = threading.Lock()
        self._held = 0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self._answer()

            def do_GET(self) -> None:
                self._answer()

            def _answer(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if self.path.rstrip("/").endswith("/users/login"):
                    with stub._lock:
                        stub._held += 1
                    stub.release.wait(timeout=120)
                    body: dict[str, object] = {"valid": False, "error": "Invalid credentials"}
                elif self.path.rstrip("/").endswith("/localisation"):
                    body = LOCALISATION
                else:
                    body = {"success": False, "error": "not found"}
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- the base signature.
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/api"

    @property
    def held(self) -> int:
        with self._lock:
            return self._held

    def wait_for_held(self, count: int, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while self.held < count:
            if time.monotonic() > deadline:
                raise AssertionError(f"only {self.held} of {count} logins reached Platform")
            time.sleep(0.05)

    def __enter__(self) -> StubPlatform:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


class Portal:
    """A running portal: its base URL and its gunicorn log."""

    def __init__(self, base_url: str, log: Path) -> None:
        self.base_url = base_url
        self.log = log

    def log_text(self) -> str:
        return self.log.read_text(errors="replace")

    def login(self, client_ip: str, timeout: float = 120.0) -> requests.Response:
        """A full login POST from ``client_ip`` (forwarded by the trusted local proxy)."""
        session = requests.Session()
        page = session.get(f"{self.base_url}/login/", timeout=10)
        token = page.cookies.get("csrftoken") or ""
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text)
        assert match is not None, page.text[:500]
        # The CSRF cookie is Secure, which requests will not send over http, so send it by hand.
        return session.post(
            f"{self.base_url}/login/",
            data={
                "email": "someone@example.com",
                "password": "not-the-password",
                "csrfmiddlewaretoken": match.group(1),
            },
            headers={"Cookie": f"csrftoken={token}", "X-Forwarded-For": client_ip},
            timeout=timeout,
            allow_redirects=False,
        )


def _portal_env(directory: Path, platform_url: str, server: dict[str, str]) -> dict[str, str]:
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.update(
        {
            "DJANGO_SETTINGS_MODULE": "config.settings.prod",
            "DJANGO_SECRET_KEY": secrets.token_urlsafe(64),
            "ALLOWED_HOSTS": "127.0.0.1",
            "PORTAL_DOMAIN": "127.0.0.1",
            "PORTAL_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            "DJANGO_SECURE_SSL_REDIRECT": "false",
            "PLATFORM_API_BASE_URL": platform_url,
            "PLATFORM_API_ALLOW_INSECURE_HTTP": "true",
            "PLATFORM_API_SECRET": secrets.token_hex(32),
            "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": secrets.token_hex(32),
            "SESSION_DB_PATH": str(directory / "portal.sqlite3"),
            "PORTAL_LOG_DIR": str(directory / "logs"),
            # macOS: a forked worker that looks up system proxy settings can crash; there is none here.
            "NO_PROXY": "*",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            **server,
        }
    )
    return env


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Stop the master and every worker in its group, even if the master has already exited."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return  # nothing left in the group
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            continue  # escalate
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)  # any worker the master left behind
        return


@contextmanager
def running_portal(platform_url: str, **server: str) -> Iterator[Portal]:
    """Start the portal with ``server`` as its PORTAL_GUNICORN_* settings; stop it on exit."""
    with TemporaryDirectory(prefix="portal-server-") as name:
        directory = Path(name)
        (directory / "logs").mkdir()
        env = _portal_env(directory, platform_url, server)
        for app in ("sessions", "common"):
            subprocess.run(  # noqa: S603 -- a fixed command.
                [sys.executable, "manage.py", "migrate", app, "--noinput"],
                cwd=PORTAL,
                env=env,
                check=True,
                capture_output=True,
                timeout=120,
            )
        log = directory / "gunicorn.log"
        with log.open("wb") as output:
            process = subprocess.Popen(  # noqa: S603 -- a fixed command.
                [
                    sys.executable,
                    "-m",
                    "gunicorn",
                    "--bind",
                    "127.0.0.1:0",
                    "--no-control-socket",
                    "config.wsgi:application",
                ],
                cwd=PORTAL,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            portal = Portal(_wait_until_ready(process, log), log)
            yield portal
        finally:
            _stop(process)


def _wait_until_ready(process: subprocess.Popen[bytes], log: Path) -> str:
    deadline = time.monotonic() + READY_TIMEOUT
    base_url = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"gunicorn exited with {process.returncode}:\n{log.read_text(errors='replace')}")
        if not base_url:
            match = re.search(r"Listening at: (http://127\.0\.0\.1:\d+)", log.read_text(errors="replace"))
            base_url = match.group(1) if match else ""
        if base_url:
            try:
                if requests.get(f"{base_url}/status/", timeout=2).status_code == 200:  # noqa: PLR2004
                    return base_url
            except requests.RequestException:
                pass
        time.sleep(0.1)
    raise AssertionError(f"the portal did not become ready:\n{log.read_text(errors='replace')}")
