"""Exercise Portal startup with real migrations and deployment checks."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "services/portal"


class PortalStartupTests(TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory(prefix="portal-startup-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / "portal.sqlite3"
        self.trace = self.root / "commands"
        (self.root / "startup_settings.py").write_text(
            "from config.settings.dev import *\n"
            "DEBUG = False\n"
            "RATE_LIMITING_ENABLED = True\n"
            "IPWARE_TRUSTED_PROXY_LIST = ['127.0.0.1/32']\n"
        )
        self.env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "TESTING": "1",
            "DJANGO_SETTINGS_MODULE": "startup_settings",
            "PYTHONPATH": os.pathsep.join((str(self.root), str(PORTAL))),
            "SESSION_DB_PATH": str(self.database),
            "PORTAL_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            "PLATFORM_API_ALLOW_INSECURE_HTTP": "true",
            "PORTAL_STARTUP_TRACE": str(self.trace),
        }
        launcher = self.root / "python"
        launcher.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['PORTAL_STARTUP_TRACE']).open('a') as trace:\n"
            "    trace.write(' '.join(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:2] == ['-'] and os.environ.get('INTEGRITY_ERROR'):\n"
            "    sys.exit(1)\n"
            "if sys.argv[1:3] == ['manage.py', 'collectstatic']:\n"
            "    sys.exit(0)\n"
            f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n"
        )
        launcher.chmod(0o700)
        gunicorn = self.root / "gunicorn"
        gunicorn.write_text("#!/bin/sh\nprintf '%s\\n' gunicorn >> \"$PORTAL_STARTUP_TRACE\"\n")
        gunicorn.chmod(0o700)
        self.env["PATH"] = str(self.root) + os.pathsep + os.environ.get("PATH", "")

    def run_command(self, *command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- commands and environment are test fixtures.
            command, cwd=PORTAL, env=self.env, text=True, capture_output=True, timeout=60, check=False
        )

    def manage(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run_command(sys.executable, "manage.py", *args)

    def start(self) -> subprocess.CompletedProcess[str]:
        return self.run_command("bash", str(ROOT / "deploy/portal/entrypoint.sh"))

    def assert_started(self) -> None:
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with sqlite3.connect(self.database) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(tables - {"sqlite_sequence"}, {"django_session", "common_counters", "django_migrations"})
        commands = self.trace.read_text().splitlines()
        expected = [
            "manage.py migrate sessions --noinput",
            "manage.py migrate common --noinput",
            "manage.py check --deploy --fail-level ERROR",
            "gunicorn",
        ]
        positions = [commands.index(command) for command in expected]
        self.assertEqual(positions, sorted(positions))

    def test_empty_database_starts_after_scoped_migrations(self) -> None:
        self.assert_started()

    def test_sessions_only_upgrade_preserves_existing_sessions(self) -> None:
        result = self.manage("migrate", "sessions", "--noinput")
        self.assertEqual(result.returncode, 0, result.stderr)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO django_session VALUES (?, ?, ?)",
                ("preserved-session", "payload", "2099-01-01 00:00:00"),
            )
        self.assert_started()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT session_key FROM django_session").fetchall(),
                [("preserved-session",)],
            )

    def test_missing_counter_table_blocks_only_deployment_checks(self) -> None:
        ordinary = self.manage("check")
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        deployment = self.manage("check", "--deploy", "--fail-level", "ERROR")
        self.assertNotEqual(deployment.returncode, 0)
        self.assertIn("portal.E002", deployment.stderr)
        health = self.run_command(
            sys.executable,
            "-c",
            (
                "import django; django.setup(); from django.test import Client; "
                "assert Client().get('/billing/', HTTP_HOST='localhost').status_code == 503"
            ),
        )
        self.assertEqual(health.returncode, 0, health.stderr)
        self.assert_started()

    def test_real_corruption_resets_guards_with_security_log(self) -> None:
        self.database.write_bytes(b"invalid SQLite database")
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("🚨", result.stderr)
        self.assertIn("replay and idempotency guards were reset", result.stderr)

    def test_other_integrity_errors_preserve_database_and_stop_startup(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE preserved (id INTEGER)")
        before = self.database.read_bytes()
        self.env["INTEGRITY_ERROR"] = "1"
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertNotIn("gunicorn", self.trace.read_text())

    def test_native_health_gate_uses_limited_route(self) -> None:
        import yaml  # noqa: PLC0415

        tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml").read_text())
        health = next(task for task in tasks if task.get("register") == "portal_health")
        self.assertTrue(health["uri"]["url"].endswith("/billing/"))
        self.assertEqual(health["uri"]["status_code"], [200, 302])
        self.assertEqual(health["uri"]["follow_redirects"], "none")
        unit = (ROOT / "deploy/ansible/roles/praho-native/templates/praho-portal.service.j2").read_text()
        commands = [line for line in unit.splitlines() if line.startswith("ExecStartPre=")]
        self.assertEqual(len(commands), 3)
        for command, expected in zip(
            commands,
            (
                "manage.py migrate sessions --noinput",
                "manage.py migrate common --noinput",
                "manage.py check --deploy --fail-level ERROR",
            ),
            strict=True,
        ):
            self.assertTrue(command.endswith(expected))

    def test_api_limiter_admits_exactly_limit_of_concurrent_requests(self) -> None:
        result = self.manage("migrate", "common", "--noinput")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_command(
            sys.executable,
            "-c",
            """
import django
django.setup()
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
from django.db import connections
from django.http import HttpResponse
from django.test import RequestFactory
from apps.common import counters
from apps.common.rate_limiting import APIRateLimitMiddleware
limit = 10
workers = limit + 5
barrier = Barrier(workers)
def hit(index: int) -> int:
    try:
        middleware = APIRateLimitMiddleware(lambda request: HttpResponse('allowed'))
        middleware.BURST_RATE_LIMIT = limit
        request = RequestFactory().get('/billing/', REMOTE_ADDR='127.0.0.1')
        barrier.wait(timeout=10)
        return middleware(request).status_code
    finally:
        connections.close_all()
with patch('apps.common.counters.time.time', return_value=10000):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        statuses = list(pool.map(hit, range(workers)))
    assert statuses.count(200) == limit, statuses
    assert statuses.count(429) == 5, statuses
    assert counters.peek('api_burst_127.0.0.1') == workers
""",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
