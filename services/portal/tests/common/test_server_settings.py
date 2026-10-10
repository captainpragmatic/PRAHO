"""The portal's gunicorn settings come from PORTAL_GUNICORN_* and refuse values that are not allowed."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase

from config.server_settings import server_settings

PORTAL = Path(__file__).resolve().parents[2]


class ServerSettingsTests(SimpleTestCase):
    def test_defaults_are_today_s_sync_workers(self) -> None:
        settings = server_settings({})
        self.assertEqual(
            {key: settings[key] for key in ("worker_class", "workers", "threads", "worker_connections")},
            {"worker_class": "sync", "workers": 2, "threads": 1, "worker_connections": 1},
        )

    def test_the_timeouts(self) -> None:
        self.assertEqual((server_settings({})["timeout"], server_settings({})["graceful_timeout"]), (60, 50))

    def test_the_limits_themselves_are_allowed(self) -> None:
        settings = server_settings(
            {
                "PORTAL_GUNICORN_WORKER_CLASS": "gthread",
                "PORTAL_GUNICORN_WORKERS": "16",
                "PORTAL_GUNICORN_THREADS": "32",
            }
        )
        self.assertEqual((settings["workers"], settings["threads"]), (16, 32))
        one = server_settings({"PORTAL_GUNICORN_WORKER_CLASS": "gthread", "PORTAL_GUNICORN_THREADS": "1"})
        self.assertEqual(one["threads"], 1)

    def test_sync_does_not_read_the_thread_count(self) -> None:
        # A rollback to sync must start even if the thread count left behind is not valid.
        settings = server_settings({"PORTAL_GUNICORN_WORKER_CLASS": "sync", "PORTAL_GUNICORN_THREADS": "junk"})
        self.assertEqual(settings["threads"], 1)

    def test_choosing_sync_always_means_one_thread(self) -> None:
        # gunicorn would otherwise turn sync into gthread whenever threads > 1, so a rollback to
        # sync that left PORTAL_GUNICORN_THREADS set would quietly stay threaded.
        settings = server_settings({"PORTAL_GUNICORN_WORKER_CLASS": "sync", "PORTAL_GUNICORN_THREADS": "4"})
        self.assertEqual((settings["worker_class"], settings["threads"]), ("sync", 1))

    def test_threaded_workers_take_no_more_connections_than_threads(self) -> None:
        settings = server_settings(
            {"PORTAL_GUNICORN_WORKER_CLASS": "gthread", "PORTAL_GUNICORN_WORKERS": "2", "PORTAL_GUNICORN_THREADS": "4"}
        )
        self.assertEqual(
            (settings["worker_class"], settings["workers"], settings["threads"], settings["worker_connections"]),
            ("gthread", 2, 4, 4),
        )

    def test_connections_close_after_each_response(self) -> None:
        self.assertEqual(server_settings({})["keepalive"], 0)
        self.assertEqual(server_settings({"PORTAL_GUNICORN_WORKER_CLASS": "gthread"})["keepalive"], 0)

    def test_values_that_are_not_allowed_refuse_to_start(self) -> None:
        for env in (
            {"PORTAL_GUNICORN_WORKER_CLASS": "gevent"},
            {"PORTAL_GUNICORN_WORKERS": "0"},
            {"PORTAL_GUNICORN_WORKERS": "17"},
            {"PORTAL_GUNICORN_WORKERS": "two"},
            {"PORTAL_GUNICORN_WORKERS": "2 # comment"},  # an inline comment kept by systemd's EnvironmentFile
            {"PORTAL_GUNICORN_WORKER_CLASS": "gthread", "PORTAL_GUNICORN_THREADS": "0"},
            {"PORTAL_GUNICORN_WORKER_CLASS": "gthread", "PORTAL_GUNICORN_THREADS": "33"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                server_settings(env)

    def test_generic_gunicorn_arguments_refuse_to_start(self) -> None:
        # GUNICORN_CMD_ARGS beats the config file, and a native install's .env is shared with
        # Platform: its "--workers 8 --timeout 120" would quietly become the portal's too.
        with self.assertRaises(ValueError):
            server_settings({"GUNICORN_CMD_ARGS": "--workers 8 --timeout 120"})
        self.assertEqual(server_settings({"GUNICORN_CMD_ARGS": " "})["workers"], 2)

    def test_an_empty_value_means_the_default(self) -> None:
        self.assertEqual(
            server_settings({"PORTAL_GUNICORN_WORKERS": "", "PORTAL_GUNICORN_WORKER_CLASS": " "})["workers"], 2
        )


class GunicornReadsTheConfigTests(SimpleTestCase):
    """What gunicorn itself takes from gunicorn.conf.py: it ignores names it does not know."""

    def effective(self, **env: str) -> dict[str, str]:
        clean = {
            k: v for k, v in os.environ.items() if k != "GUNICORN_CMD_ARGS" and not k.startswith("PORTAL_GUNICORN_")
        }
        result = subprocess.run(  # noqa: S603 -- a fixed command with test-controlled environment.
            [sys.executable, "-m", "gunicorn", "--print-config", "config.wsgi:application"],
            cwd=PORTAL,
            env={**clean, **env},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (line.partition("=") for line in result.stdout.splitlines())
        return {name.strip(): value.strip() for name, sep, value in lines if sep}

    def test_gunicorn_applies_the_portal_settings(self) -> None:
        cfg = self.effective(
            PORTAL_GUNICORN_WORKER_CLASS="gthread", PORTAL_GUNICORN_WORKERS="3", PORTAL_GUNICORN_THREADS="5"
        )
        self.assertEqual(
            {key: cfg[key] for key in ("worker_class", "workers", "threads", "worker_connections", "keepalive")},
            {"worker_class": "gthread", "workers": "3", "threads": "5", "worker_connections": "5", "keepalive": "0"},
        )
        self.assertEqual((cfg["timeout"], cfg["graceful_timeout"], cfg["accesslog"]), ("60", "50", "-"))
        self.assertIn("%(D)sus pid=%(p)s rid=%({x-request-id}o)s", cfg["access_log_format"])

    def test_gunicorn_defaults_to_sync_workers(self) -> None:
        cfg = self.effective()
        self.assertEqual((cfg["worker_class"], cfg["workers"], cfg["threads"]), ("sync", "2", "1"))

    def test_a_value_that_is_not_allowed_stops_gunicorn_and_the_launchers_check(self) -> None:
        env = {**os.environ, "PORTAL_GUNICORN_WORKERS": "0"}
        env.pop("GUNICORN_CMD_ARGS", None)
        for command in (
            [sys.executable, "-m", "gunicorn", "--print-config", "config.wsgi:application"],
            [sys.executable, "-m", "config.server_settings"],
        ):
            with self.subTest(command=command[2]):
                result = subprocess.run(  # noqa: S603 -- a fixed command with test-controlled environment.
                    command, cwd=PORTAL, env=env, capture_output=True, text=True, timeout=60, check=False
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PORTAL_GUNICORN_WORKERS", result.stderr)
