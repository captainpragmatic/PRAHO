"""The portal's gunicorn settings come from PORTAL_GUNICORN_* and refuse values that are not allowed."""

from __future__ import annotations

from django.test import SimpleTestCase

from config.server_settings import server_settings


class ServerSettingsTests(SimpleTestCase):
    def test_defaults_are_today_s_sync_workers(self) -> None:
        settings = server_settings({})
        self.assertEqual(
            {key: settings[key] for key in ("worker_class", "workers", "threads", "worker_connections")},
            {"worker_class": "sync", "workers": 2, "threads": 1, "worker_connections": 1},
        )

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
