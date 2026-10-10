"""Deployed portal logging: console always, plus files that survive external rotation when PORTAL_LOG_DIR is set."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from django.test import SimpleTestCase

from config.settings.logging_config import DEFAULT_LOG_DIR, portal_log_dir, portal_logging

PORTAL = Path(__file__).resolve().parents[2]

# Configure the deployed logging in a fresh process, log a line, let "logrotate" move the file, and
# log again: the second line must land in a new app.log, not in the moved file.
ROTATION_SCRIPT = """
import logging, logging.config, os, sys
import django
django.setup()
from config.settings.logging_config import portal_logging
log_dir = sys.argv[1]
logging.config.dictConfig(portal_logging(log_dir))
log = logging.getLogger("apps.rotation")
log.warning("before rotation")
os.rename(os.path.join(log_dir, "app.log"), os.path.join(log_dir, "app.log.1"))
log.warning("after rotation")
"""


def _referenced_handlers(config: dict[str, Any]) -> set[str]:
    names = set(config["root"]["handlers"])
    for logger in config["loggers"].values():
        names.update(logger["handlers"])
    return names


class PortalLogDirTests(SimpleTestCase):
    def test_unset_means_the_default_directory(self) -> None:
        self.assertEqual(portal_log_dir({}), DEFAULT_LOG_DIR)

    def test_empty_means_console_only(self) -> None:
        self.assertEqual(portal_log_dir({"PORTAL_LOG_DIR": ""}), "")
        self.assertEqual(portal_log_dir({"PORTAL_LOG_DIR": "  "}), "")

    def test_a_directory_is_used_as_given(self) -> None:
        self.assertEqual(portal_log_dir({"PORTAL_LOG_DIR": " /srv/logs "}), "/srv/logs")


class PortalLoggingTests(SimpleTestCase):
    def test_console_only_writes_no_files(self) -> None:
        config = portal_logging("")
        self.assertEqual(set(config["handlers"]), {"console"})
        self.assertEqual(_referenced_handlers(config), {"console"})

    def test_files_are_watched_never_rotated_in_process(self) -> None:
        config = portal_logging("/srv/logs")
        self.assertEqual(set(config["handlers"]), {"console", "file", "error_file"})
        for name, filename in (("file", "/srv/logs/app.log"), ("error_file", "/srv/logs/error.log")):
            with self.subTest(handler=name):
                handler = config["handlers"][name]
                self.assertEqual(handler["class"], "logging.handlers.WatchedFileHandler")
                self.assertEqual(handler["filename"], filename)
        self.assertEqual(_referenced_handlers(config), set(config["handlers"]))

    def test_the_apps_level_is_per_environment(self) -> None:
        self.assertEqual(portal_logging("", apps_level="DEBUG")["loggers"]["apps"]["level"], "DEBUG")
        self.assertEqual(portal_logging("")["loggers"]["apps"]["level"], "INFO")

    def test_a_line_after_external_rotation_lands_in_a_fresh_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="portal-logs-") as log_dir:
            result = subprocess.run(  # noqa: S603 -- a fixed script with a test-controlled directory.
                [sys.executable, "-c", ROTATION_SCRIPT, log_dir],
                cwd=PORTAL,
                env=dict(os.environ),  # the settings module these tests run under
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            moved = (Path(log_dir) / "app.log.1").read_text()
            fresh = (Path(log_dir) / "app.log").read_text()
        self.assertIn("before rotation", moved)
        self.assertNotIn("after rotation", moved)
        self.assertIn("after rotation", fresh)
