"""Platform log files survive several writing processes (gunicorn workers and qcluster workers).

Each process used to rotate the shared files itself (RotatingFileHandler): one renamed a file under
the others, so a rename of a file already moved failed and its record was dropped, and early
rollovers left short backups and shortened retention. The files are now written with
WatchedFileHandler, which reopens a file once logrotate (the native role) has moved it, and nothing
rotates in process.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any

from django.test import SimpleTestCase

from config.settings.log_files import DEFAULT_LOG_DIR, FILE_HANDLERS, place_log_files, platform_log_dir
from tests.settings.test_logging_configuration import _get_logging

PLATFORM_ROOT = Path(__file__).resolve().parents[2]

# Four processes write through the deployed handler while an external rotator moves the file many
# times: every line must survive, and no process may hit a logging error.
MULTI_PROCESS_SCRIPT = textwrap.dedent(
    """
    import glob, logging, logging.config, multiprocessing, os, sys, threading, time

    def writer(handler, index, lines, start):
        logging.config.dictConfig({"version": 1, "handlers": {"file": handler},
                                   "root": {"handlers": ["file"], "level": "INFO"}})
        log = logging.getLogger("rotation")
        start.wait()
        for n in range(lines):
            log.info("p%d line %05d", index, n)
            if n % 50 == 0:
                time.sleep(0.01)

    if __name__ == "__main__":
        multiprocessing.set_start_method("fork")
        handler_class, directory = sys.argv[1], sys.argv[2]
        handler = {"class": handler_class, "filename": os.path.join(directory, "app.log")}
        start = multiprocessing.Event()
        jobs = [multiprocessing.Process(target=writer, args=(handler, i, 500, start)) for i in range(4)]
        for job in jobs:
            job.start()
        moves, done = [0], threading.Event()
        def rotate():
            while not done.is_set():
                time.sleep(0.03)
                path = os.path.join(directory, "app.log")
                if os.path.exists(path):
                    moves[0] += 1
                    os.rename(path, path + "." + str(moves[0]))
        rotator = threading.Thread(target=rotate)
        rotator.start()
        start.set()
        for job in jobs:
            job.join()
        done.set()
        rotator.join()
        kept = sum(open(f).read().count("\\n") for f in glob.glob(os.path.join(directory, "app.log*")))
        print(kept, moves[0])
    """
)


def _handler_names(config: dict[str, Any]) -> set[str]:
    names = set(config["root"]["handlers"])
    for logger in config["loggers"].values():
        names.update(logger["handlers"])
    return names


class PlatformLogDirTests(SimpleTestCase):
    def test_unset_means_the_default_directory(self) -> None:
        self.assertEqual(platform_log_dir({}), DEFAULT_LOG_DIR)

    def test_empty_means_console_only(self) -> None:
        self.assertEqual(platform_log_dir({"PLATFORM_LOG_DIR": " "}), "")

    def test_a_directory_is_used_as_given(self) -> None:
        self.assertEqual(platform_log_dir({"PLATFORM_LOG_DIR": " /srv/logs "}), "/srv/logs")


class DeployedLogFilesTests(SimpleTestCase):
    def test_every_file_is_watched_and_never_rotated_in_process(self) -> None:
        for module in ("config.settings.prod", "config.settings.staging"):
            config = _get_logging(module)
            for name in FILE_HANDLERS:
                with self.subTest(module=module, handler=name):
                    handler = config["handlers"][name]
                    self.assertEqual(handler["class"], "logging.handlers.WatchedFileHandler")
                    self.assertNotIn("maxBytes", handler)
                    self.assertNotIn("backupCount", handler)
                    self.assertTrue(handler["filename"].startswith(DEFAULT_LOG_DIR + "/"))

    def test_files_follow_the_log_directory(self) -> None:
        config = place_log_files(_get_logging("config.settings.prod"), "/srv/logs")
        self.assertEqual(
            sorted(config["handlers"][name]["filename"] for name in FILE_HANDLERS),
            ["/srv/logs/app.log", "/srv/logs/audit.log", "/srv/logs/error.log", "/srv/logs/security.log"],
        )

    def test_console_only_writes_no_files_and_references_none(self) -> None:
        config = place_log_files(_get_logging("config.settings.prod"), "")
        self.assertFalse(set(FILE_HANDLERS) & set(config["handlers"]))
        self.assertLessEqual(_handler_names(config), set(config["handlers"]))
        self.assertIn("console", config["loggers"]["apps.audit"]["handlers"])

    def test_several_processes_lose_nothing_while_logrotate_moves_the_file(self) -> None:
        handler_class = _get_logging("config.settings.prod")["handlers"]["file"]["class"]
        with tempfile.TemporaryDirectory(prefix="platform-logs-") as directory:
            result = subprocess.run(  # noqa: S603 -- a fixed script with a test-controlled directory.
                [sys.executable, "-c", MULTI_PROCESS_SCRIPT, handler_class, directory],
                cwd=PLATFORM_ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            kept, moves = (int(value) for value in result.stdout.split())
        self.assertNotIn("Logging error", result.stderr)
        # Every move must be followed by a fresh app.log for the next one: a handler that does not
        # reopen keeps writing the moved file, so after the first move there is nothing to rotate.
        self.assertGreater(moves, 3, "the writers kept writing the moved file instead of reopening app.log")
        self.assertEqual(kept, 4 * 500)
