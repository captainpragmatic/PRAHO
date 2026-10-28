"""A lab lock stays held until the observing check releases its owner."""

import fcntl
import io
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.management.base import CommandError
from django.test import SimpleTestCase

from apps.provisioning.management.commands import virtualmin_lab_checks as checks
from apps.provisioning.management.commands._virtualmin_lab import LabNode


class ChainLockFixtureTests(SimpleTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "chain.lock"
        self.command = checks.Command(stdout=io.StringIO())
        self.node = LabNode("vm-b", "owned-test-node", "vm-b.praho.test", "fixture", 10102, 2523)
        self.processes = []
        execute = subprocess.Popen

        def local_transport(argv, **kwargs):
            self.assertEqual(argv[:7], ["docker", "exec", "-i", self.node.container, "python3", "-u", "-c"])
            process = execute([sys.executable, *argv[5:]], **kwargs)
            self.processes.append(process)
            return process

        self.enterContext(patch.object(checks.subprocess, "Popen", side_effect=local_transport))
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                if process.stdin:
                    process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def assert_held(self):
        with self.path.open("a") as stream, self.assertRaises(BlockingIOError):
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_released(self):
        with self.path.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertTrue(all(process.poll() is not None for process in self.processes))

    def test_acknowledgment_proves_the_kernel_lock_and_context_exit_releases_it(self):
        with self.command._hold_node_lock(self.node, str(self.path)) as held:
            self.assertIsNone(held.poll())
            self.assert_held()
        self.assert_released()

    def test_an_interrupted_check_releases_its_actual_lock_owner(self):
        with (
            self.assertRaisesRegex(RuntimeError, "consumer interrupted"),
            self.command._hold_node_lock(self.node, str(self.path)),
        ):
            self.assert_held()
            raise RuntimeError("consumer interrupted")
        self.assert_released()

    def test_another_owners_lock_is_not_mistaken_for_this_fixture_acquiring_it(self):
        with self.path.open("a") as other:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (
                self.assertRaisesRegex(CommandError, "acquire"),
                self.command._hold_node_lock(self.node, str(self.path)),
            ):
                self.fail("an unowned lock must not admit the observed check")
            self.assert_held()
        self.assert_released()

    def test_missing_ready_acknowledgment_cleans_up_without_running_the_check(self):
        with (
            patch("select.select", return_value=([], [], [])),
            self.assertRaisesRegex(CommandError, "acquire"),
            self.command._hold_node_lock(self.node, str(self.path)),
        ):
            self.fail("an unconfirmed lock must not admit the observed check")
        self.assert_released()

    def test_unconfirmed_release_fails_the_check_and_reaps_the_local_process(self):
        with (
            self.assertRaisesRegex(CommandError, "release"),
            self.command._hold_node_lock(self.node, str(self.path)) as held,
        ):
            self.assert_held()
            wait = held.wait
            attempts = []

            def delayed_acknowledgment(*, timeout=None):
                if not attempts:
                    attempts.append(True)
                    raise subprocess.TimeoutExpired("lock fixture", timeout)
                return wait(timeout=timeout)

            self.enterContext(patch.object(held, "wait", side_effect=delayed_acknowledgment))
        self.assert_released()
