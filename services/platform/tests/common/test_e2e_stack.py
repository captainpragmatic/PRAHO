"""The manual runner must fail on missing prerequisites without killing other processes."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("e2e_stack_under_test", ROOT / "scripts/e2e_stack.py")
stack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)


class E2EStackContractTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.logs = Path(directory.name)
        self.state = self.logs / "e2e-stack.json"
        for name, value in [("LOGS", self.logs), ("STATE", self.state), ("FIXTURES", self.logs / "fixtures.json")]:
            override = patch.object(stack, name, value)
            override.start()
            self.addCleanup(override.stop)

    def test_environment_drops_provider_secrets_and_never_reads_dotenv(self):
        with patch.dict(
            stack.os.environ,
            {
                "STRIPE_SECRET_KEY": "do-not-inherit",
                "DATABASE_URL": "do-not-inherit",
                "PLATFORM_API_SECRET": "do-not-inherit",
                "HOME": str(self.logs),
            },
        ):
            environment = stack.environment()
        self.assertEqual(environment["HOME"], str(self.logs))
        self.assertEqual(environment["PRAHO_SKIP_DOTENV"], "1")
        self.assertEqual(environment["E2E_STRICT"], "1")
        for name in ("STRIPE_SECRET_KEY", "DATABASE_URL", "PLATFORM_API_SECRET"):
            self.assertNotIn(name, environment)

    def test_stale_pid_is_never_signalled(self):
        self.state.write_text(json.dumps({"pid": 12345, "instance": "owned-nonce"}))
        with (
            patch.object(stack.subprocess, "run", return_value=Mock(stdout="an-unrelated-server")),
            patch.object(stack.os, "kill") as kill,
            self.assertRaisesRegex(RuntimeError, "stored PID will not be used"),
        ):
            stack.stop()
        kill.assert_not_called()

    def test_occupied_port_fails_without_killing_any_process(self):
        probe = Mock()
        probe.bind.side_effect = OSError("occupied")
        socket_context = Mock()
        socket_context.__enter__ = Mock(return_value=probe)
        socket_context.__exit__ = Mock(return_value=None)
        with (
            patch.object(stack.socket, "socket", return_value=socket_context),
            patch.object(stack.os, "kill") as kill,
            self.assertRaisesRegex(RuntimeError, "Port 8700 is occupied"),
        ):
            stack.require_free_ports()
        kill.assert_not_called()

    def test_missing_logs_block_before_fixture_or_browser_execution(self):
        with (
            patch.object(stack, "read_state", return_value={"ready": True}),
            patch.object(stack, "manage") as manage,
            self.assertRaisesRegex(RuntimeError, "log is missing or empty"),
        ):
            stack.check()
        manage.assert_not_called()

    def test_invalid_fixtures_block_before_login(self):
        for service in stack.SERVICES:
            (self.logs / f"{service}_e2e.log").write_text("server started")
        with (
            patch.object(stack, "read_state", return_value={"ready": True}),
            patch.object(stack, "manage", side_effect=subprocess.CalledProcessError(1, "validate_e2e")),
            patch.object(stack, "login") as login,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            stack.check()
        login.assert_not_called()

    def test_wrong_password_and_lost_session_are_fatal(self):
        for final_url in ("http://localhost:8701/login/", "http://localhost:8701/dashboard/"):
            with self.subTest(final_url=final_url):
                session = Mock()
                session.cookies.get.return_value = "csrf-token"
                session.post.return_value.url = final_url
                session.get.return_value.url = "http://localhost:8701/login/"
                with (
                    patch.object(stack.requests, "Session", return_value=session),
                    self.assertRaisesRegex(RuntimeError, "login failed|session did not persist"),
                ):
                    stack.login("http://localhost:8701", "/login/", "fixture@e2e.test", "wrong", "/dashboard/")

    def test_setup_failure_prevents_server_launch_and_removes_owned_state(self):
        failed = Mock(returncode=1)
        failed.poll.return_value = 1
        with (
            patch.object(stack, "require_free_ports"),
            patch.object(stack.signal, "signal"),
            patch.object(stack.subprocess, "Popen", return_value=failed) as launch,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            stack.serve("our-instance")
        self.assertEqual(launch.call_count, 1)
        self.assertIn("migrate", launch.call_args.args[0])
        self.assertFalse(self.state.exists())

    def test_cancel_during_setup_terminates_only_owned_child(self):
        handlers = {}
        child = Mock()

        def poll():
            handlers[stack.signal.SIGTERM](stack.signal.SIGTERM, None)

        child.poll.side_effect = poll
        with (
            patch.object(stack, "require_free_ports"),
            patch.object(stack.signal, "signal", side_effect=lambda sig, handler: handlers.update({sig: handler})),
            patch.object(stack.subprocess, "Popen", return_value=child) as launch,
            self.assertRaisesRegex(RuntimeError, "setup cancelled"),
        ):
            stack.serve("our-instance")
        self.assertEqual(launch.call_count, 1)
        child.terminate.assert_called_once()
        self.assertFalse(self.state.exists())

    def test_login_cannot_pass_using_expected_path_only_in_query_string(self):
        session = Mock()
        session.cookies.get.return_value = "csrf-token"
        session.post.return_value.url = "http://localhost:8701/login/?next=/dashboard/"
        with (
            patch.object(stack.requests, "Session", return_value=session),
            self.assertRaisesRegex(RuntimeError, "login failed"),
        ):
            stack.login("http://localhost:8701", "/login/", "fixture@e2e.test", "wrong", "/dashboard/")

    def test_fingerprint_changes_for_staged_unstaged_and_untracked_source(self):

        repository = self.logs / "repo"
        repository.mkdir()
        env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        git_binary = shutil.which("git")
        self.assertIsNotNone(git_binary)

        def git(*args):
            subprocess.run(  # noqa: S603 -- fixed git fixture commands in a private temporary repository
                [git_binary, *args],
                cwd=repository,
                env=env,
                check=True,
                capture_output=True,
            )

        git("init", "-q")
        source = repository / "source.py"
        source.write_text("original\n")
        git("add", "source.py")
        git(
            "-c",
            "user.name=Test Runner",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "test: fixture",
            "--signoff",
        )
        with patch.object(stack, "ROOT", repository):
            clean = stack.source_fingerprint()
            self.assertFalse(clean["dirty"])
            source.write_text("changed\n")
            unstaged = stack.source_fingerprint()
            self.assertTrue(unstaged["dirty"])
            self.assertNotEqual(clean, unstaged)
            git("add", "source.py")
            self.assertEqual(stack.source_fingerprint(), unstaged)
            (repository / "new.py").write_text("new\n")
            self.assertNotEqual(stack.source_fingerprint(), unstaged)

    def test_strict_policy_rejects_skip_and_xfail_in_a_real_pytest_session(self):

        suite = self.logs / "policy"
        suite.mkdir()
        (suite / "conftest.py").write_text('pytest_plugins = ["tests.e2e.conftest"]\n')
        env = {**os.environ, "PYTHONPATH": str(ROOT), "E2E_STRICT": "1"}
        env.pop("DJANGO_SETTINGS_MODULE", None)
        for body, expected in [
            ("assert True", 0),
            ('pytest.skip("missing prerequisite")', 1),
            ('pytest.xfail("unverified")', 1),
        ]:
            (suite / "test_policy.py").write_text(f"import pytest\ndef test_policy():\n    {body}\n")
            result = subprocess.run(  # noqa: S603 -- the generated test is fixed, trusted input
                [sys.executable, "-m", "pytest", "-p", "no:django", "-c", "/dev/null", str(suite), "-q"],
                cwd=suite,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            if expected:
                self.assertIn("Strict E2E", result.stdout)
