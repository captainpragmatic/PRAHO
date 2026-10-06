"""The manual runner must fail on missing prerequisites without killing other processes."""

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from coverage import CoverageData

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
        self.source = stack.source_version()
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
            patch.object(stack, "read_state", return_value={"ready": True, "source": self.source}),
            patch.object(stack, "manage") as manage,
            self.assertRaisesRegex(RuntimeError, "log is missing or empty"),
        ):
            stack.check()
        manage.assert_not_called()

    def test_invalid_fixtures_block_before_login(self):
        for service in stack.SERVICES:
            (self.logs / f"{service}_e2e.log").write_text("server started")
        with (
            patch.object(stack, "read_state", return_value={"ready": True, "source": self.source}),
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
            patch.object(stack, "source_version", return_value=self.source),
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
            patch.object(stack, "source_version", return_value=self.source),
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
            startup = {"source": stack.source_version()}
            self.assertEqual(stack.require_stack_source(startup), startup["source"])
            clean = stack.source_fingerprint()
            self.assertFalse(clean["dirty"])
            source.write_text("changed\n")
            unstaged = stack.source_fingerprint()
            self.assertTrue(unstaged["dirty"])
            self.assertNotEqual(clean, unstaged)
            with self.assertRaisesRegex(RuntimeError, "stack source differs"):
                stack.require_stack_source(startup)
            git("add", "source.py")
            self.assertEqual(stack.source_fingerprint(), unstaged)
            with self.assertRaisesRegex(RuntimeError, "stack source differs"):
                stack.require_stack_source(startup)
            (repository / "new.py").write_text("new\n")
            self.assertNotEqual(stack.source_fingerprint(), unstaged)
            git("add", "new.py")
            git(
                "-c",
                "user.name=Test Runner",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "test: changed fixture",
                "--signoff",
            )
            committed = stack.source_fingerprint()
            self.assertFalse(committed["dirty"])
            self.assertNotEqual(committed["source_sha256"], clean["source_sha256"])
            with self.assertRaisesRegex(RuntimeError, "stack source differs"):
                stack.require_stack_source(startup)
            restarted = {"source": stack.source_version()}
            self.assertEqual(stack.require_stack_source(restarted), restarted["source"])
            git(
                "-c",
                "user.name=Test Runner",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "-qm",
                "test: same tree new head",
                "--signoff",
            )
            self.assertEqual(stack.source_fingerprint(), committed)
            with self.assertRaisesRegex(RuntimeError, "stack source differs"):
                stack.require_stack_source(restarted)

    def test_old_or_changed_stack_blocks_before_fixture_and_browser_execution(self):
        for source in (None, {**self.source, "source_sha256": "old-source"}):
            with (
                self.subTest(source=source),
                patch.object(stack, "read_state", return_value={"ready": True, "source": source}),
                patch.object(stack, "manage") as manage,
                self.assertRaisesRegex(RuntimeError, "make stop-e2e"),
            ):
                stack.test([])
            manage.assert_not_called()

    def test_source_changed_during_passing_pytest_is_a_failed_run(self):
        for service in stack.SERVICES:
            (self.logs / f"{service}_e2e.log").write_text("server started")
        stack.FIXTURES.write_text("{}")
        process = Mock(stdout=["1 passed\n"])
        process.wait.return_value = 0
        with (
            patch.object(stack, "ROOT", self.logs),
            patch.object(stack, "check", return_value={"source": self.source}),
            patch.object(stack, "source_version", side_effect=[self.source, {**self.source, "head": "new-head"}]),
            patch.object(stack.subprocess, "Popen", return_value=process),
        ):
            self.assertEqual(stack.test([]), 1)
        evidence = json.loads(next((self.logs / "output/playwright/runs").glob("*/run.json")).read_text())
        self.assertEqual(evidence["pytest_exit_code"], 0)
        self.assertEqual(evidence["exit_code"], 1)
        self.assertTrue(evidence["source_changed_during_run"])
        self.assertEqual(evidence["stack"]["source"], self.source)

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


class CoverageReportingReportsFailureTests(TestCase):
    """`report_coverage` must say when it produced nothing, not just print and return.

    Every coverage subprocess ran with `check=False` and the return code was never read, and a service
    with no data printed a line and continued. So a browser run that measured nothing still passed the
    target whose entire purpose is measuring it. The supervisor is a detached process, so its exit code
    is never observed — the `E2E coverage: OK` marker in the log is the contract the Makefile checks,
    and these tests pin that the marker only appears when it should.
    """

    # One result per subprocess `report_coverage` runs, in order, per service: combine, xml, report.
    # Only `report`'s stdout is read, and only for a line starting with TOTAL.
    STEPS = ("combine", "xml", "report")
    TOTAL_LINE = "TOTAL                     1000    100    200     20    88%"

    def _results(self, failing: int | None = None) -> list[Mock]:
        """Successful results for every subprocess, with optionally ONE made to fail.

        The point of building all of them is that the failure under test must be the ONLY reason
        `report_coverage` can return False. The first version of this test mocked a single result of
        `returncode=1, stdout=""` for every call, which fails for two independent reasons - the status
        AND the absent TOTAL - so deleting the status check outright left the test green. A failing
        `report` here still returns its TOTAL line for exactly that reason.
        """
        results = []
        for _ in stack.SERVICES:
            results += [Mock(returncode=0, stdout=""), Mock(returncode=0, stdout="")]
            results.append(Mock(returncode=0, stdout=f"{self.TOTAL_LINE}\n"))
        if failing is not None:
            results[failing] = Mock(returncode=2, stdout=results[failing].stdout)
        return results

    def _run_with(self, results: list[Mock]) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory() as tmp:
            coverage_dir = Path(tmp)
            for service in stack.SERVICES:
                (coverage_dir / f".coverage.{service}.probe").write_text("placeholder")
            buffer = io.StringIO()
            with (
                patch.object(stack, "COVERAGE_DIR", coverage_dir),
                patch.object(stack.subprocess, "run", side_effect=results),
                contextlib.redirect_stdout(buffer),
            ):
                ok = stack.report_coverage()
        return ok, buffer.getvalue()

    def test_no_data_for_a_service_is_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(stack, "COVERAGE_DIR", Path(tmp)):
            # `assertIs(..., False)`, not `assertFalse`: the implementation this replaced returned
            # None, which is falsy, so `assertFalse` passed against the very version being fixed.
            self.assertIs(stack.report_coverage(), False)

    def test_the_ok_marker_is_printed_only_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(stack, "COVERAGE_DIR", Path(tmp)):
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                ok = stack.report_coverage()
        output = buffer.getvalue()
        self.assertIs(ok, False)
        self.assertIn("E2E coverage: FAILED", output)
        self.assertNotIn("E2E coverage: OK", output)

    def test_each_coverage_subprocess_failure_is_caught_on_its_own(self) -> None:
        """Every one of the three, independently. Two of them were unread before this branch."""
        for index, step in enumerate(self.STEPS):
            with self.subTest(step=step):
                ok, output = self._run_with(self._results(failing=index))
                self.assertIs(ok, False, f"a failing `coverage {step}` was not reported as a failure")
                self.assertIn(f"`coverage {step}` exited 2", output)
                self.assertNotIn("E2E coverage: OK", output)

    def test_a_clean_run_returns_true_and_prints_the_marker(self) -> None:
        """The positive control. Without it, a function that always returned False would pass above."""
        ok, output = self._run_with(self._results())

        self.assertIs(ok, True)
        self.assertIn("E2E coverage: OK", output)
        self.assertNotIn("E2E coverage: FAILED", output)
        self.assertIn("88%", output, "the TOTAL line the report produced should be echoed")


class CoverageUnionGateCanFailTests(TestCase):
    """`make coverage-portal-union` runs in nightly only, so its failure path had run nowhere.

    Its per-half probe asked whether each dataset was READABLE, and `coverage report` exits 0 on a
    dataset whose every file sits at 0%. So a browser half that measured nothing passed the check and
    the union silently became the unit half alone - the exact failure the target exists to prevent,
    and one its own comment claimed it had closed. Reproduced against the real recipe before the
    per-half minimum was added.

    These tests drive the recipe itself rather than a reimplementation of it, because the defect was
    in the recipe. That is what `PORTAL_UNIT_COVERAGE` / `PORTAL_E2E_COVERAGE` exist for.
    """

    IN_SCOPE = ROOT / "services" / "portal" / "apps" / "common" / "retry_after.py"
    # Resolved rather than spelled "make": the recipe under test is the deliverable, and a
    # partial executable path is one more thing that can differ between here and CI.
    MAKE = shutil.which("make") or "make"

    def _dataset(self, path: Path, *, measured: bool) -> Path:
        """A structurally valid portal dataset that either did or did not measure anything.

        For the dead half the recorded line number is impossible rather than absent. Coverage
        intersects executed lines with the file's real statements, so the file still appears in the
        report at 0% - which is the shape that slipped through. A dataset with NO files reports "No
        data to report" and exits 1, a different failure that the readability check already caught,
        so using one would have tested the wrong thing.
        """
        data = CoverageData(basename=str(path))
        data.add_lines({str(self.IN_SCOPE): list(range(1, 400)) if measured else [10**6]})
        data.write()
        return path

    def _union(self, *, unit: Path, browser: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- a fixed make target with paths this test created
            [
                self.MAKE,
                "coverage-portal-union",
                f"PORTAL_UNIT_COVERAGE={unit}",
                f"PORTAL_E2E_COVERAGE={browser}",
            ],
            cwd=ROOT,
            # `PWD` and not just `cwd`: the Makefile resolves `COVERAGE_BIN` through `$(PWD)`, which
            # is the ENVIRONMENT variable, not make's own directory. `subprocess(cwd=...)` changes
            # the directory without touching it, so the venv path resolved under services/platform -
            # where the Django runner happens to run - and every coverage call was "No such file".
            # MAKELEVEL and MAKEFLAGS are dropped because this suite is itself launched from make,
            # and inheriting them turns this into a recursive sub-make.
            env={k: v for k, v in os.environ.items() if k not in {"MAKELEVEL", "MAKEFLAGS"}}
            | {"PWD": str(ROOT)},
            capture_output=True,
            text=True,
            check=False,
        )

    def _halves(self, tmp: str, *, unit_measured: bool, browser_measured: bool) -> dict[str, Path]:
        return {
            "unit": self._dataset(Path(tmp) / "unit", measured=unit_measured),
            "browser": self._dataset(Path(tmp) / "browser", measured=browser_measured),
        }

    def test_a_browser_half_that_measured_nothing_fails_the_union(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self._union(**self._halves(tmp, unit_measured=True, browser_measured=False))

        self.assertNotEqual(result.returncode, 0, "a browser half at 0% passed the union gate")
        self.assertIn("The browser dataset", result.stdout)

    def test_a_unit_half_that_measured_nothing_fails_too(self) -> None:
        """Both directions. The gate is about EITHER half being dead, not only the browser one."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self._union(**self._halves(tmp, unit_measured=False, browser_measured=True))

        self.assertNotEqual(result.returncode, 0, "a unit half at 0% passed the union gate")
        self.assertIn("The units dataset", result.stdout)

    def test_two_measured_halves_pass(self) -> None:
        """The positive control: without it, a target that always failed would satisfy both above."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self._union(**self._halves(tmp, unit_measured=True, browser_measured=True))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("at or above the", result.stdout)


class _FakeClock:
    """A clock that only moves when the code under test sleeps, and frees the state file on cue."""

    def __init__(self, state_file: Path, release_after: float | None) -> None:
        self.now = 0.0
        self.state_file = state_file
        self.release_after = release_after

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        if self.release_after is not None and self.now >= self.release_after and self.state_file.exists():
            self.state_file.unlink()


class StopWaitsForCoverageTests(TestCase):
    """`stop()` must outlast the supervisor's coverage reporting.

    The supervisor combines and reports coverage for both services inside its own shutdown, before it
    releases the state file, and the Makefile reads the coverage verdict straight after `stop()`. On a
    GitHub runner that reporting took longer than the 20 seconds `stop()` allowed: run 37472257524
    passed all 317 browser tests, reported coverage OK, and still failed the job.
    """

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / "e2e-stack.json"
        override = patch.object(stack, "STATE", self.state)
        override.start()
        self.addCleanup(override.stop)

    def _stop(self, *, coverage: bool, release_after: float | None) -> None:
        state = {"pid": 4242, "instance": "owned-nonce", "ready": True, "coverage": coverage}
        self.state.write_text(json.dumps(state))
        clock = _FakeClock(self.state, release_after)
        with (
            patch.object(stack, "read_state", return_value=state),
            patch.object(stack.os, "kill"),
            patch.object(stack.time, "monotonic", clock.monotonic),
            patch.object(stack.time, "sleep", clock.sleep),
        ):
            stack.stop()

    def test_a_coverage_stack_is_given_time_to_finish_reporting(self) -> None:
        self._stop(coverage=True, release_after=120)

    def test_a_plain_stack_still_fails_fast(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "did not finish stopping"):
            self._stop(coverage=False, release_after=120)

    def test_a_coverage_stack_that_never_finishes_still_times_out(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "did not finish stopping"):
            self._stop(coverage=True, release_after=None)


class SupervisorOutputIsUnbufferedTests(TestCase):
    """The coverage verdict must be on disk before the Makefile reads the supervisor's log."""

    def test_the_supervisor_is_launched_unbuffered(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        logs = Path(directory.name)
        launched = Mock()
        launched.poll.return_value = 1  # exits at once, so start() reports the failed setup
        with (
            patch.object(stack, "LOGS", logs),
            patch.object(stack, "require_free_ports"),
            patch.object(stack.subprocess, "Popen", return_value=launched) as popen,
            self.assertRaisesRegex(RuntimeError, "E2E setup failed"),
        ):
            stack.start()
        command = popen.call_args.args[0]
        self.assertEqual(command[:2], [sys.executable, "-u"])
