"""The PostgreSQL runner fails the test whose worker thread leaves a database connection open (#696)."""

from __future__ import annotations

import io
import threading
import unittest
from typing import Any
from unittest import mock

from django.db import connection, connections
from django.test import TransactionTestCase

from tests import thread_connections
from tests.runner import PostgreSQLSafeRunner
from tests.thread_connections import ThreadConnectionCheck, active_check


def _open(held: list[Any]) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    held.append(connection.connection)


def _run(*tests: unittest.TestCase) -> unittest.TestResult:
    result_class = PostgreSQLSafeRunner().get_resultclass()
    runner = unittest.TextTestRunner(stream=io.StringIO(), resultclass=result_class, verbosity=0)
    return runner.run(unittest.TestSuite(tests))


def _errors(result: unittest.TestResult) -> list[tuple[str, str]]:
    return [(test.id().rsplit(".", 1)[-1], text) for test, text in result.errors]


class ThreadConnectionCheckTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("the check guards PostgreSQL sessions; SQLite test databases have none to leak")
        self.held: list[Any] = []
        self.workers: list[threading.Thread] = []
        self.releases: list[threading.Event] = []
        # A broken check must not leak its intentional connections into the outer run: release and
        # join every worker first (cleanups run last-in, first-out), then close what they opened.
        self.addCleanup(lambda: [raw.close() for raw in self.held if not raw.closed])
        self.addCleanup(self._release_and_join)

    def _release_and_join(self) -> None:
        for event in self.releases:
            event.set()
        for worker in self.workers:
            worker.join(10)

    def _install(self) -> ThreadConnectionCheck:
        check = ThreadConnectionCheck()
        check.install()
        self.addCleanup(check.uninstall)
        return check

    def _thread(self, target: Any = None, **kwargs: Any) -> threading.Thread:
        worker = threading.Thread(target=target or _open, args=kwargs.pop("args", (self.held,)), **kwargs)
        self.workers.append(worker)
        return worker

    def _event(self) -> threading.Event:
        event = threading.Event()
        self.releases.append(event)
        return event

    def test_a_worker_that_leaves_its_connection_open_fails_its_test(self) -> None:
        self._install()
        outer = self

        class Inner(unittest.TestCase):
            def test_leaks(self) -> None:
                worker = outer._thread()
                worker.start()
                worker.join()

            def test_closes(self) -> None:
                def clean() -> None:
                    _open(outer.held)
                    connection.close()

                worker = outer._thread(clean, args=())
                worker.start()
                worker.join()

        result = _run(Inner("test_leaks"), Inner("test_closes"))

        self.assertEqual([name for name, _ in _errors(result)], ["test_leaks"])
        self.assertIn("exited with 1 open database connection(s) (default)", result.errors[0][1])
        self.assertTrue(all(raw.closed for raw in self.held), "the check closes what it reports")

    def test_a_late_exit_is_recorded_on_the_test_that_started_the_thread(self) -> None:
        check = self._install()
        release, at_finish = self._event(), self._event()
        real_finish = check.finish

        def finish(result: unittest.TestResult, **kwargs: Any) -> None:
            at_finish.set()  # the last test's worker exits only once the run is finishing
            real_finish(result, **kwargs)

        check.finish = finish  # type: ignore[method-assign]  # instance-level hook for this test
        outer = self

        def late() -> None:
            release.wait(10)
            _open(outer.held)

        def child_leaks() -> None:
            child = outer._thread(name="child-worker")
            child.start()
            child.join()

        class Inner(unittest.TestCase):
            def test_starts(self) -> None:
                outer._thread(late, args=()).start()

            def test_releases(self) -> None:
                release.set()

            def test_descendant(self) -> None:
                worker = outer._thread(child_leaks, args=())
                worker.start()
                worker.join()

            def test_last(self) -> None:
                # Still running when the last test ends: finish() waits for it, then reports it.
                def after_the_last_test() -> None:
                    at_finish.wait(10)
                    _open(outer.held)

                outer._thread(after_the_last_test, args=()).start()

        result = _run(Inner("test_starts"), Inner("test_releases"), Inner("test_descendant"), Inner("test_last"))

        # The late exit races the next boundary, so only the owners are fixed, not the order.
        errors = dict(_errors(result))
        self.assertEqual(sorted(errors), ["test_descendant", "test_last", "test_starts"])
        self.assertIn("'child-worker'", errors["test_descendant"])

    def test_a_thread_no_test_started_is_a_suite_error(self) -> None:
        self._install()
        worker = self._thread()
        worker.start()
        worker.join()

        result = _run()

        self.assertEqual([str(test) for test, _ in result.errors], ["thread connections (outside any test)"])

    def test_an_unowned_parent_does_not_pass_a_test_to_its_children(self) -> None:
        self._install()
        go = self._event()
        outer = self

        def parent() -> None:
            go.wait(10)
            child = outer._thread()
            child.start()
            child.join()

        self._thread(parent, args=()).start()  # started outside any test

        class Inner(unittest.TestCase):
            def test_unrelated(self) -> None:
                go.set()
                outer.workers[0].join(10)

        result = _run(Inner("test_unrelated"))

        self.assertEqual([str(test) for test, _ in result.errors], ["thread connections (outside any test)"])

    def test_a_worker_that_outlives_a_nested_check_is_still_checked(self) -> None:
        outer_check = self._install()
        release = self._event()

        def late() -> None:
            release.wait(10)
            _open(self.held)

        worker = self._thread(late, args=())
        worker.start()
        nested = self._install()
        release.set()
        worker.join(10)
        nested.uninstall()
        result = unittest.TestResult()
        outer_check.publish(result)

        self.assertEqual(len(result.errors), 1)
        self.assertIn("exited with 1 open database connection(s)", result.errors[0][1])

    def test_a_refused_second_start_keeps_the_first_owner(self) -> None:
        self._install()
        release = self._event()
        outer = self

        def late() -> None:
            release.wait(10)
            _open(outer.held)

        class Inner(unittest.TestCase):
            def test_first(self) -> None:
                outer._thread(late, args=()).start()

            def test_second(self) -> None:
                with self.assertRaises(RuntimeError):
                    outer.workers[0].start()
                release.set()
                outer.workers[0].join(10)

        result = _run(Inner("test_first"), Inner("test_second"))

        self.assertEqual([name for name, _ in _errors(result)], ["test_first"])

    def test_the_check_reports_its_own_failures_and_keeps_the_target_exception(self) -> None:
        self._install()
        caught: list[type[BaseException]] = []
        outer = self

        def raises() -> None:
            _open(outer.held)
            raise ValueError("the worker's own error")

        class Inner(unittest.TestCase):
            def test_cannot_list(self) -> None:
                with mock.patch.object(thread_connections.connections, "all", side_effect=RuntimeError("list")):
                    worker = outer._thread()
                    worker.start()
                    worker.join()

            def test_cannot_close(self) -> None:
                wrapper_class = type(connections["default"])
                with (
                    mock.patch.object(wrapper_class, "close", side_effect=RuntimeError("close")),
                    mock.patch.object(threading, "excepthook", lambda args: caught.append(args.exc_type)),
                ):
                    worker = outer._thread(raises, args=())
                    worker.start()
                    worker.join()

        result = _run(Inner("test_cannot_list"), Inner("test_cannot_close"))

        errors = _errors(result)
        self.assertIn("could not list its database connections", errors[0][1])
        self.assertEqual([name for name, _ in errors[1:]], ["test_cannot_close", "test_cannot_close"])
        self.assertIn("could not close connection 'default'", errors[1][1] + errors[2][1])
        self.assertEqual(caught, [ValueError])

    def test_uninstall_restores_through_nested_patches(self) -> None:
        before = (threading.Thread.start, threading.Thread.run)
        check = self._install()
        with mock.patch.object(threading.Thread, "run", lambda thread: None):
            pass
        self.assertNotEqual(threading.Thread.run, before[1], "the inner patch restored the check's wrapper")
        check.uninstall()
        self.assertEqual((threading.Thread.start, threading.Thread.run), before)

        # A patch still active at uninstall keeps its value; the check's wrapper then passes through.
        check = self._install()
        later = mock.patch.object(threading.Thread, "run", threading.Thread.run)
        later.start()
        check.uninstall()
        later.stop()
        ran: list[bool] = []
        worker = threading.Thread(target=lambda: ran.append(True))
        worker.start()
        worker.join()
        self.assertEqual(ran, [True])
        self.assertIsNot(active_check(), check)

    def test_a_failing_run_still_restores_thread(self) -> None:
        before = (threading.Thread.start, threading.Thread.run)
        for phase in ("discovery", "database teardown"):
            with self.subTest(phase=phase):
                seen: list[object] = []

                def fail(*_args: Any, phase: str = phase, seen: list[object] = seen, **_kwargs: Any) -> int:
                    seen.append(active_check())
                    raise RuntimeError(phase)

                with (
                    mock.patch("django.test.runner.DiscoverRunner.run_tests", fail),
                    self.assertRaisesMessage(RuntimeError, phase),
                ):
                    PostgreSQLSafeRunner().run_tests(["tests"])
                self.assertIsInstance(seen[0], ThreadConnectionCheck)
                self.assertEqual((threading.Thread.start, threading.Thread.run), before)

    def test_a_report_after_the_summary_still_fails_the_run(self) -> None:
        # The worker's target has returned and its exit check is under way when finish() takes its
        # final snapshot; the check's report then lands after the summary.
        in_check, release = self._event(), self._event()
        real_all = thread_connections.connections.all

        def held_in_the_exit_check(*args: Any, **kwargs: Any) -> Any:
            in_check.set()
            release.wait(10)
            return real_all(*args, **kwargs)

        def run_and_leave_a_survivor(*_args: Any, **_kwargs: Any) -> int:
            check = active_check()
            assert check is not None
            worker = self._thread()
            with mock.patch.object(thread_connections.connections, "all", held_in_the_exit_check):
                worker.start()
                self.assertTrue(in_check.wait(10), "the worker never reached its exit check")
                check.finish(unittest.TestResult(), wait=0)
                release.set()
                worker.join(10)
            return 0

        with (
            mock.patch("django.test.runner.DiscoverRunner.run_tests", run_and_leave_a_survivor),
            self.assertLogs("tests.runner", "ERROR") as logs,
        ):
            failures = PostgreSQLSafeRunner().run_tests(["tests"])

        self.assertEqual(failures, 1)
        self.assertIn("Reported after the summary", logs.output[0])

    def test_parallel_runs_skip_the_check(self) -> None:
        outer_check = active_check()
        seen: list[object] = []

        def record(*_args: Any, **_kwargs: Any) -> int:
            seen.append(active_check())
            return 0

        with (
            mock.patch("django.test.runner.DiscoverRunner.run_tests", record),
            self.assertLogs("tests.runner", "WARNING") as logs,
        ):
            PostgreSQLSafeRunner(parallel=2).run_tests(["tests"])
        self.assertEqual(seen, [outer_check])
        self.assertIn("serial-only", logs.output[0])
