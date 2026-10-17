"""Fail the test whose worker thread exits with a Django database connection still open.

Django gives every thread its own connection and leaves closing it to the thread. Under the CI
settings (``CONN_MAX_AGE = None``) ``close_old_connections()`` closes only unusable connections,
so a worker that ends with it keeps its session open until the cyclic garbage collector frees
the connection object. If that has not happened when the run ends, ``DROP DATABASE`` fails and
names no test (#696). This check runs when each thread exits instead, in that thread, so the
owner is known and the garbage collector plays no part.

What it guarantees: a thread started (directly, or by a thread it started) while a test runs,
whose ``run`` is ``threading.Thread.run`` (``Thread(target=...)`` and ``ThreadPoolExecutor``
workers), has the connections it left open closed and reported as an error on that test. A
report that arrives after its test ended is recorded on that test at the next boundary; one that
arrives after the last test is recorded when the run stops.

What it does not see: a ``Thread`` subclass that overrides ``run`` (``LiveServerThread`` does, and
closes its own connections), a thread still running when the run ends (it is logged, and if it reports
after the summary the run still fails), and parallel runs (serial only). It
never calls ``gc.collect()``: that would close the leaks before they are seen.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from unittest import TestCase as UnitTestCase
from unittest import TestResult

from django.db import connections

logger = logging.getLogger(__name__)

_OWNER_ATTRIBUTE = "_praho_connection_owner"
_CHECK_ATTRIBUTE = "_praho_connection_check"
_MISSING = object()  # no owner recorded, as opposed to an owner of None (started outside any test)
# Only the most recently installed check takes on new threads, so a self-test can nest one.
_ACTIVE: list[ThreadConnectionCheck] = []


class ThreadConnectionLeakError(AssertionError):
    """A worker thread exited with a database connection open, or the check itself failed."""


class _OutsideAnyTest(UnitTestCase):
    """Where a report from a thread no test started is recorded."""

    def runTest(self) -> None:  # noqa: N802 - unittest's name  # pragma: no cover - never run
        pass

    def id(self) -> str:
        return "thread connections (outside any test)"

    def __str__(self) -> str:
        return self.id()


@dataclass(frozen=True)
class _Report:
    owner: UnitTestCase | None
    message: str


def active_check() -> ThreadConnectionCheck | None:
    return _ACTIVE[-1] if _ACTIVE else None


class ThreadConnectionCheck:
    """Patches ``Thread.start`` and ``Thread.run`` while installed; see the module docstring."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._exits_done = threading.Condition(self._lock)
        self._in_flight = 0  # exit checks under way
        self._closed = False  # no exit check starts once the late reports are being drained
        self._reports: list[_Report] = []
        self._running: set[threading.Thread] = set()
        self._current: UnitTestCase | None = None
        self._originals: tuple[Callable[..., Any], Callable[..., Any]] | None = None
        self._start_wrapper: Callable[..., Any] | None = None
        self._run_wrapper: Callable[..., Any] | None = None

    # -- installation ---------------------------------------------------------------------------

    def install(self) -> None:
        if self._originals is not None:
            raise RuntimeError("this thread connection check is already installed")
        original_start, original_run = threading.Thread.start, threading.Thread.run
        check = self

        def start(thread: threading.Thread) -> None:
            if not check._acts():
                original_start(thread)
                return
            # Set before the real start, so the new thread never runs unowned; undo it if the
            # start is refused (a second start of the same thread keeps its first owner).
            previous = (getattr(thread, _OWNER_ATTRIBUTE, _MISSING), getattr(thread, _CHECK_ATTRIBUTE, _MISSING))
            parent = threading.current_thread()
            inherited = getattr(parent, _OWNER_ATTRIBUTE, _MISSING) if getattr(parent, _CHECK_ATTRIBUTE, None) is check else _MISSING
            setattr(thread, _OWNER_ATTRIBUTE, check._current if inherited is _MISSING else inherited)
            setattr(thread, _CHECK_ATTRIBUTE, check)
            try:
                original_start(thread)
            except BaseException:
                for attribute, value in zip((_OWNER_ATTRIBUTE, _CHECK_ATTRIBUTE), previous, strict=True):
                    if value is _MISSING:
                        delattr(thread, attribute)
                    else:
                        setattr(thread, attribute, value)
                raise
            with check._lock:
                check._running.add(thread)

        def run(thread: threading.Thread) -> None:
            try:
                original_run(thread)
            finally:
                # Routed by the check the thread was started under, not the one active now, so a
                # worker that outlives a nested check is still checked.
                if getattr(thread, _CHECK_ATTRIBUTE, None) is check and check._begin_exit():
                    try:
                        check._on_thread_exit(thread)
                    finally:
                        check._end_exit()

        self._originals = (original_start, original_run)
        self._start_wrapper, self._run_wrapper = start, run
        setattr(threading.Thread, "start", start)  # noqa: B010 - restored by uninstall()
        setattr(threading.Thread, "run", run)  # noqa: B010 - restored by uninstall()
        _ACTIVE.append(self)

    def uninstall(self) -> None:
        """Restore the originals; idempotent, and never clobbers a patch made after install()."""
        if self._originals is None:
            return
        original_start, original_run = self._originals
        # A patch applied later (unittest.mock) keeps its value; this check's wrappers then pass
        # straight through because the check no longer acts.
        if threading.Thread.start is self._start_wrapper:
            setattr(threading.Thread, "start", original_start)  # noqa: B010
        if threading.Thread.run is self._run_wrapper:
            setattr(threading.Thread, "run", original_run)  # noqa: B010
        self._originals = None
        if self in _ACTIVE:
            _ACTIVE.remove(self)

    def _acts(self) -> bool:
        return self._originals is not None and active_check() is self

    # -- the check, in the exiting thread -------------------------------------------------------

    def _begin_exit(self) -> bool:
        with self._lock:
            if self._closed or self._originals is None:
                return False
            self._in_flight += 1
            return True

    def _end_exit(self) -> None:
        with self._exits_done:
            self._in_flight -= 1
            self._exits_done.notify_all()

    def _on_thread_exit(self, thread: threading.Thread) -> None:
        # Never raises: an exception here would replace the target's own, or vanish into
        # threading.excepthook. Every problem becomes a report instead.
        owner = getattr(thread, _OWNER_ATTRIBUTE, None)
        try:
            try:
                wrappers = list(connections.all(initialized_only=True))
            except Exception as exc:
                self._report(owner, f"thread {thread.name!r}: could not list its database connections: {exc!r}")
                return
            left_open: list[str] = []
            for wrapper in wrappers:
                try:
                    if wrapper.connection is None:
                        continue
                    left_open.append(wrapper.alias)
                    wrapper.close()
                except Exception as exc:
                    self._report(owner, f"thread {thread.name!r}: could not close connection {wrapper.alias!r}: {exc!r}")
            if left_open:
                self._report(
                    owner,
                    f"worker thread {thread.name!r} exited with {len(left_open)} open database connection(s) "
                    f"({', '.join(left_open)}); close it in the worker's finally with connection.close() "
                    "(close_old_connections() keeps a healthy connection open under CONN_MAX_AGE=None)",
                )
        except BaseException as exc:  # reported, never re-raised into the thread
            self._report(owner, f"thread {thread.name!r}: the connection check failed: {exc!r}")
        finally:
            with self._lock:
                self._running.discard(thread)

    def _report(self, owner: UnitTestCase | None, message: str) -> None:
        with self._lock:
            self._reports.append(_Report(owner, message))

    # -- the main thread's side -----------------------------------------------------------------

    def test_started(self, test: UnitTestCase) -> None:
        self._current = test

    def test_stopped(self, result: TestResult) -> None:
        self.publish(result)
        self._current = None

    def publish(self, result: TestResult) -> None:
        """Record every report so far as an error on the test that started its thread."""
        with self._lock:
            reports, self._reports = self._reports, []
        self._record(result, reports)

    def _record(self, result: TestResult, reports: list[_Report]) -> None:
        for report in reports:
            test = report.owner or _OutsideAnyTest()
            logger.error("🔥 [Tests] %s: %s", test.id(), report.message)
            try:
                raise ThreadConnectionLeakError(report.message)
            except ThreadConnectionLeakError:
                result.addError(test, sys.exc_info())

    def finish(self, result: TestResult, *, wait: float = 2.0) -> None:
        """At the end of the run: let watched threads exit, then publish what they reported."""
        deadline = time.monotonic() + wait
        # Re-read the registry each round: a thread may start another one while being waited on.
        while (alive := self._alive()) and time.monotonic() < deadline:
            for thread in alive:
                thread.join(max(0.0, deadline - time.monotonic()))
        # Reports and survivors are taken together, so an exit cannot fall between the two.
        with self._lock:
            reports, self._reports = self._reports, []
            survivors = [thread for thread in self._running if thread.is_alive()]
        self._record(result, reports)
        for thread in survivors:
            owner = getattr(thread, _OWNER_ATTRIBUTE, None)
            logger.warning(
                "⚠️ [Tests] Thread %r started by %s is still running; its connections cannot be checked",
                thread.name,
                owner.id() if owner else "no test",
            )

    def drain_late_reports(self, *, wait: float = 10.0) -> list[str]:
        """Reports that arrived after finish(), once every exit check under way has finished.

        No exit check starts after this is called, so none can report after it returns. One still
        running when ``wait`` runs out is itself a failure: its report could not be read.
        """
        with self._exits_done:
            self._closed = True
            self._exits_done.wait_for(lambda: self._in_flight == 0, timeout=wait)
            reports, self._reports = self._reports, []
            unfinished = self._in_flight
        messages = [f"{(report.owner or _OutsideAnyTest()).id()}: {report.message}" for report in reports]
        if unfinished:
            messages.append(f"{unfinished} thread exit check(s) still running after {wait:g}s; their reports are lost")
        return messages

    def _alive(self) -> list[threading.Thread]:
        with self._lock:
            return [thread for thread in self._running if thread.is_alive()]
