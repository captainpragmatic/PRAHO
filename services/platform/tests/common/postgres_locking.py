"""Bounded, independently connected PostgreSQL workers and exact lock observations."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event
from time import monotonic

from django.db import connection, connections


def backend_pid() -> int:
    with connection.cursor() as cursor:
        cursor.execute("SHOW transaction_isolation")
        assert cursor.fetchone()[0] == "read committed"
        cursor.execute("SET lock_timeout = '15s'")
        cursor.execute("SET statement_timeout = '25s'")
        cursor.execute("SELECT pg_backend_pid()")
        return int(cursor.fetchone()[0])


@contextmanager
def database_worker[T](action: Callable[[], T]) -> Iterator[tuple[int, Future[T]]]:
    """Always close the thread's connection, propagate errors, and bound database work."""
    ready = Event()
    pids: list[int] = []

    def run() -> T:
        connections.close_all()
        try:
            pids.append(backend_pid())
            ready.set()
            return action()
        finally:
            ready.set()
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(run)
        if not ready.wait(10):
            raise AssertionError("Database worker did not connect")
        if not pids:
            pending.result(timeout=30)
            raise AssertionError("Database worker did not capture its PID")
        yield pids[0], pending


def wait_for_blocker[T](pid: int, blocker: int, pending: Future[T], *, table: str, operation: str = "SELECT") -> str:
    """Require the intended SQL to wait on the exact writer before it may commit."""
    deadline = monotonic() + 10
    poll = Event()
    sample = None
    while monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_stat_clear_snapshot()")
            cursor.execute(
                "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
            )
            sample = cursor.fetchone()
        if sample and sample[0] == "Lock" and blocker in sample[1]:
            assert sample[2].lstrip().startswith(operation), sample
            assert table in sample[2], sample
            return str(sample[2])
        if pending.done():
            raise AssertionError(f"Worker completed without the expected wait: {pending.result()!r}")
        poll.wait(0.01)
    raise AssertionError(f"Worker {pid} did not wait on {blocker} for {table}: {sample!r}")
