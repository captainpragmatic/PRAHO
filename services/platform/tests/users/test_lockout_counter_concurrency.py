"""PostgreSQL proof that concurrent failures cannot lose a lockout increment.

increment_failed_login_attempts used to bump the counter with an F() expression, read it
back, then write the value it had read. A second failure landing between that read and
that write was overwritten, so a burst of wrong codes could stay under the threshold.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class LockoutCounterPostgresConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.user = User.objects.create_user(email="counter-race@example.test", password=PASSWORD)

    def _fail_once(self) -> None:
        close_old_connections()
        try:
            User.objects.get(pk=self.user.pk).increment_failed_login_attempts()
        finally:
            connection.close()

    def test_two_simultaneous_failures_both_count(self) -> None:
        first_writing = threading.Event()
        release_first = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        original_save = User.save

        def parking_save(instance: User, *args: Any, **kwargs: Any) -> None:
            """Park the first caller between reading the counter and writing it back."""
            nonlocal calls
            with call_lock:
                calls += 1
                call_number = calls
            if call_number == 1:
                first_writing.set()
                if not release_first.wait(timeout=10):
                    raise AssertionError("timed out releasing the first failure")
            original_save(instance, *args, **kwargs)

        with patch.object(User, "save", parking_save), ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(self._fail_once)
            self.assertTrue(first_writing.wait(timeout=10), "the first failure never reached its write")
            second = executor.submit(self._fail_once)
            # Unlocked, the second failure finishes here; locked, it waits for the first.
            with_lock_held = not _finished_within(second, seconds=1)
            release_first.set()
            first.result(timeout=15)
            second.result(timeout=15)

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 2, "a concurrent failure was lost")
        self.assertTrue(with_lock_held, "the second failure did not wait for the first")


def _finished_within(future: Any, *, seconds: float) -> bool:
    try:
        future.result(timeout=seconds)
    except TimeoutError:
        return False
    return True
