"""PostgreSQL proof that the staff 2FA step checks the code under one row lock (#590).

The SQLite tests in test_staff_login_second_factor.py show a backup code works once.
They cannot show the check is LOCKED: two simultaneous submissions of the same code from
one pending login would both read it before either spends it. Mirrors
tests/api/test_token_second_factor_concurrency.py.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.http import HttpResponse
from django.test import Client, TransactionTestCase
from django.urls import reverse

from apps.users.mfa import MFAService
from apps.users.models import User, UserLoginLog

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class StaffSecondFactorPostgresConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.user = User.objects.create_user(
            email="web-mfa-race@example.test", password=PASSWORD, is_staff=True, staff_role="support"
        )
        self.user.two_factor_enabled = True
        self.user.save(update_fields=["two_factor_enabled"])
        self.code = self.user.generate_backup_codes()[0]

    def _submit(self, client: Client) -> HttpResponse:
        close_old_connections()
        try:
            return client.post(reverse("users:mfa_verify"), {"token": self.code})
        finally:
            connection.close()

    def test_one_backup_code_sent_twice_at_once_logs_in_once(self) -> None:
        first_client = Client()
        response = first_client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})
        self.assertEqual(response["Location"], reverse("users:mfa_verify"))
        # The same pending login, submitted from two tabs at once.
        second_client = Client()
        second_client.cookies = first_client.cookies

        first_verifying = threading.Event()
        second_verifying = threading.Event()
        release_first = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        original_verify = MFAService.verify_mfa_code

        def coordinated_verify(*args: Any, **kwargs: Any) -> dict[str, Any]:
            nonlocal calls
            with call_lock:
                calls += 1
                call_number = calls
            if call_number == 1:
                first_verifying.set()
                if not release_first.wait(timeout=10):
                    raise AssertionError("timed out releasing the first verification")
            else:
                second_verifying.set()
            return original_verify(*args, **kwargs)

        with (
            patch.object(MFAService, "verify_mfa_code", side_effect=coordinated_verify),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self._submit, first_client)
            self.assertTrue(first_verifying.wait(timeout=10), "the first submission never reached verification")
            second = executor.submit(self._submit, second_client)
            try:
                self.assertFalse(
                    second_verifying.wait(timeout=1),
                    "the second submission verified the code while the first held the user row",
                )
            finally:
                release_first.set()
            responses = [first.result(timeout=15), second.result(timeout=15)]

        self.assertEqual(calls, 2, "the second submission never reached the verifier")
        logged_in = [r for r in responses if r.status_code == 302 and r["Location"] == reverse("dashboard")]
        self.assertEqual(len(logged_in), 1, [r.status_code for r in responses])
        # The loser was checked and refused. Its response is the form again (200), or a 400 when
        # the winner's login has already replaced the session both submissions shared.
        self.assertEqual(UserLoginLog.objects.filter(user=self.user, status="success").count(), 1)
        self.assertEqual(UserLoginLog.objects.filter(user=self.user, status="failed_2fa").count(), 1)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)
