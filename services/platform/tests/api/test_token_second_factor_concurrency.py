"""PostgreSQL proof that token issuance checks the second factor under one row lock (#565).

The SQLite tests in test_token_endpoint_second_factor.py show the decision is re-read
after the password check. They cannot show it is LOCKED: replacing select_for_update
with a plain read would still pass them. Two simultaneous requests carrying the same
backup code can, because without the lock both read the code before either spends it.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase
from rest_framework.response import Response
from rest_framework.test import APIClient

from apps.users.mfa import MFAService
from apps.users.models import APIToken, User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class TokenSecondFactorPostgresConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.user = User.objects.create_user(email="mfa-race@example.test", password=PASSWORD)
        self.user.two_factor_enabled = True
        self.user.save(update_fields=["two_factor_enabled"])
        self.code = self.user.generate_backup_codes()[0]

    def _obtain_token(self) -> Response:
        close_old_connections()
        try:
            return APIClient().post(
                "/api/users/token/",
                {"email": self.user.email, "password": PASSWORD, "mfa_token": self.code, "name": "race"},
                format="json",
            )
        finally:
            connection.close()

    def test_one_backup_code_sent_twice_at_once_issues_one_token(self) -> None:
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
            first = executor.submit(self._obtain_token)
            self.assertTrue(first_verifying.wait(timeout=10), "the first request never reached verification")
            second = executor.submit(self._obtain_token)
            try:
                self.assertFalse(
                    second_verifying.wait(timeout=1),
                    "the second request verified the code while the first held the user row",
                )
            finally:
                release_first.set()
            responses = [first.result(timeout=15), second.result(timeout=15)]

        self.assertEqual(sorted(response.status_code for response in responses), [200, 401])
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 1)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)
