"""PostgreSQL proof that the staff password step decides under the user row lock.

An enrolment holds the user row while it turns 2FA on. A password login that read the
row before that commit, and did not wait for the lock, signed a password-only session in
for an account that was enrolled by the time it finished. The SQLite tests in
test_login_decision_under_lock.py show the decision re-reads the row; only a real lock
shows it waits for an enrolment in flight.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from django.db import close_old_connections, connection, transaction
from django.http import HttpResponse
from django.test import Client, TransactionTestCase
from django.urls import reverse

from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class StaffLoginEnrollmentRaceTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.user = User.objects.create_user(
            email="enrol-race@example.test", password=PASSWORD, is_staff=True, staff_role="support"
        )

    def _enrol_and_hold(self, holding: threading.Event, release: threading.Event) -> None:
        """Turn 2FA on inside a transaction that holds the user row until released."""
        close_old_connections()
        try:
            with transaction.atomic():
                User.objects.select_for_update().get(pk=self.user.pk)
                User.objects.filter(pk=self.user.pk).update(two_factor_enabled=True)
                holding.set()
                if not release.wait(timeout=10):
                    raise AssertionError("timed out releasing the enrolment")
        finally:
            connection.close()

    def _password_login(self, client: Client) -> HttpResponse:
        close_old_connections()
        try:
            return client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})
        finally:
            connection.close()

    def test_password_login_during_an_enrolment_hands_off_to_the_second_factor(self) -> None:
        holding = threading.Event()
        release = threading.Event()
        client = Client()
        with ThreadPoolExecutor(max_workers=2) as executor:
            enrolment = executor.submit(self._enrol_and_hold, holding, release)
            self.assertTrue(holding.wait(timeout=10), "the enrolment never took the row")
            login = executor.submit(self._password_login, client)
            try:
                login.result(timeout=1)
                waited = False
            except FutureTimeout:
                waited = True
            finally:
                release.set()
            enrolment.result(timeout=15)
            response = login.result(timeout=15)

        self.assertEqual(response["Location"], reverse("users:mfa_verify"))
        self.assertNotIn("_auth_user_id", client.session, "a password-only session outlived the enrolment")
        self.assertTrue(waited, "the login decided without waiting for the enrolment's row lock")
