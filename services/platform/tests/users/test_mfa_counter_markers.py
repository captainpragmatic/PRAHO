"""Used codes and the attempt budget live in the database counter store, not the cache (#689).

- The replay marker was read, then the code checked, then the marker written: two requests
  with the same code could both read "unused" and both be accepted. The marker is now an
  atomic claim taken after the code checks out, so exactly one wins and a wrong code reserves
  nothing.
- A code used to confirm enrolment left no marker, so it could be replayed at sign-in.
- Both lived in the database cache, which culls entries and can be cleared: a cull handed back
  the attempt budget and forgot used codes early.
- A store failure inside the verifier was swallowed as "wrong code". On PostgreSQL that left
  the caller's transaction aborted, so the next write (counting the failed attempt) raised.
  It now surfaces as MFAStoreUnavailable, answered 503, and charges nobody.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.db import connection, transaction
from django.test import RequestFactory, TestCase

from apps.common.counters import Counter
from apps.users.mfa import MFAStoreUnavailable, TOTPService, verify_login_second_factor
from apps.users.models import User
from apps.users.pending_totp import complete_enrolment, get_or_create_pending

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


def _enrolled(email: str) -> tuple[User, str]:
    user = User.objects.create_user(email=email, password=PASSWORD)
    secret = TOTPService.generate_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = True
    user.save()
    return user, secret


class ReplayMarkerTests(TestCase):
    def setUp(self) -> None:
        self.user, self.secret = _enrolled("replay@example.ro")

    def test_two_requests_racing_with_one_code_accept_it_once(self) -> None:
        """The second request runs while the first sits between checking the code and marking it."""
        code = pyotp.TOTP(self.secret).now()
        real_verify = pyotp.TOTP.verify
        inner: list[bool] = []

        def verify_then_let_the_other_request_in(totp: pyotp.TOTP, *args: Any, **kwargs: Any) -> bool:
            accepted = real_verify(totp, *args, **kwargs)
            if not inner:
                inner.append(False)  # mark the nested call as started, so it does not recurse
                inner[0] = TOTPService.verify_token(self.user, code)
            return bool(accepted)

        with patch.object(pyotp.TOTP, "verify", verify_then_let_the_other_request_in):
            outer = TOTPService.verify_token(self.user, code)

        self.assertEqual(sorted([outer, inner[0]]), [False, True])

    def test_a_wrong_code_reserves_nothing(self) -> None:
        before = Counter.objects.count()
        self.assertFalse(TOTPService.verify_token(self.user, "000000"))
        self.assertEqual(Counter.objects.count(), before)

    def test_the_marker_outlives_a_cache_clear(self) -> None:
        code = pyotp.TOTP(self.secret).now()
        self.assertTrue(TOTPService.verify_token(self.user, code))
        cache.clear()
        self.assertFalse(TOTPService.verify_token(self.user, code))


class EnrolmentReplayTests(TestCase):
    def test_a_code_that_confirmed_enrolment_cannot_sign_in(self) -> None:
        user = User.objects.create_user(email="enrol@example.ro", password=PASSWORD)
        secret = get_or_create_pending(user)
        code = pyotp.TOTP(secret).now()
        self.assertEqual(complete_enrolment(user.pk, password=PASSWORD, code=code, request=None).status, "enabled")

        with transaction.atomic():
            locked = User.objects.select_for_update().get(pk=user.pk)
            result = verify_login_second_factor(locked, code, RequestFactory().post("/"))
        self.assertFalse(result.accepted)


class AttemptBudgetTests(TestCase):
    def setUp(self) -> None:
        self.user, self.secret = _enrolled("budget@example.ro")
        self.request = RequestFactory().post("/")

    def verify(self, code: str) -> Any:
        with transaction.atomic():
            locked = User.objects.select_for_update().get(pk=self.user.pk)
            return verify_login_second_factor(locked, code, self.request)

    def test_the_budget_holds_without_a_real_cache_and_outlives_a_clear(self) -> None:
        # Default test settings use DummyCache: a cache-held budget never ran out here.
        for _ in range(5):
            self.assertFalse(self.verify("000000").rate_limited)
        self.assertTrue(self.verify("000000").rate_limited)
        cache.clear()
        self.assertTrue(self.verify(pyotp.TOTP(self.secret).now()).rate_limited)


class StoreFailureTests(TestCase):
    """A real SQL failure, not a mocked exception: the counter table is renamed away."""

    def setUp(self) -> None:
        self.user, self.secret = _enrolled("store@example.ro")

    def _without_counter_table(self) -> Any:
        test = self

        class _Renamed:
            def __enter__(self) -> None:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE common_counters RENAME TO common_counters_away")

            def __exit__(self, *exc: object) -> None:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE common_counters_away RENAME TO common_counters")
                test.assertTrue(True)

        return _Renamed()

    def test_a_store_failure_is_reported_not_read_as_a_wrong_code(self) -> None:
        with self._without_counter_table(), self.assertRaises(MFAStoreUnavailable):
            TOTPService.verify_token(self.user, pyotp.TOTP(self.secret).now())

    def test_a_store_failure_at_sign_in_charges_no_failed_attempt(self) -> None:
        with self._without_counter_table():
            with self.assertRaises(MFAStoreUnavailable), transaction.atomic():
                locked = User.objects.select_for_update().get(pk=self.user.pk)
                verify_login_second_factor(locked, "000000", RequestFactory().post("/"))
            # The connection is still usable after the failure.
            self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_the_staff_sign_in_page_answers_503(self) -> None:
        staff, _secret = _enrolled("staff-store@example.ro")
        staff.staff_role = "support"
        staff.save(update_fields=["staff_role"])
        response = self.client.post("/auth/login/", {"email": staff.email, "password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        with self._without_counter_table():
            response = self.client.post("/auth/mfa/verify/", {"token": "000000"})
        self.assertEqual(response.status_code, 503)
