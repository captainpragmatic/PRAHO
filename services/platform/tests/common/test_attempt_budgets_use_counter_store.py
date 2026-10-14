"""Attempt budgets count on the shared counter store, not with a get/set on the default cache.

A get-then-set budget loses concurrent attempts, and the default DatabaseCache can cull a live
count away, handing the whole budget back. Each budget here must survive both.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import OperationalError, connections
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings

from apps.common.decorators import staff_rate_limit
from apps.common.models import Counter
from apps.common.security_decorators import _check_rate_limit
from apps.common.security_errors import RateLimitValidationError
from apps.users.mfa import MFAService
from apps.users.models import User
from tests.helpers.counter_concurrency import counter_database

DATABASE_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "attempt_budget_cache",
        # A cull with CULL_FREQUENCY 0 clears the whole table, as the production cache does under pressure.
        "OPTIONS": {"MAX_ENTRIES": 5, "CULL_FREQUENCY": 0},
        "TIMEOUT": 300,
    }
}


def _cull_the_cache() -> None:
    for index in range(10):
        cache.set(f"filler-{index}", index, 300)
    assert cache.get("filler-0") is None, "the cache must really have been culled"


@override_settings(RATE_LIMITING_ENABLED=True, CACHES=DATABASE_CACHE)
class AttemptBudgetTests(TestCase):
    def setUp(self) -> None:
        call_command("createcachetable", verbosity=0)
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="budget@example.com", password="x")
        self.factory = RequestFactory()

    def test_invitation_budget_survives_a_cache_cull(self) -> None:
        for _ in range(3):
            _check_rate_limit("invitation", 3, "203.0.113.5")
        _cull_the_cache()
        with self.assertRaises(ValidationError):
            _check_rate_limit("invitation", 3, "203.0.113.5")

    def test_invitation_budget_charges_the_user_as_well_as_the_address(self) -> None:
        for _ in range(3):
            _check_rate_limit("invitation", 3, "203.0.113.5", self.user)
        with self.assertRaises(ValidationError):
            _check_rate_limit("invitation", 3, "203.0.113.99", self.user)

    def test_invitation_store_failure_is_a_503(self) -> None:
        with (
            patch("apps.common.counters.increment", side_effect=OperationalError("store down")),
            self.assertRaises(RateLimitValidationError) as caught,
        ):
            _check_rate_limit("invitation", 3, "203.0.113.5")
        self.assertEqual(caught.exception.failure.status_code, 503)

    def test_mfa_budget_survives_a_cache_cull(self) -> None:
        for _ in range(5):
            self.assertTrue(MFAService._check_rate_limit(self.user))
        _cull_the_cache()
        self.assertFalse(MFAService._check_rate_limit(self.user))

    def test_a_verified_second_factor_gives_the_mfa_budget_back(self) -> None:
        for _ in range(3):
            MFAService._check_rate_limit(self.user)
        MFAService._reset_rate_limit(self.user)
        self.assertEqual(Counter.objects.filter(key__startswith=f"mfa_attempts:{self.user.id}").count(), 0)
        for _ in range(5):
            self.assertTrue(MFAService._check_rate_limit(self.user))

    def test_mfa_store_failure_denies_the_attempt(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("store down")):
            self.assertFalse(MFAService._check_rate_limit(self.user))

    def _staff_view(self) -> Callable[..., HttpResponse]:
        @staff_rate_limit(3, per_user=True)
        def view(request: HttpRequest) -> HttpResponse:
            return HttpResponse("ok")

        return view

    def _staff_request(self) -> HttpRequest:
        request = self.factory.get("/staff/probe/")
        request.user = self.user
        return request

    def test_staff_view_budget_survives_a_cache_cull(self) -> None:
        view = self._staff_view()
        self.assertEqual([view(self._staff_request()).status_code for _ in range(3)], [200, 200, 200])
        _cull_the_cache()
        response = view(self._staff_request())
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "60")

    def test_staff_view_store_failure_is_a_503(self) -> None:
        view = self._staff_view()
        with patch("apps.common.counters.increment", side_effect=OperationalError("store down")):
            response = view(self._staff_request())
        self.assertEqual(response.status_code, 503)


@override_settings(RATE_LIMITING_ENABLED=True, CACHES=DATABASE_CACHE)
class AttemptBudgetConcurrencyTests(TransactionTestCase):
    def test_concurrent_mfa_attempts_are_each_counted(self) -> None:
        user = User.objects.create_user(email="race@example.com", password="x")
        barrier = Barrier(8)

        def burst() -> list[bool]:
            try:
                barrier.wait(timeout=30)
                return [MFAService._check_rate_limit(user) for _ in range(5)]
            finally:
                connections.close_all()

        with counter_database(), patch("apps.common.counters.randbelow", return_value=1):
            call_command("createcachetable", verbosity=0)
            cache.clear()
            try:
                with ThreadPoolExecutor(max_workers=8) as executor:
                    futures = [executor.submit(burst) for _ in range(8)]
                    results = [allowed for future in futures for allowed in future.result(timeout=120)]
            finally:
                cache.clear()

        self.assertEqual(len(results), 40)
        self.assertEqual(results.count(True), 5, "exactly the budget (5 per window) is admitted, never more")
