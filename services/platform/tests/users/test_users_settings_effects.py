"""Registration limits are live, explicit overrides win, and counters survive cache clears."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.db import OperationalError, connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.common import counters
from apps.common.security_decorators import secure_user_registration
from apps.common.types import Ok, Result
from apps.customers.models import Customer
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User
from apps.users.services import SecureUserRegistrationService

REGISTRATION_KEY = "security.registration_rate_limit_per_ip"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "wp18-registration"}}


def user_data(email: str) -> dict[str, object]:
    return {
        "email": email,
        "password": "a-secure-password",
        "first_name": "Registration",
        "last_name": "Owner",
        "gdpr_consent_date": timezone.now(),
    }


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class UsersSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def set_limit(self, limit: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(REGISTRATION_KEY, limit)
        self.assertTrue(result.is_ok(), result)

    def register(self, email: str, ip: str) -> Result[tuple[User, Customer], str]:
        return cast(
            "Result[tuple[User, Customer], str]",
            SecureUserRegistrationService.register_new_customer_owner(
                user_data=user_data(email),
                customer_data={"company_name": email.split("@", 1)[0], "customer_type": "individual"},
                request_ip=ip,
            ),
        )

    def test_existing_registration_wrapper_enforces_runtime_limit_and_explicit_override_wins(self) -> None:
        ip = "192.0.2.81"
        self.set_limit(1)
        self.assertTrue(self.register("first@example.test", ip).is_ok())
        second = self.register("second@example.test", ip)
        self.assertTrue(second.is_err())
        self.assertFalse(User.objects.filter(email="second@example.test").exists())
        self.assertFalse(Customer.objects.filter(primary_email="second@example.test").exists())
        self.assertEqual(counters.peek(f"rate_limit:registration:{ip}"), 2)

        self.set_limit(3)
        self.assertTrue(self.register("third@example.test", ip).is_ok())
        self.assertTrue(self.register("fourth@example.test", ip).is_err())
        self.assertFalse(User.objects.filter(email="fourth@example.test").exists())
        self.set_limit(0)
        self.assertTrue(self.register("zero@example.test", "192.0.2.82").is_err())
        self.assertFalse(User.objects.filter(email="zero@example.test").exists())

        def registration(*, user_data: dict[str, object], request_ip: str) -> Result[str, str]:
            return Ok(str(user_data["email"]))

        for explicit_limit, configured_limit in ((0, 3), (2, 0), (5, 0)):
            self.set_limit(configured_limit)
            explicit_registration = secure_user_registration(rate_limit=explicit_limit)(registration)
            explicit_ip = f"192.0.2.{90 + explicit_limit}"
            for number in range(explicit_limit):
                self.assertTrue(
                    explicit_registration(
                        user_data=user_data(f"explicit-{number}@example.test"), request_ip=explicit_ip
                    ).is_ok()
                )
            self.assertTrue(
                explicit_registration(
                    user_data=user_data("explicit-blocked@example.test"), request_ip=explicit_ip
                ).is_err()
            )

    def test_registration_counter_survives_cache_clear_and_expires_after_one_hour(self) -> None:
        ip = "192.0.2.84"
        key = f"rate_limit:registration:{ip}"
        self.set_limit(1)
        self.assertTrue(self.register("cached-first@example.test", ip).is_ok())
        cache.clear()
        blocked = self.register("cached-second@example.test", ip)
        self.assertTrue(blocked.is_err())
        self.assertFalse(User.objects.filter(email="cached-second@example.test").exists())
        counter = counters.Counter.objects.get(key=key)
        expires_at = counter.expires_at
        self.assertEqual(counter.count, 2)
        self.assertTrue(self.register("cached-third@example.test", ip).is_err())
        counter.refresh_from_db()
        self.assertEqual(counter.expires_at, expires_at)

        with patch("apps.common.counters.time.time", return_value=expires_at + 1):
            self.assertTrue(self.register("after-expiry@example.test", ip).is_ok())
            self.assertEqual(counters.peek(key), 1)

    def test_unavailable_counter_store_refuses_registration_without_creating_a_user(self) -> None:
        self.set_limit(1)
        with patch("apps.common.counters.increment", side_effect=OperationalError("Counter store unavailable")):
            result = self.register("unavailable@example.test", "192.0.2.85")
        self.assertTrue(result.is_err())
        self.assertFalse(User.objects.filter(email="unavailable@example.test").exists())
        self.assertFalse(Customer.objects.filter(primary_email="unavailable@example.test").exists())


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class UsersSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.ip = "192.0.2.86"
        self.key = f"rate_limit:registration:{self.ip}"
        counters.reset(self.key)
        self.addCleanup(counters.reset, self.key)

    @contextmanager
    def setting_mode(self, atomic: bool) -> Generator[None]:
        if atomic:
            with transaction.atomic():
                try:
                    result = SettingsService.update_setting(REGISTRATION_KEY, 1)
                    self.assertTrue(result.is_ok(), result)
                    yield
                finally:
                    transaction.set_rollback(True)
        else:
            self.assertTrue(connection.get_autocommit())
            cache.set(SettingsService._get_cache_key(REGISTRATION_KEY), 1, version=SettingsService.CACHE_VERSION)
            yield

    def check_registration(self, atomic: bool) -> None:
        @secure_user_registration()
        def register(*, user_data: dict[str, object], request_ip: str) -> Result[str, str]:
            return Ok(str(user_data["email"]))

        with self.setting_mode(atomic):
            for number in (1, 2):
                with CaptureQueriesContext(connection) as queries:
                    result = register(user_data=user_data(f"query-{number}@example.test"), request_ip=self.ip)
                setting_queries = [
                    query
                    for query in queries.captured_queries
                    if query["sql"].lstrip().upper().startswith("SELECT")
                    and SystemSetting._meta.db_table in query["sql"]
                ]
                self.assertEqual(len(setting_queries), int(atomic))
                self.assertEqual(result.is_ok(), number == 1)
            self.assertEqual(counters.peek(self.key), 2)

    def test_registration_warm_cache_uses_no_setting_queries(self) -> None:
        self.check_registration(atomic=False)

    def test_registration_atomic_uses_one_setting_query_per_attempt(self) -> None:
        self.check_registration(atomic=True)
