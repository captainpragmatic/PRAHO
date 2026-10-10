"""Registration security refusals retain their HTTP meaning and store no pending registration."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common import counters
from apps.settings.services import SettingsService
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

MESSAGE = "Too many registration attempts. Please try again later."
COUNTER_KEY = "rate_limit:registration:198.51.100.29"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class RegistrationRateLimitResponseTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        counters.reset(COUNTER_KEY)
        result = SettingsService.update_setting("security.registration_rate_limit_per_ip", 1)
        self.assertTrue(result.is_ok(), result)

    def payload(self, name: str) -> dict[str, dict[str, object]]:
        return {
            "user_data": {
                "email": f"{name}@example.test",
                "first_name": "Ana",
                "last_name": "Pop",
            },
            "customer_data": {
                "customer_type": "company",
                "company_name": f"FX {name}",
                "address_line1": "Str. Victoriei 10",
                "city": "București",
                "postal_code": "010061",
                "data_processing_consent": True,
                "marketing_consent": False,
            },
            "client_ip": "198.51.100.29",
        }

    def test_second_registration_returns_429_and_stores_nothing(self) -> None:
        first = self.portal_post("/api/customers/register/", self.payload("first"))
        self.assertEqual(first.status_code, 202, first.content)
        self.assertEqual(list(PendingRegistration.objects.values_list("email", flat=True)), ["first@example.test"])

        second = self.portal_post("/api/customers/register/", self.payload("second"))
        self.assertEqual(second.status_code, 429, second.content)
        self.assertEqual(second["Retry-After"], "3600")
        self.assertEqual(second.json(), {"success": False, "error": MESSAGE})
        self.assertFalse(PendingRegistration.objects.filter(email="second@example.test").exists())
        self.assertEqual(counters.peek(COUNTER_KEY), 2)

    def test_counter_store_failure_returns_503_without_creating_business_rows(self) -> None:
        with patch("apps.common.security_decorators.counters.increment", side_effect=RuntimeError("store offline")):
            response = self.portal_post("/api/customers/register/", self.payload("offline"))
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(
            response.json(),
            {"success": False, "error": "Service temporarily unavailable. Please try again later."},
        )
        self.assertNotIn("Retry-After", response)
        self.assertFalse(PendingRegistration.objects.exists())
        self.assertEqual(counters.peek(COUNTER_KEY), 0)
