"""Registration security refusals retain their HTTP meaning and create no business rows."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from apps.common import counters
from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.users.models import User

MESSAGE = "Too many registration attempts. Please try again later."
COUNTER_KEY = "rate_limit:registration:198.51.100.29"


class RegistrationRateLimitResponseTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        counters.reset(COUNTER_KEY)
        result = SettingsService.update_setting("security.registration_rate_limit_per_ip", 1)
        self.assertTrue(result.is_ok(), result)
        self.api_client = APIClient()

    def payload(self, name: str) -> dict[str, dict[str, object]]:
        return {
            "user_data": {
                "email": f"{name}@example.test",
                "password": "CorrectHorse12!",
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
        }

    def test_second_registration_returns_429_and_preserves_business_row_counts(self) -> None:
        before = (User.objects.count(), Customer.objects.count())
        first = self.api_client.post(
            "/api/customers/register/", self.payload("first"), format="json", REMOTE_ADDR="198.51.100.29"
        )
        self.assertEqual(first.status_code, 201, first.content)
        after_first = (User.objects.count(), Customer.objects.count())
        self.assertEqual(after_first, (before[0] + 1, before[1] + 1))

        second = self.api_client.post(
            "/api/customers/register/", self.payload("second"), format="json", REMOTE_ADDR="198.51.100.29"
        )
        self.assertEqual(second.status_code, 429, second.content)
        self.assertEqual(second["Retry-After"], "3600")
        self.assertEqual(second.json(), {"success": False, "error": MESSAGE})
        self.assertEqual((User.objects.count(), Customer.objects.count()), after_first)
        self.assertFalse(User.objects.filter(email="second@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="FX second").exists())
        self.assertEqual(counters.peek(COUNTER_KEY), 2)

    def test_counter_store_failure_returns_503_without_creating_business_rows(self) -> None:
        before = (User.objects.count(), Customer.objects.count())
        with patch("apps.common.security_decorators.counters.increment", side_effect=RuntimeError("store offline")):
            response = self.api_client.post(
                "/api/customers/register/", self.payload("offline"), format="json", REMOTE_ADDR="198.51.100.29"
            )
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(
            response.json(),
            {"success": False, "error": "Service temporarily unavailable. Please try again later."},
        )
        self.assertNotIn("Retry-After", response)
        self.assertEqual((User.objects.count(), Customer.objects.count()), before)
        self.assertEqual(counters.peek(COUNTER_KEY), 0)
