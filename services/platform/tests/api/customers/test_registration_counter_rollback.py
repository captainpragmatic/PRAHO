"""Registration failures consume the client's allowance and leave no pending registration."""

from __future__ import annotations

import json
from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, TestCase
from rest_framework.exceptions import ValidationError

from apps.api.customers.serializers import CustomerRegistrationSerializer
from apps.audit.models import AuditEvent
from apps.common import counters
from apps.settings.services import SettingsService
from apps.users.pending_registration import PendingRegistration

COUNTER_KEY = "rate_limit:registration:198.51.100.18"


class RegistrationCounterRollbackTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        counters.reset(COUNTER_KEY)
        result = SettingsService.update_setting("security.registration_rate_limit_per_ip", 1)
        self.assertTrue(result.is_ok(), result)
        # The budget keys on the end user's IP from the Portal's signed body, never the transport address.
        self.request = RequestFactory().post(
            "/api/customers/register/",
            data=json.dumps({"client_ip": "198.51.100.18"}),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.2",
        )
        self.request._portal_authenticated = True

    def registration(self, *, first_name: str = "Ana") -> CustomerRegistrationSerializer:
        data: dict[str, dict[str, object]] = {
            "user_data": {
                "email": "registration-counter@example.test",
                "first_name": first_name,
                "last_name": "Pop",
            },
            "customer_data": {
                "customer_type": "company",
                "company_name": "Counter rollback company",
                "address_line1": "Str. Victoriei 10",
                "city": "București",
                "postal_code": "010061",
                "data_processing_consent": True,
                "marketing_consent": False,
            },
        }
        serializer = CustomerRegistrationSerializer(data=data, context={"request": self.request})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        return serializer

    def test_invalid_registration_consumes_the_allowance_and_blocks_valid_retries(self) -> None:
        with self.assertRaises(ValidationError):
            self.registration(first_name="Name123").save()
        self.assertEqual(counters.peek(COUNTER_KEY), 1)
        self.assertFalse(PendingRegistration.objects.exists())

        for expected_count in (2, 3):
            with self.assertRaises(ValidationError):
                self.registration().save()
            self.assertEqual(counters.peek(COUNTER_KEY), expected_count)
            self.assertFalse(PendingRegistration.objects.exists())

    def test_a_storage_failure_keeps_the_counter_and_its_record(self) -> None:
        with (
            patch(
                "apps.users.services.PendingRegistration.objects.create", side_effect=RuntimeError("Store unavailable")
            ),
            self.assertRaises(ValidationError),
        ):
            self.registration().save()
        self.assertEqual(counters.peek(COUNTER_KEY), 1)
        self.assertFalse(PendingRegistration.objects.exists())
        # Discarding the registration must not discard the record of the failure.
        self.assertTrue(AuditEvent.objects.filter(action="method_error").exists())

    def test_without_a_signed_client_ip_the_shared_bucket_is_charged(self) -> None:
        counters.reset("rate_limit:registration:")
        self.request = RequestFactory().post("/api/customers/register/", REMOTE_ADDR="198.51.100.18")
        self.registration().save()
        self.assertEqual(counters.peek("rate_limit:registration:"), 1)
        self.assertEqual(counters.peek(COUNTER_KEY), 0)
