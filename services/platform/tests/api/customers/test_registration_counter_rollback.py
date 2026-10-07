"""Registration failures consume allowance while business rows remain atomic."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, TestCase
from rest_framework.exceptions import ValidationError

from apps.api.customers.serializers import CustomerRegistrationSerializer
from apps.audit.models import AuditEvent
from apps.common import counters
from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.users.models import User

COUNTER_KEY = "rate_limit:registration:198.51.100.18"


class RegistrationCounterRollbackTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        counters.reset(COUNTER_KEY)
        result = SettingsService.update_setting("security.registration_rate_limit_per_ip", 1)
        self.assertTrue(result.is_ok(), result)
        self.request = RequestFactory().post("/api/customers/register/", REMOTE_ADDR="198.51.100.18")

    def registration(self, *, first_name: str = "Ana") -> CustomerRegistrationSerializer:
        data: dict[str, dict[str, object]] = {
            "user_data": {
                "email": "registration-counter@example.test",
                "password": "CorrectHorse12!",
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
        self.assertFalse(User.objects.filter(email="registration-counter@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="Counter rollback company").exists())

        for expected_count in (2, 3):
            with self.assertRaises(ValidationError):
                self.registration().save()
            self.assertEqual(counters.peek(COUNTER_KEY), expected_count)
            self.assertFalse(User.objects.filter(email="registration-counter@example.test").exists())
            self.assertFalse(Customer.objects.filter(company_name="Counter rollback company").exists())

    def test_late_business_failure_rolls_back_user_and_customer_but_keeps_the_counter(self) -> None:
        with (
            patch(
                "apps.users.services.CustomerAddress.objects.create", side_effect=RuntimeError("Address unavailable")
            ),
            self.assertRaises(ValidationError),
        ):
            self.registration().save()
        self.assertEqual(counters.peek(COUNTER_KEY), 1)
        self.assertFalse(User.objects.filter(email="registration-counter@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="Counter rollback company").exists())
        # Discarding the partial user and customer must not discard the record of the failure.
        self.assertTrue(AuditEvent.objects.filter(action="registration_system_error").exists())
