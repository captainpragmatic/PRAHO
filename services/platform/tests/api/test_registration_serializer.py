"""CustomerRegistrationSerializer.create() must surface the service's real error.

Regression (#499): the Err branch did `result.value`, but Err has no `.value`
(only `unwrap_err()`), so every registration failure raised AttributeError and was
swallowed into the opaque "Registration service temporarily unavailable" — hiding
the actual validation error from the portal and the user.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase
from rest_framework import serializers

from apps.api.customers.serializers import CustomerRegistrationSerializer
from apps.common.types import Err


class RegistrationSerializerErrorPathTests(TestCase):
    def test_service_error_message_is_surfaced(self) -> None:
        validated = {
            "user_data": {
                "email": "e@example.com",
                "password": "CorrectHorse12!",
                "first_name": "Ana",
                "last_name": "Pop",
            },
            "customer_data": {"customer_type": "company", "company_name": "Acme"},
        }
        serializer = CustomerRegistrationSerializer()

        with patch(
            "apps.api.customers.serializers.SecureUserRegistrationService.register_new_customer_owner",
            return_value=Err("Invalid characters detected"),
        ), self.assertRaises(serializers.ValidationError) as ctx:
            serializer.create(validated)

        detail = ctx.exception.detail
        flat = str(detail)
        self.assertIn("Invalid characters detected", flat)
        self.assertNotIn("temporarily unavailable", flat)
