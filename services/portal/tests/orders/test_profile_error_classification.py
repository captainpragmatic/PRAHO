"""The real profile classifier must route every platform order error correctly (#567).

tests/integration/test_platform_error_localisation.py pins PLATFORM_ORDER_ERRORS to the
platform's preflight messages and checks them against the keyword list. This drives the
production ``_is_profile_error`` itself, so a change to its logic is caught too.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.orders.platform_messages import PLATFORM_ORDER_ERRORS
from apps.orders.views import _is_profile_error

# The billing-profile fields preflight requires. Everything else must NOT open the prompt.
PROFILE_ERRORS = {
    "Please provide a contact name for your order",
    "Please provide a contact email address",
    "Please provide your street address",
    "Please provide your city",
    "Please provide your county/state",
    "Please provide your postal/ZIP code",
    "Please provide your country",
}


class ProfileErrorClassificationTests(SimpleTestCase):
    def test_every_platform_error_is_routed_by_the_production_classifier(self) -> None:
        messages = {str(message) for message in PLATFORM_ORDER_ERRORS}
        self.assertLessEqual(PROFILE_ERRORS, messages)
        for message in sorted(messages):
            with self.subTest(message=message):
                self.assertEqual(_is_profile_error(message), message in PROFILE_ERRORS)
