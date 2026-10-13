"""Each person's budget for checking a password or a code through the Portal (#689).

Enrolment verify had no budget at all, and disable, regenerate and password change refused a
wrong password before any budget was charged, so guessing was bounded only by the general
120-calls-a-minute HMAC limit. MFACredentialThrottle charges 15 an hour per person, in the
database counter store, so neither a cache cull nor a cache clear hands the budget back.

The person is the one the HMAC middleware read from the signed body, and authentication now
accepts only that same person: an id in another spelling, or a body naming two, cannot
authenticate as one account while being counted as nobody.
"""

from __future__ import annotations

import json
import time
from typing import Any

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Original-secure123!"  # test fixture, not a credential
BUDGET = 15
TOO_MANY = 429
CREDENTIAL_ENDPOINTS = {
    "mfa/verify/": {"token": "000000", "password": "wrong"},
    "mfa/disable/": {"token": "000000", "password": "wrong"},
    "mfa/regenerate-backup-codes/": {"token": "000000", "password": "wrong"},
    "change-password/": {"current_password": "wrong", "new_password": "Another-secure123!"},
}


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    RATE_LIMITING_ENABLED=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class MFACredentialBudgetTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="Budget Co", customer_type="company", status="active")

    def person(self, email: str) -> User:
        user = User.objects.create_user(email=email, password=PASSWORD)
        CustomerMembership.objects.create(user=user, customer=self.customer, role="owner", is_primary=True)
        return user

    def call(self, user: User, suffix: str, data: dict[str, Any]) -> Any:
        path = "/api/users/" + suffix
        body = {"user_id": user.pk, "customer_id": self.customer.pk, **data}
        if suffix == "change-password/":
            payload = json.dumps({**body, "timestamp": time.time()}).encode()
            return self.client.put(path, payload, content_type="application/json", **hmac_headers("PUT", path, payload))
        return self.portal_post(path, body)

    def test_each_credential_endpoint_allows_15_an_hour_per_person(self) -> None:
        for index, (suffix, data) in enumerate(CREDENTIAL_ENDPOINTS.items()):
            with self.subTest(endpoint=suffix):
                guesser = self.person(f"guesser{index}@example.com")
                bystander = self.person(f"bystander{index}@example.com")
                for _ in range(BUDGET):
                    self.assertNotEqual(self.call(guesser, suffix, data).status_code, TOO_MANY)
                self.assertEqual(self.call(guesser, suffix, data).status_code, TOO_MANY)
                # Another person's budget is their own.
                self.assertNotEqual(self.call(bystander, suffix, data).status_code, TOO_MANY)

    def test_clearing_the_cache_does_not_hand_the_budget_back(self) -> None:
        guesser = self.person("guesser@example.com")
        for _ in range(BUDGET):
            self.call(guesser, "mfa/verify/", CREDENTIAL_ENDPOINTS["mfa/verify/"])
        cache.clear()
        self.assertEqual(self.call(guesser, "mfa/verify/", CREDENTIAL_ENDPOINTS["mfa/verify/"]).status_code, TOO_MANY)

    def test_showing_the_setup_page_spends_no_budget(self) -> None:
        user = self.person("setup@example.com")
        for _ in range(BUDGET + 5):
            self.assertEqual(self.call(user, "mfa/setup/", {}).status_code, 200)

    def _verify_with_raw_body(self, raw: bytes) -> Any:
        path = "/api/users/mfa/verify/"
        return self.client.post(path, raw, content_type="application/json", **hmac_headers("POST", path, raw))

    def _reached_verification(self, response: Any) -> bool:
        """Authenticated as someone and answered by the enrolment check itself."""
        return response.status_code == 400 and response.json().get("code") in {"mfa_incorrect", "mfa_setup_expired"}

    def test_an_id_in_another_spelling_does_not_authenticate(self) -> None:
        user = self.person("spelling@example.com")
        attempt = {"customer_id": self.customer.pk, "token": "000000", "password": "wrong", "timestamp": time.time()}
        # The control: the plain id reaches the password and code check.
        control = self._verify_with_raw_body(json.dumps({**attempt, "user_id": user.pk}).encode())
        self.assertTrue(self._reached_verification(control), control.content)
        for spelling in (f"+{user.pk}", f" {user.pk}", float(user.pk), True):
            with self.subTest(user_id=spelling):
                response = self._verify_with_raw_body(json.dumps({**attempt, "user_id": spelling}).encode())
                self.assertFalse(self._reached_verification(response), response.content)

    def test_a_body_naming_two_people_does_not_authenticate(self) -> None:
        user = self.person("twice@example.com")
        other = self.person("other@example.com")
        raw = (
            f'{{"user_id": {other.pk}, "user_id": {user.pk}, "customer_id": {self.customer.pk}, '
            f'"token": "000000", "password": "wrong", "timestamp": {time.time()}}}'
        ).encode()
        response = self._verify_with_raw_body(raw)
        self.assertFalse(self._reached_verification(response), response.content)
