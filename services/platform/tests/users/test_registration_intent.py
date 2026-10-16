"""A registration keeps what the visitor came to buy, cleaned, for after its confirmation.

The portal sends the product, billing period and domain chosen on the operator's site, and the
first-touch attribution, with the registration. Platform stores only valid known keys with the
pending registration and returns them with its details, so the account's first order can resume
them on whichever device confirms the link. The account itself never depends on them.
"""

from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.legal import publish_release
from tests.users.test_registration_fiscal_identity import registration


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class RegistrationIntentTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        publish_release()

    def test_the_intent_is_kept_cleaned_and_shown_with_the_details(self) -> None:
        intent = {
            "product": "web-hosting",
            "period": "annual",
            "domain": "Example.ro",
            "utm_source": "newsletter",
            "is_staff": "true",
            "period_override": "free",
        }
        response = self.portal_post("/api/customers/register/", {**registration(), "intent": intent})
        self.assertEqual(response.status_code, 202, response.content)
        row = PendingRegistration.objects.get()
        expected = {"product": "web-hosting", "period": "annual", "domain": "example.ro", "utm_source": "newsletter"}
        self.assertEqual(row.intent, expected)

        PendingRegistration.objects.filter(pk=row.pk).update(sent_at=timezone.now())  # The link works once mailed
        response = self.portal_post(
            "/api/users/register/pending/", {"registration_id": str(row.pk), "token": row.token()}
        )
        self.assertEqual(response.json()["registration"]["intent"], expected)

    def test_a_registration_without_an_intent_has_none(self) -> None:
        self.assertEqual(self.portal_post("/api/customers/register/", registration()).status_code, 202)
        self.assertEqual(PendingRegistration.objects.get().intent, {})
