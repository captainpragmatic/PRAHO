"""Portal UI tests for recurring-payment consent and enrollment."""

from __future__ import annotations

import json
import time
import uuid
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class RecurringPaymentsViewsTestCase(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.RecurringPaymentsService.overview")
    def test_owner_sees_terms_saved_cards_and_independent_subscriptions(self, overview) -> None:
        overview.return_value = {
            "success": True,
            "terms_version": "2026-07-17",
            "terms_text": "Customer recurring authorization terms",
            "payment_methods": [{"id": 9, "display_name": "Visa 4242", "last_four": "4242", "authorization": None}],
            "subscriptions": [
                {
                    "id": str(uuid.uuid4()),
                    "number": "SUB-000001",
                    "name": "Managed Hosting",
                    "status": "active",
                    "billing_cycle": "monthly",
                    "auto_payment_enabled": False,
                    "authorization_id": None,
                    "cancel_at_period_end": False,
                }
            ],
        }

        response = self.client.get(reverse("billing:recurring_payments"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Customer recurring authorization terms")
        self.assertContains(response, "Managed Hosting")

    @patch("apps.billing.views.RecurringPaymentsService.overview")
    def test_malformed_platform_identifiers_are_ignored_instead_of_crashing_page(self, overview) -> None:
        overview.return_value = {
            "success": True,
            "terms_version": "2026-07-17",
            "terms_text": "Customer recurring authorization terms",
            "payment_methods": [
                {"id": "not-an-integer", "display_name": "Invalid card", "authorization": None},
                {"id": True, "display_name": "Boolean card", "authorization": None},
            ],
            "subscriptions": [
                {
                    "id": "not-a-uuid",
                    "number": "SUB-BROKEN",
                    "name": "Invalid subscription",
                    "status": "active",
                }
            ],
        }

        response = self.client.get(reverse("billing:recurring_payments"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Invalid card")
        self.assertNotContains(response, "Boolean card")
        self.assertNotContains(response, "Invalid subscription")

    @patch("apps.billing.views.RecurringPaymentsService.overview")
    def test_saved_card_without_optional_display_name_uses_safe_fallback(self, overview) -> None:
        authorization_id = uuid.uuid4()
        overview.return_value = {
            "success": True,
            "terms_version": "2026-07-17",
            "terms_text": "Customer recurring authorization terms",
            "payment_methods": [
                {
                    "id": 9,
                    "last_four": "4242",
                    "authorization": {"id": str(authorization_id)},
                }
            ],
            "subscriptions": [
                {
                    "id": str(uuid.uuid4()),
                    "number": "SUB-000001",
                    "name": "Managed Hosting",
                    "status": "active",
                }
            ],
        }

        response = self.client.get(reverse("billing:recurring_payments"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Card ending 4242")

    @patch("apps.billing.views.RecurringPaymentsService.begin_authorization")
    def test_begin_authorization_proxies_only_signed_identity_from_session(self, begin) -> None:
        begin.return_value = {
            "success": True,
            "setup_intent_id": "seti_portal",
            "client_secret": "seti_portal_secret",
            "payment_method_id": "pm_processor",
            "publishable_key": "pk_test_portal",
        }

        response = self.client.post(
            reverse("billing:recurring_authorization_begin"),
            data=json.dumps({"payment_method_id": 9, "terms_accepted": True, "terms_version": "2026-07-17"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        begin.assert_called_once_with(
            customer_id=42,
            user_id=7,
            payment_method_id=9,
            terms_accepted=True,
            terms_version="2026-07-17",
        )

    @patch("apps.billing.views.RecurringPaymentsService.begin_authorization")
    def test_begin_authorization_rejects_boolean_payment_method_id(self, begin) -> None:
        response = self.client.post(
            reverse("billing:recurring_authorization_begin"),
            data=json.dumps({"payment_method_id": True, "terms_accepted": True, "terms_version": "2026-07-17"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        begin.assert_not_called()

    @patch("apps.billing.views.RecurringPaymentsService.complete_authorization")
    def test_complete_authorization_rejects_boolean_payment_method_id(self, complete) -> None:
        response = self.client.post(
            reverse("billing:recurring_authorization_complete"),
            data=json.dumps({"payment_method_id": True, "setup_intent_id": "seti_portal"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        complete.assert_not_called()
