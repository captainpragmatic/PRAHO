"""Actual signed plan checkout uses native qualification and server-derived money."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import stripe

from django.test import TransactionTestCase, override_settings

from django.db import connection

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment, ProformaInvoice
from apps.billing.plan_change_models import PlanChange
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.helpers.portal_session import BoundSessionMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class ServicePlanCheckoutAPITests(BoundSessionMixin, HMACTestMixin, VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.base = f"/api/services/{self.service.pk}/plan-changes/"
        self.body = {"user_id": self.actor.pk, "customer_id": self.customer.pk}

    def test_real_signed_options_quote_confirm_creates_one_exact_standalone_proforma(self) -> None:
        options = self.portal_post(self.base + "options/", self.body)
        self.assertEqual(options.status_code, 200, options.content)
        target = next(item for item in options.json()["data"] if item["product_id"] == str(self.target.pk))
        self.assertTrue(target["available"])
        self.assertEqual(target["period_price_cents"], 20000)
        submission = str(uuid4())
        payload = {**self.body, "target_product_id": str(self.target.pk), "submission_id": submission,
                   "expected_limit_revision": 2, "total_cents": 1, "is_staff": True}
        quoted = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(quoted.status_code, 201, quoted.content)
        data = quoted.json()["data"]
        self.assertEqual((data["net_cents"], data["tax_cents"], data["total_cents"]), (6000, 1260, 7260))
        self.assertFalse(ProformaInvoice.objects.exists())
        replay = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json()["data"]["id"], data["id"])
        self.assertEqual(PlanChange.objects.count(), 1)
        confirmed_path = self.base + data["id"] + "/confirm/"
        confirmation = {**self.body, "quote_fingerprint": data["quote_fingerprint"]}
        confirmed = self.portal_post(confirmed_path, confirmation)
        self.assertEqual(confirmed.status_code, 200, confirmed.content)
        self.assertEqual(confirmed.json()["data"]["status"], "awaiting_payment")
        self.assertEqual(self.portal_post(confirmed_path, confirmation).status_code, 200)
        document = ProformaInvoice.objects.get()
        self.assertEqual((document.subtotal_cents, document.tax_cents, document.total_cents), (6000, 1260, 7260))
        line = document.lines.get()
        self.assertEqual((line.billing_cycle_id, line.quantity, line.unit_price_cents), (None, 1, 6000))
        self.assertEqual(self.service.customer_id, document.customer_id)

    def payment_checkout(self):
        change = self.confirm(self.quote())
        self.assertTrue(SettingsService.update_setting("integrations.stripe_publishable_key", "pk_test_fixture").is_ok())
        sdk = MagicMock()
        sdk.error = stripe.error

        def create(**kwargs):
            self.assertFalse(connection.in_atomic_block)
            attempt = PlanChangePaymentAttempt.objects.get()
            self.assertEqual((attempt.state, attempt.submit_count), ("submitting", 1))
            self.assertEqual(kwargs["idempotency_key"], attempt.idempotency_key)
            self.assertEqual(Payment.objects.get(pk=attempt.payment_id).amount_cents, 7260)
            return SimpleNamespace(id="pi_api_checkout", client_secret="opaque-api-secret")

        sdk.PaymentIntent.create.side_effect = create
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.api-checkout")
        return change, gateway, sdk

    def test_signed_checkout_issues_one_durable_on_session_intent_and_replays_the_same_secret(self) -> None:
        change, gateway, sdk = self.payment_checkout()
        path = self.base + str(change.pk) + "/payment-intent/"
        payload = {**self.body, "quote_fingerprint": change.request_fingerprint, "amount_cents": 1}
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            response = self.portal_post(path, payload)
            self.assertEqual(response.status_code, 200, response.content)
            replay = self.portal_post(path, payload)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(response.json()["data"], replay.json()["data"])
        self.assertEqual(response.json()["data"]["client_secret"], "opaque-api-secret")
        self.assertEqual(response.json()["data"]["publishable_key"], "pk_test_fixture")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual((Payment.objects.count(), PlanChangePaymentAttempt.objects.count()), (1, 1))
        sdk.PaymentIntent.create.assert_called_once()
        values = sdk.PaymentIntent.create.call_args.kwargs
        self.assertEqual((values["amount"], values["currency"], values["confirm"]), (7260, "ron", False))
        self.assertNotIn("off_session", values)
        self.assertNotIn("setup_future_usage", values)

    def test_membership_revoked_during_gateway_io_never_receives_the_card_secret(self) -> None:
        change, gateway, sdk = self.payment_checkout()
        create = sdk.PaymentIntent.create.side_effect

        def revoke(**kwargs):
            result = create(**kwargs)
            CustomerMembership.objects.filter(customer=self.customer, user=self.actor).update(is_active=False)
            return result

        sdk.PaymentIntent.create.side_effect = revoke
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            response = self.portal_post(self.base + str(change.pk) + "/payment-intent/",
                                        {**self.body, "quote_fingerprint": change.request_fingerprint})
        self.assertEqual(response.status_code, 403, response.content)
        self.assertNotIn("opaque-api-secret", response.content.decode())
        self.assertEqual(PlanChangePaymentAttempt.objects.get().state, "ready")

    def test_changed_payload_for_same_submission_returns_conflict(self) -> None:
        payload = {**self.body, "target_product_id": str(self.target.pk), "submission_id": str(uuid4()),
                   "expected_limit_revision": 2}
        first = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(first.status_code, 201, first.content)
        second = self.portal_post(self.base + "quote/", {**payload, "expected_limit_revision": 3})
        self.assertEqual(second.status_code, 409, second.content)
        self.assertEqual(PlanChange.objects.count(), 1)
