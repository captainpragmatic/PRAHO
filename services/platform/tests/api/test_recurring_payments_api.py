"""Integration tests for customer-controlled recurring-payment APIs."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.customers.models import Customer, CustomerPaymentMethod
from apps.users.models import CustomerMembership, User


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class RecurringPaymentsAPITestCase(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="API Mandate Customer SRL",
            company_name="API Mandate Customer SRL",
            customer_type="company",
            primary_email="api-mandate@example.test",
            status="active",
        )
        self.owner = User.objects.create_user(email="api-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        self.method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_api_mandate",
            stripe_payment_method_id="pm_api_mandate",
            display_name="Visa 4242",
            last_four="4242",
            is_default=True,
            is_active=True,
        )

    def _payload(self, action: str, **extra: object) -> dict[str, object]:
        return {
            "customer_id": self.customer.id,
            "user_id": self.owner.id,
            "action": action,
            **extra,
        }

    def test_overview_returns_saved_methods_without_exposing_processor_ids(self) -> None:
        response = self.portal_post("/api/billing/recurring-payments/", self._payload("recurring_payment_overview"))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["terms_version"], RecurringPaymentAuthorizationService.TERMS_VERSION)
        self.assertEqual(body["payment_methods"][0]["id"], self.method.id)
        self.assertNotIn("stripe_payment_method_id", body["payment_methods"][0])
        self.assertNotIn("stripe_customer_id", body["payment_methods"][0])

    def test_technical_member_cannot_read_or_manage_recurring_payment_state(self) -> None:
        technician = User.objects.create_user(email="api-tech@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=technician, role="tech")

        response = self.portal_post(
            "/api/billing/recurring-payments/",
            self._payload("recurring_payment_overview", user_id=technician.id),
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["success"])

    @patch("apps.api.billing.views.SettingsService.get_setting", return_value="pk_test_recurring")
    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_owner_can_begin_setup_intent_through_hmac_api(
        self, factory: MagicMock, _get_setting: MagicMock
    ) -> None:
        factory.return_value.create_setup_intent.return_value = {
            "success": True,
            "setup_intent_id": "seti_api_begin",
            "client_secret": "seti_api_begin_secret",
            "error": None,
        }

        response = self.portal_post(
            "/api/billing/recurring-payments/authorize/begin/",
            self._payload(
                "begin_recurring_authorization",
                payment_method_id=self.method.id,
                terms_accepted=True,
                terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            ),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["setup_intent_id"], "seti_api_begin")

    @patch("apps.api.billing.views.SettingsService.get_setting", return_value="pk_test_recurring")
    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_begin_rejects_missing_server_side_terms_acceptance(
        self, factory: MagicMock, _get_setting: MagicMock
    ) -> None:
        response = self.portal_post(
            "/api/billing/recurring-payments/authorize/begin/",
            self._payload("begin_recurring_authorization", payment_method_id=self.method.id),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("terms", response.json()["error"].lower())
        factory.assert_not_called()

    @patch("apps.api.billing.views.SettingsService.get_setting", return_value="")
    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_missing_publishable_key_fails_before_creating_remote_setup_intent(
        self, factory: MagicMock, _get_setting: MagicMock
    ) -> None:
        response = self.portal_post(
            "/api/billing/recurring-payments/authorize/begin/",
            self._payload(
                "begin_recurring_authorization",
                payment_method_id=self.method.id,
                terms_accepted=True,
                terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            ),
        )

        self.assertEqual(response.status_code, 503)
        factory.assert_not_called()

    def test_malformed_local_identifiers_return_bad_request(self) -> None:
        withdraw = self.portal_post(
            "/api/billing/recurring-payments/authorize/withdraw/",
            self._payload("withdraw_recurring_authorization", authorization_id="not-a-uuid"),
        )
        toggle = self.portal_post(
            "/api/billing/recurring-payments/subscriptions/auto-payment/",
            self._payload("set_subscription_auto_payment", subscription_id="not-a-uuid"),
        )

        self.assertEqual(withdraw.status_code, 400)
        self.assertEqual(toggle.status_code, 400)
