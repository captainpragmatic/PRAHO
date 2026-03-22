from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.api.orders.views import confirm_order
from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import CustomerMembership, User


class OrderPaymentMethodIntegrationTests(TestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )

        self.user = User.objects.create_user(email="order-payments-user@example.ro", password="testpass123")
        self.customer = Customer.objects.create(
            name="Order Payments Customer SRL",
            company_name="Order Payments Customer SRL",
            customer_type="company",
            status="active",
            primary_email="orders-payments@example.ro",
        )
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_active=True)

    def _make_order(self, **extra: object) -> Order:
        # Phase A rename: orders start as "draft", use __dict__ bypass for FSM
        # (integration tests don't have settings.TESTING=True for force_status,
        # and submit() requires _order_has_items condition).
        target_status = str(extra.pop("status", "awaiting_payment"))
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.company_name,
            customer_company=self.customer.company_name,
            **extra,
        )
        if target_status != "draft":
            # Bypass FSM protection for test setup (same technique as force_status)
            order.__dict__["status"] = target_status
            order.save(update_fields=["status"])
        return order

    def _confirm_request(self, **extra: object):
        payload: dict[str, object] = {
            "customer_id": self.customer.id,
            "user_id": self.user.id,
            "timestamp": int(time.time()),
            "payment_status": "succeeded",
        }
        payload.update(extra)

        request = self.factory.post("/api/orders/confirm/", data=payload, format="json")
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_bank_transfer_order_rejects_payment_intent_binding(self) -> None:
        order = self._make_order(payment_method="bank_transfer")
        request = self._confirm_request(payment_intent_id="pi_abcd1234EFGH5678")

        response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("does not accept payment intents", response.data["error"])

    def test_mismatched_payment_intent_is_rejected(self) -> None:
        order = self._make_order(payment_method="card", payment_intent_id="pi_original1234567890")
        request = self._confirm_request(payment_intent_id="pi_attacker1234567890")

        response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("does not match", response.data["error"])

    def test_matching_payment_intent_confirms_order(self) -> None:
        order = self._make_order(payment_method="card", payment_intent_id="pi_match1234567890")
        request = self._confirm_request(payment_intent_id="pi_match1234567890")

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(success=True, status="succeeded", error=None)

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway), \
             patch("apps.api.orders.views._provision_confirmed_order_item"):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])

        order.refresh_from_db()
        # Phase A: confirm_order does paid→provisioning (below review threshold)
        self.assertIn(order.status, ("paid", "provisioning"))
        self.assertEqual(order.payment_intent_id, "pi_match1234567890")

    def test_confirming_non_pending_order_returns_conflict(self) -> None:
        # Phase A: use "paid" status (already past payment)
        order = self._make_order(status="paid", payment_method="card", payment_intent_id="pi_done1234567890")
        request = self._confirm_request(payment_intent_id="pi_done1234567890")

        response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 409)
        self.assertIn("already processed", response.data["error"])
