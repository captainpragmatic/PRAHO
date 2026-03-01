"""
Tests for order refund wiring (O1 TODO fix).

Verifies order_refund() delegates to RefundService.refund_order().
"""

from __future__ import annotations

import inspect
import json
import uuid
from unittest.mock import patch

from django.test import RequestFactory, TestCase

from apps.billing.models import Currency
from apps.billing.refund_service import RefundResult, Result
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.views import order_refund
from apps.users.models import CustomerMembership, User


class OrderRefundViewTests(TestCase):
    """O1: order_refund() wires to RefundService.refund_order()"""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email="refund-staff@test.ro", password="testpass123", is_staff=True, staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Refund Test SRL", customer_type="company",
        )
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"},
        )
        self.order = Order.objects.create(
            customer=self.customer, status="completed",
            customer_email="refund-staff@test.ro", customer_name="Refund Test SRL",
            subtotal_cents=10000, tax_cents=1900, total_cents=11900,
            currency=self.currency,
        )

    @patch("apps.billing.refund_service.RefundService.refund_order")
    def test_refund_success(self, mock_refund):
        """Successful refund returns JSON success"""
        mock_refund.return_value = Result.ok(
            RefundResult(refund_id=uuid.uuid4(), status="completed", amount_cents=11900)
        )
        request = self.factory.post(
            f"/orders/{self.order.id}/refund/",
            {"refund_type": "full", "reason": "Customer request"},
        )
        request.user = self.user
        response = order_refund(request, self.order.id)
        self.assertEqual(response.status_code, 200)

    @patch("apps.billing.refund_service.RefundService.refund_order")
    def test_refund_error_returns_failure(self, mock_refund):
        """Failed refund returns JSON error"""
        mock_refund.return_value = Result.err("Already refunded")
        request = self.factory.post(
            f"/orders/{self.order.id}/refund/",
            {"reason": "test"},
        )
        request.user = self.user
        response = order_refund(request, self.order.id)
        data = json.loads(response.content)
        self.assertFalse(data.get("success", True))

    def test_refund_not_disabled(self):
        """order_refund no longer returns 'temporarily disabled'"""
        source = inspect.getsource(order_refund)
        self.assertNotIn("temporarily disabled", source)
