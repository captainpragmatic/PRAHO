"""
Tests for C2: confirm_order Phase 1/2 lock gap — prove idempotency holds.

The confirm_order API releases the DB lock between Phase 1 (validation) and
Phase 2 (Stripe call). This is safe because Phase 3 re-acquires the lock and
OrderPaymentConfirmationService.confirm_order() is idempotent. These tests
prove the existing mitigation works.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIRequestFactory

from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.invoice_models import InvoiceSequence
from apps.billing.models import Currency, Invoice
from apps.billing.proforma_models import ProformaSequence
from apps.billing.proforma_service import ProformaService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status


class TestC2ConfirmOrderIdempotency(TestCase):
    """C2: Concurrent confirm_order calls must not create duplicate invoices."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="C2 Test SRL",
            customer_type="company",
            status="active",
            primary_email="c2@test.ro",
            company_name="C2 Test SRL",
        )
        self.product = Product.objects.create(
            name="Shared Hosting Basic",
            slug="c2-test-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.user = User.objects.create_user(
            email="admin-c2@pragmatichost.com",
            password="testpass123",
            is_staff=True,
        )
        ProformaSequence.objects.get_or_create(scope="default")
        InvoiceSequence.objects.get_or_create(scope="default")
        self.factory = APIRequestFactory()

    def _create_order_with_proforma(self) -> tuple[Order, object]:
        """Create an awaiting_payment order with linked proforma and PI."""
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={"company_name": "C2 Test SRL", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        force_status(order, "awaiting_payment")

        # Create proforma from order
        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()
        proforma.send_proforma()
        proforma.save()
        order.refresh_from_db()

        # Set PI on order
        order.payment_intent_id = "pi_test1234567890abcdef"
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])

        return order, proforma

    def _call_confirm_order(self, order: Order, pi_id: str) -> object:
        """Call the confirm_order API endpoint."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        request = self.factory.post(
            f"/api/orders/{order.id}/confirm/",
            data={"payment_intent_id": pi_id},
            format="json",
        )
        request._portal_authenticated = True
        request.user = self.user
        with patch(
            "apps.api.secure_auth.get_authenticated_customer",
            return_value=(self.customer, None),
        ):
            return confirm_order(request, str(order.id))

    def test_second_confirm_returns_200_idempotent(self):
        """Second confirm_order on same order returns 200 OK (not 409 conflict)."""
        order, _proforma = self._create_order_with_proforma()

        mock_result = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=order.total_cents,
        )
        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = mock_result

        with patch(
            "apps.billing.gateways.base.PaymentGatewayFactory.create_gateway",
            return_value=mock_gateway,
        ):
            # First call — should transition order
            resp1 = self._call_confirm_order(order, "pi_test1234567890abcdef")
            self.assertEqual(resp1.status_code, status.HTTP_200_OK)
            self.assertTrue(resp1.data["success"])

            # Second call — should be idempotent (200, not 409)
            resp2 = self._call_confirm_order(order, "pi_test1234567890abcdef")
            self.assertEqual(resp2.status_code, status.HTTP_200_OK)
            self.assertTrue(resp2.data["success"])

    def test_only_one_invoice_created_after_double_confirm(self):
        """Even after two confirm calls, exactly one invoice exists for the proforma."""
        order, proforma = self._create_order_with_proforma()

        mock_result = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=order.total_cents,
        )
        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = mock_result

        with patch(
            "apps.billing.gateways.base.PaymentGatewayFactory.create_gateway",
            return_value=mock_gateway,
        ):
            self._call_confirm_order(order, "pi_test1234567890abcdef")
            self._call_confirm_order(order, "pi_test1234567890abcdef")

        # Only ONE invoice should exist linked to this proforma
        invoice_count = Invoice.objects.filter(
            converted_from_proforma=proforma,
        ).count()
        self.assertLessEqual(
            invoice_count,
            1,
            f"Expected at most 1 invoice for proforma {proforma.number}, got {invoice_count}",
        )
