"""Refunds are staff-only: no portal-signed customer request can move money.

The portal's "Request Refund" button was wired to `api_process_refund`, which executed
`RefundService.refund_invoice` with the customer as actor. It failed only because the portal sent
`invoice_id` where the view needed `payment_id`. The endpoint is removed; staff refund through
`invoice_refund` and `order_refund`.
"""

from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class CustomerRefundPathRemovedTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        self.customer = Customer.objects.create(name="Refund owner", customer_type="individual", status="active")
        self.owner = User.objects.create_user(email="refund-owner@example.test")
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner", is_active=True)
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=currency,
            number="INV-CUSTOMER-REFUND",
            status="paid",
            paid_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=currency,
            amount_cents=12100,
            payment_method="stripe",
            gateway_txn_id="pi_customer_refund",
            status="succeeded",
        )

    def test_a_signed_customer_refund_request_reaches_no_view(self) -> None:
        payload = {
            "payment_id": str(self.payment.pk),
            "customer_id": self.customer.pk,
            "user_id": self.owner.pk,
            "reason": "customer_request",
        }
        with (
            patch("apps.billing.refund_service.RefundService.refund_invoice") as refund_invoice,
            patch("apps.billing.refund_service.RefundService.refund_order") as refund_order,
        ):
            for path in ("/billing/process-refund/", "/api/billing/process-refund/"):
                with self.subTest(path=path):
                    response = self.portal_post(path, dict(payload))
                    self.assertEqual(response.status_code, 404, response.content)
        refund_invoice.assert_not_called()
        refund_order.assert_not_called()

    def test_the_route_name_is_gone(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse("billing:api_process_refund")
