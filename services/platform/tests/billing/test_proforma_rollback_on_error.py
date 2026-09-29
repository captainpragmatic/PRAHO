"""A failed proforma must not burn an invoice sequence number.

``ProformaService.create_from_order`` is ``@transaction.atomic``. Returning ``Err`` is
a normal return, so Django has no reason to roll back: every write made before the
failure committed while the caller was told the operation failed.

The handler directly above the broad one already called ``set_rollback(True)`` and its
comment named this exact trap — it just guarded one exception class. Everything else
consumed a number from a sequence Romanian law requires to be gapless.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.billing.proforma_service import ProformaService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


class ProformaRollbackOnErrorTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        self.customer = Customer.objects.create(
            name="Rollback Co",
            customer_type="company",
            company_name="Rollback Co",
            status="active",
            primary_email="rollback@example.com",
        )
        self.product = Product.objects.create(
            name="Shared Hosting",
            slug="hosting-rollback",
            product_type="shared_hosting",
            is_active=True,
        )

    def _order(self) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            billing_address={"company_name": "Rollback Co", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=2,
            unit_price_cents=5000,
            tax_rate=Decimal("0.1900"),
            tax_cents=1900,
            line_total_cents=11900,
        )
        return order

    def _sequence_value(self) -> int:
        sequence = ProformaSequence.objects.filter(scope="default").first()
        return sequence.last_value if sequence else 0

    def test_a_late_failure_consumes_no_sequence_number(self) -> None:
        """The audit write is the last step, well after the number is allocated."""
        order = self._order()
        before = self._sequence_value()

        with patch(
            "apps.billing.proforma_service.log_security_event",
            side_effect=RuntimeError("audit backend unavailable"),
        ):
            result = ProformaService.create_from_order(order)

        self.assertTrue(result.is_err(), "the caller must be told this failed")
        self.assertEqual(
            self._sequence_value(),
            before,
            "a proforma number was consumed for a proforma that does not exist — Romanian "
            "sequential numbering requires no gaps",
        )

    def test_a_late_failure_leaves_no_partial_proforma(self) -> None:
        order = self._order()

        with patch(
            "apps.billing.proforma_service.log_security_event",
            side_effect=RuntimeError("audit backend unavailable"),
        ):
            result = ProformaService.create_from_order(order)

        self.assertTrue(result.is_err())
        self.assertEqual(ProformaInvoice.objects.count(), 0, "a half-built proforma committed")
        order.refresh_from_db()
        self.assertIsNone(order.proforma_id, "the order still points at a proforma that was never created")

    def test_the_happy_path_still_creates_one(self) -> None:
        """Guards against 'fixing' the rollback by rolling back unconditionally."""
        result = ProformaService.create_from_order(self._order())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(ProformaInvoice.objects.count(), 1)
        self.assertGreater(self._sequence_value(), 0)
