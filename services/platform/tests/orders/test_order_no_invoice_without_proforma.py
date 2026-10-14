"""An unpaid order never receives an invoice from the pending-order task.

ADR-0038 gives an order exactly one road to an invoice: proforma first, invoice when the
payment lands. When the task could not create the missing proforma it used to issue an
invoice directly, for an order nobody had paid, bypassing that road. It now stops, says so
in the logs and the audit trail, and leaves the order awaiting payment.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency, Invoice
from apps.common.types import Err
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.tasks import process_pending_orders
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status

EVENT = "order_proforma_unavailable"


class FailedProformaFallbackTests(TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(
            name="No Proforma SRL", customer_type="company", status="active", primary_email="np@test.ro"
        )
        product = Product.objects.create(name="NP Hosting", slug="np-hosting", product_type="shared_hosting")
        self.order = Order.objects.create(
            customer=customer,
            currency=currency,
            customer_email="np@test.ro",
            customer_name="No Proforma SRL",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            payment_method="card",
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name="NP Hosting",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
            line_total_cents=12100,
        )
        force_status(self.order, "awaiting_payment")

    def _run(self) -> dict[str, Any]:
        with patch(
            "apps.billing.proforma_service.ProformaService.create_from_order",
            return_value=Err("proforma store unavailable"),
        ):
            return process_pending_orders()

    def _events(self) -> int:
        return AuditEvent.objects.filter(
            action=EVENT,
            content_type=ContentType.objects.get_for_model(Order),
            object_id=str(self.order.pk),
        ).count()

    def test_failed_proforma_fallback_creates_no_invoice(self) -> None:
        invoices_before = Invoice.objects.count()

        outcome = self._run()

        self.assertEqual(Invoice.objects.count(), invoices_before)
        self.order.refresh_from_db()
        self.assertIsNone(self.order.invoice_id)
        self.assertEqual(self.order.status, "awaiting_payment")
        self.assertEqual(self._events(), 1)
        self.assertFalse(outcome["success"], "the run must report the order it could not handle")
        errors = outcome["results"]["errors"]
        self.assertTrue(any(self.order.order_number in str(error) for error in errors), outcome)

    def test_repeated_runs_record_the_problem_once(self) -> None:
        self._run()
        self._run()

        self.assertEqual(Invoice.objects.count(), 0)
        self.assertEqual(self._events(), 1)
