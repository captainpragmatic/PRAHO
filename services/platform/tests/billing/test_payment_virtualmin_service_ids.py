"""The payment producer's persisted packet must reach real Virtualmin provisioning."""

from __future__ import annotations

from typing import cast

from apps.billing.models import Invoice
from apps.billing.signals import _trigger_virtualmin_provisioning_on_payment
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.provisioning.test_virtualmin_service_ids import QueuedVirtualminProvisioningTestBase


class PaymentVirtualminServiceIdTests(QueuedVirtualminProvisioningTestBase):
    def test_payment_producer_packet_provisions_and_persists_integer_pk_service(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="QUEUED-HOSTING", bill_to_country="DE"
        )
        order = Order.objects.create(customer=self.customer, currency=self.currency, invoice=invoice)
        product = Product.objects.create(name="Queued hosting", slug="queued-hosting", product_type="shared_hosting")
        OrderItem.objects.create(order=order, product=product, service=self.service, unit_price_cents=1000)

        packet = self.enqueue_packet(lambda: _trigger_virtualmin_provisioning_on_payment(invoice))
        args = cast("tuple[dict[str, object], ...]", packet["args"])
        self.assertEqual(args[0]["service_id"], str(self.service.pk))
        self.assertEqual(args[0]["domain"], self.service.domain)
        self.assert_created(packet)
