"""The order item form previews the VAT the order will actually carry (#689).

The form labelled and computed VAT at a fixed 21%, so a reverse-charge or non-EU customer, or one
with a custom rate, saw a wrong preview. The rate now comes from TaxService, as the saved item's
does, without writing the audit row a VIES refusal records when an order is priced.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.users.models import User


class OrderItemVATPreviewTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(
            email="vat-staff@example.ro", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.client.force_login(self.staff)
        self.currency, _ = Currency.objects.get_or_create(
            code="EUR", defaults={"name": "Euro", "symbol": "€", "decimals": 2}
        )

    def _order(self, *, country: str, company: str, vat_number: str, **profile: Any) -> Order:
        customer = Customer.objects.create(
            customer_type="company", company_name=company, primary_email=f"{country.lower()}@example.test"
        )
        CustomerTaxProfile.objects.create(customer=customer, vat_number=vat_number, **profile)
        return Order.objects.create(
            customer=customer,
            currency=self.currency,
            customer_email=customer.primary_email,
            customer_name=company,
            billing_address={"country": country, "company_name": company, "vat_number": vat_number},
        )

    def _form(self, order: Order, item: OrderItem | None = None) -> Any:
        if item is None:
            return self.client.get(reverse("orders:order_item_create", args=[order.pk]))
        return self.client.get(reverse("orders:order_item_edit", args=[order.pk, item.pk]))

    def test_a_reverse_charge_customer_is_previewed_at_zero(self) -> None:
        order = self._order(
            country="DE",
            company="Evidence GmbH",
            vat_number="DE123456789",
            is_vat_payer=True,
            vies_verification_status="valid",
            vies_verified_at=timezone.now(),
            vies_consultation_reference="test-reference",
        )
        response = self._form(order)
        self.assertEqual(response.context["vat_preview"]["rate"], "0.0000")
        self.assertNotContains(response, "21%")

    def test_a_custom_rate_is_previewed_as_a_fraction(self) -> None:
        order = self._order(
            country="RO",
            company="Redus SRL",
            vat_number="RO12345678",
            is_vat_payer=True,
            vat_rate=Decimal("11.00"),
            vat_rate_reason="Reduced rate for this activity",
        )
        preview = self._form(order).context["vat_preview"]
        # A fraction, the unit OrderItem.tax_rate uses: 100 net becomes 11.00 VAT, not 1100.
        self.assertEqual(preview["rate"], "0.1100")
        self.assertEqual(preview["percent"], "11")

    def test_previewing_an_unverified_eu_vat_payer_records_nothing(self) -> None:
        order = self._order(
            country="DE",
            company="Pending GmbH",
            vat_number="DE987654321",
            is_vat_payer=True,
            vies_verification_status="pending",
        )
        before = AuditEvent.objects.filter(action="vies_evidence_refused").count()
        response = self._form(order)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditEvent.objects.filter(action="vies_evidence_refused").count(), before)

    def test_editing_an_item_previews_the_rate_it_was_priced_at(self) -> None:
        order = self._order(country="RO", company="Stored SRL", vat_number="RO23456789", is_vat_payer=True)
        product = Product.objects.create(name="Hosting", slug="hosting-vat-preview", product_type="shared_hosting")
        item = OrderItem.objects.create(
            order=order, product=product, quantity=1, unit_price_cents=10000, tax_rate=Decimal("0.0900")
        )
        self.assertEqual(self._form(order, item).context["vat_preview"]["rate"], "0.0900")
