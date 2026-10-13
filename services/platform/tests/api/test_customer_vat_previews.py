"""Amounts shown with VAT use the customer's own rate, not Romania's for everyone (#689).

The service API added Romanian VAT to every customer's monthly cost, and order pages labelled
the stored tax "VAT (21%)" whatever rate the lines carry. A reverse-charge or non-EU customer,
or one with a custom rate, saw totals and labels that did not match their invoices.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.services.serializers import ServiceDetailSerializer
from apps.api.services.views import customer_services_summary_api
from apps.billing.currency_models import Currency
from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.service_models import Service, ServicePlan, ServicePlanPrice


def _customer(name: str, *, country: str, **profile: object) -> Customer:
    customer = Customer.objects.create(name=name, customer_type="company", company_name=name)
    CustomerAddress.objects.create(
        customer=customer,
        is_billing=True,
        address_line1="Street 1",
        city="City",
        county="County",
        postal_code="10000",
        country=country,
    )
    CustomerTaxProfile.objects.create(customer=customer, **profile)
    return customer


class ServiceVATTests(TestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.plan = ServicePlan.objects.create(name="Plan", price_monthly=Decimal("100.00"))
        ServicePlanPrice.objects.update_or_create(
            service_plan=self.plan,
            currency_id="RON",
            defaults={"monthly_price_cents": 10000, "annual_price_cents": 100000, "setup_cents": 0},
        )

    def _service(self, customer: Customer) -> Service:
        return Service.objects.create(
            customer=customer,
            service_plan=self.plan,
            currency_id="RON",
            service_name="Hosting",
            username=f"user_{customer.pk}",
            price=Decimal("100.00"),
            billing_cycle="monthly",
            status="active",
        )

    def test_a_custom_rate_gives_its_own_amount(self) -> None:
        customer = _customer(
            "Redus SRL",
            country="RO",
            vat_number="RO12345678",
            is_vat_payer=True,
            vat_rate=Decimal("11.00"),
            vat_rate_reason="Reduced rate",
        )
        data = ServiceDetailSerializer(self._service(customer)).data
        # A non-zero check: a fraction-versus-percent mix-up gives 1100.00, not 11.00.
        self.assertEqual(Decimal(str(data["vat_amount"])), Decimal("11.00"))
        self.assertEqual(Decimal(str(data["total_monthly_cost"])), Decimal("111.00"))

    def test_a_reverse_charge_customer_pays_no_vat(self) -> None:
        customer = _customer(
            "Evidence GmbH",
            country="DE",
            vat_number="DE123456789",
            is_vat_payer=True,
            vies_verification_status="valid",
            vies_verified_at=timezone.now(),
            vies_consultation_reference="test-reference",
        )
        data = ServiceDetailSerializer(self._service(customer)).data
        self.assertEqual(Decimal(str(data["vat_amount"])), Decimal("0.00"))
        self.assertEqual(Decimal(str(data["total_monthly_cost"])), Decimal("100.00"))

    def test_the_summary_uses_the_customers_rate(self) -> None:
        customer = _customer(
            "Summary SRL",
            country="RO",
            vat_number="RO23456789",
            is_vat_payer=True,
            vat_rate=Decimal("11.00"),
            vat_rate_reason="Reduced rate",
        )
        self._service(customer)
        request = APIRequestFactory().post("/api/services/summary/", {}, format="json")
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
            response = customer_services_summary_api(request)
        summary = response.data["data"]["summary"]
        self.assertEqual(Decimal(str(summary["total_monthly_cost_with_vat"])), Decimal("111.00"))


class OrderVATLabelTests(TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Labels SRL", customer_type="company", company_name="Labels SRL")
        self.order = Order.objects.create(
            customer=customer, currency=currency, customer_email="l@example.ro", customer_name="Labels SRL"
        )
        self.product = Product.objects.create(name="Hosting", slug="label-hosting", product_type="shared_hosting")

    def _item(self, rate: str) -> None:
        OrderItem.objects.create(
            order=self.order, product=self.product, quantity=1, unit_price_cents=10000, tax_rate=Decimal(rate)
        )

    def test_one_rate_on_every_line_is_named(self) -> None:
        self._item("0.1100")
        self._item("0.1100")
        self.assertEqual(self.order.uniform_vat_rate_percent, "11")

    def test_mixed_rates_name_none(self) -> None:
        self._item("0.1100")
        self._item("0.2100")
        self.assertIsNone(self.order.uniform_vat_rate_percent)
