"""Stale carts cannot create new money; idempotent historical orders keep theirs."""

import uuid
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.orders.views import calculate_cart_totals, create_order, preflight_order
from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.services import OrderCreateData, OrderService
from apps.products.models import Product, ProductPrice
from apps.settings.services import SettingsService


class CurrencyPolicyCheckoutTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Currency checkout", primary_email="currency-checkout@example.test", status="active"
        )
        self.product = Product.objects.create(name="Currency hosting", slug="currency-hosting", product_type="hosting")
        for code, cents in (("RON", 5000), ("EUR", 1000), ("USD", 1200)):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            ProductPrice.objects.create(product=self.product, currency_id=code, monthly_price_cents=cents)
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="checkout-test", fetched_at=timezone.now(),
                )
        self.factory = APIRequestFactory()
        self.initial_policy = get_selling_currency_policy()
        self.item = {"product_id": str(self.product.pk), "quantity": 1, "billing_period": "monthly"}

    def post(self, view, *, code="RON", revision=None, key=None):
        payload = {"currency": code, "items": [self.item]}
        if revision is not None:
            payload["currency_revision"] = revision
        request = self.factory.post(
            "/api/orders/test/", payload, format="json", HTTP_IDEMPOTENCY_KEY=key or uuid.uuid4().hex,
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return view(request)

    def switch(self, code):
        result = SettingsService.update_setting("billing.default_currency", code)
        self.assertIsInstance(result, Ok)
        return get_selling_currency_policy()

    def test_all_cart_endpoints_reject_a_stale_currency_without_creating_an_order(self) -> None:
        policy = self.switch("EUR")
        for view in (calculate_cart_totals, preflight_order, create_order):
            with self.subTest(view=view.__name__):
                response = self.post(view, revision=self.initial_policy.revision)
                self.assertEqual(response.status_code, 409, response.data)
                self.assertEqual(response.data["code"], "currency_changed")
                self.assertEqual(response.data["selling_currency"], "EUR")
                self.assertEqual(response.data["currency_revision"], policy.revision)
        self.assertFalse(Order.objects.exists())

    def test_returning_to_the_same_currency_still_invalidates_the_old_revision(self) -> None:
        self.switch("EUR")
        self.switch("RON")
        response = self.post(create_order, revision=self.initial_policy.revision)
        self.assertEqual(response.status_code, 409, response.data)
        self.assertFalse(Order.objects.exists())

    def test_legacy_cart_without_revision_must_be_reviewed_again(self) -> None:
        response = self.post(create_order)
        self.assertEqual(response.status_code, 409, response.data)
        self.assertFalse(Order.objects.exists())

    def test_current_policy_uses_each_explicit_price_and_currency(self) -> None:
        for code, cents in (("RON", 5000), ("EUR", 1000), ("USD", 1200)):
            with self.subTest(code=code):
                policy = self.switch(code)
                calculation = self.post(calculate_cart_totals, code=code, revision=policy.revision)
                self.assertEqual(calculation.status_code, 200, calculation.data)
                self.assertEqual(calculation.data["subtotal_cents"], cents)
                self.assertEqual(calculation.data["currency_revision"], policy.revision)
                result = self.post(create_order, code=code, revision=policy.revision)
                self.assertEqual(result.status_code, 201, result.data)
                order = Order.objects.get(pk=result.data["order"]["id"])
                self.assertEqual((order.currency_id, order.subtotal_cents), (code, cents))

    def test_existing_order_retry_keeps_its_original_currency_after_switch(self) -> None:
        key = uuid.uuid4().hex
        initial = self.post(create_order, revision=self.initial_policy.revision, key=key)
        self.assertEqual(initial.status_code, 201, initial.data)
        self.switch("EUR")
        retried = self.post(create_order, revision=self.initial_policy.revision, key=key)
        self.assertEqual(retried.status_code, 200, retried.data)
        self.assertEqual(retried.data["order"]["id"], initial.data["order"]["id"])
        self.assertEqual(Order.objects.get().currency_id, "RON")

    def test_staff_order_creation_resolves_the_runtime_default(self) -> None:
        self.switch("EUR")
        data = OrderCreateData(
            customer=self.customer,
            items=[{"product_id": str(self.product.pk), "quantity": 1, "unit_price_cents": 1000,
                    "description": self.product.name, "meta": {"billing_period": "monthly"}}],
            billing_address=OrderService.build_billing_address_from_customer(self.customer),
        )
        result = OrderService.create_order(data)
        self.assertIsInstance(result, Ok, result)
        self.assertEqual(result.value.currency_id, "EUR")
