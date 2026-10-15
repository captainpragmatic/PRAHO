"""When the VAT rules fail, an order line falls back to the operator's VAT, not Romania's.

The fallback named Romania whatever the operator's country, so a German operator's order took 21%
when the rules could not be applied. It now asks for the operator's own rate.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency
from apps.billing.tax_models import TaxRule
from apps.customers.models import Customer
from apps.orders.services import OrderCreateData, OrderService
from apps.orders.vat_rules import OrderVATCalculator
from apps.products.models import Product


@override_settings(COMPANY_COUNTRY_CODE="DE")
class VATFallbackCountryTests(TestCase):
    def test_a_failed_vat_rule_falls_back_to_the_operators_rate(self) -> None:
        TaxRule.objects.create(country_code="DE", rate=Decimal("0.19"), valid_from=date(2020, 1, 1))
        selling = get_selling_currency_policy().currency_code
        currency, _ = Currency.objects.get_or_create(code=selling, defaults={"symbol": selling, "decimals": 2})
        customer = Customer.objects.create(name="Kunde GmbH", customer_type="company", status="active")
        product = Product.objects.create(name="Hosting", slug="fallback-hosting", product_type="shared_hosting")
        data = OrderCreateData(
            customer=customer,
            currency=currency.code,
            billing_address={"country": "DE"},
            items=[{"product_id": product.pk, "quantity": 1, "unit_price_cents": 10000, "description": "Hosting"}],
        )
        real = OrderVATCalculator.calculate_vat
        calls: list[int] = []

        def line_rules_fail(**kwargs: object) -> object:
            # The order's totals are computed first; the line's own VAT is the call that fails.
            calls.append(1)
            if len(calls) > 1:
                raise RuntimeError("rules down")
            return real(**kwargs)

        with patch("apps.orders.vat_rules.OrderVATCalculator.calculate_vat", side_effect=line_rules_fail):
            result = OrderService.create_order(data)
        self.assertTrue(result.is_ok(), str(result))
        line = result.unwrap().items.get()
        self.assertEqual((line.tax_rate, line.tax_cents), (Decimal("0.1900"), 1900))
