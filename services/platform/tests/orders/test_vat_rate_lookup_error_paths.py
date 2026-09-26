"""`_get_vat_rate_for_order` must not lose a customer's VAT override in silence.

The per-customer override lookup ran under `except Exception: pass`. That is correct for the case the
comment described - a customer with no tax profile - and wrong for every other one. A DatabaseError
reading the profile produced a `CustomerVATInfo` dict WITHOUT `is_vat_payer`,
`reverse_charge_eligible` or `custom_vat_rate`, so the order silently took the country's default VAT
with nothing logged. On a Romanian fiscal document that is a wrong tax rate, and the same span is
already written correctly in `apps/api/orders/views.py:71`, which catches `ObjectDoesNotExist` alone.

Both directions are asserted: the absent-profile case must stay silent, and the database-error case
must now be loud.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import PropertyMock, patch

from django.db import DatabaseError
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.views import _get_vat_rate_for_order

VIEWS_LOGGER = "apps.orders.views"


class VatRateLookupErrorPathTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="VAT Lookup SRL",
            customer_type="company",
            status="active",
            primary_email="vat-lookup@example.test",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={"country": "RO", "company_name": "VAT Lookup SRL"},
        )

    def test_a_customer_with_no_tax_profile_resolves_quietly(self) -> None:
        """The case the original comment described. It must stay silent, or the fix is just noise."""
        with self.assertNoLogs(VIEWS_LOGGER, level="WARNING"):
            rate = _get_vat_rate_for_order(self.order)
        self.assertIsInstance(rate, Decimal)
        self.assertGreater(rate, Decimal("0"))

    def test_a_database_error_reading_the_tax_profile_is_logged_not_swallowed(self) -> None:
        """Revert the fix and this fails: `except Exception: pass` produced no log at all."""
        with (
            patch.object(
                Customer,
                "tax_profile",
                new_callable=PropertyMock,
                side_effect=DatabaseError("tax profile table unavailable"),
            ),
            self.assertLogs(VIEWS_LOGGER, level="WARNING") as logs,
        ):
            rate = _get_vat_rate_for_order(self.order)

        self.assertTrue(
            any("VAT rate lookup failed" in line for line in logs.output),
            f"a database error must reach the outer handler and be logged; got {logs.output}",
        )
        # And it still returns a usable country rate rather than raising into the caller.
        self.assertIsInstance(rate, Decimal)
        self.assertGreater(rate, Decimal("0"))
