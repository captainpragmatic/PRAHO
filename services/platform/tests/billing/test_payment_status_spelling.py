"""A payment is "cancelled", spelled once.

Stripe spells its own status "canceled" and the gateway layer maps it to a failed payment, so no
payment is ever written with the US spelling; accepting both only lets two spellings drift apart.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.billing.currency_models import Currency
from apps.billing.payment_models import _GATEWAY_TERMINAL_STATUSES, TERMINAL_PAYMENT_STATUSES, Payment
from apps.customers.customer_models import Customer


class PaymentStatusSpellingTests(TestCase):
    def test_choices_and_terminal_sets_use_one_spelling(self) -> None:
        choices = {value for value, _label in Payment.STATUS_CHOICES}
        self.assertIn("cancelled", choices)
        self.assertNotIn("canceled", choices)
        self.assertIn("cancelled", TERMINAL_PAYMENT_STATUSES)
        self.assertNotIn("canceled", TERMINAL_PAYMENT_STATUSES)
        self.assertIn("cancelled", _GATEWAY_TERMINAL_STATUSES)
        self.assertNotIn("canceled", _GATEWAY_TERMINAL_STATUSES)

    def test_the_database_rejects_the_us_spelling(self) -> None:
        customer = Customer.objects.create(
            name="Spelling SRL", customer_type="company", status="active", primary_email="spelling@test.ro"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        with self.assertRaises(IntegrityError), transaction.atomic():
            Payment.objects.create(
                customer=customer, currency=currency, amount_cents=100, payment_method="stripe", status="canceled"
            )
        Payment.objects.create(
            customer=customer, currency=currency, amount_cents=100, payment_method="stripe", status="cancelled"
        )
