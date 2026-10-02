"""The database refuses to change a payment method's encryption context.

Bank details are encrypted with the row's ``encryption_context_id`` in the
AAD, so a changed context would orphan the ciphertext. customers 0003 guards
the column with a trigger: a plpgsql function and trigger on PostgreSQL, a
RAISE(ABORT) trigger on SQLite. These tests run on SQLite in the normal suite
and on PostgreSQL in the integration job.

SQLite drops a table's triggers whenever Django rebuilds the table, so a
future migration that alters customer_payment_methods without re-creating
the trigger turns this file red.
"""

from __future__ import annotations

import uuid

from django.db import DatabaseError, transaction
from django.test import TestCase

from apps.customers.models import Customer, CustomerPaymentMethod

DETAILS = {"bank_name": "BT", "iban": "RO49AAAA1B31007593840000"}


class PaymentMethodEncryptionContextTriggerTests(TestCase):
    def setUp(self) -> None:
        customer = Customer.objects.create(
            name="Trigger Customer",
            customer_type="company",
            status="active",
            primary_email="trigger@example.test",
        )
        self.payment_method = CustomerPaymentMethod.objects.create(
            customer=customer,
            method_type="bank_transfer",
            display_name="Bank transfer",
            bank_details=DETAILS,
        )
        self.context = self.payment_method.encryption_context_id

    def test_changing_the_encryption_context_is_refused(self) -> None:
        with self.assertRaises(DatabaseError), transaction.atomic():
            CustomerPaymentMethod.objects.filter(pk=self.payment_method.pk).update(encryption_context_id=uuid.uuid4())

        self.payment_method.refresh_from_db()
        self.assertEqual(self.payment_method.encryption_context_id, self.context)
        self.assertEqual(self.payment_method.bank_details, DETAILS)

    def test_rewriting_the_same_context_and_other_columns_is_allowed(self) -> None:
        CustomerPaymentMethod.objects.filter(pk=self.payment_method.pk).update(
            encryption_context_id=self.context, display_name="Renamed"
        )

        self.payment_method.refresh_from_db()
        self.assertEqual(self.payment_method.display_name, "Renamed")
        self.assertEqual(self.payment_method.encryption_context_id, self.context)
        self.assertEqual(self.payment_method.bank_details, DETAILS)
