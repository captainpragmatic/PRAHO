"""Rolling back below this branch aborted on a restored constraint, with no explanation.

`0054` relaxed `discount_cents >= 0` into a direction-aware pair, so its reverse re-adds the
old rule - which every credit note with a discount now violates. The failure was a raw CHECK
violation from the database, on the one operation an operator reaches for when a deploy has
gone wrong. `0053`'s reverse has the same problem with the three `invoiceline_*_non_negative`
constraints and `0049`'s with the three `invoice_*_non_negative`, and both of those are on
master.

One guard covers all three. Any rollback below this branch must unapply 0054 before it can
reach 0053, so 0054's reverse is the gate, and an appended operation runs FIRST in the reverse
direction. The guard names every offending shape and the manual recipe, and - the half that is
easy to leave untested - it stays out of the way entirely when nothing offends, so a rollback
on an environment that never issued a credit note still works.
"""

from __future__ import annotations

from decimal import Decimal

from django.db import connection
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Currency,
    Invoice,
    InvoiceLine,
)
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.migrations import restore_to_leaf

ROLLBACK_TARGET = ("billing", "0053_remove_invoiceline_invoiceline_unit_price_non_negative_and_more")


class SignedDocumentRollbackGuardTest(TransactionTestCase):
    """`TransactionTestCase` because the executor runs its own transactions."""

    def tearDown(self) -> None:
        restore_to_leaf("billing")
        super().tearDown()

    def _signed_credit_note(self) -> Invoice:
        customer = CustomerFactory()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        original = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="FCT-000900",
            status="issued",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        credit_note = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="CN-000900",
            status="issued",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            discount_cents=-500,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        InvoiceLine.objects.bulk_create(
            [
                InvoiceLine(
                    invoice=credit_note,
                    kind="service",
                    description="Hosting reversal",
                    quantity=Decimal("1"),
                    unit_price_cents=-10000,
                    tax_rate=Decimal("0.2100"),
                    tax_cents=-2100,
                    line_total_cents=-12100,
                )
            ]
        )
        return credit_note

    def _roll_back(self) -> None:
        MigrationExecutor(connection).migrate([ROLLBACK_TARGET])

    def test_the_reverse_refuses_while_a_signed_credit_note_exists(self) -> None:
        self._signed_credit_note()

        with self.assertRaises(IrreversibleError) as caught:
            self._roll_back()

        message = str(caught.exception)
        self.assertIn("0054", message)
        self.assertIn("credit note", message)

    def test_the_refusal_names_every_offending_shape(self) -> None:
        """Three constraint families are restored by this rollback, not one."""
        self._signed_credit_note()

        with self.assertRaises(IrreversibleError) as caught:
            self._roll_back()

        message = str(caught.exception)
        self.assertIn("discount_cents", message)
        self.assertIn("invoice line", message)
        self.assertIn("negative totals", message)

    def test_the_reverse_succeeds_when_nothing_offends(self) -> None:
        """A guard that always refuses is not a guard, it is a wall."""
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())

        self._roll_back()

        applied = MigrationExecutor(connection).loader.applied_migrations
        self.assertIn(ROLLBACK_TARGET, applied)
        self.assertNotIn(("billing", "0054_remove_invoice_invoice_discount_non_negative_and_more"), applied)
