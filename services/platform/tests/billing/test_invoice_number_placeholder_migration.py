"""Upgrade coverage for retiring the legacy "TMP-" invoice-number placeholder.

`number` used to be NOT NULL with a static default of "TMP-000". Making it
nullable does not rewrite rows that already hold the placeholder, so the data
migration has to. A fresh-database test cannot observe any of this.
"""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from tests.helpers.migrations import restore_to_leaf

MIGRATE_FROM = ("billing", "0048_alter_refund_reason")
MIGRATE_TO = ("billing", "0049_remove_invoice_invoice_subtotal_non_negative_and_more")


class PlaceholderNumberMigrationTest(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        currency = CurrencyFactory(code="RON")
        customer = CustomerFactory()

        # An unissued document: no number, not locked.
        unissued = InvoiceFactory(customer=customer, currency=currency, status="draft")
        unissued.number = None
        unissued.save(update_fields=["number"])
        self.unissued_id = unissued.pk

        # Issued history: a real number, locked. Must survive untouched.
        issued = InvoiceFactory(customer=customer, currency=currency, number="INV-KEEP-0001")
        issued.locked_at = issued.created_at
        issued.save(update_fields=["locked_at"])
        self.issued_id = issued.pk

        # Going backwards restores the NOT NULL column, so the reverse step has to
        # invent a placeholder. That is exactly the legacy state we want to test.
        MigrationExecutor(connection).migrate([MIGRATE_FROM])

    def tearDown(self) -> None:
        restore_to_leaf("billing")
        super().tearDown()

    def _numbers(self) -> dict[int, str | None]:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, number FROM billing_invoices WHERE id IN (%s, %s)",
                           [self.unissued_id, self.issued_id])
            return dict(cursor.fetchall())

    def test_placeholder_is_retired_and_real_history_is_untouched(self) -> None:
        before = self._numbers()
        self.assertTrue(
            (before[self.unissued_id] or "").startswith("TMP-"),
            msg=f"expected a placeholder at 0048, got {before[self.unissued_id]!r}",
        )
        self.assertEqual(before[self.issued_id], "INV-KEEP-0001")

        MigrationExecutor(connection).migrate([MIGRATE_TO])

        after = self._numbers()
        self.assertIsNone(after[self.unissued_id], msg="the placeholder should have become NULL")
        self.assertEqual(after[self.issued_id], "INV-KEEP-0001", msg="issued history must never be renumbered")

    def test_a_locked_placeholder_stops_the_migration_loudly(self) -> None:
        """Renumbering locked fiscal history is never safe, so refuse and report it."""
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE billing_invoices SET number = 'TMP-BROKEN', locked_at = created_at WHERE id = %s",
                [self.issued_id],
            )

        with self.assertRaises(RuntimeError) as ctx:
            MigrationExecutor(connection).migrate([MIGRATE_TO])
        self.assertIn("placeholder number", str(ctx.exception))
        self.assertIn(str(self.issued_id), str(ctx.exception))

        # Repair the row the test deliberately broke. Without this, tearDown's
        # restore_to_leaf re-runs the same migration, hits the same guard, and
        # strands the schema at 0048 for every later test in the process.
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE billing_invoices SET number = 'INV-REPAIRED-0001' WHERE id = %s",
                [self.issued_id],
            )
