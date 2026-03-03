"""
Invoice Dataclass Schema Tests

Tests the status_display property on the Invoice dataclass defined in
apps.billing.schemas. No database access — pure Python dataclass logic.
"""

import unittest
from datetime import datetime, timezone as dt_timezone
from decimal import Decimal

from apps.billing.schemas import Currency, Invoice


def _make_invoice(status: str) -> Invoice:
    """Helper: build a minimal valid Invoice dataclass with the given status."""
    currency = Currency(id=1, code='RON', name='Romanian Leu', symbol='lei', decimal_places=2)
    now = datetime.now(tz=dt_timezone.utc)
    return Invoice(
        id=1,
        number='INV-000001',
        status=status,
        currency=currency,
        exchange_to_ron=None,
        subtotal_cents=10000,
        tax_cents=2100,
        total_cents=12100,
        issued_at=now,
        due_at=now,
        created_at=now,
        updated_at=now,
        locked_at=None,
        sent_at=None,
        paid_at=None,
    )


class InvoiceStatusDisplayTestCase(unittest.TestCase):
    """Tests for Invoice.status_display property."""

    def test_status_draft(self):
        """'draft' status maps to the 'Draft' label."""
        invoice = _make_invoice('draft')
        self.assertEqual(invoice.status_display, 'Draft')

    def test_status_issued(self):
        """'issued' status maps to the 'Issued' label."""
        invoice = _make_invoice('issued')
        self.assertEqual(invoice.status_display, 'Issued')

    def test_status_paid(self):
        """'paid' status maps to the 'Paid' label."""
        invoice = _make_invoice('paid')
        self.assertEqual(invoice.status_display, 'Paid')

    def test_status_overdue(self):
        """'overdue' status maps to the 'Overdue' label."""
        invoice = _make_invoice('overdue')
        self.assertEqual(invoice.status_display, 'Overdue')

    def test_status_cancelled(self):
        """'cancelled' status maps to the 'Cancelled' label."""
        invoice = _make_invoice('cancelled')
        self.assertEqual(invoice.status_display, 'Cancelled')

    def test_status_partially_paid(self):
        """'partially_paid' status maps to the 'Partially Paid' label."""
        invoice = _make_invoice('partially_paid')
        self.assertEqual(invoice.status_display, 'Partially Paid')

    def test_unknown_status_title_case_fallback(self):
        """Unknown status values are title-cased with underscores replaced by spaces."""
        invoice = _make_invoice('custom_status')
        self.assertEqual(invoice.status_display, 'Custom Status')

    def test_single_word_unknown_status(self):
        """Single-word unknown status is title-cased."""
        invoice = _make_invoice('pending')
        self.assertEqual(invoice.status_display, 'Pending')

    def test_multi_word_unknown_status(self):
        """Multi-word unknown status with underscores is title-cased correctly."""
        invoice = _make_invoice('awaiting_payment_confirmation')
        self.assertEqual(invoice.status_display, 'Awaiting Payment Confirmation')

    def test_all_known_statuses_are_non_empty(self):
        """All known statuses return a non-empty display string."""
        known_statuses = ['draft', 'issued', 'paid', 'overdue', 'cancelled', 'partially_paid']
        for status in known_statuses:
            with self.subTest(status=status):
                invoice = _make_invoice(status)
                self.assertTrue(
                    invoice.status_display,
                    f"status_display for '{status}' should not be empty",
                )
