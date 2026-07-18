"""First coverage for prepare_billing_table_data — focused on the date-cell guard (#286).

The dict-shaped producer contract allows created_at to be an aware datetime OR a plain
date. The guard has already been wrong once (timezone.is_aware() on a plain date raises
AttributeError because date lacks utcoffset), so both input shapes are pinned here.
"""

from datetime import UTC, date, datetime
from unittest.mock import MagicMock

from django.test import TestCase

from apps.customers.models import Customer
from apps.ui.table_helpers import prepare_billing_table_data


class BillingTableDateCellTests(TestCase):
    """Date cell renders the Romanian wall clock and tolerates plain dates."""

    @classmethod
    def setUpTestData(cls):
        cls.customer = Customer.objects.create(name="Table TZ SRL", customer_type="company")

    def _doc(self, created_at):
        return {
            "number": "INV-TBL-1",
            "type": "invoice",
            "id": 1,
            "customer": self.customer,
            "total": 121.00,
            "created_at": created_at,
            "status": "paid",
        }

    def test_aware_datetime_renders_romanian_wall_clock(self):
        """2025-12-31 22:30 UTC is 2026-01-01 00:30 in Romania — the table must show the
        Romanian date and time, not the stored UTC ones (#286)."""
        data = prepare_billing_table_data(
            [self._doc(datetime(2025, 12, 31, 22, 30, tzinfo=UTC))], MagicMock()
        )

        date_cell = data["rows"][0]["cells"][4]["content"]
        self.assertIn("01.01.2026", date_cell)
        self.assertIn("00:30", date_cell)

    def test_plain_date_passes_through_without_crashing(self):
        """A plain date is a legal producer value and has no utcoffset(): the guard must
        fall through to rendering it as given instead of raising AttributeError."""
        data = prepare_billing_table_data([self._doc(date(2026, 1, 15))], MagicMock())

        date_cell = data["rows"][0]["cells"][4]["content"]
        self.assertIn("15.01.2026", date_cell)
