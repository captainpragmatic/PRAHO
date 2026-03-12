"""
Tests for apps.common.financial_arithmetic — pure financial calculation functions.
"""

import dataclasses
from dataclasses import FrozenInstanceError
from decimal import Decimal

from django.test import SimpleTestCase

from apps.common.financial_arithmetic import (
    DocumentTotals,
    LineTotals,
    calculate_document_totals,
    calculate_line_totals,
)


class CalculateLineTotalsTests(SimpleTestCase):
    """Tests for calculate_line_totals()."""

    def test_standard_19_percent_vat(self):
        result = calculate_line_totals(10000, Decimal("0.19"))
        self.assertEqual(result.tax_cents, 1900)
        self.assertEqual(result.line_total_cents, 11900)

    def test_zero_tax_rate(self):
        result = calculate_line_totals(5000, Decimal("0"))
        self.assertEqual(result.tax_cents, 0)
        self.assertEqual(result.line_total_cents, 5000)

    def test_zero_subtotal(self):
        result = calculate_line_totals(0, Decimal("0.19"))
        self.assertEqual(result.tax_cents, 0)
        self.assertEqual(result.line_total_cents, 0)

    def test_bankers_rounding_half_even_rounds_down(self):
        # 150 * 0.19 = 28.5 → rounds to 28 (even)
        result = calculate_line_totals(150, Decimal("0.19"))
        self.assertEqual(result.tax_cents, 28)

    def test_bankers_rounding_half_even_rounds_up(self):
        # 250 * 0.19 = 47.5 → rounds to 48 (even)
        result = calculate_line_totals(250, Decimal("0.19"))
        self.assertEqual(result.tax_cents, 48)

    def test_accepts_string_tax_rate(self):
        result = calculate_line_totals(10000, "0.19")
        self.assertEqual(result.tax_cents, 1900)
        self.assertEqual(result.line_total_cents, 11900)

    def test_returns_frozen_dataclass(self):
        result = calculate_line_totals(1000, Decimal("0.19"))
        self.assertIsInstance(result, LineTotals)
        self.assertTrue(dataclasses.is_dataclass(result))
        with self.assertRaises(FrozenInstanceError):
            result.__setattr__("tax_cents", 999)

    def test_21_percent_vat(self):
        # Romanian VAT rate as of Aug 2025
        result = calculate_line_totals(10000, Decimal("0.21"))
        self.assertEqual(result.tax_cents, 2100)
        self.assertEqual(result.line_total_cents, 12100)


class CalculateDocumentTotalsTests(SimpleTestCase):
    """Tests for calculate_document_totals()."""

    def test_single_item_no_discount(self):
        items = [_FakeItem(subtotal_cents=10000, tax_cents=1900)]
        result = calculate_document_totals(items)
        self.assertEqual(result, DocumentTotals(subtotal_cents=10000, tax_cents=1900, total_cents=11900))

    def test_multiple_items(self):
        items = [
            _FakeItem(subtotal_cents=5000, tax_cents=950),
            _FakeItem(subtotal_cents=3000, tax_cents=570),
        ]
        result = calculate_document_totals(items)
        self.assertEqual(result.subtotal_cents, 8000)
        self.assertEqual(result.tax_cents, 1520)
        self.assertEqual(result.total_cents, 9520)

    def test_with_discount(self):
        items = [_FakeItem(subtotal_cents=10000, tax_cents=1900)]
        result = calculate_document_totals(items, discount_cents=2000)
        self.assertEqual(result.total_cents, 9900)

    def test_discount_exceeding_total_floors_at_zero(self):
        items = [_FakeItem(subtotal_cents=1000, tax_cents=190)]
        result = calculate_document_totals(items, discount_cents=5000)
        self.assertEqual(result.total_cents, 0)

    def test_empty_items(self):
        result = calculate_document_totals([])
        self.assertEqual(result, DocumentTotals(subtotal_cents=0, tax_cents=0, total_cents=0))

    def test_returns_frozen_dataclass(self):
        result = calculate_document_totals([])
        self.assertIsInstance(result, DocumentTotals)
        self.assertTrue(dataclasses.is_dataclass(result))
        with self.assertRaises(FrozenInstanceError):
            result.__setattr__("total_cents", 999)


class _FakeItem:
    """Satisfies HasLineTotals protocol for testing."""

    def __init__(self, subtotal_cents: int, tax_cents: int) -> None:
        self._subtotal_cents = subtotal_cents
        self._tax_cents = tax_cents

    @property
    def subtotal_cents(self) -> int:
        return self._subtotal_cents

    @property
    def tax_cents(self) -> int:
        return self._tax_cents
