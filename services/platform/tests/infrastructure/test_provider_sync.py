"""
Tests for provider sync pricing extraction.

Verifies that _extract_pricing correctly handles Hetzner API price structures,
including fallback to non-fsn1 locations for server types not available everywhere
(e.g., ARM cax* types).
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase

from apps.infrastructure.provider_sync import _extract_pricing, _max_domains_for_memory


class TestExtractPricing(TestCase):
    """Tests for _extract_pricing helper."""

    def test_extracts_fsn1_pricing(self) -> None:
        """Picks fsn1 pricing when available."""
        prices: list[dict[str, object]] = [
            {
                "location": "nbg1",
                "price_hourly": {"net": "0.0050", "gross": "0.0060"},
                "price_monthly": {"net": "3.00", "gross": "3.57"},
            },
            {
                "location": "fsn1",
                "price_hourly": {"net": "0.0052", "gross": "0.0062"},
                "price_monthly": {"net": "3.28", "gross": "3.90"},
            },
        ]

        hourly, monthly = _extract_pricing(prices)

        self.assertEqual(hourly, Decimal("0.0062"))
        self.assertEqual(monthly, Decimal("3.90"))

    def test_falls_back_to_first_location_when_no_fsn1(self) -> None:
        """Uses first available location when fsn1 is absent (e.g., ARM types)."""
        prices = [
            {
                "location": "nbg1",
                "price_hourly": {"net": "0.0040", "gross": "0.0048"},
                "price_monthly": {"net": "2.49", "gross": "2.96"},
            },
            {
                "location": "hel1",
                "price_hourly": {"net": "0.0040", "gross": "0.0048"},
                "price_monthly": {"net": "2.49", "gross": "2.96"},
            },
        ]

        hourly, monthly = _extract_pricing(prices)

        self.assertEqual(hourly, Decimal("0.0048"))
        self.assertEqual(monthly, Decimal("2.96"))

    def test_returns_zero_for_empty_prices(self) -> None:
        """Returns (0, 0) when prices list is empty."""
        hourly, monthly = _extract_pricing([])

        self.assertEqual(hourly, Decimal("0"))
        self.assertEqual(monthly, Decimal("0"))

    def test_returns_zero_for_none_prices(self) -> None:
        """Returns (0, 0) when prices is None."""
        hourly, monthly = _extract_pricing(None)

        self.assertEqual(hourly, Decimal("0"))
        self.assertEqual(monthly, Decimal("0"))

    def test_handles_missing_gross_field(self) -> None:
        """Returns 0 when price_hourly/price_monthly is not a dict."""
        prices = [
            {
                "location": "fsn1",
                "price_hourly": None,
                "price_monthly": {"net": "3.28", "gross": "3.90"},
            },
        ]

        hourly, monthly = _extract_pricing(prices)

        self.assertEqual(hourly, Decimal("0"))
        self.assertEqual(monthly, Decimal("3.90"))

    def test_single_location_pricing(self) -> None:
        """Works correctly with a single price entry."""
        prices = [
            {
                "location": "ash",
                "price_hourly": {"net": "0.0100", "gross": "0.0119"},
                "price_monthly": {"net": "6.28", "gross": "7.47"},
            },
        ]

        hourly, monthly = _extract_pricing(prices)

        self.assertEqual(hourly, Decimal("0.0119"))
        self.assertEqual(monthly, Decimal("7.47"))

    def test_fsn1_preferred_even_when_not_first(self) -> None:
        """fsn1 is selected even if it's the last entry."""
        prices = [
            {
                "location": "ash",
                "price_hourly": {"net": "0.01", "gross": "0.012"},
                "price_monthly": {"net": "6.00", "gross": "7.14"},
            },
            {
                "location": "hel1",
                "price_hourly": {"net": "0.01", "gross": "0.012"},
                "price_monthly": {"net": "6.00", "gross": "7.14"},
            },
            {
                "location": "fsn1",
                "price_hourly": {"net": "0.0052", "gross": "0.0062"},
                "price_monthly": {"net": "3.28", "gross": "3.90"},
            },
        ]

        hourly, monthly = _extract_pricing(prices)

        self.assertEqual(hourly, Decimal("0.0062"))
        self.assertEqual(monthly, Decimal("3.90"))


class TestMaxDomainsForMemory(TestCase):
    """Tests for _max_domains_for_memory tier mapping."""

    def test_memory_tiers(self) -> None:
        """Each memory tier maps to the expected max_domains value."""
        cases = [
            (1, 25),
            (2, 25),
            (4, 50),
            (8, 100),
            (16, 200),
            (32, 500),
            (64, 500),
        ]
        for memory_gb, expected in cases:
            with self.subTest(memory_gb=memory_gb):
                self.assertEqual(_max_domains_for_memory(memory_gb), expected)
