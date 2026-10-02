"""Which VAT rule is "current" is decided on the Romanian calendar, not the UTC one.

Romania's standard rate moved from 19% to 21% on 1 August 2025. Between 00:00 and 03:00
Bucharest time that day the UTC date was still 31 July, and the rule lookup read the UTC date,
so documents issued then were priced at the outgoing 19%. The cached rate made it worse: a rate
cached just before local midnight was served for up to an hour after it. Issued documents keep
their line rates forever, so a wrong rate here is permanent.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from freezegun import freeze_time

from apps.billing.tax_models import TaxRule
from apps.common.tax_service import TaxService

# 1 August 2025, 01:30 in Bucharest (EEST, UTC+3): still 31 July in UTC.
FIRST_HOURS_OF_AUGUST = datetime(2025, 7, 31, 22, 30, tzinfo=UTC)


class _RateChangeFixture(TestCase):
    def setUp(self) -> None:
        TaxRule.objects.filter(country_code="RO", tax_type="vat").delete()
        self.july = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.1900"),
            valid_from=date(2017, 1, 1), valid_to=date(2025, 7, 31), is_eu_member=True,
        )
        self.august = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.2100"),
            valid_from=date(2025, 8, 1), is_eu_member=True,
        )
        TaxService.invalidate_cache("RO")


class RuleSelectionUsesTheLocalDateTests(_RateChangeFixture):
    def test_tax_service_prices_the_first_hours_of_a_rate_change_at_the_new_rate(self) -> None:
        with patch("django.utils.timezone.now", return_value=FIRST_HOURS_OF_AUGUST):
            self.assertEqual(TaxService.get_vat_rate("RO"), Decimal("21"))

    def test_tax_rule_active_rate_uses_the_local_date(self) -> None:
        with patch("django.utils.timezone.now", return_value=FIRST_HOURS_OF_AUGUST):
            self.assertEqual(TaxRule.get_active_rate("RO", "vat"), Decimal("0.2100"))
            self.assertTrue(self.august.is_active())
            self.assertFalse(self.july.is_active())


@override_settings(CACHES=settings.LOCMEM_TEST_CACHE)
class CachedRateExpiresAtLocalMidnightTests(_RateChangeFixture):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        super().setUp()

    def test_a_rate_cached_before_local_midnight_is_not_served_after_it(self) -> None:
        with freeze_time("2025-07-31 20:30:00") as clock:  # 23:30 Bucharest, 31 July
            self.assertEqual(TaxService.get_vat_rate("RO"), Decimal("19"))
            # 00:15 Bucharest on 1 August: past local midnight, yet inside a one-hour cache window.
            clock.move_to("2025-07-31 21:15:00")
            self.assertEqual(TaxService.get_vat_rate("RO"), Decimal("21"))
