"""`customers.base_credit_score` — the number every credit score is built up from.

The setting had no test that mentioned it. It is the starting score
`CustomerCreditService.calculate_credit_score` adds and subtracts factors against, so it moves every
risk decision that reads a score, and `GOOD_CREDIT_THRESHOLD` (700) / `FAIR_CREDIT_THRESHOLD` (600)
are fixed - which means changing the base silently reclassifies customers rather than rescaling
anything.

Asserted through the calculator on a customer with no history, so the base is the only term in play.
Reading the setting back would prove storage, which the catalog checks already cover.
"""

from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.credit_service import GOOD_CREDIT_THRESHOLD, CustomerCreditService
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_full_customer

BASE_SCORE_KEY = "customers.base_credit_score"


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class BaseCreditScoreEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        # A brand-new customer: no payments, no orders, no credit events, so the only factor that
        # can move the score is the account-age bonus, which is 0 on the day of creation.
        self.customer = create_full_customer()

    def set_base(self, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(BASE_SCORE_KEY, value)
        self.assertTrue(result.is_ok(), result)

    def test_the_configured_base_is_where_a_fresh_score_starts(self) -> None:
        self.set_base(500)
        self.assertEqual(CustomerCreditService.calculate_credit_score(self.customer), 500)

    def test_a_different_base_moves_the_score_by_exactly_that_much(self) -> None:
        """Two runs, one setting changed: the difference must be the difference in the setting."""
        self.set_base(500)
        low = CustomerCreditService.calculate_credit_score(self.customer)
        self.customer.meta = {}  # the calculator caches its answer for an hour
        self.customer.save(update_fields=["meta"])
        self.set_base(800)
        high = CustomerCreditService.calculate_credit_score(self.customer)
        self.assertEqual(high - low, 300)

    def test_the_catalog_default_applies_when_nothing_is_stored(self) -> None:
        self.assertEqual(
            CustomerCreditService.calculate_credit_score(self.customer),
            SettingsService.DEFAULT_SETTINGS[BASE_SCORE_KEY],
        )

    def test_the_base_decides_which_side_of_the_good_credit_threshold_a_new_customer_lands(self) -> None:
        """The consequence that matters: the thresholds are constants, so the base reclassifies."""
        self.set_base(GOOD_CREDIT_THRESHOLD + 10)
        self.assertGreaterEqual(CustomerCreditService.calculate_credit_score(self.customer), GOOD_CREDIT_THRESHOLD)

        self.customer.meta = {}
        self.customer.save(update_fields=["meta"])
        self.set_base(GOOD_CREDIT_THRESHOLD - 10)
        self.assertLess(CustomerCreditService.calculate_credit_score(self.customer), GOOD_CREDIT_THRESHOLD)
