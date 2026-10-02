"""Promised renewal value cannot be spent in a different monetary unit."""


from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.billing.models import Currency
from apps.promotions.renewals import reserve_cycle, settle_cycle
from tests.promotions import test_renewals as renewal_fixtures


class RenewalBenefitCurrencyTests(TestCase):
    def setUp(self) -> None:
        renewal_fixtures.RenewalBenefitTests.setUp(self)
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})

    def test_benefit_uses_original_order_currency(self) -> None:
        self.assertEqual(self.benefit.currency_id, "RON")
        self.assertEqual(self.benefit.remaining_cents, 2000)
        self.benefit.currency = self.eur
        with self.assertRaises(ValidationError):
            self.benefit.save()
        self.benefit.refresh_from_db()
        self.assertEqual((self.benefit.currency_id, self.benefit.remaining_cents), ("RON", 2000))

    def test_euro_cycle_cannot_consume_ron_promise(self) -> None:
        self.subscription.currency = self.eur
        self.subscription.save(update_fields=["currency"])
        self.cycle.currency_id = self.eur.pk
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 0)
        self.benefit.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 2000)
        self.assertFalse(self.benefit.uses.exists())

    def test_prepared_ron_cycle_retains_promise_after_subscription_changes(self) -> None:
        self.cycle.currency_id = self.benefit.currency_id
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 1000)
        self.subscription.currency = self.eur
        self.subscription.save(update_fields=["currency"])
        settle_cycle(self.cycle)
        self.benefit.refresh_from_db()
        self.assertEqual((self.benefit.currency_id, self.benefit.remaining_cents), ("RON", 1000))

    def test_changed_cycle_cannot_reuse_or_settle_a_different_currency_reservation(self) -> None:
        self.cycle.currency_id = self.benefit.currency_id
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 1000)
        self.cycle.currency_id = self.eur.pk
        with self.assertRaisesMessage(ValueError, "Reserved promotion currency"):
            reserve_cycle(self.subscription, self.cycle, 2500)
        with self.assertRaisesMessage(ValueError, "Reserved promotion currency"):
            settle_cycle(self.cycle)
        self.benefit.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 2000)
        self.assertEqual(self.benefit.uses.get().status, "reserved")
