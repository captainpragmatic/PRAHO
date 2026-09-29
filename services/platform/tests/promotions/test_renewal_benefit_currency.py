"""Promised renewal value cannot be spent in a different monetary unit."""

from importlib import import_module
from types import SimpleNamespace

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TestCase

from apps.billing.models import Currency
from apps.orders.models import Order, OrderItem
from apps.promotions.models import RenewalBenefit
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

    def test_backfill_keeps_original_order_currency_and_exact_value(self) -> None:
        RenewalBenefit.objects.filter(pk=self.benefit.pk).update(
            currency=None, currency_hold_reason="Pending migration",
        )
        migration = import_module("apps.promotions.migrations.0007_renewalbenefit_currency")
        migration.backfill_benefit_currency(apps, SimpleNamespace(connection=connection))
        self.benefit.refresh_from_db()
        self.assertEqual((self.benefit.currency_id, self.benefit.remaining_cents), ("RON", 2000))
        self.assertEqual(self.benefit.currency_hold_reason, "")

    def test_backfill_holds_conflicting_original_order_links(self) -> None:
        item = self.benefit.order_item
        different_order = Order.objects.create(customer=self.subscription.customer, currency=self.eur)
        different_item = OrderItem.objects.create(
            order=different_order, product=item.product, product_name=item.product_name,
            product_type=item.product_type, quantity=1, unit_price_cents=1000,
        )
        RenewalBenefit.objects.filter(pk=self.benefit.pk).update(
            order_item=different_item, currency=None, currency_hold_reason="Pending migration",
        )
        migration = import_module("apps.promotions.migrations.0007_renewalbenefit_currency")
        migration.backfill_benefit_currency(apps, SimpleNamespace(connection=connection))
        self.benefit.refresh_from_db()
        self.assertIsNone(self.benefit.currency_id)
        self.assertTrue(self.benefit.currency_hold_reason)
        self.assertEqual(self.benefit.remaining_cents, 2000)

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
