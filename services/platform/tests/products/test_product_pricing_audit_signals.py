"""Audit-payload semantics for promotional pricing changes (#314 follow-up).

A zero-cent promotion is a legitimate ACTIVE promotion (free trial), so the
audit change detection must distinguish "no promotion" (None) from "free
promotion" (0) — truthiness conflates them and logs financially material
changes backwards.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.products.models import ProductPrice
from apps.products.signals import _check_pricing_changes


class PromotionalPricingAuditChangeTests(SimpleTestCase):
    """Exercise _check_pricing_changes with the None-vs-zero promo states."""

    @staticmethod
    def _price_with_promo_transition(old_cents: int | None, new_cents: int | None) -> ProductPrice:
        price = ProductPrice(promo_price_cents=new_cents)
        price._old_promo_price_cents = old_cents
        return price

    def test_adding_a_free_promotion_is_logged_as_promotion_added(self) -> None:
        changes = _check_pricing_changes(self._price_with_promo_transition(None, 0))
        assert changes is not None
        payload = changes["promotional_pricing_changed"]
        self.assertIs(payload["promotion_added"], True)
        self.assertIs(payload["promotion_removed"], False)

    def test_discounting_an_existing_promotion_to_free_is_neither_added_nor_removed(self) -> None:
        changes = _check_pricing_changes(self._price_with_promo_transition(1000, 0))
        assert changes is not None
        payload = changes["promotional_pricing_changed"]
        self.assertIs(payload["promotion_added"], False)
        self.assertIs(payload["promotion_removed"], False)

    def test_removing_a_free_promotion_is_logged_as_promotion_removed(self) -> None:
        changes = _check_pricing_changes(self._price_with_promo_transition(0, None))
        assert changes is not None
        payload = changes["promotional_pricing_changed"]
        self.assertIs(payload["promotion_added"], False)
        self.assertIs(payload["promotion_removed"], True)
