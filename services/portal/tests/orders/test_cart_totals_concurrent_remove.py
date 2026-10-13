"""A cart total computed while the customer removes an item does not bring the item back (#689).

The cart page asks for its totals as soon as it loads. That request saved the whole cart again
to record Platform's warnings, even when they had not changed. Sessions merge concurrent writes
key by key (ADR-0055) and the cart is one value, so a total that loaded the cart before a
removal and saved after it wrote the removed item back. The signup e2e caught it: the cart read
"Your cart is empty", and the item was there again on reload.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock, patch

from django.contrib.sessions.models import Session
from django.test import TestCase

from apps.common.session_store import SessionStore
from apps.orders.services import CartCalculationService, GDPRCompliantCartSession
from tests.orders.test_selling_currency import product, totals


class TotalsDuringRemovalTests(TestCase):
    def setUp(self) -> None:
        self.api = Mock()
        self.api.get.return_value = product("RON", 1)
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=self.api))
        store = SessionStore()
        GDPRCompliantCartSession(store).add_item("basic-hosting", 1, "monthly")
        store.save()
        assert store.session_key is not None
        self.key = store.session_key

    def _load(self) -> SessionStore:
        store = SessionStore(session_key=self.key)
        store._get_session()  # load now, as a request does when it first reads its session
        return store

    def _stored_cart(self) -> dict[str, Any]:
        data = SessionStore().decode(Session.objects.get(session_key=self.key).session_data)
        return dict(data[GDPRCompliantCartSession.SESSION_KEY])

    def _totals_then_removal(self, warnings: list[dict[str, Any]]) -> None:
        totals_request, removal = self._load(), self._load()
        GDPRCompliantCartSession(removal).remove_item("basic-hosting", "monthly")
        removal.save()
        self.api.post.return_value = {**totals("RON", 1), "warnings": warnings}
        CartCalculationService.calculate_cart_totals(GDPRCompliantCartSession(totals_request), "42", 7)
        totals_request.save()

    def test_a_total_with_unchanged_warnings_keeps_the_removal(self) -> None:
        self._totals_then_removal([])
        self.assertEqual(self._stored_cart()["items"], [])

    def test_new_warnings_are_still_recorded(self) -> None:
        warning = {"type": "price_change", "message": "The price changed."}
        store = self._load()
        self.api.post.return_value = {**totals("RON", 1), "warnings": [warning]}
        CartCalculationService.calculate_cart_totals(GDPRCompliantCartSession(store), "42", 7)
        store.save()
        self.assertEqual(self._stored_cart()["warnings"], [warning])
