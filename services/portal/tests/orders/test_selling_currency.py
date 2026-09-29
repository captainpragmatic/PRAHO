"""Portal sales use the Platform policy; existing orders retain their currency."""

import time
from unittest.mock import Mock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.orders.services import CartCalculationService, GDPRCompliantCartSession, OrderCreationService


def product(currency: str = "EUR", revision: int = 2) -> dict:
    return {
        "slug": "basic-hosting", "name": "Basic Hosting", "product_type": "shared_hosting",
        "description": "Basic hosting plan", "short_description": "Basic hosting",
        "requires_domain": False, "is_active": True,
        "selling_currency": currency, "currency_revision": revision,
        "prices": [{"currency": currency, "is_active": True, "monthly_price": "10.00", "setup_fee": "2.00"}],
    }


def totals(currency: str = "EUR", revision: int = 2) -> dict:
    return {
        "currency": currency, "selling_currency": currency, "currency_revision": revision,
        "subtotal_cents": 1200, "tax_cents": 252, "total_cents": 1452,
        "vat_rate_percent": "21.00", "promotion_quote": "fresh-promotion-quote", "warnings": [],
        "items": [{"product_slug": "basic-hosting", "billing_period": "monthly", "line_total_cents": 1452}],
    }


def currency_changed(currency: str = "EUR", revision: int = 2) -> PlatformAPIError:
    return PlatformAPIError(
        "Selling currency changed", status_code=409,
        response_data={"code": "currency_changed", "selling_currency": currency, "currency_revision": revision},
    )


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SellingCurrencyCartTests(SimpleTestCase):
    def setUp(self) -> None:
        self.api = Mock()
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=self.api))
        self.session = SessionStore()
        self.session.create()

    def cart(self, currency: str = "RON", revision: int = 1) -> GDPRCompliantCartSession:
        self.api.get.return_value = product(currency, revision)
        cart = GDPRCompliantCartSession(self.session)
        cart.add_item("basic-hosting", 1, "monthly")
        return cart

    def test_empty_cart_does_not_invent_a_currency_or_call_the_platform(self) -> None:
        cart = GDPRCompliantCartSession(self.session)
        self.assertEqual(cart.currency, "")
        self.assertIsNone(cart.cart.get("currency_revision"))
        self.api.get.assert_not_called()

    def test_new_cart_uses_each_authoritative_selling_currency(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                self.session.clear()
                cart = self.cart(code, 7)
                self.assertEqual(cart.currency, code)
                self.assertEqual(cart.cart["currency_revision"], 7)

    def test_cart_retry_identity_survives_reload_warning_and_expiry_refresh(self) -> None:
        cart = self.cart()
        version = cart.get_cart_version()
        cart.set_warnings([{"type": "notice", "message": "Review your order"}])
        cart.extend_expiry()
        self.session.save()
        reloaded = GDPRCompliantCartSession(SessionStore(session_key=self.session.session_key))
        self.assertEqual(reloaded.get_cart_version(), version)
        reloaded.update_item_quantity("basic-hosting", "monthly", 2)
        self.assertNotEqual(reloaded.get_cart_version(), version)

    def test_legacy_cart_retry_version_is_not_changed_by_loading(self) -> None:
        cart = self.cart()
        cart.cart.pop("instance_id", None)
        cart._save_cart()
        version = cart.get_cart_version()
        self.session.save()
        reloaded = GDPRCompliantCartSession(SessionStore(session_key=self.session.session_key))
        reloaded.extend_expiry()
        self.assertEqual(reloaded.get_cart_version(), version)

    def test_product_outage_cannot_add_an_unpriced_item_with_an_assumed_currency(self) -> None:
        self.api.get.side_effect = PlatformAPIError("Unavailable", status_code=503)
        cart = GDPRCompliantCartSession(self.session)
        with self.assertRaises(ValidationError):
            cart.add_item("basic-hosting", 1, "monthly", domain_name="example.com")
        self.assertFalse(cart.has_items())
        self.assertEqual(cart.currency, "")

    def test_invalid_selling_metadata_cannot_create_a_cart(self) -> None:
        for code, revision in (("GBP", 1), ("", 1), ("RON", 0), ("EUR", True), ("USD", "2")):
            with self.subTest(currency=code, revision=revision):
                self.api.get.return_value = product(code, revision)
                cart = GDPRCompliantCartSession(self.session)
                with self.assertRaises(ValidationError):
                    cart.add_item("basic-hosting", 1, "monthly")
                self.assertFalse(cart.has_items())
                self.assertEqual(cart.currency, "")

    def test_successful_calculation_with_wrong_currency_or_revision_is_rejected(self) -> None:
        cart = self.cart()
        for code, revision in (("EUR", 1), ("RON", 2)):
            with self.subTest(currency=code, revision=revision):
                self.api.post.return_value = totals(code, revision)
                with self.assertRaises(ValidationError):
                    CartCalculationService.calculate_cart_totals(cart, "42", 7)
                self.assertEqual((cart.currency, cart.currency_revision), ("RON", 1))

    def test_legacy_cart_requires_authoritative_metadata_before_calculation(self) -> None:
        cart = self.cart()
        cart.cart.pop("currency_revision", None)
        self.api.get.return_value = {"success": True, "selling_currency": "USD", "currency_revision": 3}
        self.api.post.return_value = totals("USD", 3)
        result = CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(result["currency"], "USD")
        self.assertEqual(cart.currency, "USD")
        self.api.get.assert_called_with("/api/billing/currencies/")
        self.assertEqual(self.api.post.call_args.args[1]["currency_revision"], 3)

    def test_unavailable_policy_metadata_never_submits_a_legacy_cart(self) -> None:
        cart = self.cart()
        cart.cart.pop("currency_revision", None)
        self.api.get.side_effect = PlatformAPIError("Unavailable", status_code=503)
        with self.assertRaises(ValidationError):
            CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.api.post.assert_not_called()
        self.assertEqual(cart.currency, "RON")

    def test_policy_conflict_reprices_once_and_invalidates_old_checkout_data(self) -> None:
        cart = self.cart()
        cart.set_coupon_codes(["WELCOME"])
        cart.set_gift_code("OLD-GIFT")
        cart.cart["items"][0]["sealed_price_token"] = "old-price-seal"
        cart._save_cart()
        old_version = cart.get_cart_version()
        self.api.post.side_effect = [currency_changed(), totals()]
        result = CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(result["currency"], "EUR")
        self.assertEqual(result["promotion_quote"], "fresh-promotion-quote")
        self.assertEqual(cart.currency, "EUR")
        self.assertNotEqual(cart.get_cart_version(), old_version)
        self.assertEqual(cart.get_coupon_codes(), [])
        self.assertEqual(cart.get_gift_code(), "")
        self.assertNotIn("sealed_price_token", cart.get_items()[0])
        self.assertEqual(self.api.post.call_count, 2)
        self.assertEqual(self.api.post.call_args_list[0].args[1]["currency_revision"], 1)
        self.assertEqual(self.api.post.call_args_list[1].args[1]["currency_revision"], 2)
        self.assertTrue(any(warning["type"] == "currency_change" for warning in cart.get_warnings()))

    def test_same_currency_new_revision_still_invalidates_checkout(self) -> None:
        cart = self.cart()
        old_version = cart.get_cart_version()
        self.api.post.side_effect = [currency_changed("RON", 3), totals("RON", 3)]
        CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(cart.currency, "RON")
        self.assertEqual(cart.cart["currency_revision"], 3)
        self.assertNotEqual(cart.get_cart_version(), old_version)

    def test_repeated_policy_changes_stop_after_one_calculation_retry(self) -> None:
        cart = self.cart()
        self.api.post.side_effect = [currency_changed(), currency_changed("USD", 3)]
        with self.assertRaises(ValidationError):
            CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(self.api.post.call_count, 2)

    def test_every_new_sale_request_contains_the_revision(self) -> None:
        cart = self.cart("EUR", 7)
        self.api.post.return_value = totals("EUR", 7)
        CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(self.api.post.call_args.args[1]["currency_revision"], 7)
        self.api.post.return_value = {"success": True}
        self.assertTrue(OrderCreationService.preflight_order(cart, "42", "7")["valid"])
        self.assertEqual(self.api.post.call_args.args[1]["currency_revision"], 7)
        self.api.post.return_value = {"order": {"id": "existing", "currency_code": "EUR"}}
        OrderCreationService.create_draft_order(cart, "42", "7")
        self.assertEqual(self.api.post.call_args.args[1]["currency_revision"], 7)

    def test_order_creation_conflict_stops_without_resubmitting(self) -> None:
        cart = self.cart()
        version = cart.get_cart_version()
        self.api.post.side_effect = currency_changed()
        with self.assertRaisesMessage(ValidationError, "Review"):
            OrderCreationService.create_draft_order(cart, "42", "7", promotion_quote="old-quote")
        self.api.post.assert_called_once()
        self.assertEqual(cart.currency, "EUR")
        self.assertTrue(cart.has_items())
        self.assertNotEqual(cart.get_cart_version(), version)

    def test_preflight_policy_conflict_requires_review(self) -> None:
        cart = self.cart()
        self.api.post.side_effect = currency_changed()
        result = OrderCreationService.preflight_order(cart, "42", "7")
        self.assertFalse(result["valid"])
        self.assertIn("Review", " ".join(result["errors"]))
        self.assertEqual(cart.currency, "EUR")
        self.api.post.assert_called_once()

    def test_calculation_tolerates_legacy_preflight_warning_strings(self) -> None:
        cart = self.cart()
        cart.set_warnings(["An existing preflight warning"])
        self.api.post.return_value = totals("RON", 1)
        result = CartCalculationService.calculate_cart_totals(cart, "42", 7)
        self.assertEqual(result["total_cents"], 1452)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"],
)
class SellingCurrencyViewTests(SimpleTestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update({
            "customer_id": 42, "user_id": 7,
            "user_memberships": [{"customer_id": 42, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def populate_cart(self, api: Mock) -> GDPRCompliantCartSession:
        api.get.return_value = product("RON", 1)
        session = self.client.session
        with patch("apps.orders.services.PlatformAPIClient", return_value=api):
            cart = GDPRCompliantCartSession(session)
            cart.add_item("basic-hosting", 1, "monthly")
        cart.set_coupon_codes(["OLD-COUPON"])
        cart.set_gift_code("OLD-GIFT")
        session.save()
        return cart

    def test_failed_promotion_recalculation_does_not_restore_codes_from_previous_currency(self) -> None:
        api = Mock()
        self.populate_cart(api)
        api.post.side_effect = [currency_changed(), PlatformAPIError("Unavailable", status_code=503)]
        with patch("apps.orders.services.PlatformAPIClient", return_value=api):
            response = self.client.post(
                reverse("orders:set_promotion_codes"), {"coupon_codes": "NEW", "gift_code": "NEW-GIFT"},
            )
        self.assertEqual(response.status_code, 302)
        cart = GDPRCompliantCartSession(self.client.session)
        self.assertEqual((cart.currency, cart.currency_revision), ("EUR", 2))
        self.assertEqual(cart.get_coupon_codes(), [])
        self.assertEqual(cart.get_gift_code(), "")

    def test_failed_promotion_recalculation_restores_codes_when_currency_policy_is_unchanged(self) -> None:
        api = Mock()
        self.populate_cart(api)
        api.post.side_effect = PlatformAPIError("Unavailable", status_code=503)
        with patch("apps.orders.services.PlatformAPIClient", return_value=api):
            response = self.client.post(
                reverse("orders:set_promotion_codes"), {"coupon_codes": "NEW", "gift_code": "NEW-GIFT"},
            )
        self.assertEqual(response.status_code, 302)
        cart = GDPRCompliantCartSession(self.client.session)
        self.assertEqual((cart.currency, cart.currency_revision), ("RON", 1))
        self.assertEqual(cart.get_coupon_codes(), ["OLD-COUPON"])
        self.assertEqual(cart.get_gift_code(), "OLD-GIFT")

    def test_checkout_reprices_then_requires_the_rendered_cart_version_before_order_creation(self) -> None:
        api = Mock()
        old_cart = self.populate_cart(api)
        old_version = old_cart.get_cart_version()
        api.post.side_effect = [
            currency_changed(), totals(),
            {"success": True, "warnings": ["Limited availability"]},
        ]
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=api))
        self.enterContext(patch("apps.orders.views.PlatformAPIClient", return_value=api))
        counters = self.enterContext(patch("apps.orders.views.counters"))
        counters.lookup.return_value = None
        counters.claim.return_value = True
        counters.complete.return_value = True
        response = self.client.get(reverse("orders:checkout"))
        self.assertContains(response, "14,52 EUR")
        self.assertContains(response, "Review and confirm the updated total")
        self.assertContains(response, 'value="fresh-promotion-quote"')
        new_cart = GDPRCompliantCartSession(self.client.session)
        new_version = new_cart.get_cart_version()
        self.assertNotEqual(new_version, old_version)
        self.assertContains(response, f'value="{new_version}"')
        api.post.reset_mock(side_effect=True)
        payload = {
            "cart_version": old_version, "agree_terms": "on", "payment_method": "bank_transfer",
            "promotion_quote": "fresh-promotion-quote", "idempotency_key": "currency-test",
        }
        response = self.client.post(reverse("orders:create_order"), payload, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 400)
        api.post.assert_not_called()
        order_id = "550e8400-e29b-41d4-a716-446655440099"
        api.post.side_effect = [
            {"success": True},
            {"order": {"id": order_id, "order_number": "EUR-NEW", "status": "awaiting_payment", "currency_code": "EUR"}},
        ]
        payload["cart_version"] = new_version
        response = self.client.post(reverse("orders:create_order"), payload)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("orders:confirmation", kwargs={"order_id": order_id}))
        self.assertEqual(api.post.call_count, 2)
        submitted = api.post.call_args.args[1]
        self.assertEqual((submitted["currency"], submitted["currency_revision"]), ("EUR", 2))
        self.assertEqual(submitted["promotion_quote"], "fresh-promotion-quote")
        self.assertFalse(GDPRCompliantCartSession(self.client.session).has_items())

    def test_catalog_and_detail_render_explicit_price_currency(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                data = product(code)
                for template, context in (
                    ("orders/product_catalog.html", {"products": [data]}),
                    ("orders/product_detail.html", {"product": data}),
                ):
                    rendered = render_to_string(template, context)
                    self.assertIn(f"10,00 {code}", rendered)
                    self.assertIn(f"2,00 {code}", rendered)
                    if code != "RON":
                        self.assertNotIn("10,00 RON", rendered)

    @patch("apps.orders.views.PlatformAPIClient")
    def test_detail_offers_available_periods_with_their_own_prices(self, factory: Mock) -> None:
        data = product("USD")
        data["prices"][0].update(semiannual_price="55.00", annual_price="100.00")
        factory.return_value.get.return_value = data
        response = self.client.get(reverse("orders:product_detail", kwargs={"product_slug": "basic-hosting"}))
        for period, amount in (("monthly", "10,00"), ("semiannual", "55,00"), ("annual", "100,00")):
            self.assertContains(response, f'value="{period}"')
            self.assertContains(response, f"{amount} USD")

    @patch("apps.orders.views.PlatformAPIClient")
    def test_catalog_ignores_inactive_and_foreign_currency_price_rows(self, factory: Mock) -> None:
        data = product("EUR")
        data["prices"].insert(0, {"currency": "RON", "is_active": True, "monthly_price": "999.00"})
        data["prices"].insert(0, {"currency": "EUR", "is_active": False, "monthly_price": "888.00"})
        factory.return_value.get.return_value = {"results": [data], "selling_currency": "EUR", "currency_revision": 2}
        response = self.client.get(reverse("orders:catalog"))
        self.assertContains(response, "10,00 EUR")
        self.assertNotContains(response, "999,00")
        self.assertNotContains(response, "888,00")

    @patch("apps.orders.views.PlatformAPIClient")
    def test_pending_order_keeps_its_original_currency_without_current_policy_lookup(self, factory: Mock) -> None:
        order_id = "550e8400-e29b-41d4-a716-446655440099"
        factory.return_value.post.return_value = {
            "id": order_id, "order_number": "EUR-OLD", "status": "awaiting_payment",
            "payment_method": "card", "total": "10.00", "currency_code": "EUR", "items": [],
        }
        factory.return_value.get.side_effect = AssertionError("Existing order must not read selling policy")
        response = self.client.get(reverse("orders:confirmation", kwargs={"order_id": order_id}))
        self.assertContains(response, "10.00 EUR")
        self.assertNotContains(response, "10.00 RON")
        factory.return_value.get.assert_not_called()
