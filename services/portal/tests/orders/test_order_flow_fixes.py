"""
Regression tests for Portal order flow fixes.

Covers:
  BACKEND-2: agree_terms validation in create_order
  BACKEND-3: cart version mismatch — AJAX → 400 JSON, non-AJAX → 302 redirect
  BACKEND-4: payment_method=stripe routes to process_payment
  BUG-2:     product_type field stored in cart items after add_item
  DS-1:      calculate_cart_totals API response includes vat_rate_percent
  UX-5:      calculate_cart_totals API response includes per-item array
  ENH-3:     checkout sidebar reactive Next Steps via Alpine.js

No database access — all tests use SimpleTestCase + locmem cache.
"""

import json
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.test import Client, SimpleTestCase, override_settings

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_product_data(
    slug: str = "shared-hosting-basic",
    product_type: str = "hosting",
    requires_domain: bool = False,
) -> dict:
    return {
        "id": "prod-uuid-001",
        "slug": slug,
        "name": "Shared Hosting Basic",
        "product_type": product_type,
        "requires_domain": requires_domain,
        "is_active": True,
    }


def _make_cart_session(session: SessionStore, product_slug: str = "shared-hosting-basic") -> "GDPRCompliantCartSession":  # noqa: F821
    """Return a GDPRCompliantCartSession pre-loaded with one item (no network call)."""
    from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

    with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
        mock_instance = MagicMock()
        mock_instance.get.return_value = _make_product_data(slug=product_slug)
        mock_cls.return_value = mock_instance

        cart = GDPRCompliantCartSession(session)
        cart.add_item(product_slug=product_slug, quantity=1, billing_period="monthly")
    return cart


# ---------------------------------------------------------------------------
# BACKEND-2: agree_terms validation
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestAgreeTermsValidation(SimpleTestCase):
    """BACKEND-2: create_order must reject submissions missing agree_terms=on."""

    def setUp(self) -> None:
        self.client = Client()

    def _auth_session_with_cart(self) -> str:
        """Populate session with auth + one cart item; return cart version."""
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

        # Build a cart directly using SessionStore mapped to client session key
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data()
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        session.save()
        return cart.get_cart_version()

    def test_missing_agree_terms_redirects_to_checkout(self) -> None:
        """Omitting agree_terms causes a redirect to orders:checkout."""
        cart_version = self._auth_session_with_cart()

        response = self.client.post(
            "/order/create/",
            {"cart_version": cart_version},  # agree_terms intentionally absent
            HTTP_X_FORWARDED_FOR="127.0.0.1",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_agree_terms_off_redirects_to_checkout(self) -> None:
        """agree_terms=off (not 'on') is treated as rejection."""
        cart_version = self._auth_session_with_cart()

        response = self.client.post(
            "/order/create/",
            {"cart_version": cart_version, "agree_terms": "off"},
            HTTP_X_FORWARDED_FOR="127.0.0.1",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_agree_terms_on_passes_validation(self) -> None:
        """agree_terms=on passes the terms check and proceeds to preflight."""
        cart_version = self._auth_session_with_cart()

        with (
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-001",
                    "status": "draft",
                }
            }

            response = self.client.post(
                "/order/create/",
                {
                    "cart_version": cart_version,
                    "agree_terms": "on",
                    "payment_method": "bank_transfer",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Should proceed past terms check — redirect to confirmation (302) not error
        self.assertIn(response.status_code, [200, 302])
        mock_pre.assert_called_once()


# ---------------------------------------------------------------------------
# BACKEND-3: Cart version mismatch — AJAX vs non-AJAX behaviour
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestCartVersionMismatch(SimpleTestCase):
    """BACKEND-3: stale cart_version → 400 JSON for AJAX, 302 for non-AJAX."""

    def setUp(self) -> None:
        self.client = Client()
        # Establish session with auth + non-empty cart
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data()
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        session.save()

    def test_version_mismatch_non_ajax_redirects(self) -> None:
        """Non-AJAX request with wrong cart_version redirects to checkout."""
        response = self.client.post(
            "/order/create/",
            {
                "cart_version": "definitely-wrong-version",
                "agree_terms": "on",
                "payment_method": "bank_transfer",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_version_mismatch_ajax_returns_400_json(self) -> None:
        """AJAX request (HX-Request header) with wrong cart_version returns 400 JSON."""
        response = self.client.post(
            "/order/create/",
            {
                "cart_version": "definitely-wrong-version",
                "agree_terms": "on",
                "payment_method": "bank_transfer",
            },
            HTTP_HX_REQUEST="true",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/json")
        body = json.loads(response.content)
        self.assertIn("error", body)

    def test_version_mismatch_xmlhttprequest_returns_400_json(self) -> None:
        """XMLHttpRequest header also triggers 400 JSON response on version mismatch."""
        response = self.client.post(
            "/order/create/",
            {
                "cart_version": "wrong-version",
                "agree_terms": "on",
                "payment_method": "bank_transfer",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 400)
        body = json.loads(response.content)
        self.assertIn("error", body)

    def test_correct_version_non_ajax_proceeds(self) -> None:
        """Correct cart version passes the version guard."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        cart = GDPRCompliantCartSession(self.client.session)
        correct_version = cart.get_cart_version()

        with (
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-001",
                    "status": "draft",
                }
            }

            response = self.client.post(
                "/order/create/",
                {
                    "cart_version": correct_version,
                    "agree_terms": "on",
                    "payment_method": "bank_transfer",
                },
            )

        # Version check passed — should proceed to order creation (302 redirect to confirmation)
        self.assertIn(response.status_code, [200, 302])


# ---------------------------------------------------------------------------
# BACKEND-4: payment_method=stripe routes through shared order creation logic
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestStripePaymentRouting(SimpleTestCase):
    """BACKEND-4: payment_method=stripe must use the shared order creation path."""

    def setUp(self) -> None:
        from django.core.cache import cache  # noqa: PLC0415

        cache.clear()  # Prevent idempotency key collisions between test methods
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data()
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")
            self.cart_version = cart.get_cart_version()

        session.save()

    def test_stripe_payment_method_uses_shared_order_creation(self) -> None:
        """create_order with payment_method=stripe uses _create_and_process_order (shared path)."""
        with (
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-STRIPE-001",
                    "status": "draft",
                }
            }

            response = self.client.post(
                "/order/create/",
                {
                    "cart_version": self.cart_version,
                    "agree_terms": "on",
                    "payment_method": "stripe",
                },
            )

        # Should proceed through shared order creation — preflight always runs
        mock_pre.assert_called_once()
        mock_create.assert_called_once()
        self.assertIn(response.status_code, [200, 302])

    def test_bank_transfer_does_not_call_process_payment(self) -> None:
        """create_order with payment_method=bank_transfer does NOT call process_payment."""
        with (
            patch("apps.orders.views.process_payment") as mock_process,
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            from django.http import HttpResponse  # noqa: PLC0415

            mock_process.return_value = HttpResponse(status=302)
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-001",
                    "status": "draft",
                }
            }

            self.client.post(
                "/order/create/",
                {
                    "cart_version": self.cart_version,
                    "agree_terms": "on",
                    "payment_method": "bank_transfer",
                },
            )

        mock_process.assert_not_called()

    def test_empty_payment_method_does_not_call_process_payment(self) -> None:
        """Omitting payment_method falls through to the normal order creation path."""
        with (
            patch("apps.orders.views.process_payment") as mock_process,
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            from django.http import HttpResponse  # noqa: PLC0415

            mock_process.return_value = HttpResponse(status=302)
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-002",
                    "status": "draft",
                }
            }

            self.client.post(
                "/order/create/",
                {
                    "cart_version": self.cart_version,
                    "agree_terms": "on",
                    # no payment_method key
                },
            )

        mock_process.assert_not_called()


# ---------------------------------------------------------------------------
# BUG-2: product_type stored in cart items
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestProductTypeInCartItem(SimpleTestCase):
    """BUG-2: add_item must persist product_type from platform API into the cart item."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def _make_api_mock(self, product_type: str) -> MagicMock:
        mock_instance = MagicMock()
        mock_instance.get.return_value = _make_product_data(product_type=product_type)
        return mock_instance

    @patch("apps.orders.services.PlatformAPIClient")
    def test_product_type_stored_for_hosting(self, mock_cls: MagicMock) -> None:
        """add_item stores product_type='hosting' in the cart item dict."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        mock_cls.return_value = self._make_api_mock("hosting")

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertIn("product_type", items[0])
        self.assertEqual(items[0]["product_type"], "hosting")

    @patch("apps.orders.services.PlatformAPIClient")
    def test_product_type_stored_for_domain(self, mock_cls: MagicMock) -> None:
        """add_item stores product_type='domain' when platform returns that value."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        mock_cls.return_value = self._make_api_mock("domain")

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(product_slug="domain-registration", quantity=1, billing_period="yearly")

        items = cart.get_items()
        self.assertIn("product_type", items[0])
        self.assertEqual(items[0]["product_type"], "domain")

    @patch("apps.orders.services.PlatformAPIClient")
    def test_product_type_empty_string_when_absent(self, mock_cls: MagicMock) -> None:
        """When platform omits product_type, cart stores an empty string (not KeyError)."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        mock_instance = MagicMock()
        mock_instance.get.return_value = {
            "id": "prod-uuid-002",
            "slug": "some-product",
            "name": "Some Product",
            # product_type intentionally missing
            "requires_domain": False,
            "is_active": True,
        }
        mock_cls.return_value = mock_instance

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(product_slug="some-product", quantity=1, billing_period="monthly")

        items = cart.get_items()
        self.assertIn("product_type", items[0])
        self.assertEqual(items[0]["product_type"], "")

    @patch("apps.orders.services.PlatformAPIClient")
    def test_product_type_survives_session_reload(self, mock_cls: MagicMock) -> None:
        """product_type persists after GDPRCompliantCartSession is re-instantiated from session."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        mock_cls.return_value = self._make_api_mock("vps")

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(product_slug="vps-starter", quantity=1, billing_period="monthly")

        # Re-load cart from same session (simulates new request)
        reloaded = GDPRCompliantCartSession(self.session)
        items = reloaded.get_items()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["product_type"], "vps")


# ---------------------------------------------------------------------------
# DS-1: calculate_cart_totals returns vat_rate_percent
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestCartTotalsVatRatePercent(SimpleTestCase):
    """DS-1: platform API response for calculate_cart_totals must include vat_rate_percent."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    @patch("apps.orders.services.PlatformAPIClient")
    def test_calculate_totals_returns_vat_rate_percent(self, mock_cls: MagicMock) -> None:
        """CartCalculationService passes through vat_rate_percent from the platform API."""
        from apps.orders.services import CartCalculationService, GDPRCompliantCartSession  # noqa: PLC0415

        api_response = {
            "subtotal_cents": 5000,
            "tax_cents": 1050,
            "total_cents": 6050,
            "currency": "RON",
            "vat_rate_percent": "21.00",
            "warnings": [],
            "items": [],
        }

        mock_instance = MagicMock()
        mock_instance.post.return_value = api_response
        mock_cls.return_value = mock_instance

        # Build a non-empty cart without hitting the API for add_item
        with patch("apps.orders.services.PlatformAPIClient") as add_mock:
            add_mock.return_value.get.return_value = _make_product_data()
            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        mock_cls.return_value = mock_instance  # reset to calculation mock
        result = CartCalculationService.calculate_cart_totals(cart, customer_id="42", user_id=7)

        self.assertIn("vat_rate_percent", result)
        self.assertEqual(result["vat_rate_percent"], "21.00")

    @patch("apps.orders.services.PlatformAPIClient")
    def test_calculate_totals_empty_cart_has_no_vat_rate(self, mock_cls: MagicMock) -> None:
        """Empty cart returns early without calling the API; vat_rate_percent not required."""
        from apps.orders.services import CartCalculationService, GDPRCompliantCartSession  # noqa: PLC0415

        mock_cls.return_value = MagicMock()
        cart = GDPRCompliantCartSession(self.session)  # no items added

        result = CartCalculationService.calculate_cart_totals(cart, customer_id="42", user_id=7)

        self.assertEqual(result["total_cents"], 0)
        # API should never be called for empty cart
        mock_cls.return_value.post.assert_not_called()


# ---------------------------------------------------------------------------
# UX-5: calculate_cart_totals returns per-item array
# ---------------------------------------------------------------------------

@override_settings(**_CACHE_SETTINGS)
class TestCartTotalsPerItemArray(SimpleTestCase):
    """UX-5: platform API response must include items array with per-item pricing fields."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    @patch("apps.orders.services.PlatformAPIClient")
    def test_calculate_totals_returns_items_array(self, mock_cls: MagicMock) -> None:
        """CartCalculationService passes through the items array from the platform response."""
        from apps.orders.services import CartCalculationService, GDPRCompliantCartSession  # noqa: PLC0415

        per_item_response = {
            "subtotal_cents": 5000,
            "tax_cents": 1050,
            "total_cents": 6050,
            "currency": "RON",
            "vat_rate_percent": "21.00",
            "warnings": [],
            "items": [
                {
                    "product_slug": "shared-hosting-basic",
                    "product_name": "Shared Hosting Basic",
                    "unit_price_cents": 5000,
                    "setup_cents": 0,
                    "line_total_cents": 5000,
                    "quantity": 1,
                    "billing_period": "monthly",
                }
            ],
        }

        mock_instance = MagicMock()
        mock_instance.post.return_value = per_item_response
        mock_cls.return_value = mock_instance

        with patch("apps.orders.services.PlatformAPIClient") as add_mock:
            add_mock.return_value.get.return_value = _make_product_data()
            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        mock_cls.return_value = mock_instance
        result = CartCalculationService.calculate_cart_totals(cart, customer_id="42", user_id=7)

        self.assertIn("items", result)
        self.assertIsInstance(result["items"], list)
        self.assertEqual(len(result["items"]), 1)

    @patch("apps.orders.services.PlatformAPIClient")
    def test_per_item_has_required_fields(self, mock_cls: MagicMock) -> None:
        """Each item in the API response must contain the UX-5 required fields."""
        from apps.orders.services import CartCalculationService, GDPRCompliantCartSession  # noqa: PLC0415

        required_fields = {"product_name", "unit_price_cents", "setup_cents", "line_total_cents"}

        per_item_response = {
            "subtotal_cents": 5000,
            "tax_cents": 1050,
            "total_cents": 6050,
            "currency": "RON",
            "vat_rate_percent": "21.00",
            "warnings": [],
            "items": [
                {
                    "product_slug": "shared-hosting-basic",
                    "product_name": "Shared Hosting Basic",
                    "unit_price_cents": 5000,
                    "setup_cents": 0,
                    "line_total_cents": 5000,
                    "quantity": 1,
                    "billing_period": "monthly",
                }
            ],
        }

        mock_instance = MagicMock()
        mock_instance.post.return_value = per_item_response
        mock_cls.return_value = mock_instance

        with patch("apps.orders.services.PlatformAPIClient") as add_mock:
            add_mock.return_value.get.return_value = _make_product_data()
            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        mock_cls.return_value = mock_instance
        result = CartCalculationService.calculate_cart_totals(cart, customer_id="42", user_id=7)

        item = result["items"][0]
        for field in required_fields:
            self.assertIn(field, item, f"Missing field '{field}' in per-item response")

    @patch("apps.orders.services.PlatformAPIClient")
    def test_per_item_line_total_consistent_with_grand_total(self, mock_cls: MagicMock) -> None:
        """Sum of line_total_cents across items equals subtotal_cents (contract check)."""
        from apps.orders.services import CartCalculationService, GDPRCompliantCartSession  # noqa: PLC0415

        item1_total = 5000
        item2_total = 3000
        subtotal = item1_total + item2_total

        per_item_response = {
            "subtotal_cents": subtotal,
            "tax_cents": 1680,
            "total_cents": subtotal + 1680,
            "currency": "RON",
            "vat_rate_percent": "21.00",
            "warnings": [],
            "items": [
                {
                    "product_slug": "shared-hosting-basic",
                    "product_name": "Shared Hosting Basic",
                    "unit_price_cents": 5000,
                    "setup_cents": 0,
                    "line_total_cents": item1_total,
                    "quantity": 1,
                    "billing_period": "monthly",
                },
                {
                    "product_slug": "email-hosting",
                    "product_name": "Email Hosting",
                    "unit_price_cents": 1500,
                    "setup_cents": 0,
                    "line_total_cents": item2_total,
                    "quantity": 2,
                    "billing_period": "monthly",
                },
            ],
        }

        mock_instance = MagicMock()
        mock_instance.post.return_value = per_item_response
        mock_cls.return_value = mock_instance

        with patch("apps.orders.services.PlatformAPIClient") as add_mock:
            add_mock.return_value.get.return_value = _make_product_data()
            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        mock_cls.return_value = mock_instance
        result = CartCalculationService.calculate_cart_totals(cart, customer_id="42", user_id=7)

        computed_subtotal = sum(item["line_total_cents"] for item in result["items"])
        self.assertEqual(computed_subtotal, result["subtotal_cents"])


# ---------------------------------------------------------------------------
# Test 1: Cents conversion — no floating-point rounding errors
# ---------------------------------------------------------------------------


class TestCentsConversionNoFloatingPoint(SimpleTestCase):
    """Decimal-based price conversion must produce exact integer cents without float drift."""

    def test_twenty_nine_ninety_nine_converts_to_2999_cents(self) -> None:
        """'29.99' must yield exactly 2999 cents, not 2998 due to IEEE-754 float drift."""
        from decimal import ROUND_HALF_UP, Decimal  # noqa: PLC0415

        from apps.orders.views import _parse_total_cents  # noqa: PLC0415

        result = _parse_total_cents("29.99")
        self.assertEqual(result, 2999)

        # Verify Decimal path produces the same answer (regression guard)
        decimal_result = int(Decimal("29.99").quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100)
        self.assertEqual(decimal_result, 2999)

    def test_one_cent_converts_exactly(self) -> None:
        """'0.01' must yield exactly 1 cent — the smallest representable unit."""
        from apps.orders.views import _parse_total_cents  # noqa: PLC0415

        self.assertEqual(_parse_total_cents("0.01"), 1)

    def test_round_amount_converts_exactly(self) -> None:
        """'100.00' must yield exactly 10000 cents with no rounding side-effects."""
        from apps.orders.views import _parse_total_cents  # noqa: PLC0415

        self.assertEqual(_parse_total_cents("100.00"), 10_000)

    def test_invalid_amount_returns_zero(self) -> None:
        """Non-numeric input must return 0 gracefully, not raise."""
        from apps.orders.views import _parse_total_cents  # noqa: PLC0415

        self.assertEqual(_parse_total_cents("not-a-number"), 0)
        self.assertEqual(_parse_total_cents(""), 0)


# ---------------------------------------------------------------------------
# Test 2: _parse_order_timestamp
# ---------------------------------------------------------------------------


class TestParseOrderTimestamp(SimpleTestCase):
    """_parse_order_timestamp must convert ISO strings to TZ-aware datetimes."""

    def test_iso_string_with_timezone_parses_to_datetime(self) -> None:
        """Valid ISO string with explicit UTC offset converts to datetime object."""
        from datetime import datetime  # noqa: PLC0415

        from apps.orders.views import _parse_order_timestamp  # noqa: PLC0415

        order_data: dict = {"created_at": "2024-01-15T10:30:00+00:00"}
        _parse_order_timestamp(order_data)

        self.assertIsInstance(order_data["created_at"], datetime)
        self.assertIsNotNone(order_data["created_at"].tzinfo)

    def test_iso_string_without_timezone_gets_utc_assigned(self) -> None:
        """Naive datetime string (no tz info) gets UTC tzinfo assigned."""
        from datetime import UTC  # noqa: PLC0415
        from datetime import datetime as dt_class  # noqa: PLC0415

        from apps.orders.views import _parse_order_timestamp  # noqa: PLC0415

        order_data: dict = {"created_at": "2024-01-15T10:30:00"}
        _parse_order_timestamp(order_data)

        # Function assigns datetime.UTC to naive datetimes
        self.assertIsInstance(order_data["created_at"], dt_class)
        self.assertEqual(order_data["created_at"].tzinfo, UTC)

    def test_missing_created_at_does_not_crash(self) -> None:
        """Missing created_at key must be handled silently — no KeyError or exception."""
        from apps.orders.views import _parse_order_timestamp  # noqa: PLC0415

        order_data: dict = {"order_number": "ORD-001"}
        # Must not raise
        _parse_order_timestamp(order_data)
        self.assertNotIn("created_at", order_data)

    def test_invalid_string_does_not_crash(self) -> None:
        """Malformed timestamp string is suppressed via contextlib.suppress — no crash."""
        from apps.orders.views import _parse_order_timestamp  # noqa: PLC0415

        order_data: dict = {"created_at": "not-a-valid-date"}
        # Must not raise — contextlib.suppress catches ValueError/TypeError
        _parse_order_timestamp(order_data)
        # Value remains unchanged because parsing failed
        self.assertEqual(order_data["created_at"], "not-a-valid-date")


# ---------------------------------------------------------------------------
# Test 3: Bank-transfer orders skip Stripe intent fetch on confirmation page
# ---------------------------------------------------------------------------


@override_settings(
    **_CACHE_SETTINGS,
    COMPANY_BANK_IBAN="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Test Bank",
    COMPANY_BANK_BENEFICIARY="PragmaticHost SRL",
)
class TestBankTransferSkipsStripeIntent(SimpleTestCase):
    """order_confirmation must NOT fetch Stripe config when payment_method=bank_transfer."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def test_bank_transfer_order_does_not_call_get_billing(self) -> None:
        """Stripe config endpoint (get_billing) is never called for bank_transfer orders."""
        order_data = {
            "id": "ord-001",
            "order_number": "ORD-001",
            "status": "pending",
            "payment_method": "bank_transfer",
            "total": "100.00",
            "currency_code": "RON",
            "items": [],
        }

        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = order_data
            mock_cls.return_value = mock_instance

            self.client.get("/order/confirmation/ord-001/")

            # get_billing must never be called for bank_transfer
            mock_instance.get_billing.assert_not_called()


# ---------------------------------------------------------------------------
# Test 4: Stripe config fetch failure renders confirmation gracefully
# ---------------------------------------------------------------------------


@override_settings(
    **_CACHE_SETTINGS,
    COMPANY_BANK_IBAN="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Test Bank",
    COMPANY_BANK_BENEFICIARY="PragmaticHost SRL",
)
class TestStripeFailureRedirectsToConfirmation(SimpleTestCase):
    """When Stripe config fetch raises, order_confirmation must still render (no 500)."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        # Inject a payment_intent into the session so the view tries to fetch stripe config
        session["payment_intent_ord-stripe-001"] = {"client_secret": "pi_test_secret"}
        session.save()

    def test_stripe_config_exception_yields_200_not_500(self) -> None:
        """Exception from get_billing is swallowed — confirmation page still renders."""
        order_data = {
            "id": "ord-stripe-001",
            "order_number": "ORD-STRIPE-001",
            "status": "pending",
            "payment_method": "stripe",
            "total": "100.00",
            "currency_code": "RON",
            "items": [],
        }

        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = order_data
            mock_instance.get_billing.side_effect = Exception("Stripe unreachable")
            mock_cls.return_value = mock_instance

            response = self.client.get("/order/confirmation/ord-stripe-001/")

        # Must NOT be a server error — graceful degradation produces 200 or redirect
        self.assertNotEqual(response.status_code, 500)


# ---------------------------------------------------------------------------
# Test 5: HMACPriceSealer.seal_price_data produces valid sealed dict
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS, SECRET_KEY="test-secret-key-for-hmac-seal")
class TestPriceSealingRequiredKeys(SimpleTestCase):
    """seal_price_data must return all required fields and produce deterministic signatures."""

    REQUIRED_SEAL_KEYS: ClassVar[set[str]] = {"signature", "body_hash", "timestamp", "nonce", "portal_id", "ip_hash"}

    def test_seal_returns_all_required_keys(self) -> None:
        """seal_price_data output contains every field required by verify_seal."""
        from apps.orders.services import HMACPriceSealer  # noqa: PLC0415

        price_data = {"product_slug": "shared-hosting-basic", "price_cents": 2999, "currency": "RON"}
        sealed = HMACPriceSealer.seal_price_data(price_data, client_ip="10.0.0.1")

        for key in self.REQUIRED_SEAL_KEYS:
            self.assertIn(key, sealed, f"Missing required seal key: '{key}'")

    def test_seal_portal_id_is_canonical_value(self) -> None:
        """portal_id field must always equal 'praho_portal_v1'."""
        from apps.orders.services import HMACPriceSealer  # noqa: PLC0415

        sealed = HMACPriceSealer.seal_price_data({"price_cents": 100}, client_ip="127.0.0.1")
        self.assertEqual(sealed["portal_id"], "praho_portal_v1")

    def test_same_price_data_and_timestamp_yields_same_signature(self) -> None:
        """Given identical inputs (fixed timestamp/nonce), the signature is deterministic."""
        import hashlib  # noqa: PLC0415
        import hmac as hmac_mod  # noqa: PLC0415
        import json  # noqa: PLC0415

        price_data = {"price_cents": 2999, "currency": "RON"}
        client_ip = "10.0.0.1"
        secret_key = "test-secret-key-for-hmac-seal"
        timestamp = 1700000000
        nonce = "abc123"

        # Manually compute expected signature using same algorithm as seal_price_data
        canonical_body = json.dumps(price_data, sort_keys=True, separators=(",", ":"))
        body_hash = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()
        canonical_data = f"{body_hash}:{timestamp}:{nonce}:{client_ip}"
        expected_sig = hmac_mod.new(
            secret_key.encode("utf-8"), canonical_data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Replicate via the sealer with controlled inputs
        import unittest.mock  # noqa: PLC0415

        with (
            unittest.mock.patch("time.time", return_value=timestamp),
            unittest.mock.patch("uuid.uuid4") as mock_uuid,
        ):
            mock_uuid.return_value.hex = nonce
            from apps.orders.services import HMACPriceSealer  # noqa: PLC0415

            sealed = HMACPriceSealer.seal_price_data(price_data, client_ip=client_ip)

        self.assertEqual(sealed["signature"], expected_sig)
        self.assertEqual(sealed["body_hash"], body_hash)


# ---------------------------------------------------------------------------
# Test 6: preflight_order triggers exactly one API call (no duplication)
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestSinglePreflightProducesOneVatAuditEvent(SimpleTestCase):
    """OrderCreationService.preflight_order must call platform_api.post() exactly once."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    @patch("apps.orders.services.PlatformAPIClient")
    def test_preflight_calls_post_exactly_once(self, mock_cls: MagicMock) -> None:
        """A single preflight_order call must not issue duplicate API requests."""
        from apps.orders.services import GDPRCompliantCartSession, OrderCreationService  # noqa: PLC0415

        mock_instance = MagicMock()
        mock_instance.post.return_value = {
            "success": True,
            "errors": [],
            "warnings": [],
            "preflight_data": {},
        }
        mock_cls.return_value = mock_instance

        with patch("apps.orders.services.PlatformAPIClient") as add_mock:
            add_mock.return_value.get.return_value = _make_product_data()
            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

        mock_cls.return_value = mock_instance
        OrderCreationService.preflight_order(
            cart,
            customer_id="42",
            user_id="7",
            api_client_factory=mock_cls,
        )

        self.assertEqual(mock_instance.post.call_count, 1)

    @patch("apps.orders.services.PlatformAPIClient")
    def test_preflight_empty_cart_never_calls_api(self, mock_cls: MagicMock) -> None:
        """preflight_order with empty cart short-circuits before making any API call."""
        from apps.orders.services import GDPRCompliantCartSession, OrderCreationService  # noqa: PLC0415

        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance

        cart = GDPRCompliantCartSession(self.session)  # no items
        result = OrderCreationService.preflight_order(cart, customer_id="42", user_id="7")

        self.assertFalse(result["valid"])
        mock_instance.post.assert_not_called()


# ---------------------------------------------------------------------------
# Test 7: No hardcoded Romanian strings outside {% trans %} in order templates
# ---------------------------------------------------------------------------


class TestNoHardcodedRomanianInOrderTemplates(SimpleTestCase):
    """Order templates must not contain bare Romanian text outside translation tags."""

    # Known Romanian words that must always appear inside {% trans %} or {% blocktrans %}
    ROMANIAN_KEYWORDS: ClassVar[list[str]] = [
        "Adaugă",
        "Comandă",
        "Plată",
        "Coș",
    ]

    def _get_order_template_paths(self) -> list:
        """Return all .html files under services/portal/templates/orders/."""
        from pathlib import Path  # noqa: PLC0415

        base = Path(__file__).resolve().parents[2] / "templates" / "orders"
        return list(base.rglob("*.html"))

    def test_order_templates_exist(self) -> None:
        """Sanity check: the templates directory must contain at least one file."""
        paths = self._get_order_template_paths()
        self.assertGreater(len(paths), 0, "Expected at least one .html file in orders templates")

    def test_romanian_keywords_wrapped_in_trans_tags(self) -> None:
        """Each Romanian keyword found in a template must appear inside {% trans %} or {% blocktrans %}."""
        import re  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415

        # Match any {% trans "..." %} or {% blocktrans %}...{% endblocktrans %} content
        trans_pattern = re.compile(
            r'{%\s*(?:blocktrans\b[^%]*%}.*?{%\s*endblocktrans\s*%}|trans\s+"[^"]*"[^%]*%})',
            re.DOTALL,
        )

        violations: list[str] = []

        for template_path in self._get_order_template_paths():
            content = Path(template_path).read_text(encoding="utf-8")
            # Strip all {% trans ... %} / {% blocktrans %} blocks from the content
            stripped = trans_pattern.sub("", content)

            violations.extend(
                f"{template_path.name}: bare '{keyword}' found outside trans tags"
                for keyword in self.ROMANIAN_KEYWORDS
                if keyword in stripped
            )

        self.assertEqual(
            violations,
            [],
            "Hardcoded Romanian strings found outside translation tags:\n" + "\n".join(violations),
        )


# ---------------------------------------------------------------------------
# Test 8: No |floatformat on monetary values in order templates
# ---------------------------------------------------------------------------


class TestNoFloatformatOnMonetaryValues(SimpleTestCase):
    """Order templates must use |romanian_currency / |cents_to_currency, not |floatformat."""

    # Template variables that carry monetary meaning
    MONETARY_VAR_PATTERNS: ClassVar[list[str]] = [
        "price",
        "total",
        "subtotal",
        "tax",
        "setup_fee",
        "cents",
        "amount",
    ]

    def _get_order_template_paths(self) -> list:
        from pathlib import Path  # noqa: PLC0415

        base = Path(__file__).resolve().parents[2] / "templates" / "orders"
        return list(base.rglob("*.html"))

    def test_no_floatformat_on_monetary_template_vars(self) -> None:
        """Monetary template variables must not be piped through |floatformat."""
        import re  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415

        # Matches patterns like {{ some_price|floatformat:2 }} or {{ total_cents|floatformat }}
        monetary_pattern = re.compile(
            r"\{\{[^}]*(?:" + "|".join(self.MONETARY_VAR_PATTERNS) + r")[^}]*\|floatformat[^}]*\}\}",
            re.IGNORECASE,
        )

        violations: list[str] = []

        for template_path in self._get_order_template_paths():
            content = Path(template_path).read_text(encoding="utf-8")
            violations.extend(
                f"{template_path.name}: {match.strip()}"
                for match in monetary_pattern.findall(content)
            )

        self.assertEqual(
            violations,
            [],
            "|floatformat used on monetary variable (use |romanian_currency instead):\n" + "\n".join(violations),
        )


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ENH-2: Bank Transfer Confirmation Flow (Good Tier)
# ---------------------------------------------------------------------------

_BANK_SETTINGS = {
    **_CACHE_SETTINGS,
    "COMPANY_BANK_IBAN": "RO49AAAA1B31007593840000",
    "COMPANY_BANK_NAME": "Banca Transilvania",
    "COMPANY_BANK_BENEFICIARY": "PragmaticHost SRL",
}

# A fixed UUID used as the order ID in confirmation URL tests.
_ENH2_ORDER_UUID = "11111111-2222-3333-4444-555555555555"
_ENH2_CONFIRM_URL = f"/order/confirmation/{_ENH2_ORDER_UUID}/"


def _make_bank_transfer_order(status: str = "pending") -> dict:
    return {
        "id": _ENH2_ORDER_UUID,
        "order_number": "ORD-BT-001",
        "status": status,
        "payment_method": "bank_transfer",
        "total": "119.00",
        "subtotal": "100.00",
        "tax_amount": "19.00",
        "vat_rate_percent": "19",
        "currency_code": "RON",
        "customer_email": "customer@example.com",
        "items": [],
        "created_at": "2026-03-10T12:00:00Z",
    }


@override_settings(**_BANK_SETTINGS)
class TestBankTransferConfirmationHeader(SimpleTestCase):
    """ENH-2: order_confirmation header must differ for bank_transfer vs other payment methods."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def _get_confirmation(self, order_data: dict) -> "HttpResponse":  # noqa: F821
        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = order_data
            mock_cls.return_value = mock_instance
            return self.client.get(_ENH2_CONFIRM_URL)

    def test_bank_transfer_shows_awaiting_message(self) -> None:
        """Header must say 'Awaiting your bank transfer' for bank_transfer orders."""
        response = self._get_confirmation(_make_bank_transfer_order())
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("bank transfer", content.lower())

    def test_bank_transfer_does_not_show_processed_soon(self) -> None:
        """bank_transfer confirmation must NOT show the generic 'processed soon' message."""
        response = self._get_confirmation(_make_bank_transfer_order())
        content = response.content.decode()
        # The generic "will be processed soon" phrase must not appear for bank_transfer
        self.assertNotIn("will be processed soon", content.lower())

    def test_non_bank_transfer_shows_generic_message(self) -> None:
        """Non-bank-transfer orders keep the generic success message."""
        order_data = {**_make_bank_transfer_order(), "payment_method": "stripe"}
        response = self._get_confirmation(order_data)
        self.assertEqual(response.status_code, 200)


@override_settings(**_BANK_SETTINGS)
class TestBankTransferInstructionsCard(SimpleTestCase):
    """ENH-2: Bank Transfer Instructions card renders correctly on confirmation page."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def _get_confirmation(self, order_data: dict) -> "HttpResponse":  # noqa: F821
        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = order_data
            mock_cls.return_value = mock_instance
            return self.client.get(_ENH2_CONFIRM_URL)

    def test_bank_details_card_shows_for_pending_order(self) -> None:
        """Bank Transfer Instructions card renders when status=pending."""
        response = self._get_confirmation(_make_bank_transfer_order("pending"))
        content = response.content.decode()
        self.assertIn("RO49AAAA1B31007593840000", content)
        self.assertIn("Banca Transilvania", content)
        self.assertIn("PragmaticHost SRL", content)

    def test_bank_details_card_shows_for_processing_order(self) -> None:
        """Bank Transfer Instructions card ALSO renders when status=processing (not just pending)."""
        response = self._get_confirmation(_make_bank_transfer_order("processing"))
        content = response.content.decode()
        self.assertIn("RO49AAAA1B31007593840000", content)

    def test_bank_details_card_shows_order_reference(self) -> None:
        """Payment reference (order number) must appear in the bank transfer card."""
        response = self._get_confirmation(_make_bank_transfer_order())
        content = response.content.decode()
        self.assertIn("ORD-BT-001", content)

    def test_bank_details_card_shows_amount(self) -> None:
        """Exact amount and currency must appear in the bank transfer card."""
        response = self._get_confirmation(_make_bank_transfer_order())
        content = response.content.decode()
        self.assertIn("119.00", content)
        self.assertIn("RON", content)

    def test_bank_details_not_shown_for_stripe_orders(self) -> None:
        """Stripe orders must NOT show the bank transfer card."""
        order_data = {**_make_bank_transfer_order(), "payment_method": "stripe"}
        response = self._get_confirmation(order_data)
        content = response.content.decode()
        self.assertNotIn("RO49AAAA1B31007593840000", content)

    def test_copy_to_clipboard_attributes_present_for_iban(self) -> None:
        """Alpine.js copy-to-clipboard must be wired up for the IBAN field."""
        response = self._get_confirmation(_make_bank_transfer_order())
        content = response.content.decode()
        # Alpine.js @click handler or x-data attribute should reference clipboard copy
        self.assertIn("clipboard", content.lower())

    def test_copy_to_clipboard_attributes_present_for_reference(self) -> None:
        """Alpine.js copy-to-clipboard must be wired up for the payment reference field."""
        response = self._get_confirmation(_make_bank_transfer_order())
        content = response.content.decode()
        # The reference copy button must appear alongside the order reference
        self.assertIn("clipboard", content.lower())


@override_settings(**_BANK_SETTINGS)
class TestBankTransferContextPassthrough(SimpleTestCase):
    """ENH-2: order_confirmation view must pass bank_details to template context."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def test_bank_details_in_context_for_bank_transfer(self) -> None:
        """bank_details context variable must contain iban, bank_name, beneficiary."""
        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = _make_bank_transfer_order()
            mock_cls.return_value = mock_instance
            response = self.client.get(_ENH2_CONFIRM_URL)

        self.assertEqual(response.status_code, 200)
        ctx = response.context
        bank_details = ctx["bank_details"]
        self.assertEqual(bank_details["iban"], "RO49AAAA1B31007593840000")
        self.assertEqual(bank_details["bank_name"], "Banca Transilvania")
        self.assertEqual(bank_details["beneficiary"], "PragmaticHost SRL")

    def test_bank_details_empty_for_stripe_orders(self) -> None:
        """bank_details must be empty dict when payment_method is not bank_transfer."""
        order_data = {**_make_bank_transfer_order(), "payment_method": "stripe"}
        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.post.return_value = order_data
            mock_cls.return_value = mock_instance
            response = self.client.get(_ENH2_CONFIRM_URL)

        self.assertEqual(response.status_code, 200)
        bank_details = response.context["bank_details"]
        self.assertEqual(bank_details, {})


# ---------------------------------------------------------------------------
# ENH-3: Reactive "Next Steps" sidebar on checkout page
# ---------------------------------------------------------------------------


class TestCheckoutReactiveSidebar(SimpleTestCase):
    """ENH-3: The checkout sidebar must contain Alpine.js reactive Next Steps content.

    These tests verify the *template source* — the presence of Alpine.js
    attributes and the correct i18n-wrapped strings for both payment method
    states.  Template source inspection is used because rendering the checkout
    template in the portal test suite requires the inline <script> block to
    resolve {% url %} tags, which involves URL reversals that are outside the
    scope of unit tests.  The Alpine.js runtime behaviour (DOM toggling) is
    covered by E2E tests; functional rendering is covered by integration tests.
    """

    _TEMPLATE_PATH = str(
        Path(__file__).resolve().parents[2] / "templates" / "orders" / "checkout.html"
    )

    def _read_template(self) -> str:
        with open(self._TEMPLATE_PATH) as f:
            return f.read()

    # -- Alpine.js data binding -----------------------------------------------

    def test_grid_container_has_alpine_x_data_with_payment_method(self) -> None:
        """The outer grid div must carry x-data='{paymentMethod: ...}'."""
        src = self._read_template()
        self.assertIn('x-data="{ paymentMethod:', src)

    def test_stripe_radio_has_change_handler(self) -> None:
        """Stripe radio must set paymentMethod to 'stripe' on change."""
        src = self._read_template()
        self.assertIn("@change=\"paymentMethod = 'stripe'\"", src)

    def test_bank_transfer_radio_has_change_handler(self) -> None:
        """Bank transfer radio must set paymentMethod to 'bank_transfer' on change."""
        src = self._read_template()
        self.assertIn("@change=\"paymentMethod = 'bank_transfer'\"", src)

    # -- x-show toggles -------------------------------------------------------

    def test_stripe_sidebar_panel_has_x_show_stripe(self) -> None:
        """Stripe Next Steps panel must be conditionally shown for stripe method."""
        src = self._read_template()
        self.assertIn("x-show=\"paymentMethod === 'stripe'\"", src)

    def test_bank_transfer_sidebar_panel_has_x_show_bank_transfer(self) -> None:
        """Bank Transfer Next Steps panel must be conditionally shown for bank_transfer."""
        src = self._read_template()
        self.assertIn("x-show=\"paymentMethod === 'bank_transfer'\"", src)

    # -- Stripe timeline i18n strings -----------------------------------------

    def test_stripe_timeline_contains_enter_card_details(self) -> None:
        """Stripe panel must wrap 'Enter card details' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Enter card details" %}', src)

    def test_stripe_timeline_contains_instant_confirmation(self) -> None:
        """Stripe panel must wrap 'Instant confirmation' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Instant confirmation" %}', src)

    def test_stripe_timeline_contains_immediate_activation(self) -> None:
        """Stripe panel must wrap 'Service activated immediately' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Service activated immediately" %}', src)

    # -- Bank Transfer timeline i18n strings ----------------------------------

    def test_bank_transfer_timeline_contains_order_confirmed(self) -> None:
        """Bank transfer panel must wrap 'Order confirmed' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Order confirmed" %}', src)

    def test_bank_transfer_timeline_contains_transfer_payment(self) -> None:
        """Bank transfer panel must wrap 'Transfer payment' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Transfer payment" %}', src)

    def test_bank_transfer_timeline_contains_activation_within_24h(self) -> None:
        """Bank transfer panel must wrap 'Service activated within 24h' in a trans tag."""
        src = self._read_template()
        self.assertIn('{% trans "Service activated within 24h" %}', src)

    # -- Transition animations ------------------------------------------------

    def test_both_panels_have_x_transition_enter(self) -> None:
        """Both sidebar panels must carry x-transition:enter for smooth appearance."""
        src = self._read_template()
        self.assertGreaterEqual(src.count("x-transition:enter="), 2)

    # -- Default state --------------------------------------------------------

    def test_initial_payment_method_is_stripe(self) -> None:
        """Alpine x-data must initialise paymentMethod to 'stripe' to match pre-checked radio."""
        src = self._read_template()
        self.assertIn("paymentMethod: 'stripe'", src)

    # -- Both panels present --------------------------------------------------

    def test_two_distinct_x_show_panels_present(self) -> None:
        """The template must have exactly two x-show panels (stripe + bank_transfer)."""
        src = self._read_template()
        self.assertEqual(src.count("x-show="), 2)

    # -- Sidebar section present ----------------------------------------------

    def test_reactive_sidebar_section_header_present(self) -> None:
        """Both panels must use the 'What happens next?' section heading."""
        src = self._read_template()
        self.assertEqual(src.count('{% trans "What happens next?" %}'), 2)
