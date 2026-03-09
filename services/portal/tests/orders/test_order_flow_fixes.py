"""
Regression tests for Portal order flow fixes.

Covers:
  BACKEND-2: agree_terms validation in create_order
  BACKEND-3: cart version mismatch — AJAX → 400 JSON, non-AJAX → 302 redirect
  BACKEND-4: payment_method=stripe routes to process_payment
  BUG-2:     product_type field stored in cart items after add_item
  DS-1:      calculate_cart_totals API response includes vat_rate_percent
  UX-5:      calculate_cart_totals API response includes per-item array

No database access — all tests use SimpleTestCase + locmem cache.
"""

import json
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
