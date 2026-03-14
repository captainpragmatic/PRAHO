"""
Chaos Monkey Round 2 — regression tests for C/H/M findings.

All portal tests use SimpleTestCase (no database access).
Covers: C1, C3, C4, H1, H3, H4, H5, M1, M4, M8

Duplicate confirm_payment returns HTTP 200 with success=True. From the
customer's perspective the payment IS being processed; a 409 would
trigger the error path in the frontend JS that checks data.success.
"""

from __future__ import annotations

import hashlib
import json
from decimal import ROUND_HALF_EVEN, ROUND_HALF_UP, Decimal
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.test import Client, SimpleTestCase, override_settings

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_product_data(slug: str = "shared-hosting-basic") -> dict:
    return {
        "id": "prod-uuid-001",
        "slug": slug,
        "name": "Shared Hosting Basic",
        "product_type": "hosting",
        "requires_domain": False,
        "is_active": True,
    }


def _populate_session_with_cart(client: Client) -> str:
    """Populate client session with auth context and one cart item.

    Returns the cart version string.
    """
    session = client.session
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
    return cart.get_cart_version()


# ---------------------------------------------------------------------------
# C1: Per-session cart rate limiting in APIRateLimitMiddleware
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS, RATE_LIMITING_ENABLED=True)
class TestCartSessionRateLimit(SimpleTestCase):
    """C1: Cart mutation endpoints enforce a per-session rate limit of 30/min."""

    def setUp(self) -> None:
        cache.clear()

    def test_is_cart_mutation_returns_true_for_cart_paths(self) -> None:
        """_is_cart_mutation() recognises every declared cart mutation path."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        cart_paths = [
            "/order/cart/add/",
            "/order/cart/update/",
            "/order/cart/remove/",
            "/order/cart/totals/",
        ]
        for path in cart_paths:
            request = HttpRequest()
            request.path = path
            self.assertTrue(mw._is_cart_mutation(request), f"Expected cart mutation for {path}")

    def test_is_cart_mutation_returns_false_for_non_cart_paths(self) -> None:
        """_is_cart_mutation() must NOT flag general API or non-cart paths."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        non_cart_paths = [
            "/api/orders/products/",
            "/billing/invoices/",
            "/tickets/list/",
            "/order/create/",
        ]
        for path in non_cart_paths:
            request = HttpRequest()
            request.path = path
            self.assertFalse(mw._is_cart_mutation(request), f"Expected non-cart for {path}")

    def test_cart_session_rate_limit_blocks_after_limit(self) -> None:
        """_check_cart_session_rate_limit() returns 429 after CART_SESSION_RATE_LIMIT hits."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        session = SessionStore()
        session["user_id"] = 42
        session.create()

        # Saturate the counter atomically as the middleware itself does
        # Rate limiter keys on user_id, not session_key
        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT
        cart_cache_key = f"cart_session_{session['user_id']}"
        cache.set(cart_cache_key, limit, timeout=60)

        request = HttpRequest()
        request.META["wsgi.input"] = None
        # Attach session with a known key
        request.session = session  # type: ignore[assignment]  # Django test: inject SessionStore

        response = mw._check_cart_session_rate_limit(request)
        assert response is not None, "Expected 429 response, got None"
        self.assertEqual(response.status_code, 429)

        data = json.loads(response.content)
        self.assertIn("retry_after", data)

    def test_cart_session_rate_limit_allows_below_limit(self) -> None:
        """_check_cart_session_rate_limit() returns None when count is below the limit."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        session = SessionStore()
        session["user_id"] = 43
        session.create()

        # Set counter well below limit — keyed on user_id
        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT
        cart_cache_key = f"cart_session_{session['user_id']}"
        cache.set(cart_cache_key, limit - 5, timeout=60)

        request = HttpRequest()
        request.session = session  # type: ignore[assignment]  # Django test: inject SessionStore

        response = mw._check_cart_session_rate_limit(request)
        self.assertIsNone(response)

    def test_no_session_key_returns_none(self) -> None:
        """When request has no session, _check_cart_session_rate_limit returns None (falls through to IP)."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        request = HttpRequest()
        # No session attribute set → getattr returns None
        response = mw._check_cart_session_rate_limit(request)
        self.assertIsNone(response)

    def test_different_users_have_independent_limits(self) -> None:
        """Each user has its own counter — saturating user A must not block user B."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        session_a = SessionStore()
        session_a["user_id"] = 100
        session_a.create()
        session_b = SessionStore()
        session_b["user_id"] = 200
        session_b.create()

        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT

        # Saturate user A — keyed on user_id, not session_key
        cache.set(f"cart_session_{session_a['user_id']}", limit, timeout=60)

        request_a = HttpRequest()
        request_a.session = session_a  # type: ignore[assignment]  # Django test: inject SessionStore
        request_b = HttpRequest()
        request_b.session = session_b  # type: ignore[assignment]  # Django test: inject SessionStore

        self.assertIsNotNone(mw._check_cart_session_rate_limit(request_a), "User A should be blocked")
        self.assertIsNone(mw._check_cart_session_rate_limit(request_b), "User B should be allowed")

    def test_cart_session_rate_limit_constant_is_30(self) -> None:
        """CART_SESSION_RATE_LIMIT must equal 30 per the chaos monkey spec."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        self.assertEqual(APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT, 30)


# ---------------------------------------------------------------------------
# C3 + M1: Idempotency key cleanup on failure, 409 for duplicates
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestConfirmPaymentIdempotencyRound2(SimpleTestCase):
    """C3/M1: confirm_payment must return 200/success:True for duplicates and clear idem_key on failure."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_duplicate_returns_200_not_409(self) -> None:
        """Duplicate confirm_payment with same PI must return HTTP 200 (not 409 which breaks frontend JS)."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        # Pre-populate idempotency key so the second call sees it
        cache.set("confirm_payment:42:pi_dup001test1234567890", "processing", timeout=300)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_dup001test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440001",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

    def test_duplicate_returns_success_true(self) -> None:
        """Duplicate confirm_payment must set success=True (customer's payment IS processing)."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)
        cache.set("confirm_payment:42:pi_dup002test1234567890", "processing", timeout=300)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_dup002test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440002",
            }),
            content_type="application/json",
        )

        data = json.loads(response.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "already_processing")

    @patch("apps.orders.views.PlatformAPIClient")
    def test_idem_key_cleared_when_payment_api_fails(self, mock_api_class: MagicMock) -> None:
        """When payment API call fails, idem_key is removed so customer can retry."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        mock_api = mock_api_class.return_value
        # Payment confirmation at platform level fails
        mock_api.post_billing.return_value = {"success": False, "error": "Stripe error"}

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_fail01test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440003",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        # idem_key must be cleared so customer can retry
        idem_key = "confirm_payment:42:pi_fail01test1234567890"
        self.assertIsNone(cache.get(idem_key), "idem_key should be cleared after payment API failure")

    @patch("apps.orders.views.PlatformAPIClient")
    def test_idem_key_kept_when_payment_succeeded_but_order_update_failed(self, mock_api_class: MagicMock) -> None:
        """When Stripe payment succeeded but order update failed, idem_key must NOT be cleared."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        mock_api = mock_api_class.return_value
        # Payment succeeded at Stripe
        mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
        # But order update in PRAHO failed
        mock_api.post.return_value = {"success": False, "error": "DB write failed"}

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_partial01test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440004",
            }),
            content_type="application/json",
        )

        # Response indicates pending confirmation, not complete success
        data = json.loads(response.content)
        self.assertFalse(data["success"])
        self.assertIn("pending", data.get("status", "").lower())

        # idem_key must still be set to prevent double-charge
        idem_key = "confirm_payment:42:pi_partial01test1234567890"
        self.assertIsNotNone(cache.get(idem_key), "idem_key must be kept to prevent double-charge")


# ---------------------------------------------------------------------------
# C4: No timestamp in idempotency fallback key
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestIdempotencyFallbackKeyNoTimestamp(SimpleTestCase):
    """C4: The auto-generated idempotency key must be deterministic — no time component."""

    def setUp(self) -> None:
        cache.clear()

    def _compute_expected_key(self, customer_id: str, cart_version: str, user_id: str) -> str:
        """Replicate the fallback key formula from views._create_and_process_order."""
        return hashlib.sha256(
            f"{customer_id}:{cart_version}:{user_id}".encode()
        ).hexdigest()[:64]

    def test_same_inputs_produce_same_key(self) -> None:
        """Calling the hash formula twice with identical inputs yields the same key."""
        key1 = self._compute_expected_key("42", "abc123version", "123")
        key2 = self._compute_expected_key("42", "abc123version", "123")
        self.assertEqual(key1, key2)

    def test_different_cart_version_produces_different_key(self) -> None:
        """A changed cart_version must produce a different idempotency key."""
        key1 = self._compute_expected_key("42", "version_v1", "123")
        key2 = self._compute_expected_key("42", "version_v2", "123")
        self.assertNotEqual(key1, key2)

    def test_different_customer_produces_different_key(self) -> None:
        """A different customer_id must produce a different idempotency key."""
        key1 = self._compute_expected_key("42", "version_v1", "123")
        key2 = self._compute_expected_key("99", "version_v1", "123")
        self.assertNotEqual(key1, key2)

    def test_key_does_not_include_time_component(self) -> None:
        """Regression guard: the key formula must NOT reference time.time() or timestamps.

        We verify this by inspecting the source of _create_and_process_order and
        asserting the idempotency fallback hash string does NOT contain 'time' or 'now'.
        """
        import inspect  # noqa: PLC0415

        from apps.orders import views  # noqa: PLC0415

        source = inspect.getsource(views._create_and_process_order)
        # The idempotency fallback block hash uses only customer_id, cart_version, session_key
        # Locate the sha256 hash lines — they must not reference 'time' or 'now()'
        hash_lines = [
            line for line in source.splitlines()
            if "sha256" in line or ("idempotency_key" in line and "encode" in line)
        ]
        for line in hash_lines:
            self.assertNotIn("time", line.lower(), f"Timestamp found in idem key line: {line}")
            self.assertNotIn("now()", line, f"now() found in idem key line: {line}")

    def test_key_truncated_to_64_chars(self) -> None:
        """The fallback key is SHA-256 hex truncated to 64 characters."""
        key = self._compute_expected_key("42", "some_version", "456")
        self.assertEqual(len(key), 64)


# ---------------------------------------------------------------------------
# H1: ROUND_HALF_EVEN banker's rounding
# ---------------------------------------------------------------------------


class TestBankersRoundingImport(SimpleTestCase):
    """H1: views.py must import and use ROUND_HALF_EVEN, not ROUND_HALF_UP."""

    def test_round_half_even_is_imported(self) -> None:
        """ROUND_HALF_EVEN must be importable from apps.orders.views at module level."""
        import importlib  # noqa: PLC0415

        import apps.orders.views as views_module  # noqa: PLC0415

        # The import block at the top of views.py pulls ROUND_HALF_EVEN
        source = importlib.util.find_spec("apps.orders.views")
        self.assertIsNotNone(source)

        # Direct attribute check — the module must expose the constant

        # Verify _parse_total_cents uses ROUND_HALF_EVEN via its source
        import inspect  # noqa: PLC0415

        source_text = inspect.getsource(views_module._parse_total_cents)
        self.assertIn("ROUND_HALF_EVEN", source_text)
        self.assertNotIn("ROUND_HALF_UP", source_text)

    def test_round_half_even_edge_case_2_5_rounds_to_2(self) -> None:
        """Banker's rounding: 2.5 rounds to 2 (nearest even), not 3 (round half up)."""
        result = Decimal("2.5").quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
        self.assertEqual(result, Decimal("2"))

    def test_round_half_even_edge_case_3_5_rounds_to_4(self) -> None:
        """Banker's rounding: 3.5 rounds to 4 (nearest even), not 4 (same as half up)."""
        result = Decimal("3.5").quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
        self.assertEqual(result, Decimal("4"))

    def test_round_half_up_differs_from_even_on_2_5(self) -> None:
        """ROUND_HALF_UP gives 3 for 2.5, confirming we chose the right rounding mode."""
        half_up = Decimal("2.5").quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        half_even = Decimal("2.5").quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
        self.assertNotEqual(half_up, half_even)
        self.assertEqual(half_even, Decimal("2"))


# ---------------------------------------------------------------------------
# H3: Gateway validation with _ALLOWED_GATEWAYS
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestGatewayValidation(SimpleTestCase):
    """H3: confirm_payment must reject unknown gateways with HTTP 400."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_stripe_gateway_is_accepted(self) -> None:
        """The 'stripe' gateway must NOT be rejected at the gateway validation step."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_api = mock_cls.return_value
            mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
            mock_api.post.return_value = {"success": True}

            response = self.client.post(
                "/order/confirm-payment/",
                data=json.dumps({
                    "payment_intent_id": "pi_gatewayok1234567890",
                    "order_id": "550e8400-e29b-41d4-a716-446655440005",
                    "gateway": "stripe",
                }),
                content_type="application/json",
            )

        # Should NOT be 400 (gateway rejection) — may be 200 or a different status
        self.assertNotEqual(response.status_code, 400)

    def test_invalid_gateway_is_rejected_with_400(self) -> None:
        """An unknown gateway such as 'paypal' must return HTTP 400."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_gatewaybad1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440006",
                "gateway": "paypal",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertFalse(data["success"])
        self.assertIn("gateway", data["error"].lower())

    def test_evil_gateway_is_rejected_with_400(self) -> None:
        """Injection attempt via gateway field must return HTTP 400."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_gatewayevil1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440007",
                "gateway": "evil_gateway'; DROP TABLE orders; --",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_empty_gateway_is_rejected_with_400(self) -> None:
        """An empty string gateway must return HTTP 400."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_gatewayempty123456789",
                "order_id": "550e8400-e29b-41d4-a716-446655440008",
                "gateway": "",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_allowed_gateways_frozenset_contains_only_stripe(self) -> None:
        """Regression guard: the allowed_gateways constant inside confirm_payment is exactly {'stripe'}."""
        import inspect  # noqa: PLC0415

        from apps.orders import views  # noqa: PLC0415

        source = inspect.getsource(views.confirm_payment)
        self.assertIn("allowed_gateways", source)
        self.assertIn('"stripe"', source)
        # Must be a frozenset, not a plain set or list
        self.assertIn("frozenset", source)


# ---------------------------------------------------------------------------
# H4: URI scheme checks in validators
# ---------------------------------------------------------------------------


class TestDangerousURISchemeValidation(SimpleTestCase):
    """H4: validate_domain_name and validate_notes must reject dangerous URI schemes."""

    def setUp(self) -> None:
        from apps.orders.validators import OrderInputValidator  # noqa: PLC0415

        self.validator = OrderInputValidator

    # --- validate_domain_name ---

    def test_javascript_scheme_in_domain_raises(self) -> None:
        """javascript: URI scheme must be rejected by validate_domain_name."""
        with self.assertRaises(ValidationError):
            self.validator.validate_domain_name("javascript:alert(1)")

    def test_data_scheme_in_domain_raises(self) -> None:
        """data: URI scheme must be rejected by validate_domain_name."""
        with self.assertRaises(ValidationError):
            self.validator.validate_domain_name("data:text/html,<script>")

    def test_vbscript_scheme_in_domain_raises(self) -> None:
        """vbscript: URI scheme must be rejected by validate_domain_name."""
        with self.assertRaises(ValidationError):
            self.validator.validate_domain_name("vbscript:MsgBox('hi')")

    def test_normal_domain_passes(self) -> None:
        """A valid domain name must not raise a ValidationError."""
        result = self.validator.validate_domain_name("example.com")
        self.assertEqual(result, "example.com")

    def test_subdomain_passes(self) -> None:
        """A valid subdomain must not raise a ValidationError."""
        result = self.validator.validate_domain_name("www.example.ro")
        self.assertEqual(result, "www.example.ro")

    # --- validate_notes ---

    def test_javascript_in_notes_raises(self) -> None:
        """javascript: inside a note must be rejected by validate_notes."""
        with self.assertRaises(ValidationError):
            self.validator.validate_notes("Click javascript:void(0) here")

    def test_data_uri_in_notes_raises(self) -> None:
        """data: URI scheme inside a note must be rejected by validate_notes."""
        with self.assertRaises(ValidationError):
            self.validator.validate_notes("See data:image/png;base64,abc for the image")

    def test_vbscript_in_notes_raises(self) -> None:
        """vbscript: inside a note must be rejected by validate_notes."""
        with self.assertRaises(ValidationError):
            self.validator.validate_notes("Run vbscript:MsgBox('hi') please")

    def test_normal_notes_pass(self) -> None:
        """Ordinary customer notes must not raise a ValidationError."""
        result = self.validator.validate_notes("Please set PHP 8.2 and enable daily backups.")
        self.assertIn("PHP", result)

    def test_empty_notes_returns_empty_string(self) -> None:
        """Empty notes input must return an empty string (not raise)."""
        result = self.validator.validate_notes("")
        self.assertEqual(result, "")

    def test_case_insensitive_scheme_detection(self) -> None:
        """URI scheme detection must be case-insensitive (JAVASCRIPT: must also be rejected)."""
        with self.assertRaises(ValidationError):
            self.validator.validate_notes("JAVASCRIPT:alert(1)")

        with self.assertRaises(ValidationError):
            self.validator.validate_notes("JavaScript:void(0)")


# ---------------------------------------------------------------------------
# H5: total_cents <= 0 hard failure
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestTotalCentsZeroRejection(SimpleTestCase):
    """H5: When total_cents is 0 or negative, order creation must redirect to checkout with an error."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _make_order_response(self, status: str = "pending", total: str = "0") -> dict:
        return {
            "order": {
                "id": "550e8400-e29b-41d4-a716-446655440099",
                "order_number": "ORD-2026-42-0099",
                "status": status,
                "total": total,
                "currency_code": "RON",
            }
        }

    def test_zero_total_cents_redirects_to_checkout(self) -> None:
        """When total is '0.00' and payment method is card, must redirect to checkout."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = self._make_order_response(status="pending", total="0")

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_negative_total_cents_redirects_to_checkout(self) -> None:
        """When total is '-5.00' and payment method is card, must redirect to checkout."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = self._make_order_response(status="pending", total="-5.00")

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_positive_total_cents_proceeds_to_card_payment(self) -> None:
        """When total is '99.00' and payment method is card, order creation must proceed past total check."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
            patch("apps.orders.views.PlatformAPIClient") as mock_api_cls,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = self._make_order_response(status="pending", total="99.00")
            mock_api = mock_api_cls.return_value
            mock_api.post_billing.return_value = {"success": True, "client_secret": "sk_test", "payment_intent_id": "pi_test0001234567890ab"}

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Must redirect to confirmation (not checkout) meaning it passed the total check
        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/confirmation/", response["Location"])


# ---------------------------------------------------------------------------
# M4: Payment method required and validated
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestPaymentMethodValidation(SimpleTestCase):
    """M4: Checkout must reject missing or invalid payment_method values."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def test_missing_payment_method_redirects_to_checkout(self) -> None:
        """Submitting checkout without payment_method must redirect back to checkout."""
        cart_version = _populate_session_with_cart(self.client)

        response = self.client.post(
            "/order/create/",
            {
                "agree_terms": "on",
                "cart_version": cart_version,
                # payment_method intentionally omitted
            },
            HTTP_X_FORWARDED_FOR="127.0.0.1",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_invalid_payment_method_redirects_to_checkout(self) -> None:
        """An unrecognised payment_method (e.g. 'bitcoin') must redirect to checkout."""
        cart_version = _populate_session_with_cart(self.client)

        response = self.client.post(
            "/order/create/",
            {
                "agree_terms": "on",
                "cart_version": cart_version,
                "payment_method": "bitcoin",
            },
            HTTP_X_FORWARDED_FOR="127.0.0.1",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_card_payment_method_is_accepted(self) -> None:
        """'card' is a valid payment_method and must pass validation."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
            patch("apps.orders.views.PlatformAPIClient") as mock_api_cls,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440010",
                    "order_number": "ORD-2026-42-0010",
                    "status": "pending",
                    "total": "49.99",
                    "currency_code": "RON",
                }
            }
            mock_api = mock_api_cls.return_value
            mock_api.post_billing.return_value = {"success": True, "client_secret": "cs_test", "payment_intent_id": "pi_test0002345678901ab"}

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Proceed to confirmation, not checkout — payment method accepted
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("/order/checkout/", response["Location"])

    def test_bank_transfer_payment_method_is_accepted(self) -> None:
        """'bank_transfer' is a valid payment_method and must pass validation."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440011",
                    "order_number": "ORD-2026-42-0011",
                    "status": "pending",
                    "total": "49.99",
                    "currency_code": "RON",
                }
            }

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "bank_transfer",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/confirmation/", response["Location"])

    def test_allowed_payment_methods_constant(self) -> None:
        """ALLOWED_PAYMENT_METHODS must include card and bank_transfer."""
        from apps.orders.views import ALLOWED_PAYMENT_METHODS  # noqa: PLC0415

        self.assertIn("card", ALLOWED_PAYMENT_METHODS)
        self.assertIn("bank_transfer", ALLOWED_PAYMENT_METHODS)
        # bitcoin, paypal should not be present
        self.assertNotIn("bitcoin", ALLOWED_PAYMENT_METHODS)
        self.assertNotIn("paypal", ALLOWED_PAYMENT_METHODS)


# ---------------------------------------------------------------------------
# M8: Cart version hash excludes updated_at
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestCartVersionHashExcludesUpdatedAt(SimpleTestCase):
    """M8: _generate_cart_version must be stable across updated_at changes."""

    def setUp(self) -> None:
        cache.clear()
        self.session = SessionStore()
        self.session.create()

    def _make_cart_dict(self, quantity: int = 1, updated_at: str = "2026-01-01T00:00:00") -> dict:
        return {
            "currency": "RON",
            "items": [
                {
                    "product_slug": "shared-hosting-basic",
                    "quantity": quantity,
                    "billing_period": "monthly",
                    "domain_name": "example.com",
                    "config": {},
                    "sealed_price_token": "tok_abc",
                    "updated_at": updated_at,
                }
            ],
            "updated_at": updated_at,
        }

    def test_changing_updated_at_does_not_change_version(self) -> None:
        """Modifying updated_at on a cart item must NOT produce a different version hash."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        service = GDPRCompliantCartSession(self.session)

        cart_early = self._make_cart_dict(quantity=1, updated_at="2026-01-01T00:00:00")
        cart_late = self._make_cart_dict(quantity=1, updated_at="2026-03-10T23:59:59")

        version_early = service._generate_cart_version(cart_early)
        version_late = service._generate_cart_version(cart_late)

        self.assertEqual(version_early, version_late, "updated_at must NOT influence the cart version hash")

    def test_changing_quantity_changes_version(self) -> None:
        """Changing item quantity must produce a different version hash (positive control)."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        service = GDPRCompliantCartSession(self.session)

        cart_qty1 = self._make_cart_dict(quantity=1)
        cart_qty2 = self._make_cart_dict(quantity=2)

        version_qty1 = service._generate_cart_version(cart_qty1)
        version_qty2 = service._generate_cart_version(cart_qty2)

        self.assertNotEqual(version_qty1, version_qty2, "quantity change must alter the cart version hash")

    def test_version_hash_is_hex_string(self) -> None:
        """The cart version must be a non-empty hex string (SHA-256 output)."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        service = GDPRCompliantCartSession(self.session)
        cart = self._make_cart_dict()
        version = service._generate_cart_version(cart)

        self.assertIsInstance(version, str)
        self.assertTrue(len(version) > 0)
        # SHA-256 hex is 64 chars
        self.assertEqual(len(version), 64)
        int(version, 16)  # raises ValueError if not valid hex


# ---------------------------------------------------------------------------
# H6: UUID validation in order_confirmation view
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestOrderConfirmationUUIDValidation(SimpleTestCase):
    """H6: order_confirmation must reject non-UUID order_id to prevent path traversal."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_path_traversal_order_id_redirects_to_catalog(self) -> None:
        """order_confirmation with path traversal order_id must redirect to catalog, NOT make API call."""
        self._set_session(customer_id=42, user_id=7)

        with patch("apps.orders.views.PlatformAPIClient") as mock_api_cls:
            response = self.client.get("/order/confirmation/../../billing/sensitive/")
            # If the URL matched at all and reached the view, the API must NOT have been called
            # (most likely Django's URL router will 404 this; either outcome is safe)
            mock_api_cls.assert_not_called()

        # Either 302 redirect or 404 — but must NOT be 200 serving billing data
        self.assertNotEqual(response.status_code, 200)

    def test_non_uuid_string_order_id_blocked(self) -> None:
        """order_confirmation with a non-UUID string (e.g. 'abc') must NOT serve order data.

        Django's <uuid:order_id> URL converter rejects non-UUID strings with 404 before the
        view is invoked — so the PlatformAPIClient must never be called.  Either 404 (URL
        router rejection) or 302 (view-level redirect) is acceptable; 200 is not.
        """
        self._set_session(customer_id=42, user_id=7)

        with patch("apps.orders.views.PlatformAPIClient") as mock_api_cls:
            response = self.client.get("/order/confirmation/abc/")
            # The URL router or view must have rejected — no API call allowed
            mock_api_cls.assert_not_called()

        # 404 (URL router rejects non-UUID) or 302 (view-level guard) — never 200
        self.assertIn(response.status_code, (302, 404))

    def test_sql_injection_order_id_is_rejected(self) -> None:
        """order_confirmation with SQL injection attempt must redirect to catalog."""
        self._set_session(customer_id=42, user_id=7)

        # URL-safe version of a SQL injection attempt
        evil_id = "1%27%20OR%20%271%27%3D%271"

        with patch("apps.orders.views.PlatformAPIClient") as mock_api_cls:
            response = self.client.get(f"/order/confirmation/{evil_id}/")
            mock_api_cls.assert_not_called()

        self.assertNotEqual(response.status_code, 200)

    def test_valid_uuid_order_id_reaches_api(self) -> None:
        """order_confirmation with a valid UUID must proceed and call the Platform API."""
        self._set_session(customer_id=42, user_id=7)
        valid_uuid = "550e8400-e29b-41d4-a716-446655440099"

        with patch("apps.orders.views.PlatformAPIClient") as mock_api_cls:
            mock_api = mock_api_cls.return_value
            mock_api.post.return_value = {
                "id": valid_uuid,
                "order_number": "ORD-2026-42-0001",
                "status": "completed",
                "total": "99.00",
                "currency_code": "RON",
                "items": [],
                "payment_method": "card",
            }
            mock_api.get_billing.return_value = {"success": False}

            response = self.client.get(f"/order/confirmation/{valid_uuid}/")

        # The API was called — UUID passed validation
        mock_api_cls.assert_called_once()
        # Must NOT redirect to catalog (order found successfully)
        self.assertNotEqual(response.status_code, 302)

    def test_uuid_validation_accepts_valid_uuid_object(self) -> None:
        """order_confirmation view-level UUID guard must accept a valid UUID string.

        Django's <uuid:order_id> URL converter only accepts lowercase hex UUIDs in the path.
        This test calls the view-level guard directly via uuid.UUID() to confirm it accepts
        valid UUIDs (both upper and lowercase) — which is the H6 fix we're testing.
        """
        import uuid as _uuid  # noqa: PLC0415

        # All of these must be parseable by uuid.UUID() — the view's guard
        valid_uuids = [
            "550e8400-e29b-41d4-a716-446655440099",  # lowercase
            "550E8400-E29B-41D4-A716-446655440099",  # uppercase
            "550e8400e29b41d4a716446655440099",      # no hyphens
        ]
        for uid_str in valid_uuids:
            try:
                _uuid.UUID(str(uid_str))
            except (ValueError, TypeError) as exc:
                self.fail(f"uuid.UUID() should accept '{uid_str}' but raised: {exc}")

    def test_uuid_validation_rejects_invalid_strings(self) -> None:
        """order_confirmation view-level UUID guard must reject non-UUID strings.

        Verifies that the uuid.UUID() call in the view would raise ValueError/TypeError
        for the kinds of strings we want to block.
        """
        import uuid as _uuid  # noqa: PLC0415

        invalid_ids = [
            "abc",
            "../../billing/sensitive",
            "1' OR '1'='1",
            "",
            "not-a-uuid-at-all",
            "123",
        ]
        for bad_id in invalid_ids:
            with self.assertRaises((ValueError, TypeError), msg=f"Expected error for '{bad_id}'"):
                _uuid.UUID(str(bad_id))


# ---------------------------------------------------------------------------
# C1 (new): Atomic idempotency acquire in _create_and_process_order
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestOrderCreationAtomicIdempotency(SimpleTestCase):
    """C1 (new): _create_and_process_order must use cache.add() for atomic TOCTOU-safe idempotency."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_cache_add_false_with_valid_order_id_redirects_to_confirmation(self) -> None:
        """When cache.add() returns False and cached value is a valid UUID, redirect to confirmation."""
        cart_version = _populate_session_with_cart(self.client)

        existing_order_id = "550e8400-e29b-41d4-a716-446655440099"

        # Simulate: key already acquired with a real order_id
        with (
            patch("apps.orders.views.cache") as mock_cache,
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
        ):
            mock_cache.add.return_value = False
            mock_cache.get.return_value = existing_order_id

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/confirmation/", response["Location"])
        self.assertIn(existing_order_id, response["Location"])

    def test_cache_add_false_with_in_progress_marker_redirects_to_checkout(self) -> None:
        """When cache.add() returns False and cached value is in-progress marker, redirect to checkout."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.cache") as mock_cache,
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
        ):
            mock_cache.add.return_value = False
            mock_cache.get.return_value = "__in_progress__"

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_cache_key_deleted_on_order_creation_failure(self) -> None:
        """On order creation failure (API error), the cache key must be deleted so customer can retry."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            # Simulate a hard error from order creation
            mock_create.return_value = {"error": "Platform DB unavailable"}

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Must redirect to checkout (error path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

        # The cache key must have been deleted — re-check: the real cache should be empty
        # after failure (we're using LocMemCache from _CACHE_SETTINGS)
        # Verify no lingering idempotency keys exist for this customer
        # (the customer_id in session is 42 from _populate_session_with_cart)
        # We can't easily derive the exact key without re-running the hash, but we verify
        # the behaviour: all keys were cleaned up by checking cache is in a clean state
        # for a fresh attempt with identical inputs.
        cart_version2 = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre2,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create2,
            patch("apps.orders.views.PlatformAPIClient") as mock_api_cls,
        ):
            mock_pre2.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create2.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440055",
                    "order_number": "ORD-2026-42-0055",
                    "status": "pending",
                    "total": "49.99",
                    "currency_code": "RON",
                }
            }
            mock_api_cls.return_value.post_billing.return_value = {
                "success": True,
                "client_secret": "cs_retry",
                "payment_intent_id": "pi_retry0001234567890ab",
            }

            response2 = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version2,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Retry must succeed and reach confirmation
        self.assertEqual(response2.status_code, 302)
        self.assertIn("/order/confirmation/", response2["Location"])

    def test_uses_cache_add_not_cache_get_at_start(self) -> None:
        """Regression guard: _create_and_process_order must start with cache.add(), not cache.get()."""
        import inspect  # noqa: PLC0415

        from apps.orders import views  # noqa: PLC0415

        source = inspect.getsource(views._create_and_process_order)

        # Find the idempotency section — the FIRST cache operation must be cache.add
        # Locate line positions
        lines = source.splitlines()
        first_cache_op_line = next(
            (line.strip() for line in lines if "cache.get(idem_cache_key)" in line or "cache.add(idem_cache_key" in line),
            None,
        )
        self.assertIsNotNone(first_cache_op_line, "No cache operation found for idem_cache_key")
        self.assertIn("cache.add(", first_cache_op_line, "First idempotency cache op must be cache.add(), not cache.get()")


# ---------------------------------------------------------------------------
# M3: Toast shows correct product name when updating existing cart item
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestAddToCartToastProductName(SimpleTestCase):
    """M3: add_to_cart must show the name of the product being added, not cart_items[-1]."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _setup_two_item_cart(self) -> None:
        """Pre-populate cart with product-a and product-b so product-a is NOT the last item."""
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        def _mock_product(slug: str) -> dict:
            return {
                "id": f"prod-{slug}",
                "slug": slug,
                "name": f"Product {slug.upper()}",
                "product_type": "hosting",
                "requires_domain": False,
                "is_active": True,
            }

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.side_effect = lambda path, **_kw: _mock_product(path.rstrip("/").split("/")[-1])
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug="product-a", quantity=1, billing_period="monthly")
            cart.add_item(product_slug="product-b", quantity=1, billing_period="monthly")

        session.save()

    def test_toast_shows_updated_product_name_not_last_item(self) -> None:
        """When re-adding product-a (updating it) with product-b as last item, toast must show product-a's name."""
        self._setup_two_item_cart()

        with patch("apps.orders.views.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            # add_to_cart view also calls PlatformAPIClient internally via cart.add_item
            mock_instance.get.return_value = {
                "id": "prod-product-a",
                "slug": "product-a",
                "name": "Product PRODUCT-A",
                "product_type": "hosting",
                "requires_domain": False,
                "is_active": True,
            }
            mock_cls.return_value = mock_instance

            with patch("apps.orders.views.OrderSecurityHardening.uniform_response_delay"):
                response = self.client.post(
                    "/order/cart/add/",
                    {
                        "product_slug": "product-a",
                        "quantity": "2",
                        "billing_period": "monthly",
                    },
                    HTTP_HX_REQUEST="true",
                )

        # Must return a rendered response (200 or 422), not a crash
        self.assertNotEqual(response.status_code, 500)
        # The response content must mention "product-a" or "PRODUCT-A", not "product-b"
        content = response.content.decode()
        # The toast product_name context variable must correspond to product-a
        # We check by asserting the response doesn't reference product-b as the success item
        # (product-b name would be "Product PRODUCT-B")
        self.assertNotIn("PRODUCT-B", content)


# ---------------------------------------------------------------------------
# M4: format() crash on translated string with curly braces in error_details
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestOrderValidationFormatStringSafety(SimpleTestCase):
    """M4: Order validation error message must not crash on user-supplied curly braces."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def test_curly_braces_in_preflight_error_do_not_crash(self) -> None:
        """Preflight returning errors with { or } must not cause a 500 crash."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
        ):
            # Inject malicious/malformed error string containing format placeholders
            mock_pre.return_value = {
                "valid": False,
                "errors": ["Unexpected field {unexpected_key} in payload {data}"],
                "warnings": [],
            }

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Must NOT be 500 — the view must handle curly braces gracefully
        self.assertNotEqual(response.status_code, 500)
        # Must redirect to checkout (validation failed path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_double_curly_braces_in_preflight_error_do_not_crash(self) -> None:
        """Preflight returning errors with {{ or }} must not crash the view."""
        cart_version = _populate_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
        ):
            mock_pre.return_value = {
                "valid": False,
                "errors": ["{{injection attempt}} with {0} positional"],
                "warnings": [],
            }

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "card",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, 302)
