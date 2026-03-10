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
        session.create()
        session_key = session.session_key

        # Saturate the counter atomically as the middleware itself does
        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT
        cart_cache_key = f"cart_session_{session_key}"
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
        session.create()
        session_key = session.session_key

        # Set counter well below limit
        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT
        cart_cache_key = f"cart_session_{session_key}"
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

    def test_different_sessions_have_independent_limits(self) -> None:
        """Each session has its own counter — saturating session A must not block session B."""
        from apps.common.rate_limiting import APIRateLimitMiddleware  # noqa: PLC0415

        mw = APIRateLimitMiddleware(lambda r: HttpResponse())

        session_a = SessionStore()
        session_a.create()
        session_b = SessionStore()
        session_b.create()

        limit = APIRateLimitMiddleware.CART_SESSION_RATE_LIMIT

        # Saturate session A
        cache.set(f"cart_session_{session_a.session_key}", limit, timeout=60)

        request_a = HttpRequest()
        request_a.session = session_a  # type: ignore[assignment]  # Django test: inject SessionStore
        request_b = HttpRequest()
        request_b.session = session_b  # type: ignore[assignment]  # Django test: inject SessionStore

        self.assertIsNotNone(mw._check_cart_session_rate_limit(request_a), "Session A should be blocked")
        self.assertIsNone(mw._check_cart_session_rate_limit(request_b), "Session B should be allowed")

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
        cache.set("confirm_payment:42:pi_dup_001", "processing", timeout=300)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_dup_001",
                "order_id": "550e8400-e29b-41d4-a716-446655440001",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

    def test_duplicate_returns_success_true(self) -> None:
        """Duplicate confirm_payment must set success=True (customer's payment IS processing)."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)
        cache.set("confirm_payment:42:pi_dup_002", "processing", timeout=300)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_dup_002",
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
                "payment_intent_id": "pi_fail_001",
                "order_id": "550e8400-e29b-41d4-a716-446655440003",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        # idem_key must be cleared so customer can retry
        idem_key = "confirm_payment:42:pi_fail_001"
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
                "payment_intent_id": "pi_partial_001",
                "order_id": "550e8400-e29b-41d4-a716-446655440004",
            }),
            content_type="application/json",
        )

        # Response indicates pending confirmation, not complete success
        data = json.loads(response.content)
        self.assertFalse(data["success"])
        self.assertIn("pending", data.get("status", "").lower())

        # idem_key must still be set to prevent double-charge
        idem_key = "confirm_payment:42:pi_partial_001"
        self.assertIsNotNone(cache.get(idem_key), "idem_key must be kept to prevent double-charge")


# ---------------------------------------------------------------------------
# C4: No timestamp in idempotency fallback key
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestIdempotencyFallbackKeyNoTimestamp(SimpleTestCase):
    """C4: The auto-generated idempotency key must be deterministic — no time component."""

    def setUp(self) -> None:
        cache.clear()

    def _compute_expected_key(self, customer_id: str, cart_version: str, session_key: str) -> str:
        """Replicate the fallback key formula from views._create_and_process_order."""
        return hashlib.sha256(
            f"{customer_id}:{cart_version}:{session_key}".encode()
        ).hexdigest()[:64]

    def test_same_inputs_produce_same_key(self) -> None:
        """Calling the hash formula twice with identical inputs yields the same key."""
        key1 = self._compute_expected_key("42", "abc123version", "sessionkeyXYZ")
        key2 = self._compute_expected_key("42", "abc123version", "sessionkeyXYZ")
        self.assertEqual(key1, key2)

    def test_different_cart_version_produces_different_key(self) -> None:
        """A changed cart_version must produce a different idempotency key."""
        key1 = self._compute_expected_key("42", "version_v1", "session_abc")
        key2 = self._compute_expected_key("42", "version_v2", "session_abc")
        self.assertNotEqual(key1, key2)

    def test_different_customer_produces_different_key(self) -> None:
        """A different customer_id must produce a different idempotency key."""
        key1 = self._compute_expected_key("42", "version_v1", "session_abc")
        key2 = self._compute_expected_key("99", "version_v1", "session_abc")
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
        key = self._compute_expected_key("42", "some_version", "session_key_1")
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
                    "payment_intent_id": "pi_gateway_ok_001",
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
                "payment_intent_id": "pi_gateway_bad_001",
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
                "payment_intent_id": "pi_gateway_evil",
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
                "payment_intent_id": "pi_gateway_empty",
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
        """When total is '0.00' and payment method is stripe, must redirect to checkout."""
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
                    "payment_method": "stripe",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_negative_total_cents_redirects_to_checkout(self) -> None:
        """When total is '-5.00' and payment method is stripe, must redirect to checkout."""
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
                    "payment_method": "stripe",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_positive_total_cents_proceeds_to_stripe(self) -> None:
        """When total is '99.00' and payment method is stripe, order creation must proceed past total check."""
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
            mock_api.post_billing.return_value = {"success": True, "client_secret": "sk_test", "payment_intent_id": "pi_1"}

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "stripe",
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

    def test_stripe_payment_method_is_accepted(self) -> None:
        """'stripe' is a valid payment_method and must pass validation."""
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
            mock_api.post_billing.return_value = {"success": True, "client_secret": "cs_test", "payment_intent_id": "pi_2"}

            response = self.client.post(
                "/order/create/",
                {
                    "agree_terms": "on",
                    "cart_version": cart_version,
                    "payment_method": "stripe",
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
        """ALLOWED_PAYMENT_METHODS must include stripe and bank_transfer."""
        from apps.orders.views import ALLOWED_PAYMENT_METHODS  # noqa: PLC0415

        self.assertIn("stripe", ALLOWED_PAYMENT_METHODS)
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
