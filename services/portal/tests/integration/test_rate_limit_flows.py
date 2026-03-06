"""
Rate-Limit Flow Integration Tests

Tests the cross-service rate-limit contract: Platform returns 429 with
Retry-After, Portal propagates semantic PlatformAPIError with is_rate_limited,
and views render appropriate UX (warnings, not errors).

These tests use mocked HTTP responses to validate the contract without
requiring live services.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.orders.services import CartCalculationService, OrderCreationService


def _mock_429_response(retry_after: int = 30) -> MagicMock:
    """Build a mock HTTP 429 response matching Platform's rate-limit contract."""
    resp = MagicMock()
    resp.status_code = 429
    resp.headers = {"Retry-After": str(retry_after), "content-type": "application/json"}
    resp.json.return_value = {"detail": "Too many requests", "retry_after": retry_after}
    return resp


def _mock_200_response(payload: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = payload or {"success": True}
    return resp


@pytest.mark.integration
class TestLoginRateLimitFlow:
    """Platform->Portal login 429 must surface as throttle message, not 'invalid credentials'."""

    def test_login_429_raises_rate_limited_error_not_none(self) -> None:
        """authenticate_customer must raise PlatformAPIError on 429, not return None."""
        client = PlatformAPIClient()
        mock_resp = _mock_429_response(retry_after=60)

        with patch("apps.api_client.services.portal_request", return_value=mock_resp):
            with pytest.raises(PlatformAPIError) as exc_info:
                client.authenticate_customer("test@example.com", "password123")

            assert exc_info.value.is_rate_limited is True
            assert exc_info.value.retry_after == 60
            assert exc_info.value.status_code == 429

    def test_login_401_returns_none_not_rate_limited(self) -> None:
        """Normal auth failure (401) must still return None, not raise."""
        client = PlatformAPIClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"detail": "Invalid credentials"}

        with patch("apps.api_client.services.portal_request", return_value=mock_resp):
            result = client.authenticate_customer("test@example.com", "wrong_password")

        assert result is None


@pytest.mark.integration
class TestOrdersRateLimitFlow:
    """Orders 429 must surface warning messages, not swallow or crash."""

    def test_cart_calculation_429_re_raises_rate_limited(self) -> None:
        """CartCalculationService must re-raise PlatformAPIError(is_rate_limited=True)."""
        cart = MagicMock()
        cart.has_items.return_value = True
        cart.currency = "RON"
        cart.get_api_items.return_value = [{"product_id": 1, "quantity": 1}]

        with patch("apps.orders.services.PlatformAPIClient") as mock_client:
            mock_client.return_value.post.side_effect = PlatformAPIError(
                "Too many requests", status_code=429, retry_after=30, is_rate_limited=True
            )
            with pytest.raises(PlatformAPIError) as exc_info:
                CartCalculationService.calculate_cart_totals(cart, "1", 1)

            assert exc_info.value.is_rate_limited is True

    def test_order_creation_429_re_raises_rate_limited(self) -> None:
        """OrderCreationService must re-raise PlatformAPIError(is_rate_limited=True)."""
        cart = MagicMock()
        cart.has_items.return_value = True
        cart.currency = "RON"
        cart.get_api_items.return_value = [{"product_id": 1, "quantity": 1}]
        cart.cart = {"created_at": "2026-01-01"}

        with patch("apps.orders.services.PlatformAPIClient") as mock_client:
            mock_client.return_value.post.side_effect = PlatformAPIError(
                "Too many requests", status_code=429, retry_after=30, is_rate_limited=True
            )
            with pytest.raises(PlatformAPIError) as exc_info:
                OrderCreationService.create_draft_order(cart, "1", "1")

            assert exc_info.value.is_rate_limited is True


@pytest.mark.integration
class TestRetryAfterPropagation:
    """Retry-After header from Platform must reach Portal's PlatformAPIError."""

    @pytest.mark.parametrize("retry_after", [10, 30, 60, 120])
    def test_retry_after_seconds_propagated(self, retry_after: int) -> None:
        """PlatformAPIError.retry_after must match the Retry-After header value."""
        client = PlatformAPIClient()
        mock_resp = _mock_429_response(retry_after=retry_after)

        with patch("apps.api_client.services.portal_request", return_value=mock_resp):
            with pytest.raises(PlatformAPIError) as exc_info:
                client.get("some/endpoint/", user_id=1)

            assert exc_info.value.retry_after == retry_after

    def test_missing_retry_after_defaults_gracefully(self) -> None:
        """If Platform omits Retry-After, Portal must not crash."""
        client = PlatformAPIClient()
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"content-type": "application/json"}  # No Retry-After
        resp.json.return_value = {"detail": "Too many requests"}

        with patch("apps.api_client.services.portal_request", return_value=resp):
            with pytest.raises(PlatformAPIError) as exc_info:
                client.get("some/endpoint/", user_id=1)

            assert exc_info.value.is_rate_limited is True
            # retry_after may be None or a default -- just ensure no crash
            assert exc_info.value.status_code == 429


@pytest.mark.integration
class TestIdempotentRetryContract:
    """Idempotent POST endpoints retry on 503, but never on 429."""

    def test_idempotent_post_retries_on_503(self) -> None:
        """POST with idempotent=True should retry transient 503 errors."""
        client = PlatformAPIClient()
        resp_503 = MagicMock()
        resp_503.status_code = 503
        resp_503.headers = {"content-type": "application/json"}
        resp_503.json.return_value = {"detail": "Service unavailable"}

        resp_200 = _mock_200_response({"success": True, "data": []})

        with (
            patch("apps.api_client.services.portal_request", side_effect=[resp_503, resp_200]),
            patch("time.sleep"),
        ):
            result = client._make_request("POST", "tickets/list/", user_id=1, idempotent=True)

        assert result == {"success": True, "data": []}

    def test_idempotent_post_does_not_retry_on_429(self) -> None:
        """POST with idempotent=True must NOT retry 429 -- rate limits are intentional."""
        client = PlatformAPIClient()
        mock_resp = _mock_429_response(retry_after=30)

        with patch("apps.api_client.services.portal_request", return_value=mock_resp):
            with pytest.raises(PlatformAPIError) as exc_info:
                client._make_request("POST", "tickets/list/", user_id=1, idempotent=True)

            assert exc_info.value.is_rate_limited is True
