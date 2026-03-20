"""Portal middleware tests for membership_hash cache invalidation.

Covers the three behavioral contracts introduced by PR #115:
1. Hash changes       → user_memberships session cache is cleared
2. Hash unchanged     → cache is preserved
3. Hash absent        → no crash, no invalidation (backward compat)
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils import timezone as django_timezone

from apps.users.middleware import PortalAuthenticationMiddleware


def _make_authenticated_request(session_data: dict | None = None) -> object:
    """Build a RequestFactory request with a populated session."""
    factory = RequestFactory()
    request = factory.get("/dashboard/")

    # Attach a real in-memory session
    session_middleware = SessionMiddleware(lambda r: None)
    session_middleware.process_request(request)

    # Set up authenticated session baseline
    request.session["customer_id"] = "42"
    request.session["email"] = "user@example.com"
    request.session["user_id"] = 1
    request.customer_id = "42"
    request.user = SimpleNamespace(id=1, is_authenticated=True)

    if session_data:
        for key, value in session_data.items():
            request.session[key] = value

    return request


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class MembershipHashMiddlewareTest(SimpleTestCase):
    """Test membership_hash cache invalidation in PortalAuthenticationMiddleware."""

    def _make_middleware(self) -> PortalAuthenticationMiddleware:
        return PortalAuthenticationMiddleware(get_response=lambda r: None)

    def test_hash_change_invalidates_user_memberships_cache(self) -> None:
        """When membership_hash changes, user_memberships cache entries are cleared."""
        request = _make_authenticated_request(
            session_data={
                "membership_hash": "aabbccdd11223344",
                "user_memberships": [{"customer_id": 1, "role": "owner"}],
                "user_memberships_fetched_at": "2026-03-20T10:00:00+00:00",
            }
        )
        middleware = self._make_middleware()

        with patch(
            "apps.api_client.services.api_client.validate_session_secure",
            return_value={"active": True, "membership_hash": "bbccddee22334455"},
        ):
            middleware._perform_validation(request, "42", django_timezone.now())

        assert "user_memberships" not in request.session, "Cache should be cleared when hash changes"
        assert "user_memberships_fetched_at" not in request.session
        assert request.session["membership_hash"] == "bbccddee22334455"

    def test_unchanged_hash_preserves_user_memberships_cache(self) -> None:
        """When membership_hash is the same, user_memberships cache is preserved."""
        memberships = [{"customer_id": 1, "role": "owner"}]
        request = _make_authenticated_request(
            session_data={
                "membership_hash": "ccddee1122334455",
                "user_memberships": memberships,
                "user_memberships_fetched_at": "2026-03-20T10:00:00+00:00",
            }
        )
        middleware = self._make_middleware()

        with patch(
            "apps.api_client.services.api_client.validate_session_secure",
            return_value={"active": True, "membership_hash": "ccddee1122334455"},
        ):
            middleware._perform_validation(request, "42", django_timezone.now())

        assert request.session.get("user_memberships") == memberships, "Cache must be preserved when hash is unchanged"
        assert request.session["membership_hash"] == "ccddee1122334455"

    def test_absent_hash_in_response_does_not_crash(self) -> None:
        """When Platform response has no membership_hash, middleware handles gracefully."""
        request = _make_authenticated_request(
            session_data={
                "membership_hash": "ddeeff1122334455",
                "user_memberships": [{"customer_id": 1, "role": "owner"}],
            }
        )
        middleware = self._make_middleware()

        with patch(
            "apps.api_client.services.api_client.validate_session_secure",
            return_value={"active": True},  # no membership_hash key
        ):
            result = middleware._perform_validation(request, "42", django_timezone.now())

        assert result is True, "Validation should succeed even without membership_hash"
        # Cache must be untouched — no invalidation when hash is absent
        assert "user_memberships" in request.session
        # Old hash must remain unchanged
        assert request.session.get("membership_hash") == "ddeeff1122334455"
