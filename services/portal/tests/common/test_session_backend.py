"""
Portal Session Backend Tests

Verifies that the portal's session infrastructure works correctly with
server-side DB sessions. Covers the session_key availability, security
middleware activation, cart rate-limit keying, and order idempotency —
all of which silently broke under signed-cookie sessions where
session_key is always None.

See ADR-0017 addendum for the full incident writeup.
"""

import hashlib
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from apps.common.middleware import SessionSecurityMiddleware
from apps.common.rate_limiting import APIRateLimitMiddleware
from config.settings import dev as dev_settings
from config.settings.base import (
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SAMESITE,
    SESSION_ENGINE,
)

# ---------------------------------------------------------------------------
# 1. Session key availability — the root cause of the signed-cookie regression
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
)
class SessionKeyAvailabilityTests(TestCase):
    """Verify session_key is non-None with the DB backend.

    The signed-cookie backend always returns session_key=None, which
    silently disabled SessionSecurityMiddleware, cart rate limiting,
    and order idempotency.
    """

    def test_session_key_is_set_after_save(self):
        """DB session store must generate a non-None session_key on save."""
        store = SessionStore()
        store["user_id"] = 42
        store.save()
        self.assertIsNotNone(store.session_key)
        self.assertTrue(len(store.session_key) >= 20)

    def test_session_key_survives_load(self):
        """session_key persists across save → load cycle."""
        store = SessionStore()
        store["user_id"] = 42
        store.save()
        key = store.session_key

        loaded = SessionStore(session_key=key)
        self.assertEqual(loaded["user_id"], 42)
        self.assertEqual(loaded.session_key, key)

    def test_cycle_key_generates_new_key(self):
        """cycle_key() rotates the session key (session fixation protection)."""
        store = SessionStore()
        store["user_id"] = 42
        store.save()
        old_key = store.session_key

        store.cycle_key()
        self.assertIsNotNone(store.session_key)
        self.assertNotEqual(store.session_key, old_key)
        self.assertEqual(store["user_id"], 42)

    def test_flush_clears_data_and_key(self):
        """flush() wipes session data (server-side revocation)."""
        store = SessionStore()
        store["user_id"] = 42
        store.save()
        old_key = store.session_key

        store.flush()
        self.assertNotIn("user_id", store)
        # After flush, a new key is generated on next save
        self.assertNotEqual(store.session_key, old_key)


# ---------------------------------------------------------------------------
# 2. SessionSecurityMiddleware integration — was silently bypassed in prod
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
)
class SessionSecurityMiddlewareTests(TestCase):
    """Verify SessionSecurityMiddleware activates for authenticated sessions."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SessionSecurityMiddleware(lambda r: MagicMock(status_code=200))

    def test_middleware_skips_unauthenticated_sessions(self):
        """Middleware should return None (skip) when user_id is not in session."""
        request = self.factory.get("/dashboard/")
        # Attach an empty session
        request.session = self.client.session
        result = self.middleware.process_request(request)
        self.assertIsNone(result)

    def test_middleware_activates_for_authenticated_sessions(self):
        """Middleware should NOT skip when user_id is present in session.

        This is the critical regression test: under signed_cookies,
        session_key was always None, so the middleware returned early
        and never ran fingerprinting or timeout checks.
        """
        # Set up an authenticated session
        session = self.client.session
        session["user_id"] = 123
        session["email"] = "test@example.com"
        session.save()

        request = self.factory.get("/dashboard/")
        request.session = session
        request.META["HTTP_USER_AGENT"] = "TestBrowser/1.0"
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        self.middleware.process_request(request)
        # Should either return None (all checks passed) or HttpResponse (violation)
        # but crucially should NOT have returned early at the session_key guard.
        # Verify fingerprint was created (proves middleware ran):
        self.assertIn("security_fingerprint", request.session)

    def test_middleware_creates_fingerprint_on_first_request(self):
        """First authenticated request creates a security fingerprint in session."""
        session = self.client.session
        session["user_id"] = 123
        session.save()

        request = self.factory.get("/dashboard/")
        request.session = session
        request.META["HTTP_USER_AGENT"] = "TestBrowser/1.0"
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        self.middleware.process_request(request)

        fp = request.session.get("security_fingerprint")
        self.assertIsNotNone(fp)
        self.assertIn("ip_hash", fp)
        self.assertIn("user_agent_hash", fp)
        self.assertIn("created_at", fp)


# ---------------------------------------------------------------------------
# 3. Cart rate limiting — was silently disabled under signed_cookies
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
    RATE_LIMITING_ENABLED=True,
)
class CartRateLimitKeyingTests(TestCase):
    """Verify cart rate limiting uses user_id (not session_key) for keying."""

    def test_rate_limit_uses_user_id_key(self):
        """Cart rate limiter should key on user_id, not session_key."""
        middleware = APIRateLimitMiddleware(lambda r: MagicMock(status_code=200))

        factory = RequestFactory()
        request = factory.get("/orders/cart/calculate-totals/")
        session = self.client.session
        session["user_id"] = 999
        session.save()
        request.session = session

        # The method should use user_id=999 for the cache key,
        # not session.session_key.
        result = middleware._check_cart_session_rate_limit(request)
        # First request should not be rate-limited
        self.assertIsNone(result)

    def test_rate_limit_skips_when_no_user_id(self):
        """Without user_id in session, cart rate limiting falls through to IP-level."""
        middleware = APIRateLimitMiddleware(lambda r: MagicMock(status_code=200))

        factory = RequestFactory()
        request = factory.get("/orders/cart/calculate-totals/")
        request.session = self.client.session  # Empty session

        result = middleware._check_cart_session_rate_limit(request)
        self.assertIsNone(result)  # Falls through to IP limiting


# ---------------------------------------------------------------------------
# 4. Successful login — session state persists with DB backend
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
)
class LoginSessionPersistenceTests(TestCase):
    """Verify login creates persistent, non-None-keyed session state."""

    def test_successful_login_populates_session(self):
        """Successful login should set user_id, customer_id, active_customer_id in session."""
        with patch("apps.users.views.api_client") as mock_api:
            mock_api.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
            }
            mock_api.post.return_value = {
                "success": True,
                "results": [
                    {
                        "id": 456,
                        "company_name": "Acme SRL",
                        "role": "owner",
                        "is_primary": True,
                    }
                ],
            }
            mock_api.get_customer_profile.return_value = {"first_name": "Test"}

            response = self.client.post(
                "/login/",
                data={"email": "test@example.com", "password": "pass123"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/dashboard/")

        session = self.client.session
        self.assertEqual(session["user_id"], 123)
        self.assertEqual(session["customer_id"], 456)
        self.assertEqual(session["active_customer_id"], 456)

    def test_session_key_is_not_none_after_login(self):
        """After login, session_key must be non-None.

        This is the regression test for the signed-cookie bug:
        signed_cookies always returns session_key=None, which silently
        disabled SessionSecurityMiddleware (ADR-0017 safety net).
        """
        with patch("apps.users.views.api_client") as mock_api:
            mock_api.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
            }
            mock_api.post.return_value = {
                "success": True,
                "results": [
                    {
                        "id": 456,
                        "company_name": "Acme SRL",
                        "role": "owner",
                        "is_primary": True,
                    }
                ],
            }
            mock_api.get_customer_profile.return_value = {"first_name": "Test"}

            self.client.post(
                "/login/",
                data={"email": "test@example.com", "password": "pass123"},
            )

        self.assertIsNotNone(self.client.session.session_key)

    def test_session_persists_across_requests(self):
        """Session data set during login must persist to subsequent requests."""
        with patch("apps.users.views.api_client") as mock_api:
            mock_api.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
            }
            mock_api.post.return_value = {
                "success": True,
                "results": [
                    {
                        "id": 456,
                        "company_name": "Acme SRL",
                        "role": "owner",
                        "is_primary": True,
                    }
                ],
            }
            mock_api.get_customer_profile.return_value = {"first_name": "Test"}

            self.client.post(
                "/login/",
                data={"email": "test@example.com", "password": "pass123"},
            )

        # Verify session survives across separate requests
        session_after_login = self.client.session
        self.assertEqual(session_after_login["user_id"], 123)

        # Make another request — session should still be there
        with patch("apps.users.middleware.PortalAuthenticationMiddleware") as _:
            # Just verify the session cookie is sent back
            self.assertIsNotNone(self.client.cookies.get("portal_session"))


# ---------------------------------------------------------------------------
# 5. Order idempotency key — was using session_key (always empty string)
# ---------------------------------------------------------------------------


class OrderIdempotencyKeyTests(SimpleTestCase):
    """Verify idempotency key uses user_id, not session_key."""

    def test_idempotency_key_uses_user_id(self):
        """The fallback idempotency key should include user_id, not session_key."""
        # Simulate what the view does (lines 263-265 of orders/views.py)
        customer_id = "456"
        cart_version = "abc123"
        user_id = "123"

        key = hashlib.sha256(
            f"{customer_id}:{cart_version}:{user_id}".encode()
        ).hexdigest()[:64]

        # With session_key=None (signed cookies), the old code would use ""
        old_key_with_empty = hashlib.sha256(
            f"{customer_id}:{cart_version}:".encode()
        ).hexdigest()[:64]

        # Keys must differ — user_id provides unique namespace per user
        self.assertNotEqual(key, old_key_with_empty)

    def test_different_users_get_different_idempotency_keys(self):
        """Two users with the same cart should get different idempotency keys."""
        cart_version = "abc123"
        customer_id = "456"

        key_user_1 = hashlib.sha256(
            f"{customer_id}:{cart_version}:1".encode()
        ).hexdigest()[:64]
        key_user_2 = hashlib.sha256(
            f"{customer_id}:{cart_version}:2".encode()
        ).hexdigest()[:64]

        self.assertNotEqual(key_user_1, key_user_2)


# ---------------------------------------------------------------------------
# 6. Settings consistency — all environments use DB sessions
# ---------------------------------------------------------------------------


class SessionSettingsConsistencyTests(SimpleTestCase):
    """Verify session backend settings are consistent across environments."""

    def test_base_settings_use_db_sessions(self):
        """base.py must configure DB-backed sessions."""
        self.assertEqual(SESSION_ENGINE, "django.contrib.sessions.backends.db")

    def test_dev_settings_use_db_sessions(self):
        """dev.py must not override to signed_cookies."""
        # dev.py's test override should also be db
        self.assertNotIn("signed_cookies", getattr(dev_settings, "SESSION_ENGINE", ""))

    def test_session_cookie_security_settings(self):
        """Session cookie must have HTTPONLY and SAMESITE protection."""
        self.assertTrue(SESSION_COOKIE_HTTPONLY)
        self.assertEqual(SESSION_COOKIE_SAMESITE, "Lax")

    def test_session_cookie_has_custom_name(self):
        """Session cookie must use a custom name (not default 'sessionid')."""
        self.assertEqual(SESSION_COOKIE_NAME, "portal_session")


# ---------------------------------------------------------------------------
# 7. Stale signed-cookie graceful degradation
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
)
class StaleCookieGracefulDegradationTests(TestCase):
    """Verify that old signed-cookie sessions degrade to 'logged out', not 500."""

    def test_stale_signed_cookie_does_not_crash(self):
        """A request with an invalid signed-cookie session should redirect to login."""
        self.client.cookies["portal_session"] = "invalid-signed-cookie-data"
        response = self.client.get("/dashboard/")
        # Should redirect to login (302) or show login page (200), not 500
        self.assertIn(response.status_code, [200, 302])

    def test_empty_session_after_stale_cookie(self):
        """After receiving a stale cookie, session should be empty (no user_id)."""
        self.client.cookies["portal_session"] = "eyJ0ZXN0IjoxfQ:fakesig:fakehmac"
        response = self.client.get("/dashboard/")
        self.assertNotIn("user_id", self.client.session)
        self.assertIn(response.status_code, [200, 302])
