"""Portal session revocation through the signed Platform transport."""

import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIClient
from apps.users.middleware import PortalAuthenticationMiddleware


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="session-revocation-secret",
    PORTAL_HMAC_SECRET="session-revocation-secret",
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "session-revocation-tests",
        }
    },
)
class SessionRevocationTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        # Use the real client even when the suite supplies a shared API fixture.
        client_patch = patch("apps.users.middleware.api_client", PlatformAPIClient())
        client_patch.start()
        self.addCleanup(client_patch.stop)
        self.factory = RequestFactory()

    def authenticated_request(self, session_auth_hash: str = "stored") -> HttpRequest:
        request = self.factory.get("/dashboard/")
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        now = timezone.now()
        request.session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": "user@example.com",
                "session_auth_hash": session_auth_hash,
                "authenticated_at": now.isoformat(),
                "validated_at": (now - timedelta(minutes=20)).isoformat(),
                "next_validate_at": (now - timedelta(minutes=10)).isoformat(),
            }
        )
        request.session.save()
        return request

    @staticmethod
    def transport_response(status_code: int, payload: dict[str, object]) -> MagicMock:
        response = MagicMock()
        response.status_code = status_code
        response.headers = {"content-type": "application/json"}
        response.json.return_value = payload
        return response

    def assert_rejected(self, request: HttpRequest, response: HttpResponse, downstream: MagicMock) -> None:
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/login/?next=%2Fdashboard%2F")
        downstream.assert_not_called()
        self.assertNotIn("user_id", request.session)
        self.assertNotIn("session_auth_hash", request.session)

    def test_rejected_session_is_flushed_not_failed_open(self) -> None:
        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                request = self.authenticated_request()
                downstream = MagicMock(return_value=HttpResponse("allowed"))
                denial = self.transport_response(status_code, {"active": False, "error": "Session validation failed"})
                with patch("apps.api_client.services.portal_request", return_value=denial):
                    response = PortalAuthenticationMiddleware(get_response=downstream)(request)
                self.assert_rejected(request, response, downstream)
                self.assertIsNone(cache.get("auth:fail_open:42"))

    @override_settings(PLATFORM_API_ALLOW_INSECURE_HTTP=True)
    def test_authentication_faults_use_the_bounded_fail_open_breaker(self) -> None:
        for status_code, message in ((401, "HMAC authentication failed"), (403, "Access denied")):
            with self.subTest(status_code=status_code):
                cache.clear()
                request = self.authenticated_request()
                session_key = request.session.session_key
                validated_at = request.session["validated_at"]
                fault = self.transport_response(status_code, {"error": message})
                with patch("apps.api_client.services.portal_request", return_value=fault):
                    response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
                self.assertEqual(response.content, b"allowed")
                self.assertEqual(request.session.session_key, session_key)
                self.assertEqual(request.session["user_id"], 42)
                self.assertEqual(request.session["session_auth_hash"], "stored")
                self.assertEqual(request.session["validated_at"], validated_at)
                self.assertEqual(cache.get("auth:fail_open:42"), 1)

                cache.set("auth:fail_open:42", 4)
                with patch("apps.api_client.services.portal_request", return_value=fault):
                    response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("user_id", request.session)
                self.assertEqual(cache.get("auth:fail_open:42"), 5)

    def test_empty_hash_forces_validation_before_future_deadline(self) -> None:
        request = self.authenticated_request("")
        request.session["next_validate_at"] = (timezone.now() + timedelta(minutes=10)).isoformat()
        success = self.transport_response(200, {"active": True, "session_auth_hash": "current"})
        with patch("apps.api_client.services.portal_request", return_value=success) as transport:
            response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
        transport.assert_called_once()
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["session_auth_hash"], "")
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(request.session["session_auth_hash"], "current")

    def test_two_sessions_old_hash_is_revoked_while_new_survives(self) -> None:
        current = self.authenticated_request("new")
        revoked = self.authenticated_request("old")
        self.assertNotEqual(current.session.session_key, revoked.session.session_key)

        def respond(**kwargs: object) -> MagicMock:
            body = kwargs["data"]
            assert isinstance(body, bytes)
            if json.loads(body).get("session_auth_hash") == "new":
                return self.transport_response(
                    200, {"active": True, "membership_hash": "x", "session_auth_hash": "new"}
                )
            return self.transport_response(401, {"active": False, "error": "Session validation failed"})

        current_downstream = MagicMock(return_value=HttpResponse("allowed"))
        revoked_downstream = MagicMock(return_value=HttpResponse("allowed"))
        with patch("apps.api_client.services.portal_request", side_effect=respond):
            current_response = PortalAuthenticationMiddleware(get_response=current_downstream)(current)
            revoked_response = PortalAuthenticationMiddleware(get_response=revoked_downstream)(revoked)

        self.assertEqual(current_response.content, b"allowed")
        self.assertEqual(current.session["user_id"], 42)
        self.assertEqual(current.session["session_auth_hash"], "new")
        self.assert_rejected(revoked, revoked_response, revoked_downstream)

    def test_denial_inside_soft_grace_window_is_not_deferred(self) -> None:
        request = self.authenticated_request()
        request.session["next_validate_at"] = (timezone.now() - timedelta(seconds=60)).isoformat()
        downstream = MagicMock(return_value=HttpResponse("allowed"))
        denial = self.transport_response(401, {"active": False, "error": "Session validation failed"})
        with patch("apps.api_client.services.portal_request", return_value=denial):
            response = PortalAuthenticationMiddleware(get_response=downstream)(request)
        self.assert_rejected(request, response, downstream)

    def test_outage_still_fails_open(self) -> None:
        request = self.authenticated_request()
        validated_at = request.session["validated_at"]
        next_validate_at = request.session["next_validate_at"]
        downstream = MagicMock(return_value=HttpResponse("allowed"))
        outage = self.transport_response(503, {"error": "Service unavailable"})
        with patch("apps.api_client.services.portal_request", return_value=outage) as transport:
            response = PortalAuthenticationMiddleware(get_response=downstream)(request)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(request.session["user_id"], 42)
        self.assertEqual(request.session["validated_at"], validated_at)
        self.assertEqual(request.session["next_validate_at"], next_validate_at)
        self.assertEqual(cache.get("auth:fail_open:42"), 1)
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["session_auth_hash"], "stored")

    def test_missing_hash_forces_immediate_validation(self) -> None:
        request = self.authenticated_request()
        del request.session["session_auth_hash"]
        request.session["next_validate_at"] = (timezone.now() + timedelta(minutes=10)).isoformat()
        downstream = MagicMock(return_value=HttpResponse("allowed"))
        denial = self.transport_response(401, {"active": False, "error": "Session validation failed"})
        with patch("apps.api_client.services.portal_request", return_value=denial) as transport:
            response = PortalAuthenticationMiddleware(get_response=downstream)(request)
        transport.assert_called_once()
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["session_auth_hash"], "")
        self.assert_rejected(request, response, downstream)

    def test_validation_sends_stored_hash_and_stores_echoed_one(self) -> None:
        request = self.authenticated_request("fallback")
        downstream = MagicMock(return_value=HttpResponse("allowed"))
        success = self.transport_response(200, {"active": True, "membership_hash": "x", "session_auth_hash": "current"})
        with patch("apps.api_client.services.portal_request", return_value=success) as transport:
            response = PortalAuthenticationMiddleware(get_response=downstream)(request)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["session_auth_hash"], "fallback")
        self.assertEqual(request.session["session_auth_hash"], "current")

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
        ]
    )
    def test_login_stores_hash_outside_customer_data(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 42,
                "customer_id": 7,
                "customer_data": {"id": 42, "email": "user@example.com"},
                "session_auth_hash": "login-hash",
            }
            platform.post.return_value = {"success": True, "results": []}
            platform.get_customer_profile.return_value = {}
            response = self.client.post("/login/", {"email": "user@example.com", "password": "Original-secure123!"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["user_id"], 42)
        self.assertEqual(self.client.session["session_auth_hash"], "login-hash")

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
        ]
    )
    def test_password_change_preserves_new_hash_when_session_key_rotates(self) -> None:
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com", "session_auth_hash": "old"})
        session.save()
        old_session_key = session.session_key
        other_session = self.authenticated_request("old").session
        success = self.transport_response(200, {"success": True, "session_auth_hash": "new"})
        with (
            patch("apps.users.views.api_client", PlatformAPIClient()),
            patch("apps.api_client.services.portal_request", return_value=success),
        ):
            response = self.client.post(
                "/change-password/",
                {
                    "current_password": "Original-secure123!",
                    "new_password": "Replacement-secure123!",
                    "confirm_password": "Replacement-secure123!",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["user_id"], 42)
        self.assertEqual(self.client.session["session_auth_hash"], "new")
        self.assertNotEqual(self.client.session.session_key, old_session_key)
        self.assertEqual(SessionStore(session_key=old_session_key).load(), {})
        self.assertEqual(other_session["session_auth_hash"], "old")
