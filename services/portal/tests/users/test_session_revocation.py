"""Portal session revocation through the signed Platform transport."""

import json
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIClient
from apps.common import counters
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
class SessionRevocationTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        production_settings = override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True)
        production_settings.enable()
        self.addCleanup(production_settings.disable)
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
                self.assertEqual(counters.peek("auth:fail_open:42"), 0)

    @override_settings(PLATFORM_API_ALLOW_INSECURE_HTTP=True)
    def test_authentication_faults_use_the_bounded_fail_open_breaker(self) -> None:
        for status_code, message in ((401, "HMAC authentication failed"), (403, "Access denied")):
            with self.subTest(status_code=status_code):
                cache.clear()
                counters.reset("auth:fail_open:42")
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
                self.assertEqual(counters.peek("auth:fail_open:42"), 1)

                counters.increment("auth:fail_open:42", 3600, delta=3)
                with patch("apps.api_client.services.portal_request", return_value=fault):
                    response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("user_id", request.session)
                self.assertEqual(counters.peek("auth:fail_open:42"), 5)

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
        self.assertEqual(counters.peek("auth:fail_open:42"), 1)
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

    def soft_request(self, session_auth_hash: str = "stored") -> HttpRequest:
        request = self.authenticated_request(session_auth_hash)
        request.session["next_validate_at"] = (timezone.now() - timedelta(seconds=60)).isoformat()
        request.session.save()
        return request

    def test_two_sessions_of_one_user_revalidate_independently(self) -> None:
        first = self.soft_request("first")
        second = self.soft_request("second")
        middleware = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))

        def respond(**kwargs: object) -> MagicMock:
            body = kwargs["data"]
            assert isinstance(body, bytes)
            session_hash = json.loads(body)["session_auth_hash"]
            if session_hash == "first":
                response = middleware(second)
                self.assertEqual(response.content, b"allowed")
                self.assertEqual(second.session["session_auth_hash"], "validated-second")
            return self.transport_response(
                200, {"active": True, "session_auth_hash": f"validated-{session_hash}"}
            )

        with patch("apps.api_client.services.portal_request", side_effect=respond):
            response = middleware(first)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(first.session["session_auth_hash"], "validated-first")
        self.assertIsNone(cache.get(f"validating:{first.session.session_key}"))
        self.assertIsNone(cache.get(f"validating:{second.session.session_key}"))

    def test_validation_releases_the_acquired_key_after_session_rotation(self) -> None:
        request = self.soft_request()
        acquired_key = f"validating:{request.session.session_key}"
        observed_tokens: list[str] = []

        def respond(**kwargs: object) -> MagicMock:
            token = cache.get(acquired_key)
            if isinstance(token, str):
                observed_tokens.append(token)
            request.session.cycle_key()
            return self.transport_response(200, {"active": True, "session_auth_hash": "current"})

        with patch("apps.api_client.services.portal_request", side_effect=respond):
            response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(len(observed_tokens), 1)
        self.assertIsNone(cache.get(acquired_key))
        self.assertIsNone(cache.get(f"validating:{request.session.session_key}"))

    def test_another_sessions_validation_owner_is_preserved(self) -> None:
        request = self.soft_request()
        key = f"validating:{request.session.session_key}"
        cache.set(key, "other-owner", timeout=30)
        rejection = self.transport_response(401, {"active": False})
        with patch("apps.api_client.services.portal_request", return_value=rejection):
            response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(request.session["session_auth_hash"], "stored")
        self.assertEqual(cache.get(key), "other-owner")

    def test_expired_lease_reacquired_during_validation_survives_old_owner_release(self) -> None:
        first = self.soft_request("first")
        second = self.soft_request("second")
        second.session = SessionStore(session_key=first.session.session_key)
        second.session["session_auth_hash"] = "second"
        key = f"validating:{first.session.session_key}"
        clock = [time.time()]
        entered = threading.Event()
        finish = threading.Event()
        new_tokens: list[str] = []
        responses: list[HttpResponse] = []
        pending: list[Future[HttpResponse]] = []
        middleware = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))

        def respond(**kwargs: object) -> MagicMock:
            body = kwargs["data"]
            assert isinstance(body, bytes)
            if json.loads(body)["session_auth_hash"] == "first":
                clock[0] += 31
                future = pool.submit(middleware, second)
                try:
                    self.assertTrue(entered.wait(timeout=5))
                    token = cache.get(key)
                    if isinstance(token, str):
                        new_tokens.append(token)
                except BaseException:
                    finish.set()
                    future.result(timeout=5)
                    raise
                pending.append(future)
            else:
                entered.set()
                if not finish.wait(timeout=5):
                    raise TimeoutError("Validation was not released")
            return self.transport_response(200, {"active": True, "session_auth_hash": "current"})

        with (
            ThreadPoolExecutor(max_workers=1) as pool,
            patch("django.core.cache.backends.locmem.time.time", side_effect=lambda: clock[0]),
            patch("apps.api_client.services.portal_request", side_effect=respond),
        ):
            try:
                responses.append(middleware(first))
                self.assertEqual(len(new_tokens), 1)
                self.assertEqual(cache.get(key), new_tokens[0])
            finally:
                finish.set()
                responses.extend(future.result(timeout=5) for future in pending)
        self.assertEqual([response.content for response in responses], [b"allowed", b"allowed"])
        self.assertIsNone(cache.get(key))

    def test_rate_limited_revalidation_returns_page_and_charges_breaker(self) -> None:
        request = self.soft_request()
        key = f"validating:{request.session.session_key}"
        validated_at = request.session["validated_at"]
        limited = self.transport_response(429, {"error": "Too many requests"})
        with patch("apps.api_client.services.portal_request", return_value=limited):
            response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
        self.assertEqual(response.content, b"allowed")
        self.assertEqual(counters.peek("auth:fail_open:42"), 1)
        self.assertEqual(request.session["validated_at"], validated_at)
        self.assertIsNone(cache.get(key))

    def test_five_consecutive_rate_limited_revalidations_deny_access(self) -> None:
        request = self.soft_request()
        key = f"validating:{request.session.session_key}"
        limited = self.transport_response(429, {"error": "Too many requests"})
        middleware = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))
        with patch("apps.api_client.services.portal_request", return_value=limited):
            for count in range(1, 6):
                response = middleware(request)
                self.assertEqual(counters.peek("auth:fail_open:42"), count)
                self.assertIsNone(cache.get(key))
                if count < 5:
                    self.assertEqual(response.content, b"allowed")
                    self.assertEqual(request.session["user_id"], 42)
                else:
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response["Location"], "/login/?next=%2Fdashboard%2F")
                    self.assertNotIn("user_id", request.session)
