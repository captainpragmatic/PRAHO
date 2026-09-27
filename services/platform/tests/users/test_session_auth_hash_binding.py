"""Signed Portal sessions are bound to the Platform password hash."""

import json
import time

from django.contrib.auth.tokens import default_token_generator
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.users.models import User, UserSession
from apps.users.session_backend import SessionStore
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "session-auth-hash-binding-tests",
        }
    },
)
class SessionAuthHashBindingTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.password = "Original-secure123!"
        self.user = User.objects.create_user(email="binding@example.com", password=self.password)

    def validate_session(self, session_auth_hash: str) -> HttpResponse:
        return self.portal_post(
            "/api/users/session/validate/",
            {"user_id": self.user.pk, "session_auth_hash": session_auth_hash},
        )

    def test_login_returns_session_auth_hash(self) -> None:
        response = self.portal_post("/api/users/login/", {"email": self.user.email, "password": self.password})
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["session_auth_hash"], self.user.get_session_auth_hash())
        self.assertNotIn("session_auth_hash", body["user"])

    def test_validate_requires_matching_hash(self) -> None:
        current_hash = self.user.get_session_auth_hash()
        response = self.validate_session(current_hash)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIs(response.json()["active"], True)
        self.assertEqual(response.json()["session_auth_hash"], current_hash)

        for value in ("wrong", "", None, 123, ["invalid"]):
            with self.subTest(value=value):
                response = self.portal_post(
                    "/api/users/session/validate/",
                    {"user_id": self.user.pk, "session_auth_hash": value},
                )
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json(), {"active": False, "error": "Session validation failed"})

        response = self.portal_post("/api/users/session/validate/", {"user_id": self.user.pk})
        self.assertEqual(response.status_code, 401, response.content)

    def test_password_change_revokes_old_hash(self) -> None:
        old_hash = self.user.get_session_auth_hash()
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        staff_session = SessionStore()
        staff_session["_auth_user_id"] = str(self.user.pk)
        staff_session["_auth_user_hash"] = old_hash
        staff_session.save()
        self.assertTrue(UserSession.objects.filter(user=self.user, session_key=staff_session.session_key).exists())
        other = User.objects.create_user(email="unaffected@example.com", password=self.password)
        other_session = SessionStore()
        other_session["_auth_user_id"] = str(other.pk)
        other_session.save()

        path = "/api/users/change-password/"
        body = json.dumps(
            {
                "user_id": self.user.pk,
                "current_password": self.password,
                "new_password": "Replacement-secure123!",
                "timestamp": time.time(),
            }
        ).encode()
        response = self.client.put(path, body, content_type="application/json", **hmac_headers("PUT", path, body))
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        new_hash = self.user.get_session_auth_hash()
        self.assertNotEqual(old_hash, new_hash)
        self.assertEqual(response.json(), {"success": True, "session_auth_hash": new_hash})
        self.assertFalse(Session.objects.filter(session_key=staff_session.session_key).exists())
        self.assertFalse(UserSession.objects.filter(session_key=staff_session.session_key).exists())
        self.assertTrue(Session.objects.filter(session_key=other_session.session_key).exists())
        self.assertTrue(UserSession.objects.filter(user=other, session_key=other_session.session_key).exists())
        self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.assertEqual(self.validate_session(new_hash).status_code, 200)

    def test_password_reset_confirm_revokes_old_hash(self) -> None:
        old_hash = self.user.get_session_auth_hash()
        new_password = "Reset-replacement123!"
        response = self.portal_post(
            "/api/users/password/reset/confirm/",
            {
                "token": default_token_generator.make_token(self.user),
                "uid": urlsafe_base64_encode(force_bytes(self.user.pk)),
                "new_password": new_password,
                "new_password_confirm": new_password,
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        self.assertNotEqual(self.user.get_session_auth_hash(), old_hash)
        self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.assertEqual(self.validate_session(self.user.get_session_auth_hash()).status_code, 200)

    @override_settings(SECRET_KEY="new-key", SECRET_KEY_FALLBACKS=["old-key"])
    def test_fallback_secret_matches_and_echoes_current_hash(self) -> None:
        old_key_hash = self.user._get_session_auth_hash(secret="old-key")
        current_hash = self.user.get_session_auth_hash()
        self.assertNotEqual(old_key_hash, current_hash)
        response = self.validate_session(old_key_hash)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIs(response.json()["active"], True)
        self.assertEqual(response.json()["session_auth_hash"], current_hash)
