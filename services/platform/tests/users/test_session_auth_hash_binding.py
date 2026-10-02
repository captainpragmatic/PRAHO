"""Signed Portal sessions are bound to the Platform password hash."""

import json
import time

import pyotp
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import salted_hmac
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.users.mfa import MFAService, WebAuthnCredential, WebAuthnService
from apps.users.models import User, UserSession
from apps.users.services import SessionSecurityService
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

    def enroll_mfa(self) -> tuple[str, list[str]]:
        setup = self.portal_post("/api/users/mfa/setup/", {"user_id": self.user.pk})
        self.assertEqual(setup.status_code, 200, setup.content)
        secret = setup.json()["setup_data"]["manual_entry_key"]
        response = self.portal_post(
            "/api/users/mfa/verify/", {"user_id": self.user.pk, "token": pyotp.TOTP(secret).now()}
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertEqual(response.json()["session_auth_hash"], self.user.get_session_auth_hash())
        return response.json()["session_auth_hash"], response.json()["backup_codes"]

    def test_version_zero_preserves_django_hash_and_caches_lookup(self) -> None:
        expected = salted_hmac(
            "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash",
            self.user.password,
            algorithm="sha256",
        ).hexdigest()
        fresh = User.objects.get(pk=self.user.pk)
        with self.assertNumQueries(1):
            self.assertEqual(fresh.get_session_auth_hash(), expected)
            self.assertEqual(fresh.get_session_auth_hash(), expected)
        self.assertEqual(self.validate_session(expected).status_code, 200)
        enabled_hash, _codes = self.enroll_mfa()
        self.assertNotEqual(enabled_hash, expected)

    def test_enable_and_disable_revoke_every_earlier_hash(self) -> None:
        original_hash = self.user.get_session_auth_hash()
        enabled_hash, codes = self.enroll_mfa()
        self.assertNotEqual(enabled_hash, original_hash)
        self.assertEqual(self.user.credential_version.version, 1)
        self.assertEqual(self.validate_session(original_hash).status_code, 401)
        self.assertEqual(self.validate_session(enabled_hash).status_code, 200)
        response = self.portal_post(
            "/api/users/mfa/disable/",
            {"user_id": self.user.pk, "password": self.password, "token": codes[0]},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        disabled_hash = response.json()["session_auth_hash"]
        self.assertEqual(disabled_hash, self.user.get_session_auth_hash())
        self.assertEqual(self.user.credential_version.version, 2)
        self.assertNotIn(disabled_hash, (original_hash, enabled_hash))
        self.assertFalse(self.user.two_factor_enabled)
        for revoked in (original_hash, enabled_hash):
            self.assertEqual(self.validate_session(revoked).status_code, 401)
        self.assertEqual(self.validate_session(disabled_hash).status_code, 200)

    @override_settings(SECRET_KEY="new-key", SECRET_KEY_FALLBACKS=["old-key"])
    def test_mfa_round_trip_never_revives_fallback_hashes(self) -> None:
        original_hashes = [self.user.get_session_auth_hash(), *self.user.get_session_auth_fallback_hash()]
        enabled_hash, codes = self.enroll_mfa()
        enabled_fallback = next(self.user.get_session_auth_fallback_hash())
        self.assertEqual(self.validate_session(enabled_fallback).status_code, 200)
        for old_hash in original_hashes:
            self.assertEqual(self.validate_session(old_hash).status_code, 401)
        response = self.portal_post(
            "/api/users/mfa/disable/",
            {"user_id": self.user.pk, "password": self.password, "token": codes[0]},
        )
        self.assertEqual(response.status_code, 200, response.content)
        for old_hash in [*original_hashes, enabled_hash, enabled_fallback]:
            self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.user.refresh_from_db()
        self.assertEqual(self.validate_session(next(self.user.get_session_auth_fallback_hash())).status_code, 200)

    def test_setup_and_backup_code_changes_preserve_the_current_hash(self) -> None:
        original_hash = self.user.get_session_auth_hash()
        for _attempt in range(2):
            setup = self.portal_post("/api/users/mfa/setup/", {"user_id": self.user.pk})
            self.assertEqual(setup.status_code, 200, setup.content)
            self.user.refresh_from_db()
            self.assertEqual(self.user.get_session_auth_hash(), original_hash)
        enabled_hash, codes = self.enroll_mfa()
        response = self.portal_post(
            "/api/users/mfa/regenerate-backup-codes/",
            {"user_id": self.user.pk, "password": self.password, "token": codes[0]},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertEqual(self.user.get_session_auth_hash(), enabled_hash)
        self.assertEqual(self.user.credential_version.version, 1)
        login = self.portal_post(
            "/api/users/login/",
            {
                "email": self.user.email,
                "password": self.password,
                "mfa_token": response.json()["backup_codes"][0],
            },
        )
        self.assertEqual(login.status_code, 200, login.content)
        self.assertEqual(login.json()["session_auth_hash"], enabled_hash)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)
        self.assertEqual(self.user.get_session_auth_hash(), enabled_hash)

    def test_valid_backup_code_cannot_complete_setup(self) -> None:
        setup = self.portal_post("/api/users/mfa/setup/", {"user_id": self.user.pk})
        self.assertEqual(setup.status_code, 200, setup.content)
        code = self.user.generate_backup_codes()[0]
        before = list(self.user.backup_tokens)
        old_hash = self.user.get_session_auth_hash()
        response = self.portal_post("/api/users/mfa/verify/", {"user_id": self.user.pk, "token": code})
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("Finish setup with the 6-digit code.", response.json()["token"])
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)
        self.assertEqual(self.user.backup_tokens, before)
        self.assertEqual(self.user.get_session_auth_hash(), old_hash)

    def test_stale_user_save_cannot_roll_back_credential_version(self) -> None:
        stale = User.objects.get(pk=self.user.pk)
        original_hash = stale.get_session_auth_hash()
        enabled_hash, _codes = self.enroll_mfa()
        stale.first_name = "Saved by an older request"
        stale.save()
        fresh = User.objects.get(pk=self.user.pk)
        self.assertEqual(fresh.first_name, "Saved by an older request")
        self.assertEqual(fresh.credential_version.version, 1)
        self.assertEqual(fresh.get_session_auth_hash(), enabled_hash)
        self.assertEqual(self.validate_session(original_hash).status_code, 401)

    def test_staff_enable_preserves_verified_secret_and_acting_session(self) -> None:
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        old_hash = self.user.get_session_auth_hash()
        browser = Client()
        browser.force_login(self.user)
        setup = browser.get(reverse("users:mfa_setup_totp"))
        self.assertEqual(setup.status_code, 200, setup.content)
        secret = browser.session["2fa_secret"]
        old_key = browser.session.session_key
        response = browser.post(reverse("users:mfa_setup_totp"), {"token": pyotp.TOTP(secret).now()})
        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertEqual(self.user.two_factor_secret, secret)
        self.assertTrue(self.user.two_factor_enabled)
        self.assertNotEqual(old_hash, self.user.get_session_auth_hash())
        self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.assertNotEqual(browser.session.session_key, old_key)
        self.assertEqual(browser.session["_auth_user_hash"], self.user.get_session_auth_hash())
        profile = browser.get(reverse("users:user_profile"))
        self.assertEqual(profile.status_code, 200, profile.content)
        self.assertTrue(profile.wsgi_request.user.is_authenticated)
        self.assertTrue(UserSession.objects.filter(user=self.user, session_key=browser.session.session_key).exists())

    def test_staff_disable_revokes_portal_session_and_preserves_acting_browser(self) -> None:
        # An account enabled before deployment has no version row.
        self.user.is_staff = True
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save()
        old_hash = self.user.get_session_auth_hash()
        self.assertEqual(self.validate_session(old_hash).status_code, 200)
        browser = Client()
        browser.force_login(self.user)
        old_key = browser.session.session_key
        response = browser.post(
            reverse("users:mfa_disable"),
            {"password": self.password, "token": pyotp.TOTP(self.user.two_factor_secret).now()},
        )
        self.assertRedirects(response, reverse("users:user_profile"), fetch_redirect_response=False)
        self.user.refresh_from_db()
        new_hash = self.user.get_session_auth_hash()
        self.assertFalse(self.user.two_factor_enabled)
        self.assertNotEqual(old_hash, new_hash)
        self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.assertEqual(self.validate_session(new_hash).status_code, 200)
        self.assertNotEqual(browser.session.session_key, old_key)
        self.assertEqual(browser.session["_auth_user_hash"], new_hash)
        profile = browser.get(reverse("users:user_profile"))
        self.assertEqual(profile.status_code, 200, profile.content)
        self.assertTrue(profile.wsgi_request.user.is_authenticated)
        self.assertTrue(UserSession.objects.filter(user=self.user, session_key=browser.session.session_key).exists())

    def test_service_enable_and_disable_refresh_cached_binding(self) -> None:
        original_hash = self.user.get_session_auth_hash()
        secret, codes = MFAService.enable_totp(self.user)
        enabled_hash = self.user.get_session_auth_hash()
        self.assertNotEqual(original_hash, enabled_hash)
        self.assertEqual(self.user.two_factor_secret, secret)
        self.assertEqual(len(codes), 8)
        self.assertEqual(self.validate_session(original_hash).status_code, 401)
        self.assertTrue(MFAService.disable_totp(self.user))
        disabled_hash = self.user.get_session_auth_hash()
        self.assertNotIn(disabled_hash, (original_hash, enabled_hash))
        self.assertEqual(self.user.credential_version.version, 2)
        self.assertEqual(self.validate_session(enabled_hash).status_code, 401)
        self.assertEqual(self.validate_session(disabled_hash).status_code, 200)

    def test_webauthn_credential_removal_revokes_sessions(self) -> None:
        credential = WebAuthnCredential.objects.create(
            user=self.user, credential_id="rotate-test", public_key="public-key", name="Key"
        )
        old_hash = self.user.get_session_auth_hash()
        self.assertEqual(self.validate_session(old_hash).status_code, 200)

        self.assertTrue(WebAuthnService.delete_credential(self.user, credential.pk))

        self.assertEqual(self.user.credential_version.version, 1)
        self.assertNotEqual(self.user.get_session_auth_hash(), old_hash)
        self.assertEqual(self.validate_session(old_hash).status_code, 401)
        self.assertEqual(self.validate_session(self.user.get_session_auth_hash()).status_code, 200)
        self.assertTrue(self.user.two_factor_enabled is False)

    def test_disable_all_and_recovery_each_revoke_sessions(self) -> None:
        for action in ("disable_all", "recover"):
            with self.subTest(action=action):
                self.user.two_factor_enabled = True
                self.user.two_factor_secret = pyotp.random_base32()
                self.user.save()
                old_hash = self.user.get_session_auth_hash()
                if action == "disable_all":
                    credential = WebAuthnCredential.objects.create(
                        user=self.user, credential_id="revocation-test", public_key="public-key", name="Key"
                    )
                    request = RequestFactory().post("/")
                    request.user = self.user
                    self.assertTrue(MFAService.disable_all_mfa_methods(request, self.user)["success"])
                    self.assertFalse(WebAuthnCredential.objects.filter(pk=credential.pk).exists())
                else:
                    SessionSecurityService.secure_account_after_password_reset(self.user)
                fresh = User.objects.get(pk=self.user.pk)
                # A password reset keeps enrolled 2FA (#595); disabling everything does not.
                self.assertEqual(fresh.two_factor_enabled, action == "recover")
                if action == "disable_all":
                    self.assertEqual(fresh.two_factor_secret, "")
                    self.assertEqual(fresh.backup_tokens, [])
                self.assertNotEqual(fresh.get_session_auth_hash(), old_hash)
                self.assertEqual(self.validate_session(old_hash).status_code, 401)
                self.assertEqual(self.validate_session(fresh.get_session_auth_hash()).status_code, 200)
