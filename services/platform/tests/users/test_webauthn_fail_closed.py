"""WebAuthn verification must fail closed (#596).

No verification library is installed, yet is_supported() always said yes, and
verify_authentication accepted any request naming an active credential: it checked no
signature, trusted a client-claimed signCount, and (with a library) verified against a
challenge taken from the client's own payload. Registration stored credentials with
public_key="unknown" after a structure check. Nothing reaches these paths today, so the
fix is to refuse rather than to finish WebAuthn.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import RequestFactory, TestCase

from apps.users.mfa import WebAuthnCredential, WebAuthnService
from apps.users.models import User

SERVER_CHALLENGE_KEY = "webauthn_challenge"


class WebAuthnFailClosedTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="passkey@example.ro", password="unused-fixture-password")
        self.credential = WebAuthnCredential.objects.create(
            user=self.user, credential_id="cred-1", public_key="stored-public-key", name="Key", sign_count=3
        )
        self.request = RequestFactory().post("/")
        self.request.session = import_module(settings.SESSION_ENGINE).SessionStore()
        self.request.user = self.user

    def issue_challenge(self) -> str:
        return str(WebAuthnService.generate_authentication_options(self.request, self.user)["challenge"])

    def authenticate(self, data: dict[str, Any]) -> bool:
        return WebAuthnService.verify_authentication(self.request, self.user, data)

    def assertion(self, **extra: Any) -> dict[str, Any]:
        return {"id": "cred-1", "challenge": "client-chosen-challenge", "signCount": 999, **extra}

    def fake_library(self, result: dict[str, Any] | None) -> MagicMock:
        library = MagicMock()
        library.verify_authentication_response.return_value = result
        return library

    # --- authentication -------------------------------------------------------------

    def test_without_a_library_authentication_is_refused_and_nothing_is_marked_used(self) -> None:
        self.issue_challenge()
        with patch("apps.users.mfa.webauthn", None), patch.object(WebAuthnCredential, "mark_as_used") as marked:
            self.assertFalse(self.authenticate(self.assertion()))
        marked.assert_not_called()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.sign_count, 3)
        self.assertIsNone(self.credential.last_used)

    def test_library_checks_the_session_challenge_not_the_clients(self) -> None:
        challenge = self.issue_challenge()
        library = self.fake_library({"verified": True, "new_sign_count": 4})
        with patch("apps.users.mfa.webauthn", library):
            self.assertTrue(self.authenticate(self.assertion()))
        self.assertEqual(library.verify_authentication_response.call_args.kwargs["expected_challenge"], challenge)

    def test_the_challenge_is_single_use(self) -> None:
        self.issue_challenge()
        library = self.fake_library(None)
        # Both results would pass on their own (the counter advances), so only the spent
        # challenge can refuse the second.
        library.verify_authentication_response.side_effect = [
            {"verified": True, "new_sign_count": 4},
            {"verified": True, "new_sign_count": 5},
        ]
        with patch("apps.users.mfa.webauthn", library):
            self.assertTrue(self.authenticate(self.assertion()))
            self.assertFalse(self.authenticate(self.assertion()), "a challenge was accepted twice")

    def test_missing_session_challenge_is_refused(self) -> None:
        library = self.fake_library({"verified": True, "new_sign_count": 4})
        with patch("apps.users.mfa.webauthn", library):
            self.assertFalse(self.authenticate(self.assertion()))
        library.verify_authentication_response.assert_not_called()

    def test_sign_count_comes_from_the_verified_result_not_the_client(self) -> None:
        self.issue_challenge()
        with patch("apps.users.mfa.webauthn", self.fake_library({"verified": True, "new_sign_count": 7})):
            self.assertTrue(self.authenticate(self.assertion(signCount=999)))
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.sign_count, 7)

    def test_a_sign_count_that_did_not_advance_is_refused(self) -> None:
        self.issue_challenge()
        with patch("apps.users.mfa.webauthn", self.fake_library({"verified": True, "new_sign_count": 3})):
            self.assertFalse(self.authenticate(self.assertion(signCount=999)))

    # --- registration -----------------------------------------------------------------

    def registration(self) -> dict[str, Any]:
        return {"id": "new-cred", "type": "public-key", "response": {"publicKey": "client-claimed-key"}}

    def test_without_a_library_registration_stores_nothing(self) -> None:
        WebAuthnService.generate_registration_options(self.request, self.user)
        with patch("apps.users.mfa.webauthn", None):
            result = WebAuthnService.verify_registration_response(self.request, self.registration(), "Key")
            self.assertFalse(WebAuthnService.verify_registration(self.user, self.registration()))
        self.assertFalse(result["success"])
        self.assertFalse(WebAuthnCredential.objects.filter(credential_id="new-cred").exists())

    def test_regression_guard_registration_uses_the_session_challenge_and_the_verified_key(self) -> None:
        challenge = WebAuthnService.generate_registration_options(self.request, self.user)["challenge"]
        library = MagicMock()
        library.verify_registration_response.return_value = {
            "verified": True,
            "credential_public_key": b"verified-key",
            "sign_count": 0,
        }
        with patch("apps.users.mfa.webauthn", library):
            result = WebAuthnService.verify_registration_response(self.request, self.registration(), "Key")
        self.assertTrue(result["success"])
        self.assertEqual(library.verify_registration_response.call_args.kwargs["challenge"], challenge)
        stored = WebAuthnCredential.objects.get(credential_id="new-cred")
        self.assertNotEqual(stored.public_key, "unknown")
        self.assertNotEqual(stored.public_key, "client-claimed-key")

    def test_registration_without_a_verified_key_stores_nothing(self) -> None:
        WebAuthnService.generate_registration_options(self.request, self.user)
        library = MagicMock()
        library.verify_registration_response.return_value = {"verified": True}
        with patch("apps.users.mfa.webauthn", library):
            result = WebAuthnService.verify_registration_response(self.request, self.registration(), "Key")
        self.assertFalse(result["success"])
        self.assertFalse(WebAuthnCredential.objects.filter(credential_id="new-cred").exists())

    def test_is_supported_only_with_a_verification_library(self) -> None:
        with patch("apps.users.mfa.webauthn", None):
            self.assertFalse(WebAuthnService.is_supported())
        with patch("apps.users.mfa.webauthn", MagicMock()):
            self.assertTrue(WebAuthnService.is_supported())
