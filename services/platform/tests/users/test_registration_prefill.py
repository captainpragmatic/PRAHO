"""Registration links that open with a company's details filled in (apps.users.registration_prefill).

The token is AES-256-GCM on the existing keyring, bound to this purpose and valid for 7 days, so
it reveals nothing of what it carries, and anything but an intact, unexpired prefill token minted
here yields nothing. The portal only forwards it.
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.common.encryption import encrypt_sensitive_data
from apps.users.registration_prefill import (
    MAX_TOKEN_LENGTH,
    PREFILL_AAD,
    PREFILL_LIFETIME,
    mint_registration_prefill,
    read_registration_prefill,
)
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

FIELDS = {"email": "ana@quill.example", "company_name": "Quill Lantern SRL", "cui": "14399840"}
INTENT = {"product": "web-hosting", "period": "annual"}


def flip_last_character(token: str) -> str:
    prefix, _, body = token.rpartition(":")
    raw = bytearray(base64.urlsafe_b64decode(body))
    raw[-1] ^= 1
    return f"{prefix}:{base64.urlsafe_b64encode(bytes(raw)).decode()}"


class RegistrationPrefillTests(TestCase):
    def test_token_is_opaque_and_tampered_expired_oversized_or_unknown_fields_yield_nothing(self) -> None:
        token = mint_registration_prefill(FIELDS, {**INTENT, "is_staff": "1"})
        for secret in ("ana@quill", "Quill Lantern", "14399840", "web-hosting"):
            self.assertNotIn(secret, token)
            self.assertNotIn(secret, base64.urlsafe_b64decode(token.rpartition(":")[2] + "==").decode("latin-1"))
        self.assertEqual(read_registration_prefill(token), {"fields": FIELDS, "intent": INTENT})

        expired_at = time.time() + PREFILL_LIFETIME.total_seconds() + 1
        other_purpose = encrypt_sensitive_data(json.dumps({"exp": int(expired_at), "fields": FIELDS, "intent": {}}))
        unknown_field = encrypt_sensitive_data(
            json.dumps({"exp": int(expired_at), "fields": {**FIELDS, "is_staff": "1"}, "intent": {}}), aad=PREFILL_AAD
        )
        with patch("apps.users.registration_prefill.time.time", return_value=expired_at):
            expired = read_registration_prefill(token)
        for name, result in {
            "tampered": read_registration_prefill(flip_last_character(token)),
            "expired": expired,
            "oversized": read_registration_prefill("aes:v2:" + "A" * MAX_TOKEN_LENGTH),
            "another purpose": read_registration_prefill(other_purpose),
            "unknown field": read_registration_prefill(unknown_field),
            "not a token": read_registration_prefill("hello"),
        }.items():
            with self.subTest(name):
                self.assertEqual(result, {})

    def test_minting_refuses_a_field_a_link_cannot_fill(self) -> None:
        for fields in ({"is_staff": "1"}, {"cui": "1" * 21}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                mint_registration_prefill(fields)


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class RegistrationPrefillAPITests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_the_portal_forwards_the_token_and_gets_the_details(self) -> None:
        token = mint_registration_prefill(FIELDS, INTENT)
        response = self.portal_post("/api/users/register/prefill/", {"token": token})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json(), {"success": True, "prefill": {"fields": FIELDS, "intent": INTENT}})
        response = self.portal_post("/api/users/register/prefill/", {"token": flip_last_character(token)})
        self.assertEqual(response.json(), {"success": True, "prefill": {}})

    @override_settings(PORTAL_DOMAIN="portal.example.test")
    def test_staff_mint_a_link_on_the_portal(self) -> None:
        from io import StringIO  # noqa: PLC0415

        out = StringIO()
        call_command(
            "mint_registration_link",
            "--email=ana@quill.example",
            "--company-name=Quill Lantern SRL",
            "--cui=14399840",
            "--product=web-hosting",
            "--period=annual",
            stdout=out,
        )
        link = urlsplit(out.getvalue().strip().splitlines()[-1])
        self.assertEqual((link.scheme, link.netloc, link.path), ("https", "portal.example.test", "/register/"))
        prefill = read_registration_prefill(parse_qs(link.query)["p"][0])
        self.assertEqual(prefill, {"fields": FIELDS, "intent": INTENT})
