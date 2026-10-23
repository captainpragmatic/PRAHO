"""e-Factura OAuth tokens are sealed for their own row and field, or refused (#751 follow-up, secret hooks).

The token save hook encrypted a token only when it did not start with "aes:", so a value that only looked
like ciphertext was stored as is. A token is now kept only if it decrypts for this row and field, and a
replacement that is refused leaves the tokens it would have replaced active.
"""

from __future__ import annotations

from django.test import TestCase

from apps.billing.efactura.token_storage import OAuthToken
from apps.common.encryption import EncryptionError

CUI = "RO12345678"


class TokenSealTests(TestCase):
    def test_a_token_that_only_looks_like_ciphertext_is_refused(self) -> None:
        for field in ("access_token", "refresh_token"):
            for value in ("aes:v1:superseded", "aes:v2:not-ciphertext"):
                with self.subTest(field=field, value=value), self.assertRaises(EncryptionError):
                    OAuthToken.store_token(CUI, **{"access_token": "at", "expires_in": 3600, field: value})

    def test_a_refused_replacement_leaves_the_current_token_active(self) -> None:
        current = OAuthToken.store_token(CUI, access_token="working-token", expires_in=3600)

        with self.assertRaises(EncryptionError):
            OAuthToken.store_token(CUI, access_token="aes:v2:not-ciphertext", expires_in=3600)

        current.refresh_from_db()
        self.assertTrue(current.is_active, "the working token is still the one in use")

    def test_a_status_write_on_a_token_holding_an_unreadable_value_succeeds(self) -> None:
        token = OAuthToken.store_token(CUI, access_token="working-token", expires_in=3600)
        OAuthToken.objects.filter(pk=token.pk).update(access_token="aes:v1:superseded")
        token.refresh_from_db()

        token.mark_used()
        token.deactivate()

        self.assertFalse(OAuthToken.objects.get(pk=token.pk).is_active)
