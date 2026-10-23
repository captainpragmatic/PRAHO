"""Rotating a vault credential whose stored username no key can read (#751 follow-up, secret consumers).

A rotation with no new username reuses the stored one. When that one is stored under a superseded format
it cannot be read: the rotation failed with a generic error and counted against the credential, and the
fix, a rotation with a new username, was never named. A failed rotation also saved the whole row it had
loaded, writing its old ciphertext back over a value the store path wrote meanwhile.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.credential_vault import CredentialData, CredentialVault, EncryptedCredential, RotationData
from apps.common.types import Err, Ok

SERVICE = {"service_type": "virtualmin", "service_identifier": "node.example.com"}


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class LegacyRotationTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.vault = CredentialVault()
        self.assertTrue(self.vault.store_credential(CredentialData(**SERVICE, username="api-user", password="old")).is_ok())
        self.row = EncryptedCredential.objects.get(**SERVICE, is_active=True)
        probe = patch.object(CredentialVault, "_test_credential", return_value=Ok(True))
        probe.start()
        self.addCleanup(probe.stop)

    def _make_username_unreadable(self) -> None:
        EncryptedCredential.objects.filter(pk=self.row.pk).update(encrypted_username=b"superseded-format-0123456789abcdef")

    def _stored(self) -> tuple[str, str]:
        username, password, _metadata = self.vault.get_credential(**SERVICE).unwrap()
        return username, password

    def test_an_unreadable_username_asks_for_a_new_one_and_counts_no_failure(self) -> None:
        self._make_username_unreadable()

        result = self.vault.rotate_credential(RotationData(**SERVICE))

        self.assertTrue(result.is_err())
        self.assertIn("new username", result.unwrap_err(), "the operator is told what to provide")
        row = EncryptedCredential.objects.get(pk=self.row.pk)
        self.assertEqual((row.rotation_in_progress, row.rotation_failure_count), (False, 0))

    def test_a_rotation_with_a_new_username_heals_the_row(self) -> None:
        self._make_username_unreadable()

        result = self.vault.rotate_credential(RotationData(**SERVICE, new_username="api-user-2", new_password="new"))

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(self._stored(), ("api-user-2", "new"))

    def test_a_failed_rotation_never_writes_back_the_values_it_loaded(self) -> None:
        def stored_meanwhile_then_refused(*args: object) -> object:
            self.vault.store_credential(CredentialData(**SERVICE, username="stored-meanwhile", password="current"))
            return Err("refused")

        with patch.object(CredentialVault, "_test_credential", side_effect=stored_meanwhile_then_refused):
            self.vault.rotate_credential(RotationData(**SERVICE, new_username="api-user-2", new_password="new"))

        self.assertEqual(self._stored(), ("stored-meanwhile", "current"), "the store path's write stands")
