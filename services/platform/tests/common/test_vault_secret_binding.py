"""Vault ciphertext is authenticated against its owning row and field."""

from django.test import TestCase

from apps.common.credential_vault import CredentialData, EncryptedCredential, get_credential_vault


class VaultSecretBindingTests(TestCase):
    def store(self, name: str) -> EncryptedCredential:
        get_credential_vault().store_credential(
            CredentialData(service_type="virtualmin", service_identifier=name, username="user", password="password")
        ).unwrap()
        return EncryptedCredential.objects.get(service_type="virtualmin", service_identifier=name)

    def test_swapped_password_is_refused(self) -> None:
        original, other = self.store("original"), self.store("other")
        EncryptedCredential.objects.filter(pk=other.pk).update(encrypted_password=original.encrypted_password)
        result = get_credential_vault().get_credential("virtualmin", "other", user=None, reason="test")
        self.assertTrue(result.is_err())

    def test_username_cannot_be_used_as_password(self) -> None:
        row = self.store("original")
        EncryptedCredential.objects.filter(pk=row.pk).update(encrypted_password=row.encrypted_username)
        result = get_credential_vault().get_credential("virtualmin", "original", user=None, reason="test")
        self.assertTrue(result.is_err())

    def test_legacy_unbound_ciphertext_is_refused(self) -> None:
        row = self.store("legacy")
        unbound = get_credential_vault()._encrypt_data(b"old-password")
        EncryptedCredential.objects.filter(pk=row.pk).update(encrypted_password=unbound)
        result = get_credential_vault().get_credential("virtualmin", "legacy", user=None, reason="test")
        self.assertTrue(result.is_err())
