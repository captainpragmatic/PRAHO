"""A create-only store never replaces a stored secret (used for the account-name certificate keys)."""

from __future__ import annotations

from django.test import TestCase

from apps.common.credential_vault import CredentialData, get_credential_vault


def _data(secret: str, *, create_only: bool) -> CredentialData:
    return CredentialData(
        service_type="acme_certificate_key",
        service_identifier="h7k3p2q8.praho-sites.net@attempt",
        username="acme",
        password=secret,
        user=None,
        reason="test",
        create_only=create_only,
    )


class CreateOnlyStoreTests(TestCase):
    def test_a_second_create_only_store_fails_and_the_first_secret_stands(self) -> None:
        vault = get_credential_vault()
        self.assertTrue(vault.store_credential(_data("first", create_only=True)).is_ok())

        second = vault.store_credential(_data("second", create_only=True))

        self.assertTrue(second.is_err())
        read = vault.get_credential("acme_certificate_key", "h7k3p2q8.praho-sites.net@attempt", user=None, reason="t")
        self.assertEqual(read.unwrap()[1], "first")

    def test_an_ordinary_store_still_updates(self) -> None:
        vault = get_credential_vault()
        vault.store_credential(_data("first", create_only=False)).unwrap()
        vault.store_credential(_data("second", create_only=False)).unwrap()

        read = vault.get_credential("acme_certificate_key", "h7k3p2q8.praho-sites.net@attempt", user=None, reason="t")
        self.assertEqual(read.unwrap()[1], "second")
