"""setup_credential_vault never overwrites a stored credential it cannot read, and counts only what it wrote.

The migration step treated any failed read as "absent": a credential that exists but cannot be read (bound
to another name, or written under another key) was overwritten from the environment without --force, and
every attempt was counted as migrated whether it succeeded or not (#751 follow-up, M19 review).
"""

from __future__ import annotations

import os
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from apps.common.credential_vault import CredentialData, EncryptedCredential, get_credential_vault

ENV = {
    "VIRTUALMIN_USERNAME": "global-user",
    "VIRTUALMIN_PASSWORD": "global-password",
    "VIRTUALMIN_MASTER_USERNAME": None,
    "VIRTUALMIN_MASTER_PASSWORD": None,
    "VIRTUALMIN_SSH_USERNAME": None,
    "VIRTUALMIN_SSH_PASSWORD": None,
}


def _run(*flags: str) -> str:
    out = StringIO()
    call_command("setup_credential_vault", "--migrate-env-vars", *flags, stdout=out)
    return out.getvalue()


def _global() -> EncryptedCredential:
    return EncryptedCredential.objects.get(service_type="virtualmin", service_identifier="global")


@override_settings(**ENV)
class SetupCredentialVaultTests(TestCase):
    def _store_global(self, password: str) -> None:
        get_credential_vault().store_credential(
            CredentialData(service_type="virtualmin", service_identifier="global", username="u", password=password)
        ).unwrap()

    def test_an_unreadable_stored_credential_is_not_overwritten_without_force(self) -> None:
        self._store_global("stored-password")
        EncryptedCredential._base_manager.filter(pk=_global().pk).update(encrypted_password=b"vault:v2:" + os.urandom(40))
        before = bytes(_global().encrypted_password)
        with self.assertRaisesRegex(CommandError, "1 credential"):
            _run()
        self.assertEqual(bytes(_global().encrypted_password), before)

    def test_a_readable_stored_credential_is_left_and_not_counted(self) -> None:
        self._store_global("stored-password")
        self.assertIn("Migrated 0 credentials", _run())
        self.assertEqual(get_credential_vault().get_credential("virtualmin", "global").unwrap()[1], "stored-password")

    def test_a_missing_credential_is_stored_and_counted(self) -> None:
        self.assertIn("Migrated 1 credentials", _run())
        self.assertEqual(get_credential_vault().get_credential("virtualmin", "global").unwrap()[1], "global-password")

    def test_force_replaces_an_unreadable_credential(self) -> None:
        self._store_global("stored-password")
        EncryptedCredential._base_manager.filter(pk=_global().pk).update(encrypted_password=b"vault:v2:" + os.urandom(40))
        self.assertIn("Migrated 1 credentials", _run("--force"))
        self.assertEqual(get_credential_vault().get_credential("virtualmin", "global").unwrap()[1], "global-password")
