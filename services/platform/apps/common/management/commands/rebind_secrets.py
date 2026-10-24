"""Re-bind stored secrets to their natural key (#751 follow-up, M19).

The migrations common 0005 and provisioning 0012 do this once. Run this after a deploy if anything ran the
previous release while they did (a web or worker process left running writes the old formula). It is
idempotent, locks each row through its read and write, and aborts with nothing changed on a secret that
opens under neither formula. Run it with the platform and its workers stopped.
"""

from __future__ import annotations

from typing import Any

from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DEFAULT_DB_ALIAS, transaction
from django.db.utils import DatabaseError

from apps.common.encryption import KeyringDecryptionError
from apps.common.secret_rebind import HostnamePassword, RebindAbortedError, rebind_hostname_passwords, rebind_vault


class Command(BaseCommand):
    help = "Re-bind vault credentials and server API passwords to their natural key (idempotent)."

    def handle(self, *args: Any, **options: Any) -> None:
        alias = DEFAULT_DB_ALIAS
        try:
            with transaction.atomic(using=alias):  # All three or none
                results = self._rebind(alias)
        except (RebindAbortedError, KeyringDecryptionError, DatabaseError) as error:
            raise CommandError(f"Nothing was changed: {error}") from error
        for name, counts in results.items():
            self.stdout.write(f"{name}: {counts}")

    def _rebind(self, alias: str) -> dict[str, Any]:
        return {
            "Vault credentials": rebind_vault(
                apps.get_model("common", "EncryptedCredential"),
                alias,
                getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None),
                lock=True,
            ),
            "Virtualmin server passwords": rebind_hostname_passwords(
                HostnamePassword(
                    apps.get_model("provisioning", "VirtualminServer"),
                    "encrypted_api_password",
                    lambda row: row.pk,
                    binary=True,
                ),
                alias,
                lock=True,
            ),
            "Server passwords": rebind_hostname_passwords(
                HostnamePassword(
                    apps.get_model("provisioning", "Server"),
                    "_api_password_encrypted",
                    lambda row: row.encryption_context_id,
                    binary=False,
                ),
                alias,
                lock=True,
            ),
        }
