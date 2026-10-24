"""Migrations common 0005 / provisioning 0012 and `rebind_secrets` move stored secrets to the natural-key AAD.

Populated rows are written under the previous formula, then the migration functions run against them (with
the app registry, as the migration executor would hand them historical models of the same tables).
"""

from __future__ import annotations

import base64
import os
import threading
import time
from importlib import import_module
from io import StringIO
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, TransactionTestCase

from apps.common.credential_vault import CredentialData, EncryptedCredential, get_credential_vault
from apps.common.encryption import DecryptionError, KeyringDecryptionError, encrypt_sensitive_data
from apps.common.secret_rebind import RebindAbortedError, context_aad
from apps.common.types import Result
from apps.provisioning.service_models import Server
from apps.provisioning.virtualmin_models import VirtualminServer

VAULT_MIGRATION = import_module("apps.common.migrations.0005_bind_credential_natural_key")
SERVER_MIGRATION = import_module("apps.provisioning.migrations.0012_bind_server_hostname")
EDITOR = SimpleNamespace(connection=connection)


def _vault_cipher() -> AESGCM:
    return AESGCM(base64.urlsafe_b64decode(settings.CREDENTIAL_VAULT_MASTER_KEY))


def _old_vault_value(row: EncryptedCredential, field: str, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    aad = context_aad("common_credentials", field, str(row.pk))
    return b"vault:v2:" + nonce + _vault_cipher().encrypt(nonce, plaintext, aad)


def _credential(identifier: str, password: str) -> EncryptedCredential:
    get_credential_vault().store_credential(
        CredentialData(service_type="virtualmin", service_identifier=identifier, username="user", password=password)
    ).unwrap()
    row = EncryptedCredential.objects.get(service_identifier=identifier)
    EncryptedCredential._base_manager.filter(pk=row.pk).update(
        encrypted_username=_old_vault_value(row, "encrypted_username", b"user"),
        encrypted_password=_old_vault_value(row, "encrypted_password", password.encode()),
    )
    return EncryptedCredential.objects.get(pk=row.pk)


def _read(identifier: str) -> Result[tuple[str, str, dict[str, Any] | None], str]:
    return get_credential_vault().get_credential("virtualmin", identifier, user=None, reason="test")


class VaultMigrationTests(TestCase):
    def test_forward_binds_old_rows_and_backward_restores_the_old_formula(self) -> None:
        _credential("node.example.com", "secret-1")
        self.assertTrue(_read("node.example.com").is_err(), "under the old formula the new code refuses")
        VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        self.assertEqual(_read("node.example.com").unwrap()[1], "secret-1")
        VAULT_MIGRATION.unbind_natural_key(apps, EDITOR)
        row = EncryptedCredential.objects.get(service_identifier="node.example.com")
        body = bytes(row.encrypted_password)[len(b"vault:v2:") :]
        aad = context_aad("common_credentials", "encrypted_password", str(row.pk))
        self.assertEqual(_vault_cipher().decrypt(body[:12], body[12:], aad), b"secret-1")

    def test_a_second_run_changes_nothing(self) -> None:
        _credential("node.example.com", "secret-1")
        VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        before = bytes(EncryptedCredential.objects.get(service_identifier="node.example.com").encrypted_password)
        VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        after = bytes(EncryptedCredential.objects.get(service_identifier="node.example.com").encrypted_password)
        self.assertEqual(before, after)

    def test_a_wrong_master_key_aborts_with_nothing_changed(self) -> None:
        row = _credential("node.example.com", "secret-1")
        before = bytes(row.encrypted_password)
        wrong = base64.urlsafe_b64encode(os.urandom(32)).decode()
        with self.settings(CREDENTIAL_VAULT_MASTER_KEY=wrong), self.assertRaises(RebindAbortedError):
            VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        self.assertEqual(bytes(EncryptedCredential.objects.get(pk=row.pk).encrypted_password), before)

    def test_a_failure_after_an_earlier_row_rolls_the_earlier_row_back(self) -> None:
        first = _credential("a.example.com", "secret-a")
        second = _credential("b.example.com", "secret-b")
        ordered = sorted((first, second), key=lambda row: str(row.pk))
        good, bad = ordered[0], ordered[1]
        good_before = bytes(good.encrypted_password)
        EncryptedCredential._base_manager.filter(pk=bad.pk).update(encrypted_password=b"vault:v2:" + os.urandom(40))
        with self.assertRaises(RebindAbortedError):
            VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        self.assertEqual(bytes(EncryptedCredential.objects.get(pk=good.pk).encrypted_password), good_before)

    def test_a_superseded_value_is_skipped_and_counted(self) -> None:
        row = _credential("node.example.com", "secret-1")
        EncryptedCredential._base_manager.filter(pk=row.pk).update(encrypted_password=b"x" * 40)
        with self.assertLogs("apps.common.migrations.0005_bind_credential_natural_key", "WARNING") as logs:
            VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
        self.assertIn("1 credential values are in a superseded format", logs.output[0])
        self.assertEqual(bytes(EncryptedCredential.objects.get(pk=row.pk).encrypted_password), b"x" * 40)

    def test_an_empty_vault_needs_no_key(self) -> None:
        with self.settings(CREDENTIAL_VAULT_MASTER_KEY=""):
            VAULT_MIGRATION.bind_natural_key(apps, EDITOR)


def _old_server_password(server: VirtualminServer, password: str) -> None:
    aad = context_aad("provisioning_virtualmin_servers", "encrypted_api_password", str(server.pk))
    VirtualminServer._base_manager.filter(pk=server.pk).update(
        encrypted_api_password=encrypt_sensitive_data(password, aad=aad).encode()
    )


class ServerMigrationTests(TestCase):
    def setUp(self) -> None:
        self.server = VirtualminServer.objects.create(name="n", hostname="node.example.com", api_username="acl")
        _old_server_password(self.server, "P1")
        self.host = Server.objects.create(
            name="Host", hostname="host.example.com", server_type="shared", primary_ip="192.0.2.10",
            location="Bucharest", datacenter="DC1", cpu_model="x", cpu_cores=2, ram_gb=4, disk_type="ssd",
            disk_capacity_gb=50, os_type="linux",
        )
        aad = context_aad("provisioning_servers", "_api_password_encrypted", str(self.host.encryption_context_id))
        Server._base_manager.filter(pk=self.host.pk).update(_api_password_encrypted=encrypt_sensitive_data("S1", aad=aad))

    def test_forward_binds_both_models_and_backward_restores_them(self) -> None:
        SERVER_MIGRATION.bind_hostname(apps, EDITOR)
        self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).get_api_password(), "P1")
        self.assertEqual(Server.objects.get(pk=self.host.pk).get_api_password(), "S1")
        SERVER_MIGRATION.unbind_hostname(apps, EDITOR)
        with self.assertRaises(DecryptionError):  # The old formula again: the new code refuses it
            VirtualminServer.objects.get(pk=self.server.pk).get_api_password()
        SERVER_MIGRATION.bind_hostname(apps, EDITOR)
        self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).get_api_password(), "P1")

    def test_another_rows_ciphertext_aborts_with_nothing_changed(self) -> None:
        other = VirtualminServer.objects.create(name="o", hostname="other.example.com", api_username="acl")
        _old_server_password(other, "P2")
        VirtualminServer._base_manager.filter(pk=self.server.pk).update(
            encrypted_api_password=bytes(VirtualminServer.objects.get(pk=other.pk).encrypted_api_password)
        )
        with self.assertRaises(RebindAbortedError):
            SERVER_MIGRATION.bind_hostname(apps, EDITOR)
        with self.assertRaises(DecryptionError):  # Unchanged: still the old formula
            Server.objects.get(pk=self.host.pk).get_api_password()

    def test_a_keyring_without_the_key_raises_instead_of_skipping(self) -> None:
        other_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        keys = patch("apps.common.encryption.get_encryption_keys", return_value=[base64.urlsafe_b64decode(other_key)])
        with keys, self.assertRaises(KeyringDecryptionError):
            SERVER_MIGRATION.bind_hostname(apps, EDITOR)


class RebindCommandTests(TestCase):
    def test_the_command_rebinds_and_reports(self) -> None:
        _credential("node.example.com", "secret-1")
        out = StringIO()
        call_command("rebind_secrets", stdout=out)
        self.assertIn("Vault credentials: 2 re-bound", out.getvalue())  # Its username and its password
        self.assertEqual(_read("node.example.com").unwrap()[1], "secret-1")

    def test_a_failure_in_a_later_table_changes_nothing_anywhere(self) -> None:
        row = _credential("node.example.com", "secret-1")
        before = bytes(row.encrypted_password)
        server = VirtualminServer.objects.create(name="n", hostname="node.example.com", api_username="acl")
        VirtualminServer._base_manager.filter(pk=server.pk).update(
            encrypted_api_password=encrypt_sensitive_data("x", aad=b"another-context").encode()
        )
        with self.assertRaisesRegex(CommandError, "Nothing was changed"):
            call_command("rebind_secrets", stdout=StringIO())
        self.assertEqual(bytes(EncryptedCredential.objects.get(pk=row.pk).encrypted_password), before)


class MigrationLockTests(TransactionTestCase):
    """A credential stored while the migration re-binds its row is not overwritten by the migration's copy."""

    def test_a_rotation_during_the_migration_keeps_the_new_secret(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        _credential("node.example.com", "old-secret")
        rebound, resume = threading.Event(), threading.Event()
        rebind = import_module("apps.common.secret_rebind").rebind_vault_value
        errors: list[BaseException] = []

        def pause_after_reading(*args: Any, **kwargs: Any) -> Any:
            value = rebind(*args, **kwargs)
            if not rebound.is_set():
                rebound.set()
                resume.wait(10)
            return value

        def migrate() -> None:
            try:
                with patch("apps.common.secret_rebind.rebind_vault_value", side_effect=pause_after_reading):
                    VAULT_MIGRATION.bind_natural_key(apps, EDITOR)
            except BaseException as error:  # Surfaced below
                errors.append(error)
            finally:
                connection.close()

        def rotate() -> None:
            try:
                get_credential_vault().store_credential(
                    CredentialData(
                        service_type="virtualmin", service_identifier="node.example.com",
                        username="user", password="new-secret",
                    )
                ).unwrap()
            except BaseException as error:
                errors.append(error)
            finally:
                connection.close()

        migration = threading.Thread(target=migrate)
        migration.start()
        self.assertTrue(rebound.wait(10))
        # Deterministic: while the migration holds the row, another connection cannot take it
        with self.assertRaises(DatabaseError), transaction.atomic():
            EncryptedCredential.objects.select_for_update(nowait=True).filter(service_identifier="node.example.com").first()
        rotation = threading.Thread(target=rotate)
        rotation.start()
        time.sleep(0.5)  # Unlocked, the rotation commits here, before the migration writes its copy
        resume.set()
        migration.join(10)
        rotation.join(10)

        self.assertFalse(migration.is_alive() or rotation.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(_read("node.example.com").unwrap()[1], "new-secret")
