"""Persistent secrets reject transplantation, legacy ciphertext and plaintext."""

import uuid
from dataclasses import replace
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.billing.efactura.token_storage import OAuthToken
from apps.common.encryption import DecryptionError, EncryptionError, encrypt_sensitive_data, hash_backup_code
from apps.domains.models import Domain, DomainOrderItem, Registrar
from apps.notifications.models import EmailLog
from apps.provisioning.security_utils import SecureTaskParameters
from apps.provisioning.service_models import Server
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.models import SystemSetting
from apps.users.mfa import MFAService
from apps.users.models import User


class PersistentSecretBindingTests(SimpleTestCase):
    def test_queued_secret_parameters_are_bound_to_their_creation_context(self) -> None:
        parameters = SecureTaskParameters.create({"password": "secret"})
        self.assertEqual(parameters.decrypt(), {"password": "secret"})
        changed = replace(parameters, created_at="2000-01-01T00:00:00+00:00")
        with self.assertRaises(ValidationError):
            changed.decrypt()

    def test_ciphertext_cannot_move_between_rows(self) -> None:
        cases = (
            (
                User,
                "_two_factor_secret",
                lambda row: setattr(row, "two_factor_secret", "secret"),
                lambda row: row.two_factor_secret,
            ),
            (
                Registrar,
                "api_key",
                lambda row: row.set_encrypted_credentials(api_key="secret"),
                lambda row: row.get_api_credentials()[1],
            ),
            (
                Domain,
                "epp_code",
                lambda row: row.set_encrypted_epp_code("secret"),
                lambda row: row.get_decrypted_epp_code(),
            ),
            (
                DomainOrderItem,
                "epp_code",
                lambda row: row.set_encrypted_epp_code("secret"),
                lambda row: row.get_decrypted_epp_code(),
            ),
            (
                Server,
                "_api_password_encrypted",
                lambda row: row.set_api_password("secret"),
                lambda row: row.get_api_password(),
            ),
            (
                VirtualminServer,
                "encrypted_api_password",
                lambda row: row.set_api_password("secret"),
                lambda row: row.get_api_password(),
            ),
            (
                VirtualminAccount,
                "encrypted_password",
                lambda row: row.set_password("secret"),
                lambda row: row.get_password(),
            ),
        )
        for model, field, write, read in cases:
            with self.subTest(model=model.__name__):
                original, other = model(), model()
                write(original)
                self.assertEqual(read(original), "secret")
                setattr(other, field, getattr(original, field))
                with self.assertRaises(DecryptionError):
                    read(other)

    def test_totp_rejects_legacy_and_plaintext_without_disabling_mfa(self) -> None:
        for stored in ("secret", encrypt_sensitive_data("secret")):
            with self.subTest(stored=stored[:7]):
                row = User(_two_factor_secret=stored, two_factor_enabled=True)
                with self.assertRaises(DecryptionError):
                    _ = row.two_factor_secret
                self.assertTrue(row.two_factor_enabled)
                self.assertEqual(row._two_factor_secret, stored)

    def test_registrar_keys_are_bound_to_their_field(self) -> None:
        row = Registrar()
        row.set_encrypted_credentials(api_key="key", api_secret="secret")
        row.api_secret = row.api_key
        with self.assertRaises(DecryptionError):
            row.get_decrypted_api_secret()


class PersistentSecretStorageTests(TestCase):
    def test_backup_code_recovers_access_when_totp_ciphertext_is_legacy(self) -> None:
        user = User.objects.create_user(email="recovery@example.com", password="password")
        user.two_factor_enabled = True
        user._two_factor_secret = encrypt_sensitive_data("legacy-secret")
        user.backup_tokens = [hash_backup_code("12345678")]
        user.save()
        result = MFAService.verify_mfa_code(user, "12345678")
        self.assertTrue(result["success"])
        self.assertEqual(result["method"], "backup_code")
        user.refresh_from_db()
        self.assertTrue(user.two_factor_enabled)
        self.assertEqual(user.backup_tokens, [])

    def test_email_encryption_failure_cannot_persist_plaintext(self) -> None:
        before = EmailLog.objects.count()
        with (
            patch("apps.notifications.models.encrypt_model_secret", side_effect=EncryptionError("unavailable")),
            self.assertRaises(EncryptionError),
        ):
            EmailLog.objects.create(to_addr="test@example.com", subject="test", body_text="secret")
        self.assertEqual(EmailLog.objects.count(), before)

    def test_oauth_tokens_reject_cross_field_and_cross_row_copies(self) -> None:
        token = OAuthToken(cui="1", access_token="access", refresh_token="refresh", expires_at=timezone.now())
        token.save()
        self.assertEqual(token.decrypted_access_token, "access")
        token.refresh_token = token.access_token
        with self.assertRaises(DecryptionError):
            _ = token.decrypted_refresh_token
        other = OAuthToken(cui="2", access_token=token.access_token)
        with self.assertRaises(DecryptionError):
            _ = other.decrypted_access_token

    def test_sensitive_settings_reject_plaintext_reads(self) -> None:
        row = SystemSetting(key="test.secret", is_sensitive=True, value="plaintext")
        with self.assertRaises(DecryptionError):
            row.get_typed_value()

    def test_email_bodies_are_bound_to_row_and_field(self) -> None:
        row = EmailLog.objects.create(to_addr="test@example.com", subject="test", body_text="text", body_html="html")
        self.assertEqual(row.get_decrypted_body_text(), "text")
        row.body_html = row.body_text
        with self.assertRaises(DecryptionError):
            row.get_decrypted_body_html()
        other = EmailLog(body_text=row.body_text)
        with self.assertRaises(DecryptionError):
            other.get_decrypted_body_text()

    @skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL context-guard migrations")
    def test_integer_row_context_cannot_be_changed_through_bulk_update(self) -> None:
        user = User.objects.create_user(email="immutable@example.com", password="password")
        original = user.encryption_context_id
        with self.assertRaises(DatabaseError), transaction.atomic():
            User.objects.filter(pk=user.pk).update(encryption_context_id=uuid.uuid4())
        user.refresh_from_db()
        self.assertEqual(user.encryption_context_id, original)

    @skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL context-guard migrations")
    def test_uuid_row_identity_cannot_be_changed_through_bulk_update(self) -> None:
        row = EmailLog.objects.create(to_addr="test@example.com", subject="test", body_text="secret")
        with self.assertRaises(DatabaseError), transaction.atomic():
            EmailLog.objects.filter(pk=row.pk).update(id=uuid.uuid4())
        row.refresh_from_db()
        self.assertEqual(row.get_decrypted_body_text(), "secret")
