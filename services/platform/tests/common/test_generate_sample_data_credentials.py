"""
Tests for generate_sample_data's dev credential enforcement.

Locks in the durable fix for the "printed credentials table advertises a stale password"
bug: the seeder now force-resets every advertised dev account's password from a single
source of truth (DEV_USER_CREDENTIALS), so an existing row whose password has drifted is
corrected on every run instead of being silently skipped by a create-only guard.
"""

from io import StringIO

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.common.management.commands.generate_sample_data import (
    DEV_USER_CREDENTIALS,
    Command,
)

User = get_user_model()


class EnsureCredentialPasswordsTests(TestCase):
    """The central password-enforcement loop keeps the advertised table honest."""

    def test_refreshes_stale_admin_password(self) -> None:
        """Reproduces the reported bug: an existing admin with a drifted password.

        This is the reversion lock-in — it fails if _ensure_credential_passwords is removed
        or stops resetting an already-existing row.
        """
        User.objects.create_superuser(
            first_name="Admin",
            last_name="PRAHO",
            email="admin@pragmatichost.com",
            password="stale-wrong-password",
        )

        command = Command(stdout=StringIO())
        command._ensure_credential_passwords()

        admin = User.objects.get(email="admin@pragmatichost.com")
        self.assertTrue(admin.check_password("admin123"))
        self.assertFalse(admin.check_password("stale-wrong-password"))

    def test_every_advertised_credential_authenticates(self) -> None:
        """After the reset, every advertised account matches its table password."""
        for _label, email, _password in DEV_USER_CREDENTIALS:
            User.objects.create_user(email=email, password="wrong-seed-password")

        command = Command(stdout=StringIO())
        command._ensure_credential_passwords()

        for _label, email, password in DEV_USER_CREDENTIALS:
            user = User.objects.get(email=email)
            self.assertTrue(
                user.check_password(password),
                msg=f"{email} does not authenticate with its advertised password",
            )

    def test_missing_account_is_skipped_not_created(self) -> None:
        """Advertised accounts absent from the DB are skipped, never created."""
        command = Command(stdout=StringIO())
        command._ensure_credential_passwords()

        self.assertEqual(User.objects.count(), 0)

    def test_print_credentials_lists_source_of_truth(self) -> None:
        """The printed table is data-driven: every SoT email + password appears verbatim."""
        out = StringIO()
        command = Command(stdout=out)
        command._print_credentials()

        text = out.getvalue()
        for _label, email, password in DEV_USER_CREDENTIALS:
            self.assertIn(email, text)
            self.assertIn(password, text)
