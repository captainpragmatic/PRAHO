"""
Tests for the ensure_superuser management command.
"""

import os
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

User = get_user_model()


class EnsureSuperuserTestCase(TestCase):
    """Tests for idempotent superuser creation from env vars."""

    def test_creates_superuser_from_env_vars(self) -> None:
        """With both env vars set and no existing superuser, creates one."""
        out = StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_EMAIL": "boss@example.com", "DJANGO_SUPERUSER_PASSWORD": "strongpass123!"},
        ):
            call_command("ensure_superuser", stdout=out)

        self.assertTrue(User.objects.filter(email="boss@example.com", is_superuser=True).exists())
        self.assertIn("Superuser created", out.getvalue())

    def test_skips_when_superuser_exists(self) -> None:
        """If a superuser already exists, does not create another."""
        User.objects.create_superuser(email="existing@example.com", password="existingpass123!")
        out = StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_EMAIL": "new@example.com", "DJANGO_SUPERUSER_PASSWORD": "newpass123!"},
        ):
            call_command("ensure_superuser", stdout=out)

        self.assertFalse(User.objects.filter(email="new@example.com").exists())
        self.assertIn("already exists", out.getvalue())

    def test_skips_when_env_vars_missing(self) -> None:
        """Without env vars, prints hint and creates nothing."""
        out = StringIO()
        with patch.dict("os.environ", {}, clear=True):
            os.environ.pop("DJANGO_SUPERUSER_EMAIL", None)
            os.environ.pop("DJANGO_SUPERUSER_PASSWORD", None)
            call_command("ensure_superuser", stdout=out)

        self.assertEqual(User.objects.filter(is_superuser=True).count(), 0)
        self.assertIn("Hint", out.getvalue())

    @override_settings(DEBUG=False)
    def test_rejects_weak_password_in_prod(self) -> None:
        """In non-DEBUG mode, rejects common passwords (even if long enough)."""
        with (
            patch.dict(
                "os.environ",
                {"DJANGO_SUPERUSER_EMAIL": "admin@example.com", "DJANGO_SUPERUSER_PASSWORD": "password1234"},
            ),
            self.assertRaises(CommandError) as ctx,
        ):
            call_command("ensure_superuser")

        self.assertFalse(User.objects.filter(email="admin@example.com").exists())
        self.assertIn("deny list", str(ctx.exception))

    @override_settings(DEBUG=False)
    def test_rejects_short_password_in_prod(self) -> None:
        """In non-DEBUG mode, rejects passwords under 12 chars."""
        with (
            patch.dict(
                "os.environ",
                {"DJANGO_SUPERUSER_EMAIL": "admin@example.com", "DJANGO_SUPERUSER_PASSWORD": "short"},
            ),
            self.assertRaises(CommandError) as ctx,
        ):
            call_command("ensure_superuser")

        self.assertFalse(User.objects.filter(email="admin@example.com").exists())
        self.assertIn("12 characters", str(ctx.exception))

    @override_settings(DEBUG=True)
    def test_allows_weak_password_in_dev(self) -> None:
        """In DEBUG mode, weak passwords are allowed for convenience."""
        out = StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_EMAIL": "dev@example.com", "DJANGO_SUPERUSER_PASSWORD": "admin123"},
        ):
            call_command("ensure_superuser", stdout=out)

        self.assertTrue(User.objects.filter(email="dev@example.com", is_superuser=True).exists())

    def test_force_flag_creates_additional_superuser(self) -> None:
        """--force bypasses the 'already exists' check."""
        User.objects.create_superuser(email="first@example.com", password="firstpass123!")
        out = StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_EMAIL": "second@example.com", "DJANGO_SUPERUSER_PASSWORD": "secondpass123!"},
        ):
            call_command("ensure_superuser", force=True, stdout=out)

        self.assertTrue(User.objects.filter(email="second@example.com", is_superuser=True).exists())
        self.assertEqual(User.objects.filter(is_superuser=True).count(), 2)

    def test_skips_duplicate_email(self) -> None:
        """If a user with that email already exists (even non-superuser), skips."""
        User.objects.create_user(email="taken@example.com", password="somepass123!")
        out = StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_EMAIL": "taken@example.com", "DJANGO_SUPERUSER_PASSWORD": "newpass123!"},
        ):
            call_command("ensure_superuser", stdout=out)

        self.assertIn("already exists", out.getvalue())
