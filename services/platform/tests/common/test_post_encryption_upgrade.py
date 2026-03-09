"""Tests for post_encryption_upgrade management command."""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.test import TestCase


class PostEncryptionUpgradeCommandTests(TestCase):
    """Tests for the post_encryption_upgrade management command."""

    def test_report_servers_renders_actual_counts(self) -> None:
        """Prove the VirtualminAccount import works — not the 'Could not check' fallback."""
        out = StringIO()
        call_command("post_encryption_upgrade", stdout=out)
        output = out.getvalue()

        # The _report_servers section should render actual counts
        self.assertIn("Accounts needing password:", output)
        # Must NOT contain the fallback error message
        self.assertNotIn("Could not check", output)

    def test_full_report_completes_without_error(self) -> None:
        """All report sections should render without hitting except fallbacks."""
        out = StringIO()
        call_command("post_encryption_upgrade", stdout=out)
        output = out.getvalue()

        # Verify key sections are present
        self.assertIn("2FA Status:", output)
        self.assertIn("Provisioning Credentials:", output)
        self.assertIn("Sensitive Settings:", output)
        self.assertIn("Report complete.", output)
