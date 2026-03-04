"""Tests for security linter allowlist matching."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.api.security_linter import OutboundHTTPVisitor


class TestAllowlistMatching(SimpleTestCase):
    """Verify allowlist matches path segments/stem, not substrings."""

    def test_allowlist_rejects_substring_match(self):
        """A file whose name merely *contains* an allowed word must NOT be allowed."""
        visitor = OutboundHTTPVisitor("apps/evil/my_deploy_hack.py")
        self.assertFalse(visitor._is_allowed)

    def test_allowlist_accepts_exact_stem(self):
        """A file whose stem exactly matches an allowed entry must be allowed."""
        visitor = OutboundHTTPVisitor("apps/common/outbound_http.py")
        self.assertTrue(visitor._is_allowed)

    def test_allowlist_accepts_directory_segment(self):
        """A file inside an allowed directory segment must be allowed."""
        visitor = OutboundHTTPVisitor("apps/billing/efactura/client.py")
        self.assertTrue(visitor._is_allowed)

    def test_allowlist_rejects_unrelated_file(self):
        """A completely unrelated file must not be allowed."""
        visitor = OutboundHTTPVisitor("apps/users/views.py")
        self.assertFalse(visitor._is_allowed)
