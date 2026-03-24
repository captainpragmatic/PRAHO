"""
Tests for the humanize_slug template filter.
Covers PR #132 review finding: no test coverage for new filter.
"""

from django.test import TestCase

from apps.ui.templatetags.formatting import humanize_slug


class HumanizeSlugFilterTestCase(TestCase):
    """Test humanize_slug template filter edge cases."""

    def test_underscores_replaced_and_title_cased(self) -> None:
        self.assertEqual(humanize_slug("shared_hosting"), "Shared Hosting")

    def test_hyphens_replaced_and_title_cased(self) -> None:
        self.assertEqual(humanize_slug("vps-managed"), "Vps Managed")

    def test_mixed_separators(self) -> None:
        self.assertEqual(humanize_slug("dedicated_server-v2"), "Dedicated Server V2")

    def test_empty_string(self) -> None:
        self.assertEqual(humanize_slug(""), "")

    def test_none_returns_empty(self) -> None:
        result = humanize_slug(None)  # type-safe: tests runtime None resilience
        self.assertEqual(result, "")

    def test_already_readable(self) -> None:
        self.assertEqual(humanize_slug("Shared Hosting"), "Shared Hosting")

    def test_all_caps_slug(self) -> None:
        self.assertEqual(humanize_slug("VPS_HOSTING"), "Vps Hosting")

    def test_single_word(self) -> None:
        self.assertEqual(humanize_slug("hosting"), "Hosting")
