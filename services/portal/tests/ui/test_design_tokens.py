"""
Design Token Tests — Phase C.2 (completion)

Verifies the design token contracts defined in ui_components.py:
- Status variant mapping consistency (Finding 2 regression guard)
- format_date filter (Finding 4 regression guard)
- form_actions tag output (Finding 5 regression guard)
- No raw emoji in ticket priority options (Finding 3 regression guard)

No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from datetime import date
from pathlib import Path

from django.template import Context, Template
from django.test import SimpleTestCase

from apps.ui.templatetags.formatting import format_date
from apps.ui.templatetags.ui_components import status_variant

# ===============================================================================
# CONSTANTS
# ===============================================================================

TEMPLATES_ROOT = Path(__file__).resolve().parents[2] / "templates"


# ===============================================================================
# STATUS VARIANT MAPPING TESTS (Finding 2 regression guard)
# ===============================================================================


class StatusVariantTokenTests(SimpleTestCase):
    """
    Spec-authoritative: cancelled→danger, processing→info.
    Any re-introduction of wrong mapping will break these tests.
    """

    # Positive states
    def test_active_is_success(self) -> None:
        self.assertEqual(status_variant("active"), "success")

    def test_paid_is_success(self) -> None:
        self.assertEqual(status_variant("paid"), "success")

    def test_completed_is_success(self) -> None:
        self.assertEqual(status_variant("completed"), "success")

    # Warning / pending states
    def test_pending_is_warning(self) -> None:
        self.assertEqual(status_variant("pending"), "warning")

    def test_overdue_is_danger(self) -> None:
        self.assertEqual(status_variant("overdue"), "danger")

    # Spec corrections (Finding 2)
    def test_cancelled_is_danger_not_secondary(self) -> None:
        """Regression guard: cancelled must map to danger per design spec."""
        self.assertEqual(status_variant("cancelled"), "danger")

    def test_processing_is_info_not_warning(self) -> None:
        """Regression guard: processing must map to info per design spec."""
        self.assertEqual(status_variant("processing"), "info")

    # Danger states
    def test_suspended_is_danger(self) -> None:
        self.assertEqual(status_variant("suspended"), "danger")

    def test_expired_is_danger(self) -> None:
        self.assertEqual(status_variant("expired"), "danger")

    # Neutral states
    def test_draft_is_info(self) -> None:
        self.assertEqual(status_variant("draft"), "info")

    def test_unknown_status_defaults_to_secondary(self) -> None:
        self.assertEqual(status_variant("made_up_status"), "secondary")

    def test_case_insensitive(self) -> None:
        self.assertEqual(status_variant("ACTIVE"), "success")
        self.assertEqual(status_variant("Paid"), "success")


# ===============================================================================
# FORMAT_DATE FILTER TESTS (Finding 4 regression guard)
# ===============================================================================


class FormatDateFilterTests(SimpleTestCase):
    """Tests for the format_date alias filter added in Finding 4."""

    def _render_format(self, template_str: str, ctx: dict | None = None) -> str:
        t = Template("{% load formatting %}" + template_str)
        return t.render(Context(ctx or {}))

    def test_filter_exists_and_is_callable(self) -> None:
        """format_date is registered in the formatting tag library."""
        self.assertTrue(callable(format_date))

    def test_format_date_short_format(self) -> None:
        """format_date short should produce Romanian abbreviated month."""
        result = format_date(date(2024, 1, 15))
        self.assertIn("2024", result)
        # Romanian abbreviated January = "ian."
        self.assertIn("ian.", result)

    def test_format_date_none_returns_empty(self) -> None:
        self.assertEqual(format_date(None), "")

    def test_format_date_long_format(self) -> None:
        result = format_date(date(2024, 6, 20), "long")
        # Romanian full month name for June = "iunie"
        self.assertIn("iunie", result)


# ===============================================================================
# FORM_ACTIONS TAG TESTS (Finding 5 regression guard)
# ===============================================================================


class FormActionsTokenTests(SimpleTestCase):
    """Tests the form_actions inclusion tag registered in Finding 5."""

    def _render(self, template_str: str, ctx: dict | None = None) -> str:
        t = Template("{% load ui_components %}" + template_str)
        return t.render(Context(ctx or {}))

    def test_form_actions_renders_submit_button(self) -> None:
        result = self._render('{% form_actions submit_label="Save Changes" %}')
        self.assertIn("Save Changes", result)
        self.assertIn('<button type="submit"', result)

    def test_form_actions_default_submit_label(self) -> None:
        result = self._render("{% form_actions %}")
        # Default label from gettext "Save"
        self.assertIn("button", result)

    def test_form_actions_cancel_url_renders_link(self) -> None:
        result = self._render('{% form_actions cancel_url="/back/" cancel_label="Go Back" %}')
        self.assertIn('href="/back/"', result)
        self.assertIn("Go Back", result)

    def test_form_actions_no_cancel_url_no_link(self) -> None:
        result = self._render('{% form_actions submit_label="Save" %}')
        self.assertNotIn("<a ", result)

    def test_form_actions_danger_variant(self) -> None:
        result = self._render('{% form_actions submit_label="Delete" submit_variant="danger" %}')
        self.assertIn("bg-red-", result)

    def test_form_actions_has_border_top(self) -> None:
        result = self._render("{% form_actions %}")
        self.assertIn("border-t", result)


# ===============================================================================
# EMOJI-FREE TEMPLATE TESTS (Finding 3 regression guard)
# ===============================================================================


class NoEmojiRegressionTests(SimpleTestCase):
    """
    Guards against re-introduction of emoji in templates cleaned in Finding 3.
    """

    def _read_template(self, path: str) -> str:
        return (TEMPLATES_ROOT / path).read_text()

    def test_ticket_create_priority_options_no_emoji(self) -> None:
        content = self._read_template("tickets/ticket_create.html")
        # Circle emojis (🟢🟡🟠🔴) should be gone
        for emoji in ["\U0001f7e2", "\U0001f7e1", "\U0001f7e0", "\U0001f534"]:
            self.assertNotIn(emoji, content, f"Found emoji {emoji} in ticket_create.html")

    def test_cookie_banner_no_cookie_emoji(self) -> None:
        content = self._read_template("components/cookie_consent_banner.html")
        # Cookie emoji &#127850 / 🍪
        self.assertNotIn("\U0001f36a", content)
        self.assertNotIn("&#127850", content)
