"""
Badge Component Tests — Phase C.2

Tests for the {% badge %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies text rendering, variant CSS classes, size classes, icon integration,
dismissible button, and roundedness. No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from django.template import Context, Template
from django.test import SimpleTestCase


def _render(template_str: str, context: dict | None = None) -> str:
    """Render a template string using Django's template system."""
    t = Template("{% load ui_components %}" + template_str)
    return t.render(Context(context or {}))


# ===============================================================================
# TEXT RENDERING TESTS
# ===============================================================================


class BadgeTextTests(SimpleTestCase):
    """Tests that the badge text is rendered correctly."""

    def test_text_appears_in_output(self) -> None:
        result = _render('{% badge "Active" %}')
        self.assertIn("Active", result)

    def test_variable_text_interpolated(self) -> None:
        result = _render("{% badge status_text %}", {"status_text": "Pending"})
        self.assertIn("Pending", result)

    def test_empty_text_renders_span(self) -> None:
        result = _render('{% badge "" %}')
        self.assertIn("<span", result)

    def test_text_with_special_html_chars_escaped(self) -> None:
        """Badge text should be auto-escaped by Django's template engine."""
        result = _render('{% badge label %}', {"label": "<script>xss</script>"})
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)


# ===============================================================================
# VARIANT CSS TESTS
# ===============================================================================


class BadgeVariantTests(SimpleTestCase):
    """Tests that each variant maps to the expected Tailwind CSS classes."""

    def _badge_with_variant(self, variant: str) -> str:
        return _render(f'{{% badge "Test" variant="{variant}" %}}')

    def test_success_variant_uses_green_classes(self) -> None:
        self.assertIn("bg-green-100", self._badge_with_variant("success"))

    def test_warning_variant_uses_yellow_classes(self) -> None:
        self.assertIn("bg-yellow-100", self._badge_with_variant("warning"))

    def test_danger_variant_uses_red_classes(self) -> None:
        self.assertIn("bg-red-100", self._badge_with_variant("danger"))

    def test_primary_variant_uses_blue_classes(self) -> None:
        self.assertIn("bg-blue-100", self._badge_with_variant("primary"))

    def test_secondary_variant_uses_slate_classes(self) -> None:
        self.assertIn("bg-slate-100", self._badge_with_variant("secondary"))

    def test_info_variant_uses_cyan_classes(self) -> None:
        self.assertIn("bg-cyan-100", self._badge_with_variant("info"))

    def test_default_variant_falls_back_to_slate(self) -> None:
        """Unknown / default variant should still render with slate colours."""
        result = _render('{% badge "Test" %}')
        self.assertIn("bg-slate-100", result)


# ===============================================================================
# SIZE TESTS
# ===============================================================================


class BadgeSizeTests(SimpleTestCase):
    """Tests for the size= parameter."""

    def test_size_xs(self) -> None:
        result = _render('{% badge "XS" size="xs" %}')
        self.assertIn("px-1.5", result)

    def test_size_sm(self) -> None:
        result = _render('{% badge "SM" size="sm" %}')
        self.assertIn("px-2", result)

    def test_size_lg(self) -> None:
        result = _render('{% badge "LG" size="lg" %}')
        self.assertIn("px-3", result)

    def test_default_size_is_md(self) -> None:
        """Without an explicit size, the medium (px-2.5) sizing should apply."""
        result = _render('{% badge "MD" %}')
        self.assertIn("px-2.5", result)


# ===============================================================================
# ROUNDED TESTS
# ===============================================================================


class BadgeRoundedTests(SimpleTestCase):
    """Tests for the rounded= parameter."""

    def test_rounded_full(self) -> None:
        result = _render('{% badge "Pill" rounded="full" %}')
        self.assertIn("rounded-full", result)

    def test_rounded_lg(self) -> None:
        result = _render('{% badge "LG" rounded="lg" %}')
        self.assertIn("rounded-lg", result)

    def test_rounded_sm(self) -> None:
        result = _render('{% badge "SM" rounded="sm" %}')
        self.assertIn("rounded", result)

    def test_default_rounded_is_md(self) -> None:
        result = _render('{% badge "Default" %}')
        self.assertIn("rounded-md", result)


# ===============================================================================
# ICON TESTS
# ===============================================================================


class BadgeIconTests(SimpleTestCase):
    """Tests that icons appear inside the badge when requested."""

    def test_icon_left_renders_svg(self) -> None:
        result = _render('{% badge "Active" icon="check" icon_position="left" %}')
        self.assertIn("<svg", result)

    def test_icon_right_renders_svg(self) -> None:
        result = _render('{% badge "Active" icon="check" icon_position="right" %}')
        self.assertIn("<svg", result)

    def test_no_icon_no_svg(self) -> None:
        """Badge without icon should not contain any <svg>."""
        result = _render('{% badge "No icon" %}')
        self.assertNotIn("<svg", result)


# ===============================================================================
# DISMISSIBLE TESTS
# ===============================================================================


class BadgeDismissibleTests(SimpleTestCase):
    """Tests for the dismissible= parameter."""

    def test_dismissible_renders_close_button(self) -> None:
        result = _render('{% badge "Closing" dismissible=True %}')
        self.assertIn("<button", result)
        self.assertIn("type=\"button\"", result)

    def test_non_dismissible_has_no_button(self) -> None:
        result = _render('{% badge "Static" dismissible=False %}')
        self.assertNotIn("<button", result)

    def test_default_is_not_dismissible(self) -> None:
        result = _render('{% badge "Default" %}')
        self.assertNotIn("<button", result)


# ===============================================================================
# CSS CLASS INJECTION TESTS
# ===============================================================================


class BadgeCssClassTests(SimpleTestCase):
    """Tests for the css_class= parameter."""

    def test_custom_css_class_present(self) -> None:
        result = _render('{% badge "Label" css_class="font-mono" %}')
        self.assertIn("font-mono", result)

    def test_html_id_rendered(self) -> None:
        result = _render('{% badge "Label" html_id="status-badge" %}')
        self.assertIn('id="status-badge"', result)

    def test_no_html_id_by_default(self) -> None:
        result = _render('{% badge "Label" %}')
        self.assertNotIn('id="', result)


# ===============================================================================
# STATUS FILTER INTEGRATION
# ===============================================================================


class BadgeStatusFilterIntegrationTests(SimpleTestCase):
    """Tests composing badge with status_variant/status_icon/status_label filters."""

    def test_badge_with_status_variant_filter(self) -> None:
        result = _render(
            '{% badge status|status_label variant=status|status_variant %}',
            {"status": "active"},
        )
        self.assertIn("Active", result)
        self.assertIn("bg-green-100", result)

    def test_badge_with_pending_status(self) -> None:
        result = _render(
            '{% badge status|status_label variant=status|status_variant %}',
            {"status": "pending"},
        )
        self.assertIn("Pending", result)
        self.assertIn("bg-yellow-100", result)
