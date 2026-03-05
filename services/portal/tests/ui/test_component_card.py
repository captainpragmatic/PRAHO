"""
Card Component Tests — Phase C.2 (completion)

Tests for the {% card %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies title, subtitle, header/footer sections, and css_class passthrough.
No database access.
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
# BASIC RENDERING TESTS
# ===============================================================================


class CardBasicTests(SimpleTestCase):
    """Tests basic card renders a container div."""

    def test_renders_div_container(self) -> None:
        result = _render("{% card %}")
        self.assertIn("<div", result)

    def test_default_css_classes_applied(self) -> None:
        result = _render("{% card %}")
        self.assertIn("bg-white", result)
        self.assertIn("rounded-lg", result)

    def test_custom_css_class_overrides_default(self) -> None:
        result = _render('{% card css_class="custom-class" %}')
        self.assertIn("custom-class", result)
        # When css_class provided, default classes are replaced
        self.assertNotIn("bg-white shadow rounded-lg", result)


# ===============================================================================
# HEADER SECTION TESTS
# ===============================================================================


class CardHeaderTests(SimpleTestCase):
    """Tests card header rendering with title and subtitle."""

    def test_title_shown_when_provided(self) -> None:
        result = _render('{% card title="My Card" %}')
        self.assertIn("My Card", result)

    def test_title_not_shown_without_title(self) -> None:
        result = _render("{% card %}")
        self.assertNotIn("<h3", result)

    def test_subtitle_renders_when_provided(self) -> None:
        result = _render('{% card subtitle="Sub text" %}')
        self.assertIn("Sub text", result)

    def test_header_shown_when_title_provided(self) -> None:
        """has_header is auto-derived from title presence."""
        result = _render('{% card title="T" %}')
        self.assertIn("border-b", result)

    def test_no_header_no_border_bottom(self) -> None:
        """No title → no header → no border-b."""
        result = _render("{% card %}")
        self.assertNotIn("border-b", result)


# ===============================================================================
# FOOTER SECTION TESTS
# ===============================================================================


class CardFooterTests(SimpleTestCase):
    """Tests card footer rendering."""

    def test_footer_content_shown_when_has_footer(self) -> None:
        result = _render('{% card has_footer=True footer="Footer text" %}')
        self.assertIn("Footer text", result)

    def test_footer_has_border_top(self) -> None:
        result = _render('{% card has_footer=True footer="x" %}')
        self.assertIn("border-t", result)

    def test_no_footer_section_by_default(self) -> None:
        result = _render("{% card %}")
        # Footer div shouldn't render without has_footer
        self.assertNotIn("bg-slate-50", result)
