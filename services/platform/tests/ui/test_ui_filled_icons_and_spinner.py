"""
Tests for filled icon style and spinner template tags (Phase F).

Verifies:
- Filled icons render with correct viewBox, fill attributes
- Outline icons remain unchanged (backward compatibility)
- Spinner renders accessible HTML with correct sizes/colors
"""

from django.template import Context, Template
from django.test import TestCase

from apps.ui.templatetags.ui_components import (
    _FILLED_ICON_PATHS,
    _SPINNER_SIZES,
    icon,
    spinner,
)


class FilledIconTests(TestCase):
    """Tests for {% icon name style="filled" %}"""

    def test_filled_icon_renders_svg(self):
        result = icon("check-circle", style="filled")
        self.assertIn("<svg", result)
        self.assertIn("</svg>", result)

    def test_filled_icon_viewbox_20(self):
        result = icon("check-circle", style="filled")
        self.assertIn('viewBox="0 0 20 20"', result)

    def test_filled_icon_fill_attribute(self):
        result = icon("check-circle", style="filled")
        self.assertIn('fill="currentColor"', result)
        self.assertNotIn("stroke=", result)

    def test_filled_icon_fill_rule(self):
        result = icon("check-circle", style="filled")
        self.assertIn('fill-rule="evenodd"', result)
        self.assertIn('clip-rule="evenodd"', result)

    def test_outline_default_unchanged(self):
        result = icon("check")
        self.assertIn('viewBox="0 0 24 24"', result)
        self.assertIn('stroke="currentColor"', result)
        self.assertIn('fill="none"', result)

    def test_unknown_filled_returns_empty(self):
        result = icon("nonexistent-icon", style="filled")
        self.assertEqual(result, "")

    def test_unknown_outline_returns_empty(self):
        result = icon("nonexistent-icon")
        self.assertEqual(result, "")

    def test_all_filled_icons_render(self):
        for name in _FILLED_ICON_PATHS:
            result = icon(name, style="filled")
            self.assertIn("<svg", result, f"Filled icon '{name}' failed to render")

    def test_filled_icon_tuple_paths(self):
        """Icons with multiple paths (tuples) should render multiple <path> elements."""
        result = icon("currency-dollar", style="filled")
        self.assertEqual(result.count("<path"), 2)

    def test_filled_icon_css_class(self):
        result = icon("check-circle", style="filled", css_class="text-green-400")
        self.assertIn("text-green-400", result)

    def test_filled_icon_size(self):
        result = icon("check-circle", style="filled", size="lg")
        self.assertIn("w-6 h-6", result)

    def test_outline_style_explicit(self):
        result = icon("check", style="outline")
        self.assertIn('viewBox="0 0 24 24"', result)

    def test_filled_icon_via_template(self):
        t = Template('{% load ui_components %}{% icon "check-circle" style="filled" %}')
        rendered = t.render(Context({}))
        self.assertIn('viewBox="0 0 20 20"', rendered)
        self.assertIn('fill="currentColor"', rendered)


class SpinnerTests(TestCase):
    """Tests for {% spinner %}"""

    def test_spinner_renders_div(self):
        result = spinner()
        self.assertIn("<div", result)
        self.assertIn("animate-spin", result)

    def test_spinner_has_role_status(self):
        result = spinner()
        self.assertIn('role="status"', result)

    def test_spinner_sr_only_text(self):
        result = spinner()
        self.assertIn('class="sr-only"', result)

    def test_spinner_default_size(self):
        result = spinner()
        self.assertIn("w-4 h-4", result)
        self.assertIn("border-2", result)

    def test_spinner_sizes(self):
        for size_name, (dim, _border) in _SPINNER_SIZES.items():
            result = spinner(size=size_name)
            self.assertIn(dim, result, f"Size '{size_name}' missing dimension '{dim}'")

    def test_spinner_color_blue(self):
        result = spinner(color="blue")
        self.assertIn("border-blue-500", result)

    def test_spinner_color_white(self):
        result = spinner(color="white")
        self.assertIn("border-white", result)

    def test_spinner_border_t_transparent(self):
        result = spinner()
        self.assertIn("border-t-transparent", result)

    def test_spinner_custom_css_class(self):
        result = spinner(css_class="mr-2")
        self.assertIn("mr-2", result)

    def test_spinner_via_template(self):
        t = Template('{% load ui_components %}{% spinner size="lg" color="blue" %}')
        rendered = t.render(Context({}))
        self.assertIn("animate-spin", rendered)
        self.assertIn("border-blue-500", rendered)
        self.assertIn('role="status"', rendered)
