"""
Icon Template Tag Tests — Phase C.2

Tests for the {% icon %} simple tag in apps.ui.templatetags.ui_components.
Verifies SVG rendering, size variants, CSS class injection, and completeness
across all registered icons. No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from django.template import Context, Template
from django.test import SimpleTestCase

from apps.ui.templatetags.ui_components import _ICON_PATHS

# Keep in sync automatically with the icon registry under test.
ALL_ICON_NAMES = sorted(_ICON_PATHS.keys())


def _render(template_str: str, context: dict | None = None) -> str:
    """Render a template string using Django's template engine."""
    t = Template("{% load ui_components %}" + template_str)
    return t.render(Context(context or {}))


# ===============================================================================
# BASIC RENDERING TESTS
# ===============================================================================


class IconTagBasicTests(SimpleTestCase):
    """Tests for basic {% icon %} rendering behaviour."""

    def test_known_icon_renders_svg_element(self) -> None:
        """A known icon name should return an <svg> element."""
        result = _render('{% icon "check" %}')
        self.assertIn("<svg", result)
        self.assertIn("</svg>", result)

    def test_unknown_icon_returns_empty_string(self) -> None:
        """An unknown icon name should silently return an empty string."""
        result = _render('{% icon "nonexistent_icon_xyz" %}')
        self.assertEqual(result.strip(), "")

    def test_svg_has_viewbox_attribute(self) -> None:
        """The SVG should include the canonical 24x24 viewBox."""
        result = _render('{% icon "check" %}')
        self.assertIn('viewBox="0 0 24 24"', result)

    def test_svg_is_aria_hidden(self) -> None:
        """Icons must be aria-hidden to avoid screen-reader noise."""
        result = _render('{% icon "check" %}')
        self.assertIn('aria-hidden="true"', result)

    def test_svg_has_stroke_attributes(self) -> None:
        """Icon SVGs use stroke-based rendering."""
        result = _render('{% icon "check" %}')
        self.assertIn('stroke="currentColor"', result)
        self.assertIn('fill="none"', result)


# ===============================================================================
# SIZE VARIANT TESTS
# ===============================================================================


class IconTagSizeTests(SimpleTestCase):
    """Tests for the size= parameter mapping to Tailwind w-/h- classes."""

    def _icon_with_size(self, size: str) -> str:
        return _render(f'{{% icon "check" size="{size}" %}}')

    def test_size_xs(self) -> None:
        self.assertIn("w-3", self._icon_with_size("xs"))
        self.assertIn("h-3", self._icon_with_size("xs"))

    def test_size_sm(self) -> None:
        self.assertIn("w-4", self._icon_with_size("sm"))
        self.assertIn("h-4", self._icon_with_size("sm"))

    def test_size_md_default(self) -> None:
        """Default size (md) should produce w-5 h-5."""
        result = _render('{% icon "check" %}')
        self.assertIn("w-5", result)
        self.assertIn("h-5", result)

    def test_size_md_explicit(self) -> None:
        self.assertIn("w-5", self._icon_with_size("md"))

    def test_size_lg(self) -> None:
        self.assertIn("w-6", self._icon_with_size("lg"))

    def test_size_xl(self) -> None:
        self.assertIn("w-8", self._icon_with_size("xl"))

    def test_size_2xl(self) -> None:
        self.assertIn("w-10", self._icon_with_size("2xl"))


# ===============================================================================
# CSS CLASS INJECTION TESTS
# ===============================================================================


class IconTagCssClassTests(SimpleTestCase):
    """Tests for the css_class= parameter."""

    def test_custom_css_class_included(self) -> None:
        result = _render('{% icon "check" css_class="text-green-500" %}')
        self.assertIn("text-green-500", result)

    def test_default_no_extra_class(self) -> None:
        """Without css_class, no extra classes should appear beyond size."""
        result = _render('{% icon "check" %}')
        self.assertNotIn("text-green-500", result)

    def test_multiple_css_classes(self) -> None:
        result = _render('{% icon "warning" css_class="text-yellow-400 animate-pulse" %}')
        self.assertIn("text-yellow-400", result)
        self.assertIn("animate-pulse", result)


# ===============================================================================
# MULTI-PATH ICONS TESTS
# ===============================================================================


class IconTagMultiPathTests(SimpleTestCase):
    """Tests for icons registered as tuples of paths (multiple <path> elements)."""

    def test_settings_icon_renders_svg(self) -> None:
        """settings is a tuple of two paths — SVG should still render."""
        result = _render('{% icon "settings" %}')
        self.assertIn("<svg", result)

    def test_map_pin_icon_renders_svg(self) -> None:
        """map-pin is a tuple of two paths — SVG should still render."""
        result = _render('{% icon "map-pin" %}')
        self.assertIn("<svg", result)

    def test_eye_icon_renders_svg(self) -> None:
        """eye is a tuple of two paths — SVG should still render."""
        result = _render('{% icon "eye" %}')
        self.assertIn("<svg", result)

    def test_adjustments_icon_renders_svg(self) -> None:
        """adjustments is a tuple — SVG should still render."""
        result = _render('{% icon "adjustments" %}')
        self.assertIn("<svg", result)


# ===============================================================================
# COMPLETENESS TEST — every icon in _ICON_PATHS must render a valid SVG
# ===============================================================================


class IconTagCompletenessTests(SimpleTestCase):
    """
    Completeness guard — ensures no icon in _ICON_PATHS is silently broken.

    🚨 If a new icon is added to _ICON_PATHS and breaks rendering, this test
    will catch it. O(N) over the icon registry — acceptable for a test suite.
    """

    def test_all_icons_render_non_empty_svg(self) -> None:
        """Every registered icon name must yield an <svg> element."""
        broken: list[str] = []
        for name in ALL_ICON_NAMES:
            result = _render(f'{{% icon "{name}" %}}')
            if "<svg" not in result:
                broken.append(name)
        self.assertListEqual(
            broken,
            [],
            msg=f"These icons did not render an <svg>: {broken}",
        )

    def test_all_icons_count_matches_registry(self) -> None:
        """Registry should stay non-empty and contain canonical baseline icons."""
        self.assertGreater(len(ALL_ICON_NAMES), 0)
        baseline = {"check", "x", "warning", "info", "menu", "chevron-right"}
        self.assertTrue(baseline.issubset(set(ALL_ICON_NAMES)))
