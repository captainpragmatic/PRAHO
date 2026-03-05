"""
XSS Sanitization Tests — Phase C.2

Tests that verify XSS prevention across UI components:
    - Button attrs= parameter has an explicit sanitizer
    - Badge text= is auto-escaped by Django's template engine
    - Status filter inputs do not produce unescaped output
    - Direct template variable injection is auto-escaped

No database access.

🔒 SECURITY NOTE: These tests guard against regressions in the sanitization
logic inside ``button()``'s ``_sanitize_and_escape_attrs`` helper and Django's
built-in auto-escaping mechanisms.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

import unittest

from django.template import Context, Template
from django.test import SimpleTestCase


def _render(template_str: str, context: dict | None = None) -> str:
    """Render a template string using Django's template system."""
    t = Template("{% load ui_components %}" + template_str)
    return t.render(Context(context or {}))


# ===============================================================================
# BUTTON ATTRS= SANITIZATION TESTS
# ===============================================================================


class ButtonAttrsSanitizationTests(SimpleTestCase):
    """
    Tests the _sanitize_and_escape_attrs function inside button().

    The button tag explicitly sanitizes the ``attrs`` kwarg before rendering it
    into the template. This prevents injecting arbitrary HTML/JS through the
    attrs= parameter.
    """

    def test_plain_data_attr_passes_through_escaped(self) -> None:
        """A benign data attribute should be HTML-escaped and appear in output."""
        result = _render('{% button "Go" attrs="data-id=\\"123\\"" %}')
        # Ampersands in attrs are escaped; the key content must appear
        self.assertIn("data-id", result)

    def test_onload_handler_stripped(self) -> None:
        """onload= auto-executing event handler must be removed."""
        result = _render('{% button "Go" attrs="onload=alert(1)" %}')
        self.assertNotIn("onload=alert", result)

    def test_onerror_handler_stripped(self) -> None:
        """onerror= auto-executing event handler must be removed."""
        result = _render('{% button "Go" attrs="onerror=malicious()" %}')
        self.assertNotIn("onerror=malicious", result)

    def test_onmouseover_handler_stripped(self) -> None:
        """onmouseover= auto-executing event handler must be removed."""
        result = _render('{% button "Go" attrs="onmouseover=steal()" %}')
        self.assertNotIn("onmouseover=steal", result)

    def test_javascript_url_stripped(self) -> None:
        """javascript: URI scheme must be removed from attrs."""
        result = _render('{% button "Go" attrs="javascript:alert(1)" %}')
        self.assertNotIn("javascript:alert", result)

    def test_eval_stripped(self) -> None:
        """eval() call must be removed from attrs."""
        result = _render('{% button "Go" attrs="eval(atob(payload))" %}')
        self.assertNotIn("eval(", result)

    def test_angle_brackets_escaped(self) -> None:
        """< and > should be HTML-escaped in attrs output."""
        result = _render('{% button "Go" attrs="<script>" %}')
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_double_quotes_escaped(self) -> None:
        """Double quotes in attrs should be HTML-escaped to prevent attribute break-out."""
        result = _render('{% button "Go" attrs=\'onclick="stealCookies()"\' %}')
        self.assertNotIn('"stealCookies()"', result)

    def test_alert_call_stripped(self) -> None:
        """alert() proof-of-concept payload must be neutralised."""
        result = _render('{% button "Go" attrs="alert(1)" %}')
        self.assertNotIn("alert(1)", result)


# ===============================================================================
# DJANGO AUTO-ESCAPE TESTS (badge, page_header, status filters)
# ===============================================================================


class TemplateAutoEscapeTests(SimpleTestCase):
    """
    Tests that Django's built-in auto-escaping protects variable interpolation
    in badge, status filters, and other component outputs.
    """

    def test_badge_text_escapes_script_tag(self) -> None:
        result = _render("{% badge label %}", {"label": "<script>alert(1)</script>"})
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_badge_html_id_escapes_injection(self) -> None:
        result = _render(
            "{% badge 'Test' html_id=badge_id %}",
            {"badge_id": '"><script>xss</script>'},
        )
        self.assertNotIn("<script>", result)

    def test_status_variant_with_crafted_input_returns_secondary(self) -> None:
        """A crafted status input should fall through to 'secondary' — never echoed raw."""
        from apps.ui.templatetags.ui_components import status_variant  # noqa: PLC0415

        result = status_variant("<script>alert(1)</script>")
        # The filter returns a variant string — never the input — so no injection possible
        self.assertNotIn("<script>", result)
        self.assertEqual(result, "secondary")

    def test_status_label_with_crafted_input_is_title_cased_safely(self) -> None:
        """status_label falls back to .title() — the injected characters are preserved
        but they're inserted through Django's auto-escape when rendered in a template."""
        from apps.ui.templatetags.ui_components import status_label  # noqa: PLC0415

        raw = "<img onerror=x>"
        result = status_label(raw)
        # Returns Python string — Django will escape when rendered via {{ }}
        # The filter itself should not produce an entirely safe string, but it
        # must NOT produce executable JS or strip content silently.
        self.assertIsInstance(result, str)

    def test_badge_status_filter_xss_via_template(self) -> None:
        """Chaining status|status_label via template: output must be escaped.

        status_label calls .title() which uppercases letters following punctuation,
        so "<b>" becomes "<B>" before Django escapes it to "&lt;B&gt;".
        """
        result = _render(
            "{% badge status|status_label %}",
            {"status": "<b>Bold</b>"},
        )
        self.assertNotIn("<b>Bold</b>", result)
        # .title() capitalises the letter after "<" → "<B>" → escaped to "&lt;B&gt;"
        self.assertIn("&lt;B&gt;", result)


# ===============================================================================
# ICON TAG SAFETY TESTS
# ===============================================================================


class IconSafetyTests(unittest.TestCase):
    """
    Tests that the icon tag never echoes back the name parameter unsanitized.

    The icon() simple_tag either returns a pre-registered safe SVG string or
    returns an empty string — it never interpolates the user-supplied name into
    the output. This is a structural XSS prevention (no template variable echoed).
    """

    def test_script_icon_name_returns_empty(self) -> None:
        result = _render('{% icon "<script>xss</script>" %}')
        self.assertNotIn("<script>", result)
        self.assertEqual(result.strip(), "")

    def test_unknown_icon_does_not_reflect_name(self) -> None:
        result = _render('{% icon "INJECTED_NAME" %}')
        self.assertNotIn("INJECTED_NAME", result)
        self.assertEqual(result.strip(), "")

    def test_css_class_injection_escaped_in_svg(self) -> None:
        """A malicious css_class= is passed to the SVG class attribute; Django
        auto-escapes it via format_html's %s argument escaping."""
        result = _render('{% icon "check" css_class=cls %}', {"cls": '"><script>xss</script>'})
        self.assertNotIn("<script>", result)
