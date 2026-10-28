"""
Regression tests for the HTML-safety contract of the UI template tags.

These pin the behaviour that the Bandit B308/B703 clean-up relies on:
- icon() builds its <path> markup with format_html_join, so path data is escaped
  and the result is SafeString for single- and multi-path icons alike.
- page_header / section_card pass the rendered slot (NodeList.render, already SafeString)
  to their component template unescaped, while variables inside the slot stay escaped.
- highlight_search escapes its input on the early-return path.
"""

from unittest.mock import patch

from django.template import Context, Template
from django.test import SimpleTestCase
from django.utils.safestring import SafeString

from apps.ui.templatetags import ui_components
from apps.ui.templatetags.formatting import highlight_search
from apps.ui.templatetags.ui_components import icon


class IconPathMarkupTests(SimpleTestCase):
    def test_outline_single_path_icon_is_safe_with_one_path(self):
        result = icon("dashboard")
        self.assertIsInstance(result, SafeString)
        self.assertEqual(result.count("<path"), 1)
        self.assertIn('viewBox="0 0 24 24"', result)

    def test_outline_tuple_icon_is_safe_with_every_path(self):
        result = icon("settings")
        self.assertIsInstance(result, SafeString)
        self.assertEqual(result.count("<path"), 2)

    def test_filled_single_path_icon_is_safe_with_one_path(self):
        result = icon("check-circle", style="filled")
        self.assertIsInstance(result, SafeString)
        self.assertEqual(result.count("<path"), 1)

    def test_path_data_is_escaped(self):
        with patch.dict(ui_components._ICON_PATHS, {"hostile": 'M0 0"><script>alert(1)</script>'}):
            result = icon("hostile")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)


class SlotRenderingTests(SimpleTestCase):
    def test_page_header_actions_render_markup_but_escape_variables(self):
        template = Template(
            '{% load ui_components %}{% page_header title="T" %}<b class="x">go</b>{{ hostile }}{% end_page_header %}'
        )
        rendered = template.render(Context({"hostile": "<script>alert(1)</script>"}))
        self.assertIn('<b class="x">go</b>', rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)

    def test_section_card_content_renders_markup_but_escapes_variables(self):
        template = Template(
            '{% load ui_components %}{% section_card title="T" %}<i class="y">body</i>{{ hostile }}{% end_section_card %}'
        )
        rendered = template.render(Context({"hostile": "<script>alert(1)</script>"}))
        self.assertIn('<i class="y">body</i>', rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)


class HighlightSearchEarlyReturnTests(SimpleTestCase):
    def test_empty_search_term_escapes_text(self):
        result = highlight_search("<b>Ana & Co</b>", "")
        self.assertIsInstance(result, SafeString)
        self.assertEqual(result, "&lt;b&gt;Ana &amp; Co&lt;/b&gt;")

    def test_empty_text_returns_empty_safe_string(self):
        result = highlight_search("", "x")
        self.assertIsInstance(result, SafeString)
        self.assertEqual(result, "")
