"""The checkout's validation-error list shows customers only the reasons.

A `{# ... #}` comment in the list was split across two lines. Django reads a comment only on one
line, so whenever preflight failed the customer saw the developer note "Degrade to the
untranslated originals rather than to an empty list..." as a list entry.
"""

from __future__ import annotations

from django.template.base import TextNode
from django.template.loader import get_template
from django.test import SimpleTestCase


class CheckoutTemplateTextTests(SimpleTestCase):
    def test_no_developer_note_reaches_the_page(self) -> None:
        nodelist = get_template("orders/checkout.html").template.nodelist
        text = "".join(node.s for node in nodelist.get_nodes_by_type(TextNode))

        self.assertIn("display_errors", get_template("orders/checkout.html").template.source)
        self.assertFalse("Degrade to the untranslated" in text, "the developer note renders as page text")
        self.assertFalse("{#" in text, "a comment renders as page text")
