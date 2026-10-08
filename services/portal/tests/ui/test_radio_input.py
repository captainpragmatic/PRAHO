"""Radio inputs retain their checked state and work with sibling peer labels."""

from __future__ import annotations

from html.parser import HTMLParser

from django.template import Context, Template
from django.test import SimpleTestCase


class _Elements(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def _parse(html: str) -> _Elements:
    parser = _Elements()
    parser.feed(html)
    parser.close()
    return parser


class RadioInputTests(SimpleTestCase):
    def test_radio_feedback_is_linked_after_the_input_label_pair(self) -> None:
        html = Template(
            '{% load ui_components %}{% input_field "action" input_type="radio" '
            'value="cancel_request" html_id="action_cancel_request" label="Cancel request" '
            'error="Choose another action" help_text="Select an action" help_text_below="You can retry" %}'
        ).render(Context({}))
        elements = _parse(html).elements
        attributes = elements[0][1]
        self.assertEqual(attributes.get("aria-invalid"), "true")
        self.assertEqual(
            attributes.get("aria-describedby"),
            "action_cancel_request-error action_cancel_request-help action_cancel_request-help-below",
        )
        self.assertEqual([tag for tag, _ in elements], ["input", "label", "p", "p", "p"])
        self.assertEqual(elements[1][1]["for"], attributes["id"])
        self.assertRegex(html, r"/>\s*<label\b")
        self.assertEqual(
            {attrs["id"] for tag, attrs in elements if tag == "p"},
            {"action_cancel_request-error", "action_cancel_request-help", "action_cancel_request-help-below"},
        )
        for text in ("Choose another action", "Select an action", "You can retry"):
            self.assertIn(text, html)

    def test_radio_states_labels_and_peer_siblings(self) -> None:
        tag = (
            '{% load ui_components %}{% input_field "action" input_type="radio" '
            'value="cancel_request" html_id="action_cancel_request" css_class="sr-only peer"'
        )
        default_html = Template(tag + " %}").render(Context({}))
        default = _parse(default_html)
        self.assertEqual([element for element, _ in default.elements], ["input"])
        self.assertNotIn("checked", default.elements[0][1])

        for checked in (False, True):
            for label in (None, "Cancel request"):
                with self.subTest(checked=checked, label=label):
                    html = Template(tag + " checked=checked label=label %}").render(
                        Context({"checked": checked, "label": label})
                    )
                    elements = _parse(html).elements
                    self.assertEqual([element for element, _ in elements], ["input", "label"] if label else ["input"])
                    attributes = elements[0][1]
                    self.assertEqual(attributes["type"], "radio")
                    self.assertEqual(attributes["name"], "action")
                    self.assertEqual(attributes["value"], "cancel_request")
                    self.assertEqual(attributes["id"], "action_cancel_request")
                    self.assertEqual(attributes["class"], "sr-only peer")
                    self.assertEqual("checked" in attributes, checked)
                    if label:
                        self.assertEqual(elements[1][1]["for"], "action_cancel_request")
                        self.assertIn(label, html)

        sibling_html = Template(
            tag + ' checked=True %}<label for="action_cancel_request" class="peer-checked:bg-blue-500">Cancel</label>'
        ).render(Context({}))
        sibling = _parse(sibling_html).elements
        self.assertEqual([element for element, _ in sibling], ["input", "label"])
        self.assertEqual(sibling[0][1]["id"], sibling[1][1]["for"])
        self.assertIn("checked", sibling[0][1])
        self.assertEqual(sibling[1][1]["class"], "peer-checked:bg-blue-500")
