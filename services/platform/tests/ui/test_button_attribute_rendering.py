"""Regression tests for browser-visible button attribute values."""

from html.parser import HTMLParser

from django.template import Context, Template
from django.test import SimpleTestCase


class AttributeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.buttons: list[dict[str, str | None]] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        if tag in ("button", "a"):
            self.buttons.append(dict(attrs))


class ButtonAttributeRenderingTests(SimpleTestCase):
    def render_button(self, attrs: str) -> AttributeParser:
        html = Template('{% load ui_components %}{% button "Apply" attrs=attrs %}').render(Context({"attrs": attrs}))
        parsed = AttributeParser()
        parsed.feed(html)
        self.assertEqual(len(parsed.buttons), 1)
        return parsed

    def test_quoted_values_are_decoded_without_delimiter_quotes(self) -> None:
        parsed = self.render_button('hx-include="#audit-filters" data-count="5" aria-label="Apply all filters"')
        self.assertEqual(parsed.buttons[0]["hx-include"], "#audit-filters")
        self.assertEqual(parsed.buttons[0]["data-count"], "5")
        self.assertEqual(parsed.buttons[0]["aria-label"], "Apply all filters")

    def test_literal_attribute_contents_cannot_create_markup_or_handlers(self) -> None:
        parsed = self.render_button(
            'data-note="&quot; onmouseover=&quot;evil() <script>text</script>" onclick="evil()"'
        )
        self.assertEqual(parsed.buttons[0]["data-note"], '" onmouseover="evil() <script>text</script>')
        self.assertNotIn("onclick", parsed.buttons[0])
        self.assertNotIn("onmouseover", parsed.buttons[0])
        self.assertNotIn("script", parsed.tags)

    def test_executable_attributes_are_rejected(self) -> None:
        parsed = self.render_button(
            'hx-on:click="evil()" @click="evil()" style="color:red" formaction="javascript:evil()" data-ok="yes"'
        )
        self.assertEqual(parsed.buttons[0]["data-ok"], "yes")
        for key in ("hx-on:click", "@click", "style", "formaction"):
            self.assertNotIn(key, parsed.buttons[0])

    def test_explicit_hx_include_is_supported(self) -> None:
        html = Template('{% load ui_components %}{% button "Apply" hx_include="#audit-filters" %}').render(Context())
        parsed = AttributeParser()
        parsed.feed(html)
        self.assertEqual(parsed.buttons[0].get("hx-include"), "#audit-filters")


class AttributeMappingTests(SimpleTestCase):
    """A view-built `attrs` mapping is checked where it enters, not left to whichever copy the browser keeps (#821).

    The string form keeps its rule (an owned name is dropped and the argument wins), which templates rely on. A mapping
    comes from Python, so a clash there is a bug in the view: it is refused instead of half-rendered.
    """

    def render_mapping(self, attrs: dict[str, str], arguments: str = "") -> AttributeParser:
        html = Template('{% load ui_components %}{% button "Apply" attrs=attrs ' + arguments + " %}").render(
            Context({"attrs": attrs})
        )
        parsed = AttributeParser()
        parsed.feed(html)
        self.assertEqual(len(parsed.buttons), 1)
        return parsed

    def test_names_are_written_in_lower_case(self) -> None:
        parsed = self.render_mapping({"Data-Code": "AB12"})
        self.assertEqual(parsed.buttons[0]["data-code"], "AB12")

    def test_two_spellings_of_one_name_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.render_mapping({"data-Code": "a", "data-code": "b"})

    def test_a_name_the_component_writes_is_refused(self) -> None:
        for attrs, arguments in (
            ({"data-action": "invoke"}, ""),
            ({"Data-Action": "invoke"}, 'data_action="copy"'),
            ({"data-copy": "theirs"}, 'data_copy="mine"'),
            ({"aria-label": "theirs"}, 'icon="copy" icon_only=True aria_label="Mine"'),
        ):
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                self.render_mapping(attrs, arguments)

    def test_values_stay_escaped(self) -> None:
        parsed = self.render_mapping({"data-note": '"><script>evil()</script>'})
        self.assertEqual(parsed.buttons[0]["data-note"], '"><script>evil()</script>')
        self.assertNotIn("script", parsed.tags)
