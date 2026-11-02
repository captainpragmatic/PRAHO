"""The button wires an Alpine component's methods through named arguments, never through attrs.

Several hand-written buttons existed only because the component took no Alpine binding. The trust contract:
expressions are written in templates (template literals), never built from server data, which goes through `data-*`
attributes a registered component method reads. `attrs` keeps refusing every executable attribute. Each expression is
escaped once; the browser decodes it before Alpine parses it, so `"` and `&` survive.
"""

from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def render(arguments: str) -> Parser:
    html = Template('{% load ui_components %}{% button "Save" ' + arguments + " %}").render(Context())
    parsed = Parser()
    parsed.feed(html)
    return parsed


def control(parsed: Parser) -> dict[str, str | None]:
    controls = [attrs for tag, attrs in parsed.elements if tag in ("button", "a")]
    assert len(controls) == 1, parsed.elements
    return controls[0]


def label(parsed: Parser) -> dict[str, str | None]:
    return next(attrs for tag, attrs in parsed.elements if tag == "span" and "btn-label" in (attrs.get("class") or ""))


class AlpineArgumentTests(SimpleTestCase):
    def test_click_disabled_and_show_land_on_the_button(self) -> None:
        attrs = control(render('alpine_click=\'pick("a & b")\' alpine_disabled="saving" alpine_show="dirty"'))
        self.assertEqual(attrs["@click"], 'pick("a & b")')
        self.assertEqual(attrs[":disabled"], "saving")
        self.assertEqual(attrs["x-show"], "dirty")

    def test_text_replaces_only_the_label_so_icon_and_spinner_survive(self) -> None:
        parsed = render('icon="check" hx_post="/x/" alpine_text="label"')
        self.assertNotIn("x-text", control(parsed))
        self.assertEqual(label(parsed)["x-text"], "label")
        self.assertTrue(any(tag == "svg" for tag, _attrs in parsed.elements))
        self.assertTrue(any("btn-spinner" in (attrs.get("class") or "") for _tag, attrs in parsed.elements))

    def test_a_link_takes_a_click_but_neither_disabled_binding_nor_id(self) -> None:
        self.assertEqual(control(render('href="/x/" alpine_click="go()"'))["@click"], "go()")
        for arguments in ('href="/x/" alpine_disabled="busy"', 'href="/x/" button_id="save"'):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(TemplateSyntaxError, "not on a link"):
                render(arguments)

    def test_attrs_still_refuses_executable_attributes(self) -> None:
        attrs = control(render('attrs=\'@click="steal()" x-on:click="steal()" :class="x" onclick="steal()"\''))
        for name in ("@click", "x-on:click", ":class", "onclick"):
            self.assertNotIn(name, attrs)
