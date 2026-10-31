"""Every value the button writes is escaped once, and `attrs` never writes an attribute a second time.

Values arrive through `{% trans … as v %}`, which marks them safe, so the component escapes each one itself. Before
this, `hx_confirm` and `data_confirm` were written raw: a translation with a `"` closed the attribute. And `attrs`
accepts any `data-*`, `aria-*`, `tabindex` or `hx-include`, so it could repeat one the component already writes; the
browser keeps the first copy, so which value won depended on the order in button.html.
"""

from html.parser import HTMLParser

from django.template import Context, Template
from django.test import SimpleTestCase

TRICKY = 'Say "yes" & it\'s <b>done</b>'


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[list[tuple[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("button", "a"):
            self.controls.append(attrs)


def render(arguments: str) -> tuple[str, list[tuple[str, str | None]]]:
    source = (
        "{% load i18n ui_components %}"
        '{% trans "' + TRICKY.replace('"', '\\"') + '" as tricky %}'
        '{% button "Go" ' + arguments + " %}"
    )
    html = Template(source).render(Context())
    parsed = Parser()
    parsed.feed(html)
    assert len(parsed.controls) == 1, html
    return html, parsed.controls[0]


class EscapingTests(SimpleTestCase):
    def test_confirmation_prompts_reach_the_browser_exactly_as_written(self) -> None:
        for argument, attribute in (("hx_confirm", "hx-confirm"), ("data_confirm", "data-confirm")):
            with self.subTest(argument=argument):
                html, attrs = render(f'hx_post="/x/" {argument}=tricky')
                self.assertEqual(dict(attrs)[attribute], TRICKY)
                self.assertNotIn("<b>", html)


class OwnershipTests(SimpleTestCase):
    def test_attrs_never_repeats_an_attribute_the_component_writes(self) -> None:
        for argument, attribute in (
            ('data_copy="mine"', "data-copy"),
            ('data_invoke="mine"', "data-invoke"),
            ('data_confirm="mine"', "data-confirm"),
            ('hx_post="/x/" hx_include="mine"', "hx-include"),
        ):
            with self.subTest(attribute=attribute):
                _html, attrs = render(f"{argument} attrs='{attribute}=\"theirs\"'")
                names = [name for name, _value in attrs]
                self.assertEqual(names.count(attribute), 1, attrs)
                self.assertEqual(dict(attrs)[attribute], "mine")

    def test_a_disabled_link_keeps_its_own_tabindex_and_aria_disabled(self) -> None:
        _html, attrs = render('href="/x/" disabled=True attrs=\'tabindex="3" aria-disabled="false"\'')
        names = [name for name, _value in attrs]
        self.assertEqual(names.count("tabindex"), 1, attrs)
        self.assertEqual(names.count("aria-disabled"), 1, attrs)
        self.assertEqual(dict(attrs)["tabindex"], "-1")
        self.assertEqual(dict(attrs)["aria-disabled"], "true")

    def test_attrs_still_adds_what_the_component_does_not_write(self) -> None:
        _html, attrs = render('attrs=\'data-copy="theirs" tabindex="3"\'')
        self.assertEqual(dict(attrs)["data-copy"], "theirs")
        self.assertEqual(dict(attrs)["tabindex"], "3")
