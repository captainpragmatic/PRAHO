"""`{% disclosure %}`: the button that shows and hides a region the page already shows and hides (#821).

The page keeps its own state (the region's `x-show`) and the disclosure only reads and flips it, so there is never a
second owner. It names the region it controls, reports `aria-expanded` from that state, and says "show" or "hide" in
words. The state expression is a plain name (a property path), which is all the pages need and keeps it CSP-simple.
"""

from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase

DEFAULTS = 'expanded_expr="showAdvanced" toggle_expr="showAdvanced = !showAdvanced"'


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[tuple[str, str]] = []
        self._open: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))
        if tag == "span":
            self._open.append(dict(attrs).get("x-show") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "span" and self._open:
            self._open.pop()

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text.append((self._open[-1] if self._open else "", data.strip()))


def render(arguments: str) -> tuple[str, Parser]:
    html = Template(
        "{% load i18n ui_components %}"
        '{% trans "Show Advanced Options" as closed %}{% trans "Hide Advanced Options" as opened %}'
        "{% disclosure " + arguments + " %}"
    ).render(Context({"tricky": 'Show "all" <b>'}))
    parsed = Parser()
    parsed.feed(html)
    return html, parsed


class DisclosureTests(SimpleTestCase):
    def test_it_names_the_region_follows_the_page_s_state_and_flips_it(self) -> None:
        _html, parsed = render(f'"advanced-options" opened closed {DEFAULTS}')
        buttons = [attrs for tag, attrs in parsed.elements if tag == "button"]
        self.assertEqual(len(buttons), 1)
        button = buttons[0]
        self.assertEqual(button["type"], "button")
        self.assertEqual(button["aria-controls"], "advanced-options")
        self.assertEqual(button[":aria-expanded"], "showAdvanced")
        self.assertEqual(button["@click"], "showAdvanced = !showAdvanced")
        self.assertIn("ui-btn", (button["class"] or "").split())

    def test_both_labels_render_and_only_one_shows_for_each_state(self) -> None:
        _html, parsed = render(f'"advanced-options" opened closed {DEFAULTS}')
        self.assertEqual(
            parsed.text, [("!showAdvanced", "Show Advanced Options"), ("showAdvanced", "Hide Advanced Options")]
        )

    def test_the_chevron_turns_with_the_state(self) -> None:
        _html, parsed = render(f'"advanced-options" opened closed {DEFAULTS}')
        turning = [attrs for tag, attrs in parsed.elements if tag == "span" and attrs.get(":class")]
        self.assertEqual([attrs[":class"] for attrs in turning], ["{ 'rotate-180': showAdvanced }"])
        self.assertEqual(len([tag for tag, _attrs in parsed.elements if tag == "svg"]), 1)

    def test_it_never_touches_the_region(self) -> None:
        html, _parsed = render(f'"advanced-options" opened closed {DEFAULTS}')
        self.assertNotIn('id="advanced-options"', html)
        self.assertEqual(html.count("<button"), 1)

    def test_labels_and_classes_are_escaped(self) -> None:
        html, parsed = render(f'"advanced-options" tricky tricky {DEFAULTS} class="flex text-sm"')
        self.assertNotIn("<b>", html)
        self.assertEqual([text for _shown, text in parsed.text], ['Show "all" <b>', 'Show "all" <b>'])
        button = next(attrs for tag, attrs in parsed.elements if tag == "button")
        self.assertEqual((button["class"] or "").split()[-2:], ["flex", "text-sm"])

    def test_an_icon_leads_the_label(self) -> None:
        _html, parsed = render(f'"settings-nav" opened closed {DEFAULTS} icon="menu"')
        self.assertEqual(len([tag for tag, _attrs in parsed.elements if tag == "svg"]), 2)

    def test_a_missing_name_or_an_expression_that_is_not_a_plain_name_is_refused(self) -> None:
        for arguments in (
            f'"" opened closed {DEFAULTS}',
            f'"bad id" opened closed {DEFAULTS}',
            '"x" opened closed expanded_expr="open || evil()" toggle_expr="open = !open"',
            '"x" opened closed expanded_expr="" toggle_expr="open = !open"',
            '"x" opened closed expanded_expr="open" toggle_expr=""',
            '"x" "" closed expanded_expr="open" toggle_expr="open = !open"',
        ):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments)
