"""`{% icon_button %}` is `{% button %}` with only its icon showing, so it can't be left without a name (#821).

Hand-written icon controls were the ones with no accessible name. The alias takes the name first, refuses a blank one
or an icon the catalog doesn't have, and keeps the name as the tooltip unless the page gives another.
"""

from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, list[tuple[str, str | None]]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, attrs))


def render(arguments: str) -> tuple[str, Parser]:
    html = Template(
        '{% load i18n ui_components %}{% trans "Copy CUI" as name %}{% icon_button ' + arguments + " %}"
    ).render(Context({"blank": "  "}))
    parsed = Parser()
    parsed.feed(html)
    return html, parsed


def control(parsed: Parser) -> list[tuple[str, str | None]]:
    controls = [attrs for tag, attrs in parsed.elements if tag in ("button", "a")]
    assert len(controls) == 1, parsed.elements
    return controls[0]


class IconButtonTests(SimpleTestCase):
    def test_it_is_named_by_aria_label_with_the_label_kept_for_screen_readers(self) -> None:
        html, parsed = render('"copy" name variant="bare" data_copy="RO123" data_action="copy"')
        attrs = control(parsed)
        names = [name for name, _value in attrs]
        self.assertEqual(len(names), len(set(names)), attrs)
        self.assertEqual(dict(attrs)["aria-label"], "Copy CUI")
        self.assertIn('class="btn-label htmx-indicator-text sr-only"', html)
        self.assertIn(">Copy CUI</span>", html)

    def test_the_name_is_the_tooltip_unless_the_page_gives_one(self) -> None:
        self.assertEqual(dict(control(render('"copy" name')[1]))["title"], "Copy CUI")
        self.assertEqual(dict(control(render('"copy" name title="Copy"')[1]))["title"], "Copy")

    def test_a_blank_name_or_an_unknown_icon_is_refused(self) -> None:
        for arguments in ('"copy" blank', '"copy" ""', '"no-such-icon" name'):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments)

    def test_svg_class_reaches_the_svg(self) -> None:
        _html, parsed = render('"chevron-down" name icon_size="md" svg_class="chevron-icon"')
        svg = next(dict(attrs) for tag, attrs in parsed.elements if tag == "svg")
        self.assertIn("chevron-icon", (svg["class"] or "").split())
        self.assertIn("w-5", (svg["class"] or "").split())

    def test_icon_only_and_icon_are_its_own_to_set(self) -> None:
        for arguments in ('"copy" name icon_only=False', '"copy" name icon="x"'):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments)
