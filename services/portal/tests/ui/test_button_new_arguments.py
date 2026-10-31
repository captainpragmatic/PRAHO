"""The button covers the hand-written buttons' needs: icon-only, loading, form actions, input groups, two icons.

Each argument here replaced a raw `<button>` that drifted from the component's look because the component could not
express it. The checks that guard misuse fail loudly: an icon-only button with no accessible name, and a
`formaction` that could leave the site (a dropped one would submit the form to its default action instead).
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


def render(arguments: str, label: str = '"Go"') -> tuple[str, Parser]:
    source = (
        '{% load i18n ui_components %}{% trans "Remove line" as named %}{% button ' + label + " " + arguments + " %}"
    )
    html = Template(source).render(Context())
    parsed = Parser()
    parsed.feed(html)
    return html, parsed


def control(parsed: Parser) -> dict[str, str | None]:
    controls = [dict(attrs) for tag, attrs in parsed.elements if tag in ("button", "a")]
    assert len(controls) == 1, parsed.elements
    return controls[0]


def label_span(parsed: Parser) -> dict[str, str | None]:
    return next(
        dict(attrs)
        for tag, attrs in parsed.elements
        if tag == "span" and "btn-label" in (dict(attrs).get("class") or "")
    )


class LoadingAndDisabledElementTests(SimpleTestCase):
    def test_loading_gives_a_plain_form_button_the_spinner(self) -> None:
        html, _parsed = render('type="submit" loading=True')
        self.assertIn("btn-spinner", html)

    def test_hx_disabled_elt_reaches_the_button(self) -> None:
        _html, parsed = render('hx_post="/x/" hx_disabled_elt="this"')
        self.assertEqual(control(parsed)["hx-disabled-elt"], "this")


class IconOnlyTests(SimpleTestCase):
    def test_the_label_is_for_screen_readers_and_the_name_is_aria_label(self) -> None:
        for extra in ("", ' href="/x/"'):
            with self.subTest(link=bool(extra)):
                _html, parsed = render('icon="x" icon_only=True aria_label=named' + extra)
                self.assertEqual(control(parsed)["aria-label"], "Remove line")
                self.assertIn("sr-only", label_span(parsed)["class"] or "")
                svg = next(dict(attrs) for tag, attrs in parsed.elements if tag == "svg")
                self.assertNotIn("mr-2", svg.get("class") or "")

    def test_attrs_cannot_add_a_second_accessible_name(self) -> None:
        _html, parsed = render('icon="x" icon_only=True aria_label=named attrs=\'aria-label="other"\'')
        names = [name for tag, attrs in parsed.elements if tag == "button" for name, _value in attrs]
        self.assertEqual(names.count("aria-label"), 1)

    def test_an_icon_only_button_needs_a_name_and_an_icon(self) -> None:
        for arguments in (
            'icon="x" icon_only=True',
            'icon="x" icon_only=True aria_label="  "',
            "icon_only=True aria_label=named",
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(TemplateSyntaxError, "icon_only needs"):
                render(arguments)

    def test_label_class_reaches_the_label(self) -> None:
        _html, parsed = render('icon="x" label_class="hidden sm:inline"')
        self.assertIn("hidden sm:inline", label_span(parsed)["class"] or "")


class FormactionTests(SimpleTestCase):
    def test_a_path_on_this_site_is_kept(self) -> None:
        _html, parsed = render('type="submit" formaction="/orders/create/?with=item"')
        self.assertEqual(control(parsed)["formaction"], "/orders/create/?with=item")

    def test_anything_that_could_leave_the_site_stops_the_render(self) -> None:
        for value in (
            "//evil.example/x",
            "/\\\\evil.example/x",
            "/\t/evil.example/x",
            "javascript:alert(1)",
            "https://evil.example/x",
            "orders/create/",
            "",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(TemplateSyntaxError, "formaction must"):
                Template('{% load ui_components %}{% button "Go" type="submit" formaction=value %}').render(
                    Context({"value": value or " "})
                )

    def test_a_link_has_no_formaction(self) -> None:
        with self.assertRaisesRegex(TemplateSyntaxError, "formaction must"):
            render('href="/x/" formaction="/y/"')


class JoinedAndIconTests(SimpleTestCase):
    def test_the_right_half_of_an_input_group_has_only_right_corners(self) -> None:
        _html, parsed = render('joined="right"')
        classes = (control(parsed)["class"] or "").split()
        self.assertIn("rounded-r-lg", classes)
        self.assertIn("rounded-l-none", classes)
        self.assertNotIn("rounded-lg", classes)

    def test_stop_and_play_are_catalog_icons(self) -> None:
        for name in ("stop", "play"):
            with self.subTest(icon=name):
                html = Template("{% load ui_components %}{% icon name %}").render(Context({"name": name}))
                self.assertIn("<path", html)
