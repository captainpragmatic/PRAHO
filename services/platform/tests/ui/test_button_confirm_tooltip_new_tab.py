"""The button component carries confirmation text, a tooltip and a new tab itself.

Without these arguments, every button that opens the dangerous-action modal or explains why it is
disabled was written by hand beside the component, each with its own classes. Values arrive the way
templates pass them, through `{% trans … as v %}`, which marks them safe: the component must escape them
once, and callers must not escape them first.
"""

from html.parser import HTMLParser

from django.template import Context, Template
from django.test import SimpleTestCase

TRICKY = 'Say "yes" & it\'s <b>done</b>; Fish &amp; chips'


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[list[tuple[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("button", "a"):
            self.controls.append(attrs)


def render(arguments: str) -> tuple[str, dict[str, str | None], list[tuple[str, str | None]]]:
    source = (
        "{% load i18n ui_components %}"
        '{% trans "' + TRICKY.replace('"', '\\"') + '" as tricky %}'
        '{% button "Go" ' + arguments + " %}"
    )
    html = Template(source).render(Context())
    parsed = Parser()
    parsed.feed(html)
    assert len(parsed.controls) == 1, html
    return html, dict(parsed.controls[0]), parsed.controls[0]


class ConfirmationArgumentsTests(SimpleTestCase):
    def test_translated_confirmation_text_reaches_the_modal_exactly_as_written(self) -> None:
        _html, attrs, _raw = render(
            'data_action="confirm-dangerous" confirm_title=tricky confirm_message=tricky '
            'confirm_text=tricky submit_form="status-form-suspend"'
        )
        self.assertEqual(attrs["data-action"], "confirm-dangerous")
        for name in ("data-title", "data-message", "data-confirm-text"):
            self.assertEqual(attrs[name], TRICKY, name)
        self.assertEqual(attrs["data-submit-form"], "status-form-suspend")

    def test_translated_text_cannot_break_out_of_its_attribute(self) -> None:
        html, _attrs, _raw = render("confirm_message=tricky")
        self.assertNotIn("<b>", html)
        self.assertIn("&lt;b&gt;", html)

    def test_title_is_a_tooltip_on_links_and_buttons(self) -> None:
        for extra in ("", ' href="/x/"'):
            _html, attrs, _raw = render("title=tricky" + extra)
            self.assertEqual(attrs["title"], TRICKY, extra or "button")

    def test_attrs_cannot_add_a_second_copy_of_an_owned_attribute(self) -> None:
        _html, _attrs, raw = render(
            "title=tricky confirm_title=tricky "
            'attrs=\'title="other" data-title="other" data-message="other" '
            'data-confirm-text="other" data-submit-form="other" data-ok="kept"\''
        )
        names = [name for name, _value in raw]
        for owned in ("title", "data-title", "data-message", "data-confirm-text", "data-submit-form"):
            self.assertLessEqual(names.count(owned), 1, owned)
        self.assertEqual(dict(raw)["title"], TRICKY)
        self.assertEqual(dict(raw)["data-title"], TRICKY)
        self.assertEqual(dict(raw)["data-ok"], "kept")

    def test_defaults_render_none_of_the_new_attributes(self) -> None:
        for extra in ("", ' href="/x/"'):
            _html, attrs, _raw = render('variant="secondary"' + extra)
            for name in (
                "title",
                "data-title",
                "data-message",
                "data-confirm-text",
                "data-submit-form",
                "target",
                "rel",
            ):
                self.assertNotIn(name, attrs, f"{name} {extra or 'button'}")


class NewTabTests(SimpleTestCase):
    def test_a_link_opens_in_a_new_tab_without_a_handle_on_this_one(self) -> None:
        _html, attrs, _raw = render('href="/customers/1/" new_tab=True')
        self.assertEqual(attrs["href"], "/customers/1/")
        self.assertEqual(attrs["target"], "_blank")
        self.assertEqual(attrs["rel"], "noopener")

    def test_a_button_has_no_tab_to_open(self) -> None:
        _html, attrs, _raw = render("new_tab=True")
        self.assertNotIn("target", attrs)
        self.assertNotIn("rel", attrs)
