"""The portal's own copy of the button arguments reaches the shared template (see the Platform twin).

Both services keep a ButtonConfig and a tag context of their own over one shared button.html; an argument
missing from the portal copy would be dropped there silently.
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


def render(arguments: str) -> list[tuple[str, str | None]]:
    source = (
        '{% load i18n ui_components %}{% trans "' + TRICKY.replace('"', '\\"') + '" as tricky %}'
        '{% button "Go" ' + arguments + " %}"
    )
    parsed = Parser()
    parsed.feed(Template(source).render(Context()))
    assert len(parsed.controls) == 1
    return parsed.controls[0]


class PortalButtonArgumentTests(SimpleTestCase):
    def test_every_new_argument_reaches_the_page_once_and_exactly(self) -> None:
        raw = render(
            'href="/x/" new_tab=True title=tricky confirm_title=tricky confirm_message=tricky confirm_text=tricky '
            'submit_form="f-1" attrs=\'title="other" data-title="other"\''
        )
        names = [name for name, _value in raw]
        attrs = dict(raw)
        for name in ("title", "data-title", "data-message", "data-confirm-text"):
            self.assertEqual(names.count(name), 1, name)
            self.assertEqual(attrs[name], TRICKY, name)
        self.assertEqual(attrs["data-submit-form"], "f-1")
        self.assertEqual((attrs["target"], attrs["rel"]), ("_blank", "noopener"))
