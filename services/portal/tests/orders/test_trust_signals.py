"""Regression coverage for the rendered responsive trust badge contract."""

from __future__ import annotations

from html.parser import HTMLParser

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import translation


class _BadgeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[dict[str, str]] = []
        self.badges: list[tuple[dict[str, str], dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"path", "circle", "rect", "line", "polyline", "polygon", "ellipse"}:
            self.stack.append({name: value or "" for name, value in attrs})

    def handle_endtag(self, tag: str) -> None:
        if tag not in {"path", "circle", "rect", "line", "polyline", "polygon", "ellipse"}:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if data.strip() == "Romanian Data Center":
            index = next(
                index for index, attrs in enumerate(self.stack) if "inline-flex" in attrs.get("class", "").split()
            )
            self.badges.append((self.stack[index - 1], self.stack[index]))


class TrustSignalsTests(SimpleTestCase):
    def test_data_center_badge_is_hidden_below_sm_and_visible_from_sm(self) -> None:
        with translation.override("en"):
            markup = render_to_string("orders/partials/trust_signals.html")
        parser = _BadgeParser()
        parser.feed(markup)
        self.assertEqual(len(parser.badges), 1)
        wrapper, badge = parser.badges[0]
        self.assertEqual(wrapper["class"].split(), ["hidden", "sm:block"])
        self.assertIn("inline-flex", badge["class"].split())
        self.assertNotIn("hidden", badge["class"].split())
