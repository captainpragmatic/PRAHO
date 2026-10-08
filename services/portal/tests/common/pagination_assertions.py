"""Assertions for rendered pagination URLs."""

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from django.http import HttpResponse
from django.test import SimpleTestCase
from django.utils.translation import gettext

SEARCH = "a&b c+d#e"


class _PaginationLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "a" and attributes.get("aria-label") == gettext("Go to next page"):
            self.links.append(attributes)


def assert_next_query(case: SimpleTestCase, response: HttpResponse, expected: dict[str, list[str]]) -> None:
    case.assertEqual(response.status_code, 200)
    parser = _PaginationLinks()
    parser.feed(response.content.decode())
    case.assertTrue(parser.links, "The response must render a next-page link")
    for link in parser.links:
        href = link.get("href")
        case.assertIsNotNone(href)
        parts = urlsplit(href or "")
        case.assertEqual(parts.fragment, "")
        case.assertEqual(parse_qs(parts.query, keep_blank_values=True), {"page": ["2"], **expected})
        if link.get("hx-get"):
            htmx_parts = urlsplit(link["hx-get"] or "")
            case.assertEqual(htmx_parts.fragment, "")
            case.assertEqual(parse_qs(htmx_parts.query, keep_blank_values=True), {"page": ["2"], **expected})
