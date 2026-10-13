"""Assertions for rendered pagination URLs."""

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from django.http import HttpResponse
from django.test import SimpleTestCase
from django.urls import Resolver404, resolve
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


def _assert_htmx_path(case: SimpleTestCase, path: str, htmx_view: str | None) -> None:
    """An HTMX page link's path must reach a view; an empty path means the current page."""
    if not path and htmx_view is None:
        return
    try:
        match = resolve(path)
    except Resolver404:
        case.fail(f"The next-page hx-get goes to {path!r}, which no URL pattern serves")
    if htmx_view is not None:
        case.assertEqual(match.view_name, htmx_view, f"The next-page hx-get goes to {path!r}")


def assert_next_query(
    case: SimpleTestCase,
    response: HttpResponse,
    expected: dict[str, list[str]],
    *,
    htmx_view: str | None = None,
) -> None:
    """The next-page link keeps the query; with `htmx_view`, its hx-get must reach that view."""
    case.assertEqual(response.status_code, 200)
    parser = _PaginationLinks()
    parser.feed(response.content.decode())
    case.assertTrue(parser.links, "The response must render a next-page link")
    if htmx_view is not None:
        case.assertTrue(any(link.get("hx-get") for link in parser.links), "The next-page link must use HTMX")
    for link in parser.links:
        href = link.get("href")
        case.assertIsNotNone(href)
        parts = urlsplit(href or "")
        case.assertEqual(parts.fragment, "")
        case.assertEqual(parse_qs(parts.query, keep_blank_values=True), {"page": ["2"], **expected})
        if link.get("hx-get"):
            htmx_parts = urlsplit(link["hx-get"] or "")
            _assert_htmx_path(case, htmx_parts.path, htmx_view)
            case.assertEqual(htmx_parts.fragment, "")
            case.assertEqual(parse_qs(htmx_parts.query, keep_blank_values=True), {"page": ["2"], **expected})


def next_page_url(case: SimpleTestCase, response: HttpResponse) -> str:
    """Return the actual rendered Next href for a follow-up client request."""
    case.assertEqual(response.status_code, 200)
    parser = _PaginationLinks()
    parser.feed(response.content.decode())
    case.assertTrue(parser.links, "The response must render a next-page link")
    href = parser.links[0].get("href")
    case.assertIsNotNone(href)
    case.assertTrue(href)
    return href or ""
