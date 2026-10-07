"""Both services share pagination with distinct request and browser-history URLs."""

from __future__ import annotations

from html.parser import HTMLParser

from django.core.paginator import Paginator
from django.template.loader import render_to_string
from django.test import SimpleTestCase


class _PaginationHTML(HTMLParser):
    def __init__(self, content: str) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.feed(content)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value for name, value in attrs if value is not None}
        if tag == "a" and attributes.get("data-slot") == "pagination-link":
            self.links.append(attributes)


class PaginationPushURLTests(SimpleTestCase):
    def test_separate_push_url_covers_all_navigation_branches_and_preserves_defaults(self) -> None:
        paginator = Paginator(range(100), 10)
        params = "&q=hosting%20%26%20mail%2B%C3%A9&status=open&priority=high"
        for page_number in (1, 5, 10):
            context = {
                "page_obj": paginator.page(page_number),
                "extra_params": params,
                "htmx_target": "#results",
                "htmx_url": "/tickets/search/",
                "push_url": "/tickets/",
            }
            with self.subTest(page=page_number):
                links = _PaginationHTML(render_to_string("components/pagination.html", context)).links
                navigation = [link for link in links if "hx-get" in link]
                self.assertEqual(len(navigation), 4 if page_number in (1, 10) else 8)
                for link in navigation:
                    with self.subTest(href=link["href"]):
                        self.assertEqual(link["hx-get"], "/tickets/search/" + link["href"])
                        self.assertEqual(link["hx-target"], "#results")
                        self.assertEqual(link.get("hx-push-url"), "/tickets/" + link["href"])
                # Existing callers retain the request-URL history behavior.
                context.pop("push_url")
                default_links = _PaginationHTML(render_to_string("components/pagination.html", context)).links
                self.assertEqual(
                    [link["hx-push-url"] for link in default_links if "hx-get" in link],
                    ["true"] * len(navigation),
                )
                context.pop("htmx_target")
                plain_links = _PaginationHTML(render_to_string("components/pagination.html", context)).links
                self.assertEqual([link for link in plain_links if "hx-push-url" in link], [])
