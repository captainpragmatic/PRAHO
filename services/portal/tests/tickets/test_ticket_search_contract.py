"""The ticket URL contract must survive real rendering and Platform-style paging."""

from __future__ import annotations

from copy import deepcopy
from html.parser import HTMLParser
from typing import TypedDict, cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from django.conf import settings
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import resolve, reverse

from apps.api_client.services import PlatformAPIError
from apps.common.localisation import LocalisationDefaults
from apps.tickets.services import TicketFilters, TicketsAPIClient


class _TicketRow(TypedDict):
    id: int
    customer_id: int
    title: str
    description: str
    ticket_number: str
    status: str
    priority: str
    created_at: str


def _row(ticket_id: int, customer_id: int, title: str) -> _TicketRow:
    return {
        "id": ticket_id,
        "customer_id": customer_id,
        "title": title,
        "description": "Support request",
        "ticket_number": f"T-{ticket_id}",
        "status": "open",
        "priority": "high",
        "created_at": "2026-10-01T12:00:00Z",
    }


class _PagedPlatform:
    """Fake only the HTTP boundary; retain the real portal API adapter."""

    def __init__(self) -> None:
        self.rows = [
            _row(901, 2, "hosting & mail+é"),
            _row(900, 1, "Unrelated request"),
            *[_row(ticket_id, 1, "hosting & mail+é") for ticket_id in range(1, 46)],
            _row(902, 2, "hosting & mail+é"),
        ]
        self.requests: list[dict[str, object]] = []

    def request(
        self, method: str, endpoint: str, data: dict[str, object] | None = None, **_kwargs: object
    ) -> dict[str, object]:
        if method != "POST" or endpoint != "/tickets/" or data is None:
            raise AssertionError(f"Unexpected transport request: {method} {endpoint}")
        self.requests.append(dict(data))
        customer_id = int(str(data["customer_id"]))
        query = str(data.get("search", "")).strip().casefold()
        rows = [
            row
            for row in self.rows
            if row["customer_id"] == customer_id
            and (not data.get("status") or row["status"] == data["status"])
            and (not data.get("priority") or row["priority"] == data["priority"])
            and any(
                query in value.casefold()
                for value in (row["title"], row["description"], row["ticket_number"], row["status"])
            )
        ]
        # Platform reads page + limit, defaults to 20, and slices by offset.
        try:
            page = int(str(data.get("page", 1)))
            limit = min(int(str(data.get("limit", 20))), 100)
        except (ValueError, TypeError):
            page, limit = 1, 20
        page = max(page, 1)
        offset = (page - 1) * limit
        pages = (len(rows) + limit - 1) // limit
        return {
            "success": True,
            "data": {
                "tickets": rows[offset : offset + limit],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": len(rows),
                    "pages": pages,
                    "has_next": page < pages,
                    "has_previous": page > 1,
                },
            },
        }


class _TicketHTML(HTMLParser):
    def __init__(self, content: bytes) -> None:
        super().__init__(convert_charrefs=True)
        self.ticket_ids: list[int] = []
        self.links: list[dict[str, str]] = []
        self.search: dict[str, str] = {}
        self.feed(content.decode())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value for key, value in attrs if value is not None}
        # Only desktop rows: the same ticket is also rendered as a mobile card.
        if tag == "tr" and "data-href" in attributes:
            self.ticket_ids.append(int(urlsplit(attributes["data-href"]).path.rstrip("/").rsplit("/", 1)[1]))
        if tag == "a" and attributes.get("data-slot") == "pagination-link":
            self.links.append(attributes)
        if tag == "input" and attributes.get("id") == "list-filter-search":
            self.search = attributes


_TEST_TEMPLATES = deepcopy(settings.TEMPLATES)
cast(dict[str, object], _TEST_TEMPLATES[0]["OPTIONS"])["context_processors"] = [
    "django.template.context_processors.request",
    "django.template.context_processors.i18n",
]


@override_settings(TEMPLATES=_TEST_TEMPLATES, LANGUAGE_CODE="en")
class TicketSearchContractTests(SimpleTestCase):
    def setUp(self) -> None:
        self.platform = _PagedPlatform()
        self.enterContext(
            patch("apps.tickets.services.TicketsAPIClient._make_request", side_effect=self.platform.request)
        )
        self.enterContext(
            patch("apps.tickets.views.tickets_api.get_tickets_summary", return_value={"open_tickets": 45})
        )
        self.enterContext(
            patch(
                "apps.common.localisation_services.api_client.get_localisation_defaults",
                return_value={"success": True, "localisation": LocalisationDefaults().customer_payload()},
            )
        )

    def _render(self, url: str, *, htmx: bool = False) -> _TicketHTML:
        request = RequestFactory().get(url, headers={"HX-Request": "true"} if htmx else {})
        request.session = SessionStore()
        request.session.update({"customer_id": 1, "user_id": 7})
        request._messages = FallbackStorage(request)
        match = resolve(urlsplit(url).path)
        response: HttpResponse = match.func(request, **match.kwargs)
        self.assertEqual(response.status_code, 200)
        return _TicketHTML(response.content)

    def _url(self, route: str, *, page: int = 1, query: str = "hosting") -> str:
        return reverse(route) + "?" + urlencode({"q": query, "status": "open", "priority": "high", "page": page})

    def test_full_page_forwards_q_and_renders_only_matching_own_tickets(self) -> None:
        page = self._render(self._url("tickets:list"))
        self.assertEqual(page.ticket_ids, list(range(1, 21)))
        self.assertEqual(self.platform.requests[-1]["search"], "hosting")
        self.assertEqual(page.search["name"], "q")
        self.assertEqual(page.search["value"], "hosting")

    def test_htmx_forwards_q_and_renders_only_matching_own_tickets(self) -> None:
        """Coverage addition: HTMX already translates URL q to the signed search field."""
        page = self._render(self._url("tickets:search_api"), htmx=True)
        self.assertEqual(page.ticket_ids, list(range(1, 21)))
        self.assertEqual(self.platform.requests[-1]["search"], "hosting")
        self.assertEqual(self.platform.requests[-1]["customer_id"], 1)
        self.assertEqual(self.platform.requests[-1]["user_id"], 7)

    def test_api_adapter_sends_limit_and_returns_the_requested_slice(self) -> None:
        result = TicketsAPIClient().get_customer_tickets(1, 7, TicketFilters(page=2, search="hosting"))
        self.assertEqual(self.platform.requests[-1].get("limit"), 20)
        self.assertNotIn("page_size", self.platform.requests[-1])
        self.assertEqual([row["id"] for row in result["results"]], list(range(21, 41)))
        self.assertEqual(result["count"], 45)

    def _walk_rendered_links(self, *, htmx: bool) -> None:
        query = "hosting & mail+é"
        url = self._url("tickets:search_api" if htmx else "tickets:list", query=query)
        seen: list[int] = []
        for page_number, expected in enumerate((list(range(1, 21)), list(range(21, 41)), list(range(41, 46))), 1):
            page = self._render(url, htmx=htmx)
            self.assertEqual(page.ticket_ids, expected)
            self.assertTrue(set(page.ticket_ids).isdisjoint(seen))
            seen.extend(page.ticket_ids)
            for link in page.links:
                params = parse_qs(urlsplit(link["href"]).query)
                self.assertEqual(params.get("q"), [query])
                self.assertNotIn("search", params)
                self.assertEqual(params["status"], ["open"])
                self.assertEqual(params["priority"], ["high"])
            next_links = [link for link in page.links if link.get("aria-label") == "Go to next page"]
            self.assertEqual(len(next_links), 1 if page_number < 3 else 0)
            if next_links:
                # Resolve the rendered href; never construct a page URL in the traversal.
                url = urljoin(url, next_links[0]["href"])
        self.assertEqual(seen, list(range(1, 46)))
        self.assertEqual(len(set(seen)), 45)
        self.assertTrue({900, 901, 902}.isdisjoint(seen))

    def test_full_page_filtered_paging_follows_rendered_hrefs_without_gaps(self) -> None:
        self._walk_rendered_links(htmx=False)

    def test_htmx_filtered_paging_follows_rendered_hrefs_without_gaps(self) -> None:
        self._walk_rendered_links(htmx=True)

    def test_htmx_honours_page_two_with_the_filter(self) -> None:
        page = self._render(self._url("tickets:search_api", page=2), htmx=True)
        self.assertEqual(page.ticket_ids, list(range(21, 41)))

    def test_full_page_next_link_loads_the_matching_htmx_slice(self) -> None:
        url = self._url("tickets:list")
        page = self._render(url)
        next_links = [link for link in page.links if link.get("aria-label") == "Go to next page"]
        self.assertEqual(len(next_links), 1)
        link = next_links[0]
        self.assertEqual(link.get("hx-target"), "#tickets-content")
        htmx_url = link["hx-get"]
        self.assertEqual(urlsplit(htmx_url).path, reverse("tickets:search_api"))
        self.assertEqual(parse_qs(urlsplit(htmx_url).query), parse_qs(urlsplit(link["href"]).query))
        self.assertEqual(self._render(htmx_url, htmx=True).ticket_ids, list(range(21, 41)))

    def test_search_placeholder_names_only_supported_fields(self) -> None:
        page = self._render(self._url("tickets:list"))
        self.assertEqual(page.search["placeholder"], "Search by ticket number, subject, description, or status…")

    def test_error_page_search_placeholder_names_only_supported_fields(self) -> None:
        with patch(
            "apps.tickets.views.tickets_api.get_customer_tickets",
            side_effect=PlatformAPIError("Request failed", status_code=500),
        ):
            page = self._render(self._url("tickets:list"))
        self.assertEqual(page.search["placeholder"], "Search by ticket number, subject, description, or status…")
