"""Every request that fills a results region is synchronised on that region (#751 follow-up, LOW hx-sync).

htmx inherits hx-sync, and `this` names the element that declares it. The product results container
declared `this:drop`, so every toggle and pagination link inside it synced on the container and a click
during a filter request was dropped. Billing, audit and GDPR filter forms declared nothing, so a filter
response and the region's initial load (or a page change) could land out of order. Product filters queue
the latest selection behind the initial load, so that load is not aborted and the newest selection wins.
Other filter forms, search boxes and pagination links replace their region's in-flight request. Action
toggles sync on themselves, so a filter never cancels them and a double click does not toggle twice.
"""

from __future__ import annotations

from html.parser import HTMLParser

from django.template import Context, Template
from django.test import TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.products.models import Product
from apps.users.models import User

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _Requests(HTMLParser):
    """Each element that issues a request, with its own and its effective (inherited) hx-sync."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.found: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if "hx-get" in values or "hx-post" in values:
            inherited = next((a["hx-sync"] for _, a in reversed(self.stack) if "hx-sync" in a), None)
            self.found.append(
                {
                    "tag": tag,
                    "id": values.get("id"),
                    "url": values.get("hx-get") or values.get("hx-post"),
                    "href": values.get("href"),
                    "target": values.get("hx-target"),
                    "own": values.get("hx-sync"),
                    "effective": values.get("hx-sync", inherited),
                }
            )
        if tag not in VOID:
            self.stack.append((tag, values))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


def _requests(html: str) -> list[dict[str, str | None]]:
    parser = _Requests()
    parser.feed(html)
    return parser.found


class ResultsRegionSyncTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="sync-admin@example.com", password="Sync-pass123!", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.admin)

    def _page(self, name: str, query: str = "", *, htmx: bool = False) -> list[dict[str, str | None]]:
        headers = {"HTTP_HX_REQUEST": "true"} if htmx else {}
        response = self.client.get(reverse(name) + query, **headers)
        self.assertEqual(response.status_code, 200)
        return _requests(response.content.decode())

    def test_the_product_filters_queue_the_latest_selection_and_nothing_inherits_a_drop(self) -> None:
        found = self._page("products:product_list")
        (container,) = [r for r in found if r["id"] == "product-results"]
        self.assertIsNone(container["own"], "the results container declares no sync for its children to inherit")
        (form,) = [r for r in found if r["tag"] == "form" and r["target"] == "#product-results"]
        self.assertEqual(form["own"], "#product-results:queue last")

    def test_product_toggles_sync_on_themselves_and_pages_replace_with_an_encoded_search(self) -> None:
        Product.objects.bulk_create(
            Product(name=f"Plan a&b {index}", slug=f"plan-{index}", product_type="shared_hosting")
            for index in range(21)
        )
        found = self._page("products:product_list_htmx", "?search=a%26b", htmx=True)
        toggles = [r for r in found if r["url"] and "/toggle-" in r["url"]]
        self.assertGreaterEqual(len(toggles), 4)
        self.assertEqual({r["own"] for r in toggles}, {"this:drop"})
        pages = [r for r in found if r["target"] == "#product-results" and r["tag"] == "a"]
        self.assertTrue(pages)
        self.assertEqual({r["own"] for r in pages}, {"#product-results:replace"})
        for page in pages:
            self.assertIn("search=a%26b", page["url"] or "")
            self.assertIn("search=a%26b", page["href"] or "")

    def test_a_swapped_in_toggle_keeps_its_own_sync(self) -> None:
        product = Product.objects.create(name="Toggle", slug="toggle", product_type="shared_hosting")
        response = self.client.post(f"/products/{product.slug}/toggle-active/", HTTP_HX_REQUEST="true")
        (toggle,) = _requests(response.content.decode())
        self.assertEqual(toggle["own"], "this:drop")

    def test_billing_filters_replace_the_regions_request(self) -> None:
        found = self._page("billing:invoice_list")
        (form,) = [r for r in found if r["tag"] == "form" and r["target"] == "#billing-results"]
        self.assertEqual(form["own"], "#billing-results:replace")

    def test_audit_filters_apply_button_and_pages_replace_the_regions_request(self) -> None:
        found = self._page("audit:logs")
        region = [r for r in found if r["target"] == "#audit-results"]
        self.assertEqual(len(region), 2, "the filter form and the Apply button")
        self.assertEqual({r["own"] for r in region}, {"#audit-results:replace"})
        for index in range(3):
            AuditEvent.objects.create(action="login_success", category="authentication", severity="low",
                                      description=f"event {index}")
        pages = [r for r in self._page("audit:logs_list", "?page_size=1", htmx=True)
                 if r["target"] == "#audit-results"]
        self.assertTrue(pages)
        self.assertEqual({r["own"] for r in pages}, {"#audit-results:replace"})

    def test_gdpr_filters_replace_the_regions_request(self) -> None:
        found = self._page("audit:gdpr_management_dashboard")
        (form,) = [r for r in found if r["tag"] == "form" and r["target"] == "#gdpr-results"]
        self.assertEqual(form["own"], "#gdpr-results:replace")

    def test_the_settings_search_replaces_its_own_request(self) -> None:
        found = self._page("settings:home")
        (search,) = [r for r in found if r["target"] == "#search-results"]
        self.assertEqual(search["own"], "this:replace")


class PaginationSyncTests(TestCase):
    def test_the_pagination_component_carries_the_sync_it_is_given(self) -> None:
        from django.core.paginator import Paginator  # noqa: PLC0415

        page = Paginator(list(range(30)), 10).get_page(2)
        template = Template(
            "{% include 'components/pagination.html' with page_obj=page htmx_target='#r' htmx_url='/x/' "
            "htmx_sync='#r:replace' %}"
        )
        links = [r for r in _requests(template.render(Context({"page": page}))) if r["target"] == "#r"]
        self.assertGreaterEqual(len(links), 3)
        self.assertEqual({r["own"] for r in links}, {"#r:replace"})

    def test_gdpr_pages_pass_the_regions_sync(self) -> None:
        from pathlib import Path  # noqa: PLC0415

        from django.conf import settings  # noqa: PLC0415

        source = (Path(settings.BASE_DIR) / "templates/audit/partials/gdpr_export_requests_list.html").read_text()
        self.assertIn("htmx_sync='#gdpr-results:replace'", source)

    def test_billing_pages_pass_the_regions_sync(self) -> None:
        from pathlib import Path  # noqa: PLC0415

        from django.conf import settings  # noqa: PLC0415

        source = (Path(settings.BASE_DIR) / "templates/billing/partials/billing_list.html").read_text()
        self.assertIn("htmx_target='#billing-results' htmx_url=billing_url htmx_sync='#billing-results:replace'", source)
