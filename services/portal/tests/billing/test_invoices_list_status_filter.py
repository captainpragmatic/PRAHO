"""Regression tests for invoices_list.html's status filter, swapped from a raw <select> to
{% input_field type="select" %} - Phase 4's TMPL003 fix for the billing area.

Content, not status: a status-only check would pass even if the swap dropped the attributes the
filter relies on. Elements are found by tag and name via HTMLParser, not by a page-wide substring
search, so an unrelated element elsewhere on the page cannot satisfy an assertion.

The invoice-detail refund-request modal these tests once covered was removed with the customer
refund flow; tests/billing/test_invoice_refund_removed.py proves it is gone.
"""

from __future__ import annotations

import time
from datetime import timedelta
from html.parser import HTMLParser
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.schemas import BillingDocumentPage


class _TagAttrFinder(HTMLParser):
    """Finds every element of one tag name and records its attributes - list_page_filters.html
    hardcodes hx-sync/hx-indicator on its OWN tabs and search input too, so a page-wide
    substring check for "hx-sync=" is satisfied by those and proves nothing about the select
    this test means to check."""

    def __init__(self, tag_name: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tag_name = tag_name
        self.elements: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == self.tag_name:
            self.elements.append(dict(attrs))


def _element_with_name(html: str, tag_name: str, name: str) -> dict:
    parser = _TagAttrFinder(tag_name)
    parser.feed(html)
    matches = [el for el in parser.elements if el.get("name") == name]
    assert matches, f"no <{tag_name} name={name!r}> found; {tag_name}s seen: {parser.elements}"
    assert len(matches) == 1, f"expected exactly one <{tag_name} name={name!r}>, found {len(matches)}"
    return matches[0]


class InvoicesListStatusFilterTests(TestCase):
    """invoices/partials/invoice_extra_filters.html's <select>, swapped to
    {% input_field type="select" %}. hx-sync/hx-indicator did not exist on input_field before
    Phase 4 - losing either would let a stale in-flight filter request race a newer one, or
    leave the loading skeleton stuck forever."""

    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["session_auth_hash"] = "test-session"
        session["validated_at"] = now.isoformat()
        session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_status_select_keeps_its_htmx_wiring(self, mock_fetch) -> None:
        """list_page_filters.html hardcodes hx-sync/hx-indicator on its own tabs and search
        input too - this must check the status <select> specifically, or a page-wide substring
        match would pass even if this exact select lost every one of these attributes."""
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"))

        self.assertEqual(response.status_code, 200)
        select = _element_with_name(response.content.decode(), "select", "status")
        self.assertEqual(select.get("hx-get"), reverse("billing:invoices_search_api"))
        self.assertEqual(select.get("hx-target"), "#invoices-content")
        self.assertEqual(select.get("hx-sync"), "closest .list-filters-sync:replace")
        self.assertEqual(select.get("hx-trigger"), "change")
        self.assertEqual(select.get("hx-include"), "#list-filter-search, #list-filter-active-tab")
        self.assertEqual(select.get("hx-indicator"), "#invoices-skeleton")
        self.assertIn("list-filter-extra-select", select.get("class", ""))

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_selected_status_is_marked_selected_on_the_right_option(self, mock_fetch) -> None:
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"), {"status": "paid"})

        content = response.content.decode()
        self.assertIn('<option value="paid" selected>', content)
