"""Billing list and HTMX links round-trip the request query."""

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.schemas import BillingDocumentPage, Currency, Invoice
from apps.common.account_health import remember_account_health
from tests.common.pagination_assertions import SEARCH, assert_next_query


class BillingPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["email"] = "owner@example.test"
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        # A fresh banner cache for the active customer keeps the banner fetch off the network.
        remember_account_health(session, 42, {}, {}, {})
        session.save()

    def check_page(self, route: str) -> None:
        document = Invoice(
            id=1,
            number="PAGING",
            status="issued",
            currency=Currency(id=1, code="RON", name="Leu"),
            exchange_to_ron=None,
            subtotal_cents=1000,
            tax_cents=0,
            total_cents=1000,
            issued_at=None,
            due_at=None,
            created_at=timezone.now(),
            updated_at=None,
            locked_at=None,
            sent_at=None,
            paid_at=None,
        )
        page = BillingDocumentPage(documents=[document], total_items=21, invoice_count=21)
        with patch("apps.billing.views.InvoiceViewService.get_customer_documents", return_value=page):
            response = self.client.get(
                reverse(route),
                {"q": SEARCH, "status": "issued", "type": "invoice", "facet": ["one", "two"], "page": "1"},
            )
        assert_next_query(
            self, response, {"q": [SEARCH], "status": ["issued"], "type": ["invoice"], "facet": ["one", "two"]}
        )

    def test_list_next_link_round_trips_filters(self) -> None:
        self.check_page("billing:invoices_list")

    def test_search_next_link_round_trips_filters(self) -> None:
        self.check_page("billing:invoices_search_api")
