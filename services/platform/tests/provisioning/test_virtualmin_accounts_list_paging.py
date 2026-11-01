"""The Virtualmin accounts list pages, filters, and answers its own htmx requests with the table only.

- Pagination never showed: the table checked `is_paginated`/`page_obj`, which the view never passed, so accounts past
  the first page could not be reached. Its links were also `href="?page={{ … }}"` inside a template tag, never filled.
- The filter form posted with htmx into #accounts-container, and the view answered with the full page, so each
  search nested a whole copy of the page inside the list. It also offered a Hosting Plan filter the view ignores,
  while the view's Server filter had no control.
- Sync with no active server redirected; htmx followed it and nested the full page the same way.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.urls import reverse

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.ui.node_harness import Markup

PAGE_SIZE = "apps.provisioning.virtualmin_views.ACCOUNTS_PER_PAGE"


class AccountsListPagingTests(VirtualminViewsFixture):
    def setUp(self) -> None:
        super().setUp()
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="second.example.com",
            domain="second.example.com",
            username="seconduser",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        self.second = VirtualminAccount.objects.create(
            domain="second.example.com",
            service=service,
            server=self.server,
            virtualmin_username="secondexample",
            template_name="Default",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=service.id,
        )
        self.url = reverse("provisioning:virtualmin_accounts")

    def test_the_second_page_is_reachable_and_keeps_the_filters(self) -> None:
        with patch(PAGE_SIZE, 1):
            first = self.client.get(self.url, {"status": "active", "search": "example"})
            links = [attrs.get("href", "") for tag, attrs in Markup(first.content.decode()).elements if tag == "a"]
            page_two = [href for href in links if "page=2" in href]
            self.assertTrue(page_two, "no link to page 2")
            self.assertIn("status=active", page_two[0])
            self.assertIn("search=example", page_two[0])
            self.assertNotIn("{{", first.content.decode())

            second = self.client.get(self.url, {"status": "active", "search": "example", "page": 2})
            domains = {self.account.domain, self.second.domain}
            shown = {d for d in domains if d in second.content.decode()}
            self.assertEqual(len(shown), 1)

    def test_htmx_filtering_answers_with_the_table_only(self) -> None:
        response = self.client.get(self.url, {"search": "second"}, HTTP_HX_REQUEST="true")
        html = response.content.decode()
        self.assertNotIn("<html", html)
        self.assertNotIn('id="accounts-container"', html)
        self.assertIn(self.second.domain, html)
        self.assertNotIn(self.account.domain, html)

    def test_the_filter_form_offers_exactly_the_filters_the_view_applies(self) -> None:
        page = Markup(self.client.get(self.url).content.decode())
        names = {attrs.get("name") for tag, attrs in page.elements if tag in ("input", "select") and attrs.get("name")}
        self.assertEqual(names & {"search", "status", "server", "plan"}, {"search", "status", "server"})
        server_options = {attrs.get("value") for tag, attrs in page.elements if tag == "option"}
        self.assertIn(str(self.server.pk), server_options)

    def test_htmx_sync_with_no_active_server_goes_to_the_list_as_a_page(self) -> None:
        VirtualminServer.objects.update(status="disabled")
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["HX-Redirect"], self.url)

    def test_filtering_updates_the_bulk_actions_link_too(self) -> None:
        response = self.client.get(self.url, {"server": str(self.server.pk)}, HTTP_HX_REQUEST="true")
        oob = [a for t, a in Markup(response.content.decode()).elements if a.get("hx-swap-oob")]
        self.assertEqual(len(oob), 1)
        self.assertEqual(oob[0].get("id"), "bulk-actions-link")
        self.assertIn(f"server={self.server.pk}", response.content.decode())

    def test_an_empty_search_still_offers_a_working_create_account(self) -> None:
        response = self.client.get(self.url, {"search": "no-such-account"}, HTTP_HX_REQUEST="true")
        links = [a.get("href") for t, a in Markup(response.content.decode()).elements if t == "a"]
        self.assertIn(reverse("provisioning:virtualmin_account_new"), links)
