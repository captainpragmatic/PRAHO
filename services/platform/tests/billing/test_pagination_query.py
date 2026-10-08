"""Billing pagination preserves encoded and repeated request parameters."""

from datetime import timedelta

from django.http import HttpResponse
from django.template.loader import render_to_string
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice
from apps.customers.models import Customer
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class BillingPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        staff = User.objects.create_user(email="billing-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name=SEARCH, company_name=SEARCH, primary_email="billing@example.test")
        for number in range(26):
            ProformaInvoice.objects.create(
                customer=customer,
                currency=currency,
                number=f"PAGING-{number}",
                valid_until=timezone.now() + timedelta(days=30),
            )

    def check_page(self, route: str) -> None:
        parameters = {"q": SEARCH, "search": SEARCH, "type": "proforma", "facet": ["one", "two"], "page": "1"}
        response = self.client.get(reverse(route), parameters)
        self.assertEqual(response.status_code, 200)
        if route != "billing:billing_list_htmx":
            response = HttpResponse(
                render_to_string(
                    "billing/partials/billing_list.html",
                    {
                        "documents": response.context["documents"],
                        "page_obj": response.context["page_obj"],
                        "extra_params": response.context["extra_params"],
                    },
                )
            )
        assert_next_query(
            self, response, {"q": [SEARCH], "search": [SEARCH], "type": ["proforma"], "facet": ["one", "two"]}
        )

    def test_full_billing_list_next_link_round_trips_filters(self) -> None:
        self.check_page("billing:invoice_list")

    def test_proforma_list_next_link_round_trips_filters(self) -> None:
        self.check_page("billing:proforma_list")

    def test_htmx_billing_list_next_link_round_trips_filters(self) -> None:
        self.check_page("billing:billing_list_htmx")
