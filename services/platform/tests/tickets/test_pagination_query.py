"""Ticket pagination preserves the original GET query."""

from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class TicketPaginationQueryTests(TestCase):
    def test_list_next_link_round_trips_filters(self) -> None:
        staff = User.objects.create_user(email="ticket-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        customer = Customer.objects.create(name=SEARCH, primary_email="tickets@example.test")
        for number in range(26):
            Ticket.objects.create(
                customer=customer, title=f"{SEARCH} {number}", description="Pagination", status="open"
            )
        response = self.client.get(
            reverse("tickets:list"),
            {"q": SEARCH, "search": SEARCH, "status": "open", "facet": ["one", "two"], "page": "1"},
        )
        assert_next_query(
            self, response, {"q": [SEARCH], "search": [SEARCH], "status": ["open"], "facet": ["one", "two"]}
        )
