"""Ticket links preserve all GET keys, including repeated filters."""

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from tests.common.pagination_assertions import SEARCH, assert_next_query


class TicketPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["account_health_data"] = {"invoice": {}, "services": {}, "tickets": {}}
        session["account_health_fetched_at"] = time.time()
        session.save()

    def check_page(self, route: str) -> None:
        data = {"results": [{"id": 1, "title": "Paging", "status": "open", "priority": "normal"}], "count": 51}
        with (
            patch("apps.tickets.views.tickets_api.get_customer_tickets", return_value=data),
            patch("apps.tickets.views.tickets_api.get_tickets_summary", return_value={"open_tickets": 51}),
        ):
            response = self.client.get(
                reverse(route), {"q": SEARCH, "status": "open", "facet": ["one", "two"], "page": "1"}
            )
        assert_next_query(self, response, {"q": [SEARCH], "status": ["open"], "facet": ["one", "two"]})

    def test_list_next_link_round_trips_filters(self) -> None:
        self.check_page("tickets:list")

    def test_search_next_link_round_trips_filters(self) -> None:
        self.check_page("tickets:search_api")
