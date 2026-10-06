"""Service list and HTMX links preserve encoded filters."""

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from tests.common.pagination_assertions import SEARCH, assert_next_query


class ServicePaginationQueryTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["account_health_data"] = {"invoice": {}, "services": {}, "tickets": {}}
        session["account_health_fetched_at"] = time.time()
        session.save()

    def check_page(self, route: str) -> None:
        data = {
            "results": [
                {
                    "id": 1,
                    "service_name": "Paging",
                    "status": "active",
                    "currency_code": "RON",
                    "service_plan_type_display": "Hosting",
                    "monthly_price": "1.00",
                }
            ],
            "count": 21,
        }
        with (
            patch("apps.services.views.services_api.get_customer_services", return_value=data),
            patch("apps.services.views.services_api.get_services_summary", return_value={"active_services": 21}),
        ):
            response = self.client.get(
                reverse(route), {"q": SEARCH, "status": "active", "facet": ["one", "two"], "page": "1"}
            )
        assert_next_query(self, response, {"q": [SEARCH], "status": ["active"], "facet": ["one", "two"]})

    def test_list_next_link_round_trips_filters(self) -> None:
        self.check_page("services:list")

    def test_search_next_link_round_trips_filters(self) -> None:
        self.check_page("services:search_api")
