"""Customer pagination must separate the page and encoded filter parameters."""

from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class CustomerPaginationQueryTests(TestCase):
    def test_list_next_link_round_trips_filters(self) -> None:
        staff = User.objects.create_user(email="customer-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        for number in range(26):
            Customer.objects.create(
                name=f"{SEARCH} {number}", primary_email=f"customer-{number}@example.test", status="active"
            )
        response = self.client.get(
            reverse("customers:list"), {"q": SEARCH, "status": "active", "facet": ["one", "two"], "page": "1"}
        )
        assert_next_query(self, response, {"q": [SEARCH], "status": ["active"], "facet": ["one", "two"]})
