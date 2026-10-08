"""Order pagination preserves the complete filter query."""

from django.test import TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class OrderPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        staff = User.objects.create_user(email="order-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name=SEARCH, company_name=SEARCH, primary_email="orders@example.test")
        for number in range(16):
            Order.objects.create(customer=customer, currency=currency, order_number=f"PAGING-{number}")

    def check_page(self, route: str) -> None:
        parameters = {"q": SEARCH, "search": SEARCH, "status": "draft", "facet": ["one", "two"], "page": "1"}
        response = self.client.get(reverse(route), parameters)
        assert_next_query(
            self, response, {"q": [SEARCH], "search": [SEARCH], "status": ["draft"], "facet": ["one", "two"]}
        )

    def test_full_list_next_link_round_trips_filters(self) -> None:
        self.check_page("orders:order_list")

    def test_htmx_list_next_link_round_trips_filters(self) -> None:
        self.check_page("orders:order_list_htmx")
