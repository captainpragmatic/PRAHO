"""Coverage addition: domain pagination already encodes the entire QueryDict."""

from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class DomainPaginationQueryTests(TestCase):
    def test_admin_list_next_link_round_trips_filters(self) -> None:
        staff = User.objects.create_user(email="domain-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        customer = Customer.objects.create(name=SEARCH, primary_email="domains@example.test")
        registrar = Registrar.objects.create(name="paging", display_name="Paging")
        tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        Domain.objects.bulk_create(
            [
                Domain(name=f"paging-{number}.test", customer=customer, registrar=registrar, tld=tld)
                for number in range(51)
            ]
        )
        response = self.client.get(
            reverse("domains:admin_list"),
            {"q": SEARCH, "search": SEARCH, "status": "pending", "facet": ["one", "two"], "page": "1"},
        )
        assert_next_query(
            self, response, {"q": [SEARCH], "search": [SEARCH], "status": ["pending"], "facet": ["one", "two"]}
        )
