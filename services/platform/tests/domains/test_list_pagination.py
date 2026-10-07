"""Regression tests for customer domain list pagination."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import urljoin

from django.core.paginator import Page
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.users.models import CustomerMembership, User
from tests.common.pagination_assertions import SEARCH, next_page_url


class DomainListPaginationTests(TestCase):
    def test_next_page_preserves_filters_and_matching_domains(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        user = User.objects.create_user(email="domain-list-pagination@example.test")
        self.client.force_login(user)
        customer = Customer.objects.create(name=SEARCH, primary_email="matching@example.test")
        other = Customer.objects.create(name="Other customer", primary_email="other@example.test")
        outsider = Customer.objects.create(name=SEARCH, primary_email="outsider@example.test")
        for accessible in (customer, other):
            CustomerMembership.objects.create(user=user, customer=accessible, role="owner")
        registrar = Registrar.objects.create(name="list-paging", display_name="List Paging")
        tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        other_tld = TLD.objects.create(
            extension="net", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        now = timezone.now()

        def domain(
            name: str,
            *,
            owner: Customer = customer,
            extension: TLD = tld,
            status: str = "active",
            expiry_days: int = 10,
        ) -> Domain:
            return Domain(
                name=name,
                customer=owner,
                registrar=registrar,
                tld=extension,
                status=status,
                expires_at=now + timedelta(days=expiry_days),
            )

        matching = Domain.objects.bulk_create([domain(f"matching-{number:02d}.test") for number in range(26)])
        for number, item in enumerate(matching):
            item.created_at = now - timedelta(minutes=number)
        Domain.objects.bulk_update(matching, ["created_at"])
        excluded = Domain.objects.bulk_create(
            [
                domain("wrong-search.test", owner=other),
                domain("wrong-status.test", status="pending"),
                domain("wrong-tld.net", extension=other_tld),
                domain("wrong-expiry.test", expiry_days=60),
                domain("wrong-tenant.test", owner=outsider),
            ]
        )
        url = reverse("domains:list")
        parameters = {
            "search": SEARCH,
            "status": "active",
            "tld": "test",
            "expiry": "expiring",
            "facet": ["one", "two"],
            "page": ["7", "1"],
        }
        response = self.client.get(url, parameters)
        first_page: Page[Domain] = response.context["domains"]
        self.assertEqual(first_page.paginator.count, 26)
        self.assertEqual([item.pk for item in first_page], [item.pk for item in matching[:25]])

        next_response = self.client.get(urljoin(url, next_page_url(self, response)))
        self.assertEqual(next_response.status_code, 200)
        self.assertEqual(
            dict(next_response.wsgi_request.GET.lists()),
            {
                "page": ["2"],
                "search": [SEARCH],
                "status": ["active"],
                "tld": ["test"],
                "expiry": ["expiring"],
                "facet": ["one", "two"],
            },
        )
        second_page: Page[Domain] = next_response.context["domains"]
        self.assertEqual(second_page.number, 2)
        self.assertEqual(second_page.paginator.count, 26)
        self.assertEqual([item.pk for item in second_page], [matching[25].pk])
        self.assertContains(next_response, matching[25].name)
        for item in [*matching[:25], *excluded]:
            self.assertNotContains(next_response, item.name)
