"""Staff domain list regressions exercised through the real view."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar


class DomainAdminRenderingTests(TestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.staff = get_user_model().objects.create_user(
            email="domain-staff@example.test", password="SecurePass123!", staff_role="support"
        )
        self.client.force_login(self.staff)
        self.url = reverse("domains:admin_list")

    def test_empty_list_and_clear_filter_links_render(self) -> None:
        response = self.client.get(self.url, {"status": "active"})
        self.assertContains(response, "No domains found")
        self.assertContains(response, f'href="{self.url}"', count=2)

    def test_populated_list_renders_owned_customer_domain(self) -> None:
        customer = Customer.objects.create(
            name="Domain Owner", customer_type="company", primary_email="owner@example.test"
        )
        tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        registrar = Registrar.objects.create(
            name="domain-admin-test",
            display_name="Test Registrar",
            website_url="https://example.test",
            api_endpoint="https://example.test/api",
        )
        Domain.objects.create(name="owned.test", tld=tld, registrar=registrar, customer=customer, status="active")
        response = self.client.get(self.url)
        self.assertContains(response, "owned.test")
        self.assertContains(response, f'href="{self.url}"')

    def test_customer_cannot_open_staff_list(self) -> None:
        customer_user = get_user_model().objects.create_user(
            email="customer-list@example.test", password="SecurePass123!"
        )
        self.client.force_login(customer_user)
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse("dashboard"), fetch_redirect_response=False)

    def test_customer_name_search_combines_with_expiry_and_status(self) -> None:
        tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        registrar = Registrar.objects.create(
            name="filter-test",
            display_name="Filter Registrar",
            website_url="https://example.test",
            api_endpoint="https://example.test/api",
        )
        owner = Customer.objects.create(
            name="Search Owner", customer_type="company", primary_email="search@example.test"
        )
        other = Customer.objects.create(name="Other Owner", customer_type="company", primary_email="other@example.test")
        for name, customer in (("matching.test", owner), ("excluded.test", other)):
            Domain.objects.create(
                name=name,
                customer=customer,
                tld=tld,
                registrar=registrar,
                status="active",
                expires_at=timezone.now() + timezone.timedelta(days=10),
            )
        response = self.client.get(self.url, {"search": "Search Owner", "expiry": "expiring", "status": "active"})
        self.assertContains(response, "matching.test")
        self.assertNotContains(response, "excluded.test")
