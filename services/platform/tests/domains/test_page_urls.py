"""The domain pages send people and requests to routes that exist.

The list's row actions and the register page's availability check were written as /app/… URLs,
which no route serves, so each answered 404. The list also offered a DNS page that does not exist.
"""

from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.users.models import User


class DomainPageUrlTests(TestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name="Domain links", primary_email="domain-links@example.test")
        registrar = Registrar.objects.create(name="links", display_name="Links")
        tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        self.domain = Domain.objects.create(
            name="links.test",
            customer=customer,
            registrar=registrar,
            tld=tld,
            status="active",
            expires_at=timezone.now() + timedelta(days=90),
        )

    def test_the_list_row_actions_reach_their_pages(self) -> None:
        staff = User.objects.create_user(email="domain-links-staff@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)

        response = self.client.get(reverse("domains:list"))

        self.assertEqual(response.status_code, 200)
        renew = reverse("domains:renew", kwargs={"domain_id": self.domain.pk})
        detail = reverse("domains:detail", kwargs={"domain_id": self.domain.pk})
        self.assertContains(response, f'href="{renew}"')
        self.assertContains(response, f'href="{detail}"')
        self.assertNotContains(response, "Manage DNS")  # no such page exists
        self.assertNotContains(response, "/app/")

    def test_the_availability_check_posts_to_its_route(self) -> None:
        self.client.force_login(User.objects.create_user(email="domain-links-customer@example.test"))

        response = self.client.get(reverse("domains:register"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"fetch('{reverse('domains:check_availability')}'")
