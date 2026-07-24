"""Customer-visible renewal page rendering regressions."""

from __future__ import annotations

from datetime import timedelta

from dateutil.relativedelta import relativedelta
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar

User = get_user_model()


class DomainRenewTemplateTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="renewal-staff@example.test",
            password="StrongPass123!",
            staff_role="support",
        )
        self.customer = Customer.objects.create(
            name="Renewal Customer",
            company_name="Renewal Customer SRL",
            customer_type="company",
            primary_email="renewals@example.test",
        )
        self.tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )
        self.registrar = Registrar.objects.create(
            name="renewal-registrar",
            display_name="Renewal Registrar",
            website_url="https://renew.example.test",
            api_endpoint="https://api.renew.example.test",
        )
        self.domain = Domain.objects.create(
            name="renew-me.ro",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
            expires_at=timezone.now() + timedelta(days=90),
        )
        self.client.force_login(self.user)

    def test_renewal_page_has_valid_markup_and_summary_script(self) -> None:
        response = self.client.get(reverse("domains:renew", kwargs={"domain_id": self.domain.id}))

        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertNotIn(r"\n", html)
        self.assertNotIn(r"\"", html)
        self.assertIn('id="renewal-form"', html)
        self.assertIn('id="renewal-summary"', html)
        self.assertIn("function updateSummary()", html)
        self.assertIn("radio.addEventListener('change', updateSummary)", html)
        self.assertNotIn("summaryDiv.innerHTML", html)
        self.assertIn("periodValue.textContent = cost.periodLabel", html)
        self.assertIn("newExpiryValue.textContent = cost.newExpiryLabel", html)
        self.assertIn("totalCostValue.textContent = cost.displayCost", html)
        renewal_costs = response.context["renewal_costs"]
        self.assertEqual(renewal_costs[0]["new_expiry"], self.domain.expires_at + relativedelta(years=1))
        self.assertEqual(renewal_costs[-1]["new_expiry"], self.domain.expires_at + relativedelta(years=5))
        self.assertRegex(html, r'<script nonce="[^"]*">')
