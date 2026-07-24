"""W1: the availability endpoint must consult the registrar, failing closed on uncertainty."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.domains.models import TLD, Registrar, TLDRegistrarAssignment

User = get_user_model()


class CheckAvailabilityViewTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="u@test.com", password="StrongPass123!")
        self.client.force_login(self.user)
        self.tld = TLD.objects.create(
            extension="com", description=".com", registration_price_cents=1000, renewal_price_cents=1000,
            transfer_price_cents=1000, registrar_cost_cents=500, min_registration_period=1, max_registration_period=10,
        )
        self.registrar = Registrar.objects.create(
            name="reg", display_name="Reg", website_url="https://r.example",
            api_endpoint="https://api.r.example", status="active",
        )
        TLDRegistrarAssignment.objects.create(tld=self.tld, registrar=self.registrar, is_primary=True, is_active=True, priority=1)
        self.com_ro_tld = TLD.objects.create(
            extension="com.ro",
            description=".com.ro",
            registration_price_cents=2500,
            renewal_price_cents=2300,
            transfer_price_cents=2100,
            registrar_cost_cents=1500,
            min_registration_period=2,
            max_registration_period=3,
            is_featured=True,
        )
        TLDRegistrarAssignment.objects.create(
            tld=self.com_ro_tld,
            registrar=self.registrar,
            is_primary=True,
            is_active=True,
            priority=1,
        )
        self.url = reverse("domains:check_availability")

    def test_registrar_says_unavailable(self) -> None:
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, False)):
            resp = self.client.post(self.url, {"domain_name": "taken.com"})
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertFalse(data["available"])

    def test_registrar_says_available(self) -> None:
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, True)):
            resp = self.client.post(self.url, {"domain_name": "free.com"})
        data = resp.json()
        self.assertTrue(data["available"])

    def test_fails_closed_when_registrar_check_errors(self) -> None:
        """A gateway error must NOT report the domain as available."""
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(False, False)):
            resp = self.client.post(self.url, {"domain_name": "unknown.com"})
        data = resp.json()
        self.assertFalse(data.get("available", False))

    def test_available_domain_advertises_only_resolved_tld_registration_periods(self) -> None:
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, True)):
            response = self.client.post(self.url, {"domain_name": "free.com.ro"})

        data = response.json()
        self.assertEqual(
            data["registration_periods"],
            [
                {"years": 2, "total_cost_cents": 5000},
                {"years": 3, "total_cost_cents": 7500},
            ],
        )
        self.assertEqual(set(data["pricing"]), {"2_years", "3_years"})
        self.assertNotIn("1_year", data["pricing"])

    def test_registration_form_populates_periods_from_availability_policy(self) -> None:
        response = self.client.get(reverse("domains:register"))

        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertNotIn('<option value="1" selected>', html)
        self.assertIn("selectDomain(this.dataset.domain, data.registration_periods)", html)
        self.assertIn("registrationPeriods.forEach", html)
        self.assertIn("registrationPrices[period.years] = period.total_cost_cents", html)
        self.assertIn("yearsSelect.value = String(registrationPeriods[0].years)", html)
        featured_price = next(
            price for price in response.context["tld_pricing"] if price["tld"] == self.com_ro_tld
        )
        self.assertEqual(featured_price["years"], 2)
        self.assertEqual(featured_price["cost_cents"], 5000)
