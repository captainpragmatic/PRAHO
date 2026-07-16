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
