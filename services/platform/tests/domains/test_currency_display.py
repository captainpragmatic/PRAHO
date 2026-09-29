"""Domain pages display the unit attached to each quote or recorded order."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment, TLDRetailPrice
from apps.orders.models import Order
from apps.settings.models import SystemSetting
from apps.users.models import User


class DomainCurrencyDisplayTests(TestCase):
    def setUp(self) -> None:
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="domain-display-test", fetched_at=timezone.now(),
                )
        self.user = User.objects.create_user(email="domain-billing@example.test", staff_role="billing", is_staff=True)
        self.client.force_login(self.user)
        self.customer = Customer.objects.create(name="Domain customer", primary_email="domain@example.test")
        self.tld = TLD.objects.create(
            extension="display", is_featured=True, registration_price_cents=6000, renewal_price_cents=5000,
            transfer_price_cents=4500, redemption_fee_cents=10000, min_registration_period=1,
            max_registration_period=2, whois_privacy_available=True,
        )
        for code in ("EUR", "USD"):
            TLDRetailPrice.objects.create(
                tld=self.tld, currency_id=code, registration_price_cents=1200, renewal_price_cents=1300,
                transfer_price_cents=1100, whois_privacy_price_cents=250,
            )
        self.registrar = Registrar.objects.create(name="display-registrar", currency="USD")
        TLDRegistrarAssignment.objects.create(tld=self.tld, registrar=self.registrar, is_primary=True)
        self.domain = Domain.objects.create(
            name="existing.display", tld=self.tld, registrar=self.registrar, customer=self.customer,
            status="active", registrar_domain_id="existing", expires_at=timezone.now() + timedelta(days=90),
        )

    @staticmethod
    def set_display_policy(code: str) -> None:
        # These view tests isolate display from the separately tested switch-admission workflow.
        SystemSetting.objects.update_or_create(
            key="billing.default_currency", defaults={"value": code, "data_type": "string", "revision": 2},
        )

    def test_order_history_keeps_each_original_currency_after_policy_switch(self) -> None:
        for code, cents in (("EUR", 1234), ("USD", 4567), ("RON", 9876)):
            order = Order.objects.create(customer=self.customer, currency_id=code)
            DomainOrderItem.objects.create(
                order=order, domain=self.domain, domain_name=self.domain.name, tld=self.tld, action="renew",
                years=1, unit_price_cents=cents, total_price_cents=cents,
            )
        self.set_display_policy("USD")
        response = self.client.get(reverse("domains:detail", args=[self.domain.pk]))
        for value in ("12,34 EUR", "45,67 USD", "98,76 RON"):
            self.assertContains(response, value)
        self.assertNotContains(response, "12,34 RON")
        self.assertNotContains(response, "45,67 RON")

    def test_registration_card_displays_the_retail_quote_currency_not_registrar_currency(self) -> None:
        self.set_display_policy("EUR")
        response = self.client.get(reverse("domains:register"))
        self.assertContains(response, "12,00 EUR")
        self.assertNotContains(response, "12,00 RON")
        self.assertNotContains(response, "12,00 USD")
        self.assertEqual(response.context["tld_pricing"][0]["currency"], "EUR")

    def test_availability_carries_same_currency_privacy_cost_for_each_period(self) -> None:
        self.set_display_policy("EUR")
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, True)):
            response = self.client.post(reverse("domains:check_availability"), {"domain_name": "new.display"})
        self.assertEqual(response.json()["registration_periods"], [
            {"years": 1, "total_cost_cents": 1200, "currency": "EUR", "whois_cost_cents": 250},
            {"years": 2, "total_cost_cents": 2400, "currency": "EUR", "whois_cost_cents": 500},
        ])

    def test_unavailable_privacy_does_not_add_a_ron_charge_to_foreign_quote(self) -> None:
        self.tld.whois_privacy_available = False
        self.tld.save(update_fields=["whois_privacy_available"])
        self.set_display_policy("USD")
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, True)):
            response = self.client.post(reverse("domains:check_availability"), {"domain_name": "new.display"})
        self.assertFalse(response.json()["whois_privacy_available"])
        for period in response.json()["registration_periods"]:
            self.assertEqual(period["currency"], "USD")
            self.assertEqual(period["whois_cost_cents"], 0)

    def test_renewal_options_and_javascript_summary_use_the_quote_currency(self) -> None:
        self.set_display_policy("EUR")
        eur_domain = Domain.objects.create(
            name="euro.display", tld=self.tld, registrar=self.registrar, customer=self.customer,
            status="active", expires_at=self.domain.expires_at,
        )
        response = self.client.get(reverse("domains:renew", args=[eur_domain.pk]))
        self.assertContains(response, "13,00 EUR")
        self.assertContains(response, "26,00 EUR")
        self.assertContains(response, "displayCost: '26,00 EUR'")
        self.assertContains(response, "13,00 EUR/year")
        self.assertNotContains(response, "26,00 RON")
        self.assertEqual(response.context["renewal_costs"][0]["currency"], "EUR")

    def test_original_renewal_quote_stays_in_ron_after_storefront_switch(self) -> None:
        self.set_display_policy("EUR")
        response = self.client.get(reverse("domains:renew", args=[self.domain.pk]))
        self.assertContains(response, "50,00 RON")
        self.assertContains(response, "100,00 RON")
        self.assertNotContains(response, "13,00 EUR")
        self.assertEqual(response.context["renewal_costs"][0]["currency"], "RON")

    def test_unproven_legacy_price_does_not_relabel_a_manual_renewal(self) -> None:
        self.set_display_policy("EUR")
        Domain.objects.filter(pk=self.domain.pk).update(
            billing_currency=None, renewal_unit_price_cents=None, renewal_terms={},
        )
        response = self.client.get(reverse("domains:renew", args=[self.domain.pk]))
        self.assertContains(response, "Price requires review")
        self.assertIsNone(response.context["renewal_costs"][0]["cost_cents"])
        self.assertNotContains(response, "13,00 EUR")
        self.assertNotContains(response, "50,00 RON")

    def test_legacy_staff_catalog_fields_retain_explicit_ron_labels(self) -> None:
        self.set_display_policy("EUR")
        response = self.client.get(reverse("domains:tld_list"))
        for value in ("60,00 RON", "50,00 RON", "45,00 RON", "100,00 RON"):
            self.assertContains(response, value)
        self.assertNotContains(response, "60,00 EUR")
