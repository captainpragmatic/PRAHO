"""Staff tax changes validate exemption reasons and numeric bounds."""

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from tests.factories.core_factories import create_staff_user


@override_settings(COMPANY_COUNTRY_CODE="RO")
class VATStaffFormTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Evidence GmbH", company_name="Evidence GmbH", customer_type="company",
            primary_email="vat-forms@example.test",
        )
        CustomerAddress.objects.create(
            customer=self.customer, is_primary=True, is_billing=True, is_current=True,
            country="DE", address_line1="Teststrasse 1", city="Berlin", county="Berlin", postal_code="10115",
        )
        self.profile = CustomerTaxProfile.objects.create(
            customer=self.customer, vat_number="DE136695976", is_vat_payer=True,
        )
        self.client.force_login(create_staff_user(staff_role="admin"))

    def _data(self, rate: str, reason: str = "") -> dict[str, str]:
        return {
            "name": "Evidence GmbH", "company_name": "Evidence GmbH", "customer_type": "company",
            "primary_email": "vat-forms@example.test", "vat_number": "DE136695976", "is_vat_payer": "on",
            "vat_rate": rate, "vat_rate_reason": reason, "payment_terms": "30", "credit_limit": "0",
            "preferred_currency": "RON", "address_line1": "Teststrasse 1", "city": "Berlin",
            "county": "Berlin", "postal_code": "10115", "country": "DE", "billing_same_as_primary": "on",
            "data_processing_consent": "on",
        }

    def test_both_staff_forms_reject_rates_outside_zero_to_one_hundred(self) -> None:
        for route in ("customers:tax_profile", "customers:edit"):
            for rate in ("-0.01", "100.01"):
                with self.subTest(route=route, rate=rate):
                    response = self.client.post(reverse(route, args=[self.customer.pk]), self._data(rate))
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("vat_rate", response.context["form"].errors)
                    self.profile.refresh_from_db()
                    self.assertIsNone(self.profile.vat_rate)

    def test_both_staff_forms_require_and_persist_cross_border_exemption_reason(self) -> None:
        for route in ("customers:tax_profile", "customers:edit"):
            with self.subTest(route=route):
                url = reverse(route, args=[self.customer.pk])
                response = self.client.post(url, self._data("0"))
                self.assertEqual(response.status_code, 200)
                self.assertIn("vat_rate_reason", response.context["form"].errors)
                response = self.client.post(url, self._data("0", "diplomatic"))
                self.assertEqual(response.status_code, 302)
                self.profile.refresh_from_db()
                self.assertEqual(self.profile.vat_rate, 0)
                self.assertEqual(self.profile.vat_rate_reason, "diplomatic")
