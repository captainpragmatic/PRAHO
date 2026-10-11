"""The staff proforma form names each customer with its VAT number (#622).

The option's `({{ customer.tax_profile.vat_number }})` tag was split across two lines. Django
reads a variable tag only on one line, so every customer with a VAT number was listed with the
literal template text instead of the number. The bug surfaced while checking the Platform
template conversions.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import User


class ProformaFormCustomerOptionTests(TestCase):
    def test_customer_option_shows_the_vat_number(self) -> None:
        customer = Customer.objects.create(
            customer_type="company", company_name="Optiune Test SRL", primary_email="option@test.ro"
        )
        CustomerTaxProfile.objects.create(customer=customer, vat_number="RO14399840", is_vat_payer=True)
        staff = User.objects.create_user(email="proforma-option@test.ro", password="x", staff_role="billing")
        self.client.force_login(staff)

        response = self.client.get(reverse("billing:proforma_create"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Optiune Test SRL (RO14399840)")
        self.assertNotContains(response, "tax_profile.vat_number }}")
