"""The proforma form offers the operator's VAT rates and keeps each line's own (ADR-0062).

The form offered literal 21% and 11% options and chose a line's option by comparing a
localised rate, which never matched in Romanian: opening a proforma there re-rated every line
to the first option on save, and its prices and quantities rendered with a decimal comma a
number input drops, so saving zeroed them.
The options now come from TaxService for the operator, plus any rate a line already carries,
compared without localisation.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal
from io import StringIO

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice, ProformaLine
from apps.billing.tax_models import TaxRule
from apps.customers.models import Customer
from apps.users.models import User


def selected_rates(html: str) -> list[str]:
    """The selected option value of each line's VAT select, in line order."""
    selects = re.findall(r'<select name="line_\d+_vat_rate".*?</select>', html, flags=re.S)
    return [m.group(1) for s in selects if (m := re.search(r'<option value="([^"]*)"\s+selected', s))]


def offered_rates(html: str) -> list[str]:
    """The option values of the first line's VAT select."""
    select = re.search(r'<select name="line_0_vat_rate".*?</select>', html, flags=re.S)
    assert select is not None
    return re.findall(r'<option value="([^"]*)"', select.group(0))


class ProformaVatRateOptionsTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.staff = User.objects.create_user(email="rates@example.com", password="x", is_staff=True)
        self.staff.staff_role = "billing"
        self.staff.save()
        self.client.force_login(self.staff)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(customer_type="company", company_name="Rates SRL")

    def test_a_romanian_edit_form_keeps_each_lines_rate_and_price(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-RATES-1",
            valid_until=timezone.now() + timezone.timedelta(days=30),
        )
        for rate in ("0.1100", "0.0000", "0.0900"):
            ProformaLine.objects.create(
                proforma=proforma, kind="service", description=f"Line at {rate}", unit_price_cents=1250,
                tax_rate=Decimal(rate),
            )
        self.staff.profile.preferred_language = "ro"
        self.staff.profile.save()

        html = self.client.get(reverse("billing:proforma_edit", args=[proforma.pk])).content.decode()

        self.assertIn('lang="ro"', html)
        self.assertEqual(selected_rates(html), ["11", "0", "9"])
        # A number input drops a localised "12,5" or "1,000", so saving would have zeroed them.
        self.assertRegex(html, r'name="line_0_unit_price"[^>]*value="12\.5"')
        self.assertRegex(html, r'name="line_0_quantity"[^>]*value="1\.000"')

    def test_a_romanian_operator_keeps_its_seeded_reduced_rate(self) -> None:
        call_command("setup_tax_rules", stdout=StringIO())

        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        self.assertEqual(offered_rates(html), ["21", "11", "0"])

    @override_settings(COMPANY_COUNTRY_CODE="DE")
    def test_a_german_operator_is_offered_its_own_rates(self) -> None:
        TaxRule.objects.create(
            country_code="DE", rate=Decimal("0.19"), reduced_rate=Decimal("0.07"), valid_from=date(2020, 1, 1)
        )

        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        self.assertEqual(offered_rates(html), ["19", "7", "0"])
        self.assertNotIn("TVA", html)
