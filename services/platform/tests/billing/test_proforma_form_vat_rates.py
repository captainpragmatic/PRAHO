"""The staff proforma form offers and defaults VAT rates from TaxService, never a fixed 21% (#689).

The line VAT select listed literal 21/11/0 options. A line saved at any other rate (a historical
19%, a custom 25.5%) re-rendered with 21% selected, so saving the edit silently re-rated it. A
rejected create dropped every submitted rate outside the three literals, an empty rate fell back
to "21", and the Python fallback truncated the supplier rate with int(). Every customer got the
same 21% default, even a reverse-charge customer whose invoices carry 0%.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from decimal import Decimal
from typing import Any, cast

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice, ProformaLine
from apps.billing.tax_models import TaxRule
from apps.common.tax_service import TaxService
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.users.models import User


def _customer(name: str, *, country: str, **profile: object) -> Customer:
    customer = Customer.objects.create(
        name=name,
        customer_type="company",
        company_name=name,
        primary_email=f"{name.split(maxsplit=1)[0].lower()}@test.ro",
    )
    CustomerAddress.objects.create(
        customer=customer,
        is_billing=True,
        address_line1="Street 1",
        city="City",
        county="County",
        postal_code="10000",
        country=country,
    )
    CustomerTaxProfile.objects.create(customer=customer, **profile)
    return customer


def _customer_option(html: str, customer: Customer) -> str:
    match = re.search(rf'<option value="{customer.pk}"[^>]*>', html, re.S)
    assert match is not None, f"no option for customer {customer.pk}"
    return match.group(0)


def _vat_select(html: str, index: int) -> str:
    match = re.search(rf'<select name="line_{index}_vat_rate"[^>]*>(.*?)</select>', html, re.S)
    assert match is not None, f"no VAT select for line {index}"
    return match.group(0)


def _selected_value(select_html: str) -> str:
    selected = re.findall(r'<option value="([^"]*)"\s+selected', select_html)
    assert len(selected) == 1, f"expected exactly one selected option, got {selected}"
    return selected[0]


def _form_config(html: str) -> dict[str, Any]:
    match = re.search(r'<script id="proforma-form-config" type="application/json">(.*?)</script>', html, re.S)
    assert match is not None, "no proforma-form-config script"
    return cast("dict[str, Any]", json.loads(match.group(1)))


class ProformaFormVatRateTests(TestCase):
    def setUp(self) -> None:
        TaxService.invalidate_cache()
        self.addCleanup(TaxService.invalidate_cache)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.staff = User.objects.create_user(
            email="proforma-vat@test.ro", password="x", is_staff=True, staff_role="billing"
        )
        self.client.force_login(self.staff)

    def _supplier_rule(self, rate: str) -> None:
        """A rule in force today for the supplier's own country, so its standard rate is not 21."""
        TaxRule.objects.create(
            country_code=TaxService.get_supplier_country(),
            tax_type="vat",
            rate=Decimal(rate),
            valid_from=timezone.localdate() - timedelta(days=1),
        )
        TaxService.invalidate_cache()

    def _proforma(self, customer: Customer, tax_rate: str) -> ProformaInvoice:
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            currency=self.currency,
            number="PRO-VAT-001",
            valid_until=timezone.now() + timedelta(days=30),
        )
        ProformaLine.objects.create(
            proforma=proforma,
            kind="service",
            description="Custom-rate hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal(tax_rate),
            line_total_cents=12550,
        )
        return proforma

    # --- customer defaults -------------------------------------------------

    def test_each_customer_option_carries_its_own_previewed_rate(self) -> None:
        domestic = _customer("Domestic SRL", country="RO", vat_number="RO12345678", is_vat_payer=True)
        reverse_charge = _customer(
            "Evidence GmbH",
            country="DE",
            vat_number="DE123456789",
            is_vat_payer=True,
            vies_verification_status="valid",
            vies_verified_at=timezone.now(),
            vies_consultation_reference="test-reference",
        )
        custom = _customer(
            "Custom SRL",
            country="RO",
            vat_number="RO23456789",
            is_vat_payer=True,
            vat_rate=Decimal("25.50"),
            vat_rate_reason="Agreed custom rate",
        )

        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        self.assertIn('data-vat-rate="21"', _customer_option(html, domestic))
        self.assertIn('data-vat-rate="0"', _customer_option(html, reverse_charge))
        self.assertIn('data-vat-rate="25.5"', _customer_option(html, custom))

    def test_a_customer_with_an_unreadable_billing_country_gets_the_supplier_rate(self) -> None:
        broken = _customer("Broken SRL", country="Atlantis", vat_number="", is_vat_payer=False)
        self._supplier_rule("0.1900")

        response = self.client.get(reverse("billing:proforma_create"))

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-vat-rate="19"', _customer_option(response.content.decode(), broken))

    def test_new_lines_follow_the_customer_and_saved_lines_do_not(self) -> None:
        """The empty first line is marked as a default the customer switch may rewrite."""
        customer = _customer("Switch SRL", country="RO", vat_number="", is_vat_payer=False)
        create_html = self.client.get(reverse("billing:proforma_create")).content.decode()
        self.assertIn("data-vat-default", _vat_select(create_html, 0))
        self.assertEqual(_form_config(create_html)["defaultVatRate"], "21")
        # The customer change handler reads the option's rate and rewrites only marked selects.
        self.assertIn("dataset.vatRate", create_html)
        self.assertIn(".line-vat[data-vat-default]", create_html)

        edit_html = self.client.get(
            reverse("billing:proforma_edit", args=[self._proforma(customer, "0.2100").pk])
        ).content.decode()
        self.assertNotIn("data-vat-default", _vat_select(edit_html, 0))

    @override_settings(COMPANY_COUNTRY_CODE="DE")
    def test_without_a_customer_the_first_line_defaults_to_the_supplier_standard_rate(self) -> None:
        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        select = _vat_select(html, 0)
        self.assertEqual(_selected_value(select), "19")
        self.assertNotIn('value="21"', select)

    def test_the_reduced_and_zero_rates_come_from_tax_service(self) -> None:
        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        values = re.findall(r'<option value="([^"]*)"', _vat_select(html, 0))
        reduced = TaxService.get_reduced_vat_rate(TaxService.get_supplier_country())
        assert reduced is not None
        self.assertEqual(values, ["21", format(reduced.normalize(), "f"), "0"])

    # --- stored and submitted rates survive --------------------------------

    def test_a_custom_line_rate_survives_an_edit_round_trip(self) -> None:
        customer = _customer("Roundtrip SRL", country="RO", vat_number="", is_vat_payer=False)
        proforma = self._proforma(customer, "0.2550")

        html = self.client.get(reverse("billing:proforma_edit", args=[proforma.pk])).content.decode()
        self.assertEqual(_selected_value(_vat_select(html, 0)), "25.5")

        response = self.client.post(
            reverse("billing:proforma_edit", args=[proforma.pk]),
            {
                "customer": str(customer.pk),
                "valid_until": (timezone.localdate() + timedelta(days=30)).isoformat(),
                "line_0_description": "Custom-rate hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": _selected_value(_vat_select(html, 0)),
            },
        )

        self.assertEqual(response.status_code, 302)
        line = ProformaLine.objects.get(proforma=proforma)
        self.assertEqual(line.tax_rate, Decimal("0.2550"))
        # A non-zero check: 100 net at 25.5% is exactly 25.50 VAT.
        proforma.refresh_from_db()
        self.assertEqual(proforma.tax_cents, 2550)

    def test_a_rejected_create_keeps_each_submitted_rate(self) -> None:
        customer = _customer("Rejected SRL", country="RO", vat_number="", is_vat_payer=False)

        response = self.client.post(
            reverse("billing:proforma_create"),
            {
                "customer": str(customer.pk),
                "currency": "RON",
                "currency_revision": "",  # unreadable revision: the form is re-rendered, nothing saved
                "line_0_description": "Alpha",
                "line_0_quantity": "1",
                "line_0_unit_price": "10.00",
                "line_0_vat_rate": "25.50",
                "line_1_description": "Beta",
                "line_1_quantity": "1",
                "line_1_unit_price": "10.00",
                "line_1_vat_rate": "0",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProformaInvoice.objects.filter(customer=customer).exists())
        html = response.content.decode()
        self.assertEqual(_selected_value(_vat_select(html, 0)), "25.5")
        self.assertEqual(_selected_value(_vat_select(html, 1)), "0")

    def test_a_posted_fractional_rate_is_not_truncated(self) -> None:
        customer = _customer("Fraction SRL", country="RO", vat_number="", is_vat_payer=False)
        proforma = self._proforma(customer, "0.2100")

        self.client.post(
            reverse("billing:proforma_edit", args=[proforma.pk]),
            {
                "customer": str(customer.pk),
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "25.5",
            },
        )

        self.assertEqual(ProformaLine.objects.get(proforma=proforma).tax_rate, Decimal("0.2550"))

    def test_an_empty_rate_takes_the_supplier_rate_without_truncating_it(self) -> None:
        """The old fallback was str(int(rate)) of Romania's rate: 25.5 became 25."""
        self._supplier_rule("0.2550")
        customer = _customer("Empty SRL", country="RO", vat_number="", is_vat_payer=False)
        proforma = self._proforma(customer, "0.2100")

        self.client.post(
            reverse("billing:proforma_edit", args=[proforma.pk]),
            {
                "customer": str(customer.pk),
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "",
            },
        )

        self.assertEqual(ProformaLine.objects.get(proforma=proforma).tax_rate, Decimal("0.2550"))

    @override_settings(COMPANY_COUNTRY_CODE="DE")
    def test_an_empty_rate_falls_back_to_the_supplier_country_not_romania(self) -> None:
        customer = _customer("Fallback SRL", country="RO", vat_number="", is_vat_payer=False)
        proforma = self._proforma(customer, "0.2100")

        self.client.post(
            reverse("billing:proforma_edit", args=[proforma.pk]),
            {
                "customer": str(customer.pk),
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "",
            },
        )

        self.assertEqual(ProformaLine.objects.get(proforma=proforma).tax_rate, Decimal("0.1900"))

    # --- summary label ------------------------------------------------------

    def test_the_summary_label_is_translated_not_hard_coded(self) -> None:
        html = self.client.get(reverse("billing:proforma_create")).content.decode()

        self.assertNotIn("'TVA", html)
        config = _form_config(html)
        self.assertEqual(config["labels"]["vat"], "VAT:")
        self.assertEqual(config["labels"]["vatRate"], "VAT ({rate}%):")
