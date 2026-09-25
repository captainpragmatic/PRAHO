"""Two reporting screens computed figures no human ever saw.

`billing_reports` runs four aggregate queries and puts `monthly_stats` and `total_revenue` in
the context. `reports.html` rendered a heading, a link to the D390 review and the sentence
"Financial reporting interface - Staff only". Every number was discarded at the template.

`vat_report.html` was worse, because it looked like it worked. Two of its three summary cards
read `total_sales` and `net_sales`, which appear nowhere in `apps/` - the view supplies
`total_vat` and `total_net` - so `|default:0` rendered them as `0,00 RON` permanently. The third
read the right key through the wrong filter chain: `romanian_currency` only formats, and
`cents_to_currency` is what divides by 100, so a VAT total in cents was printed as whole lei.
On the screen whose entire purpose is Romanian VAT compliance, collected VAT read 100x high.

The amounts below are chosen so that no expected string is a substring of a wrong one, which is
the only way these assertions discriminate: 88,73 / 18,63 / 107,36 share no tail with each other
nor with `0,00 RON`.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice
from tests.factories.billing_factories import CustomerFactory
from tests.factories.core_factories import create_admin_user

NET = 8873
VAT = 1863
GROSS = 10736


class BillingReportScreenTestCase(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="report_screens"))

    def _paid_invoice(self) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-000700",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=NET,
            tax_cents=VAT,
            total_cents=GROSS,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        # `status` is a protected FSMField; this is the shape every sibling test uses.
        Invoice.objects.filter(pk=invoice.pk).update(status="paid")
        return invoice


class FinancialReportsScreenTests(BillingReportScreenTestCase):
    def test_the_all_time_total_is_rendered(self) -> None:
        self._paid_invoice()

        response = self.client.get(reverse("billing:reports"))

        self.assertContains(response, "107,36 RON")

    def test_the_monthly_series_is_rendered(self) -> None:
        self._paid_invoice()
        now = timezone.now()

        response = self.client.get(reverse("billing:reports"))

        self.assertContains(response, f"{now.month:02d}.{now.year}")

    def test_the_screen_survives_having_nothing_to_report(self) -> None:
        response = self.client.get(reverse("billing:reports"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "107,36")


class VatReportScreenTests(BillingReportScreenTestCase):
    def test_every_summary_card_renders_a_real_figure(self) -> None:
        """`0,00 RON` was the permanent output of two cards reading keys that do not exist."""
        self._paid_invoice()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertNotContains(response, "0,00 RON")

    def test_collected_vat_is_not_rendered_in_cents(self) -> None:
        self._paid_invoice()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, "18,63 RON")
        self.assertNotContains(response, "1.863,00 RON")

    def test_net_and_gross_are_both_rendered(self) -> None:
        self._paid_invoice()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, "88,73 RON")
        self.assertContains(response, "107,36 RON")
