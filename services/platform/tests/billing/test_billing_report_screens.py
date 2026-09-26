"""Two reporting screens computed figures no human ever saw.

`billing_reports` runs four aggregate queries and puts `monthly_stats` and `total_revenue` in
the context. `reports.html` rendered a heading, a link to the D390 review and the sentence
"Financial reporting interface - Staff only". Every number was discarded at the template.

`vat_report.html` was worse, because it looked like it worked. Two of its three summary cards
read `total_sales` and `net_sales`, which appear nowhere in `apps/` - the view supplies
`total_vat` and `total_net` - so `|default:0` rendered them as `0,00 RON` permanently. The third
read the right key through the wrong filter chain: `romanian_currency` only formats, and
`cents_to_currency` is what divides by 100, as the table rows immediately below already did. So
a VAT total in cents was printed as whole lei, 100x high, on the screen whose entire purpose is
Romanian VAT compliance.

TWO invoices, with amounts chosen so nothing collides. That is not incidental. With one invoice
the summary aggregate and that invoice's own row are the SAME number, so asserting the figure
appears proves only that *something* rendered it - a first version of these tests passed with
the card deleted, because the table row underneath still carried the value. Every expected
string below is also checked against being a tail of another: none of 88,73 / 18,63 / 107,36 /
51,37 / 10,79 / 62,16 / 140,10 / 29,42 / 169,52 contains `0,00 RON`, which is what the
missing-key assertion depends on.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice
from tests.factories.billing_factories import CustomerFactory
from tests.factories.core_factories import create_admin_user

# (net, vat, gross) per invoice, and the aggregates they sum to.
FIRST = (8873, 1863, 10736)
SECOND = (5137, 1079, 6216)
TOTAL_NET = "140,10 RON"
TOTAL_VAT = "29,42 RON"
TOTAL_GROSS = "169,52 RON"


class BillingReportScreenTestCase(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="report_screens"))

    def _paid_invoices(self) -> None:
        for index, (net, vat, gross) in enumerate((FIRST, SECOND)):
            invoice = Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f"FCT-00070{index}",
                status="draft",
                issued_at=timezone.now(),
                subtotal_cents=net,
                tax_cents=vat,
                total_cents=gross,
                bill_to_name="Test Company SRL",
                bill_to_country="RO",
                issuer_provider=ISSUER_BUILTIN,
            )
            # `status` is a protected FSMField; this is the shape every sibling test uses.
            Invoice.objects.filter(pk=invoice.pk).update(status="paid")


class FinancialReportsScreenTests(BillingReportScreenTestCase):
    def test_the_all_time_total_is_rendered(self) -> None:
        """Counted, not merely found.

        With a single month of data the all-time total and that month's revenue are the same
        figure by definition, so the card and the row are indistinguishable by value. The count
        is what separates them: delete either and this drops to one.
        """
        self._paid_invoices()

        response = self.client.get(reverse("billing:reports"))

        self.assertContains(response, TOTAL_GROSS, count=2)

    def test_the_monthly_series_is_rendered(self) -> None:
        self._paid_invoices()
        now = timezone.now()

        response = self.client.get(reverse("billing:reports"))

        self.assertContains(response, f"{now.month:02d}.{now.year}")

    def test_the_screen_survives_having_nothing_to_report(self) -> None:
        response = self.client.get(reverse("billing:reports"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, TOTAL_GROSS)


class VatReportScreenTests(BillingReportScreenTestCase):
    def test_every_summary_card_renders_a_real_figure(self) -> None:
        """`0,00 RON` was the permanent output of two cards reading keys that do not exist."""
        self._paid_invoices()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertNotContains(response, "0,00 RON")

    def test_collected_vat_is_not_rendered_in_cents(self) -> None:
        self._paid_invoices()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, TOTAL_VAT)
        self.assertNotContains(response, "2.942,00 RON")

    def test_net_and_gross_are_both_rendered(self) -> None:
        """Aggregates, so neither can be satisfied by an invoice's own row."""
        self._paid_invoices()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, TOTAL_NET)
        self.assertContains(response, TOTAL_GROSS)


class MixedCurrencyReportTests(TestCase):
    """Adding lei to euros produces a number that is wrong under any label.

    EUR and USD are staff-selectable `Currency` rows, and an invoice inherits its order's
    currency, so both reports could genuinely hold more than one. The aggregates sum
    `total_cents` with no conversion and no grouping, and the templates hardcoded `RON` - so a
    100-lei invoice beside a 100-euro one displayed as 200,00 RON. Rendering the figure is what
    exposed it; a label cannot fix it, because the sum itself means nothing.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.client.force_login(create_admin_user(username="mixed_currency"))
        self.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "\u20ac", "decimals": 2})[0]

    def _paid(self, currency: Currency, amounts: tuple[int, int, int], number: str) -> None:
        net, vat, gross = amounts
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=net,
            tax_cents=vat,
            total_cents=gross,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        Invoice.objects.filter(pk=invoice.pk).update(status="paid")

    def _both(self) -> None:
        self._paid(self.ron, FIRST, "FCT-000710")
        self._paid(self.eur, SECOND, "FCT-000711")

    def test_the_revenue_screen_keeps_the_currencies_apart(self) -> None:
        self._both()

        response = self.client.get(reverse("billing:reports"))

        self.assertContains(response, "107,36 RON")
        self.assertContains(response, "62,16 EUR")
        self.assertNotContains(response, TOTAL_GROSS)

    def test_the_vat_screen_keeps_the_currencies_apart(self) -> None:
        self._both()

        response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, "18,63 RON")
        self.assertContains(response, "10,79 EUR")
        self.assertNotContains(response, TOTAL_VAT)


class VatReportTimezoneBoundaryTests(BillingReportScreenTestCase):
    """The VAT report silently dropped everything issued "today" for three hours a night.

    `end_date` defaulted to `timezone.now().date()` - a UTC date - while `created_at__date`
    resolves in the active timezone, which is `Europe/Bucharest`. Between 21:00 and 24:00 UTC
    those two disagree, so an invoice issued at 01:00 Bucharest carried `created_at__date` of
    tomorrow relative to a range that ended yesterday, and fell outside it.

    The screen showed an empty compliance report during exactly the window a Romanian
    accountant working late would be reading it, and said nothing. `views.py:866` in this same
    file already used `timezone.localdate()`, which is the idiom this was missing.

    Discovered because these tests assert the rendered figures rather than a status code: the
    page returned 200 throughout.
    """

    # 22:32 UTC on the 25th is 01:32 on the 26th in Bucharest — inside the broken window.
    UTC_EVENING = datetime(2026, 9, 25, 22, 32, tzinfo=UTC)

    def test_an_invoice_issued_after_local_midnight_is_still_reported(self) -> None:
        self._paid_invoices()
        Invoice.objects.filter(customer=self.customer).update(created_at=self.UTC_EVENING)

        with patch.object(timezone, "now", return_value=self.UTC_EVENING):
            response = self.client.get(reverse("billing:vat_report"))

        self.assertContains(response, TOTAL_VAT, msg_prefix="collected VAT vanished across the UTC/local date boundary")
        self.assertContains(response, TOTAL_NET)

    def test_the_period_defaults_to_local_dates_not_utc(self) -> None:
        """The range itself must be expressed in the timezone the lookup compares against."""
        with patch.object(timezone, "now", return_value=self.UTC_EVENING):
            response = self.client.get(reverse("billing:vat_report"))

        self.assertEqual(response.context["end_date"], date(2026, 9, 26))
        self.assertEqual(response.context["start_date"], date(2026, 9, 1))
