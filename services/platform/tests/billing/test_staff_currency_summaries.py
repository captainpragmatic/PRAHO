"""Staff summary cards show currency-specific totals, including fractional units."""

from datetime import UTC, datetime
from unittest.mock import patch

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from lxml import etree

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, Invoice, Payment, ProformaInvoice
from apps.common.views import _calculate_monthly_revenue
from apps.customers.models import Customer
from apps.provisioning.service_models import ServicePlan, ServicePlanPrice
from apps.settings.models import SystemSetting
from apps.users.models import User
from tests.factories import CustomerFactory


@override_settings(LANGUAGE_CODE="en")
class StaffCurrencySummaryTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.staff = User.objects.create_user(email="currency-staff@example.test", is_staff=True, staff_role="billing")
        cls.customer = CustomerFactory()
        cls.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        cls.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        cls.invoices = []
        for index, (currency, amount) in enumerate(((cls.eur, 10000), (cls.eur, 3000), (cls.ron, 7000))):
            cls.invoices.append(Invoice.objects.create(
                customer=cls.customer, currency=currency, number=f"INV-CURRENCY-{index}", status="paid",
                subtotal_cents=amount, total_cents=amount, due_at=timezone.now(),
            ))
        for index, (currency, amount) in enumerate(((cls.eur, 1234), (cls.eur, 678), (cls.ron, 555))):
            ProformaInvoice.objects.create(
                customer=cls.customer, currency=currency, number=f"PRO-CURRENCY-{index}",
                subtotal_cents=amount, total_cents=amount,
                valid_until=timezone.now() + timezone.timedelta(days=14),
            )
        Payment.objects.bulk_create([
            Payment(customer=cls.customer, invoice=invoice, currency=invoice.currency, amount_cents=amount,
                    payment_method="bank", status="succeeded")
            for invoice, amount in zip(cls.invoices, (2000, 1500, 5000), strict=True)
        ])

    def setUp(self) -> None:
        self.client.force_login(self.staff)

    def _card_text(self, content: bytes, heading: str) -> str:
        doc = etree.HTML(content)
        cards = doc.xpath("//p[normalize-space(.)=$heading]/..", heading=heading)
        self.assertEqual(len(cards), 1)
        return " ".join(cards[0].itertext())

    def test_monthly_revenue_card_keeps_both_recorded_currencies(self) -> None:
        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["stats"]["monthly_revenue_by_currency"], {"EUR": 13000, "RON": 7000})
        card = self._card_text(response.content, "Paid invoices this month")
        self.assertIn("130,00 EUR", card)
        self.assertIn("70,00 RON", card)
        self.assertNotIn("200,00 RON", card)

    def test_combined_billing_cards_keep_currencies_and_fractional_amounts(self) -> None:
        response = self.client.get("/billing/invoices/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["invoice_totals_by_currency"], {"EUR": 13000, "RON": 7000})
        self.assertEqual(response.context["proforma_totals_by_currency"], {"EUR": 1912, "RON": 555})
        proformas = self._card_text(response.content, "Proforma Value")
        self.assertIn("19,12 EUR", proformas)
        self.assertIn("5,55 RON", proformas)
        invoices = self._card_text(response.content, "Invoice Revenue")
        self.assertIn("130,00 EUR", invoices)
        self.assertIn("70,00 RON", invoices)

    def test_proforma_listing_also_uses_currency_groups(self) -> None:
        response = self.client.get("/billing/proformas/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["proforma_totals_by_currency"], {"EUR": 1912, "RON": 555})
        card = self._card_text(response.content, "Proforma Value")
        self.assertIn("19,12 EUR", card)
        self.assertIn("5,55 RON", card)

    def test_payment_footer_groups_currency_despite_payment_date_ordering(self) -> None:
        response = self.client.get("/billing/payments/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["payment_totals_by_currency"], {"EUR": 3500, "RON": 5000})
        doc = etree.HTML(response.content)
        totals = doc.xpath("//p[starts-with(normalize-space(.), 'Total:')]")
        footer = " ".join(" ".join(total.itertext()) for total in totals)
        self.assertIn("35,00 EUR", footer)
        self.assertIn("50,00 RON", footer)
        self.assertNotIn("85,00 RON", footer)

    def test_customer_invoice_rows_keep_each_original_currency(self) -> None:
        response = self.client.get(f"/customers/{self.customer.pk}/")
        self.assertEqual(response.status_code, 200)
        doc = etree.HTML(response.content)
        for invoice in self.invoices:
            links = doc.xpath("//*[@data-href=$path]", path=f"/billing/invoices/{invoice.pk}/")
            self.assertEqual(len(links), 1)
            row = " ".join(links[0].itertext())
            self.assertIn(invoice.currency_id, row)
            if invoice.currency_id == "EUR":
                self.assertNotIn("RON", row)

    def test_draft_invoice_currency_cannot_be_relabelled_in_edit_form(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.eur, number="INV-EUR-DRAFT", status="draft",
            subtotal_cents=1250, total_cents=1250,
        )
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertEqual(response.status_code, 200)
        doc = etree.HTML(response.content)
        fields = doc.xpath("//*[@name='currency']")
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].get("value"), "EUR")
        self.assertIn("readonly", fields[0].attrib)
        self.assertContains(response, "0.00 EUR")
        self.assertNotContains(response, "0.00 RON")

    def test_plan_list_uses_explicit_selling_price_without_relabelling_legacy_price(self) -> None:
        priced = ServicePlan.objects.create(name="Priced plan", price_monthly="51.23")
        unpriced = ServicePlan.objects.create(name="Unpriced plan", price_monthly="84.56")
        ServicePlanPrice.objects.create(service_plan=priced, currency=self.eur, monthly_price_cents=999)
        get_selling_currency_policy()
        SystemSetting.objects.filter(key="billing.default_currency").update(value="EUR")
        response = self.client.get("/provisioning/plans/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["currency"], "EUR")
        self.assertContains(response, "9,99 EUR")
        self.assertContains(response, unpriced.name)
        self.assertContains(response, "Price unavailable")
        self.assertNotContains(response, "51.23")
        self.assertNotContains(response, "84.56")


class MonthlyRevenueCutoffTests(TestCase):
    """The current month is the Romanian calendar month, and it starts at local midnight on the 1st.

    The cutoff used to be `timezone.now().replace(day=1)` - the current UTC instant with only the day
    changed. On the 1st (UTC) that is "right now", so every invoice created earlier the same day fell
    before it and the card showed nothing; on every other day it silently dropped the first hours of
    the 1st. Zeroing the UTC time is not enough either: the dashboard serves a Romanian business, and
    an invoice created at 01:30 on 1 October in Bucharest is still 30 September in UTC.
    """

    NOW = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)  # 1 October, 11:00 in Bucharest

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = CustomerFactory()
        cls.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        created = {
            "same-utc-day": (datetime(2026, 10, 1, 5, 0, tzinfo=UTC), 1000),
            "bucharest-first": (datetime(2026, 9, 30, 22, 30, tzinfo=UTC), 200),  # 1 Oct 01:30 local
            "previous-month": (datetime(2026, 9, 30, 20, 0, tzinfo=UTC), 30),  # 30 Sep 23:00 local
        }
        for index, (label, (created_at, amount)) in enumerate(created.items()):
            invoice = Invoice.objects.create(
                customer=cls.customer,
                currency=cls.ron,
                number=f"INV-CUTOFF-{index}-{label}",
                status="paid",
                subtotal_cents=amount,
                total_cents=amount,
                due_at=cls.NOW,
            )
            Invoice.objects.filter(pk=invoice.pk).update(created_at=created_at)

    def test_current_month_is_the_local_calendar_month_from_its_first_moment(self) -> None:
        with patch("django.utils.timezone.now", return_value=self.NOW):
            totals = _calculate_monthly_revenue(Customer.objects.filter(pk=self.customer.pk))

        self.assertEqual(totals, {"RON": 1200})

    def test_cutoff_compares_the_raw_timestamp_so_the_index_still_applies(self) -> None:
        """The cutoff must be a timestamp compared directly with created_at.

        Wrapping created_at in a date conversion (created_at__date) is correct but makes the
        database evaluate the conversion on every invoice, so the (customer, -created_at) index
        cannot bound the scan and the staff dashboard degrades as invoice history grows.
        """
        with patch("django.utils.timezone.now", return_value=self.NOW), CaptureQueriesContext(connection) as queries:
            _calculate_monthly_revenue(Customer.objects.filter(pk=self.customer.pk))

        revenue_sql = next(q["sql"] for q in queries.captured_queries if "SUM(" in q["sql"].upper())
        self.assertNotIn("django_datetime_cast_date", revenue_sql)
        self.assertNotIn("::date", revenue_sql.lower())
        self.assertRegex(revenue_sql, r'"created_at" >= ')
