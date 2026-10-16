"""The operator's home currency follows its country (ADR-0041 addendum).

Accounts are kept in the national currency of the country the operator is established in: the
euro in the euro area, else its own currency, RON for a Romanian operator. Every frozen exchange
rate is to that currency and records which one it was, so a fiscal reader never mistakes a rate
to PLN for a rate to RON. New sales default to the home currency when PRAHO can sell in it.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from io import StringIO

from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.billing.checks import check_home_currency_matches_issued_invoices
from apps.billing.config import EU_COUNTRY_CODES
from apps.billing.currency_policy import SELLING_CURRENCY_KEY, get_selling_currency_policy
from apps.billing.currency_service import NATIONAL_CURRENCIES, default_selling_currency, home_currency
from apps.billing.models import Currency, FXRate, Invoice
from apps.customers.models import Customer
from apps.orders.services import OrderPaymentConfirmationService
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting

GERMAN = {"COMPANY_COUNTRY_CODE": "DE"}
POLISH = {"COMPANY_COUNTRY_CODE": "PL"}


class NationalCurrencyTests(SimpleTestCase):
    def test_every_eu_member_state_has_exactly_one_accounting_currency(self) -> None:
        self.assertEqual(set(NATIONAL_CURRENCIES), set(EU_COUNTRY_CODES))
        euro_area = {country for country, currency in NATIONAL_CURRENCIES.items() if currency == "EUR"}
        self.assertEqual(len(euro_area), 21)  # Bulgaria joined on 1 January 2026, Croatia in 2023
        self.assertIn("BG", euro_area)
        self.assertEqual(NATIONAL_CURRENCIES["RO"], "RON")

    def test_home_currency_follows_the_operator(self) -> None:
        self.assertEqual(home_currency(), "RON")
        for country, expected in (("DE", "EUR"), ("PL", "PLN"), ("GR", "EUR")):
            with self.subTest(country=country), override_settings(COMPANY_COUNTRY_CODE=country):
                self.assertEqual(home_currency(), expected)

    @override_settings(COMPANY_COUNTRY_CODE="US")
    def test_an_operator_outside_the_eu_has_no_home_currency(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "US"):
            home_currency()

    def test_new_sales_default_to_the_home_currency_when_it_can_be_sold(self) -> None:
        self.assertEqual(default_selling_currency(), "RON")
        # The catalog default is what the migration seeds and the runtime falls back to.
        self.assertEqual(CATALOG_BY_KEY["billing.default_currency"].default, default_selling_currency())
        for settings_, expected in ((GERMAN, "EUR"), (POLISH, "EUR")):
            with self.subTest(settings=settings_), override_settings(**settings_):
                self.assertEqual(default_selling_currency(), expected)


class HomeCurrencySnapshotTests(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(customer_type="company", company_name="FX Home SA", status="active")

    def _issue(self, currency: Currency, number: str) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer, currency=currency, number=number,
            subtotal_cents=10000, tax_cents=2300, total_cents=12300,
        )
        invoice.issued_at = timezone.make_aware(datetime(2026, 7, 20, 10, 0))
        invoice.issue()
        invoice.save()
        invoice.refresh_from_db()
        return invoice

    def _rate(self, quote: Currency, rate: str) -> FXRate:
        return FXRate.objects.create(
            base_code=self.eur, quote_code=quote, rate=Decimal(rate), as_of=date(2026, 7, 17),
            source=FXRate.Source.ECB, source_reference="https://www.ecb.europa.eu/stats/eurofxref/",
            fetched_at=timezone.now(),
        )

    @override_settings(**POLISH)
    def test_a_polish_operator_freezes_a_euro_invoice_against_pln(self) -> None:
        call_command("ensure_home_currency", stdout=StringIO())  # run on every deploy by setup_initial_data
        pln = Currency.objects.get(code="PLN")
        self._rate(pln, "4.25")

        invoice = self._issue(self.eur, "INV-PL-EUR-1")

        self.assertEqual(invoice.exchange_rate_to_home, Decimal("4.25"))
        self.assertEqual(invoice.home_currency_code, "PLN")
        self.assertIsNone(invoice.ron_exchange_rate())  # never mistaken for a rate to RON

    def test_a_romanian_operator_freezes_against_ron_and_stamps_home_on_ron_invoices(self) -> None:
        self._rate(self.ron, "4.97")

        foreign = self._issue(self.eur, "INV-RO-EUR-1")
        domestic = self._issue(self.ron, "INV-RO-RON-1")

        self.assertEqual((foreign.home_currency_code, foreign.ron_exchange_rate()), ("RON", Decimal("4.97")))
        self.assertEqual((domestic.home_currency_code, domestic.exchange_rate_to_home), ("RON", None))

    def test_changing_the_operators_country_under_issued_invoices_is_refused(self) -> None:
        self._issue(self.ron, "INV-RO-RON-CHECK")
        self.assertEqual(check_home_currency_matches_issued_invoices(databases=["default"]), [])
        with override_settings(**GERMAN):
            errors = check_home_currency_matches_issued_invoices(databases=["default"])
        self.assertEqual([error.id for error in errors], ["billing.E003"])
        self.assertIn("RON", errors[0].msg)

    @override_settings(**GERMAN)
    def test_a_german_operators_euro_invoice_is_domestic(self) -> None:
        invoice = self._issue(self.eur, "INV-DE-EUR-1")
        self.assertEqual((invoice.home_currency_code, invoice.exchange_rate_to_home), ("EUR", None))


class ReviewThresholdTests(TestCase):
    def test_the_standing_review_limit_is_in_the_default_selling_currency(self) -> None:
        # Unconfigured, the single legacy limit applies to the default selling currency; others review every order.
        self.assertEqual((OrderPaymentConfirmationService._get_review_threshold("RON"), OrderPaymentConfirmationService._get_review_threshold("EUR")), (500000, 0))
        for operator, sold, other in ((GERMAN, "EUR", "RON"), (POLISH, "EUR", "PLN")):
            with self.subTest(operator=operator), override_settings(**operator):
                self.assertEqual(
                    (
                        OrderPaymentConfirmationService._get_review_threshold(sold),
                        OrderPaymentConfirmationService._get_review_threshold(other),
                    ),
                    (500000, 0),
                )


class SellingCurrencyDefaultTests(TestCase):
    @override_settings(**GERMAN)
    def test_a_german_operator_without_a_selling_policy_sells_in_euro(self) -> None:
        SystemSetting.objects.filter(key=SELLING_CURRENCY_KEY).delete()
        self.assertEqual(get_selling_currency_policy().currency_code, "EUR")
        with transaction.atomic():
            self.assertEqual(get_selling_currency_policy(lock=True).currency_code, "EUR")
        self.assertEqual(SystemSetting.objects.get(key=SELLING_CURRENCY_KEY).value, "EUR")
