"""The two `billing.efactura_*` deadline settings, asserted on the deadline they produce.

Neither had a test that mentioned it. They are not cosmetic: OUG 89/2025 gives 5 WORKING days to
submit an invoice to ANAF, and `billing.efactura_submission_deadline_days` is the number the working-
day calculator is handed. `billing.efactura_deadline_warning_hours` decides when staff are told a
deadline is coming, so a wrong value means either noise or a missed legal deadline with no warning.

The deadline is compared against `submission_deadline_datetime` called directly with the expected
number of days rather than against a hardcoded date. That asserts what is actually in question - the
stored setting reaches the calculator - without this file re-implementing the Romanian public-holiday
calendar, which would make it a test of a copy rather than of the code.
"""

from __future__ import annotations

import datetime

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument
from apps.billing.efactura.working_days import submission_deadline_datetime
from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.settings.services import SettingsService

DEADLINE_DAYS_KEY = "billing.efactura_submission_deadline_days"
WARNING_HOURS_KEY = "billing.efactura_deadline_warning_hours"


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class EFacturaDeadlineSettingEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Deadline Effects SRL",
            customer_type="company",
            status="active",
            primary_email="deadline-effects@example.test",
        )
        # Yesterday, whichever weekday that is. The tests never assume a calendar position: each
        # compares against `submission_deadline_datetime` called with the same instant, so the only
        # thing under test is which number of days the property hands it.
        self.issued_at = timezone.now().replace(microsecond=0) - datetime.timedelta(days=1)
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="EF-DEADLINE-0001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            issued_at=self.issued_at,
        )
        self.document = EFacturaDocument.objects.create(invoice=invoice, document_type="invoice")

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_the_configured_number_of_working_days_is_what_the_calculator_receives(self) -> None:
        self.set_value(DEADLINE_DAYS_KEY, 3)
        self.assertEqual(self.document.submission_deadline, submission_deadline_datetime(self.issued_at, 3))

    def test_more_days_moves_the_deadline_later_and_fewer_moves_it_earlier(self) -> None:
        """The discriminating pair: a hardcoded 5 could not satisfy both."""
        self.set_value(DEADLINE_DAYS_KEY, 2)
        short = self.document.submission_deadline
        self.set_value(DEADLINE_DAYS_KEY, 15)
        long = self.document.submission_deadline

        self.assertEqual(short, submission_deadline_datetime(self.issued_at, 2))
        self.assertEqual(long, submission_deadline_datetime(self.issued_at, 15))
        self.assertLess(short, long)

    def test_the_catalog_default_is_the_five_days_the_law_requires(self) -> None:
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[DEADLINE_DAYS_KEY], 5)
        self.assertEqual(self.document.submission_deadline, submission_deadline_datetime(self.issued_at, 5))

    def test_an_invoice_that_was_never_issued_has_no_deadline(self) -> None:
        """The guard the property opens with, pinned so the tests above cannot mask its removal."""
        self.document.invoice.issued_at = None
        self.document.invoice.save(update_fields=["issued_at"])
        self.document.refresh_from_db()
        self.assertIsNone(self.document.submission_deadline)

    def test_a_wide_warning_window_raises_the_alert_that_a_narrow_one_does_not(self) -> None:
        """Same document, same deadline, opposite answers - the setting is the only variable."""
        self.set_value(DEADLINE_DAYS_KEY, 15)

        self.set_value(WARNING_HOURS_KEY, 1)
        self.assertFalse(self.document.is_deadline_approaching)

        self.set_value(WARNING_HOURS_KEY, 24 * 365)
        self.assertTrue(self.document.is_deadline_approaching)

    def test_the_warning_window_does_not_change_whether_the_deadline_has_passed(self) -> None:
        """`is_deadline_passed` must stay independent: a wide warning is not a missed deadline."""
        self.set_value(DEADLINE_DAYS_KEY, 15)
        self.set_value(WARNING_HOURS_KEY, 24 * 365)

        self.assertTrue(self.document.is_deadline_approaching)
        self.assertFalse(self.document.is_deadline_passed)
