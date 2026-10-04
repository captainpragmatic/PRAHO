"""Revenue and VAT report two separate things, fiscal and cash, each dated to its own event.

**Fiscal** is what the documents say: invoices in the revenue population on their fiscal date
(the tax point, else the Romanian calendar date of issue), less the ISSUED credit notes that
reverse one of those invoices, on the date the note reached the customer (OPANAF 705/2020). A
credit note against an invoice the report never counted subtracts nothing.

**Cash** is what moved: collected invoices less the refunds settled against them, each refund on
the day the money went back. It is the same computation the report has always made.

Neither month is rewritten later. A January sale refunded in March is +X in January and -X in
March on both axes; a January report run in April answers as it did in February. Every assertion
below is per month, because "nets to zero over the year" is equally true of the old answer and
proves nothing about which month carries the correction.

The correction is no longer taken from the `Refund` row on the fiscal side (ADR-0048 revised,
ADR-0053): every settled refund of an issued invoice now produces a credit note on both issuer
paths, so the fiscal document is available everywhere and is the only thing the VAT period may
follow.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.urls import reverse

from apps.billing.fiscal_correction_models import STATE_COMMUNICATED
from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.refund_models import Refund
from tests.billing._revenue_report_helpers import YEAR, RevenueRecognitionTestCase, local_at
from tests.billing._storno_helpers import SELLER, StornoTestCase
from tests.factories.core_factories import create_admin_user
from tests.helpers.fsm_helpers import force_status


class FiscalAndCashSeriesTests(RevenueRecognitionTestCase):
    def test_the_sale_stays_in_its_month_and_the_refund_lands_in_its_own(self) -> None:
        """January sale, March refund and March credit note: +X then -X on both axes, month by month."""
        invoice = self._paid_invoice(50000, month=1)
        force_status(invoice, "refunded")
        refund = self._refund(invoice, 50000, month=3)
        self._communicated_note(refund, issued_month=3, sent_month=3)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 1)), 50000, f"January must still show the sale; got {fiscal}")
        self.assertEqual(fiscal.get((YEAR, 3)), -50000, f"March must carry the credit note; got {fiscal}")
        self.assertEqual(cash.get((YEAR, 1)), 50000, f"cash: January collected the money; got {cash}")
        self.assertEqual(cash.get((YEAR, 3)), -50000, f"cash: March returned it; got {cash}")

    def test_a_credit_note_counts_when_the_customer_received_it_not_when_it_was_issued(self) -> None:
        """Issued on 31 March, emailed on 2 April: April's period, per OPANAF 705/2020."""
        invoice = self._paid_invoice(50000, month=1)
        force_status(invoice, "refunded")
        refund = self._refund(invoice, 50000, month=3)
        self._communicated_note(refund, issued_month=3, sent_month=4, sent_day=2)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 3), 0), 0, f"the note had not reached the customer in March; got {fiscal}")
        self.assertEqual(fiscal.get((YEAR, 4)), -50000, f"April is the communication month; got {fiscal}")
        self.assertEqual(cash.get((YEAR, 3)), -50000, "cash follows the money, which went back in March")

    def test_a_partial_refund_subtracts_only_what_was_returned(self) -> None:
        invoice = self._paid_invoice(50000, month=1)
        refund = self._refund(invoice, 20000, month=2)
        # The status the real flow reaches. Leaving it `paid` is why an earlier version of
        # this test passed while the whole 500 was dropping out of the report.
        force_status(invoice, "partially_refunded")
        self._communicated_note(refund, issued_month=2, sent_month=2)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 1)), 50000)
        self.assertEqual(fiscal.get((YEAR, 2)), -20000, f"only the credited part; got {fiscal}")
        self.assertEqual(cash.get((YEAR, 2)), -20000, f"only the returned part; got {cash}")
        self.assertEqual(self._totals(), (30000, 30000))

    def test_an_order_path_refund_subtracts_from_cash_like_a_direct_one(self) -> None:
        """`refund_order` leaves the refund's own invoice NULL; the order still names it."""
        from apps.orders.models import Order  # noqa: PLC0415

        invoice = self._paid_invoice(50000, month=1)
        order = Order.objects.create(
            order_number=f"ORD-REV-{uuid.uuid4().hex[:8]}",
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            status="completed",
            subtotal_cents=50000,
            tax_cents=0,
            total_cents=50000,
            customer_email="billing@example.test",
            customer_name="Test Company SRL",
        )
        refund = Refund.objects.create(
            customer=self.customer,
            order=order,
            currency=self.currency,
            amount_cents=20000,
            original_amount_cents=50000,
            refund_type="partial",
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        Refund.objects.filter(pk=refund.pk).update(created_at=local_at(2), processed_at=local_at(2))
        force_status(invoice, "partially_refunded")

        _fiscal, cash = self._report()

        self.assertEqual(cash.get((YEAR, 2)), -20000, f"the order-path refund must subtract; got {cash}")
        self.assertEqual(self._totals()[1], 30000)

    def test_both_issuers_report_the_same_numbers(self) -> None:
        """The parity rule: one business event, one answer, whichever system issued the storno.

        The built-in note is dated by its email, the SmartBill one by the sending date staff
        recorded; both are the day the customer received it. Two currencies keep the scenarios
        apart, because an issued document can no longer be deleted to reset between them.
        """
        eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})[0]

        builtin = self._paid_invoice(50000, month=1, issuer=ISSUER_BUILTIN)
        force_status(builtin, "refunded")
        self._communicated_note(self._refund(builtin, 50000, month=3), issued_month=3, sent_month=3)

        provider = self._paid_invoice(50000, month=1, issuer=ISSUER_SMARTBILL, currency=eur)
        force_status(provider, "refunded")
        self._provider_note(self._refund(provider, 50000, month=3, currency=eur), issued_month=3, sent_month=3)

        builtin_series = self._report("RON")
        provider_series = self._report("EUR")

        self.assertEqual(builtin_series[0], {(YEAR, 1): 50000, (YEAR, 3): -50000})
        self.assertEqual(provider_series, builtin_series, "same event, same fiscal and cash series")
        self.assertEqual(self._totals("EUR"), self._totals("RON"))

    def test_a_credit_note_subtracts_once_from_fiscal_and_never_from_cash(self) -> None:
        """The note is the fiscal record of the refund; the refund is the cash record. One each."""
        invoice = self._paid_invoice(50000, issuer=ISSUER_SMARTBILL, month=1)
        force_status(invoice, "refunded")
        self._provider_note(self._refund(invoice, 50000, month=3), issued_month=3, sent_month=3)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 3)), -50000, f"the note subtracts once; got {fiscal}")
        self.assertEqual(cash.get((YEAR, 3)), -50000, f"the refund subtracts once, the note not at all; got {cash}")

    def test_every_credit_note_on_one_original_subtracts_in_its_own_month(self) -> None:
        """An original may carry several notes, one per correction; none may hide another."""
        invoice = self._paid_invoice(50000, month=1)
        force_status(invoice, "partially_refunded")
        self._communicated_note(self._refund(invoice, 20000, month=2), issued_month=2, sent_month=2)
        self._communicated_note(self._refund(invoice, 10000, month=4), issued_month=4, sent_month=4)

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 2)), -20000, f"the first note; got {fiscal}")
        self.assertEqual(fiscal.get((YEAR, 4)), -10000, f"the second note; got {fiscal}")
        self.assertEqual(self._vat(4), 0)

    def test_a_smartbill_note_counts_on_the_day_staff_recorded_it_was_sent(self) -> None:
        """Issued in SmartBill on 31 March, sent on 2 April: April's, like a built-in note."""
        invoice = self._paid_invoice(59500, issuer=ISSUER_SMARTBILL, month=1, tax=9500)
        force_status(invoice, "refunded")
        refund = self._refund(invoice, 59500, month=3)
        self._provider_note(refund, issued_month=3, sent_month=4, sent_day=2, tax=9500)

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 3), 0), 0, f"not sent in March; got {fiscal}")
        self.assertEqual(fiscal.get((YEAR, 4)), -59500, f"April is the sending month; got {fiscal}")
        self.assertEqual((self._vat(3), self._vat(4)), (0, -9500))

    def test_a_note_linked_before_sending_dates_existed_counts_on_its_own_date(self) -> None:
        """An `attached` row has no sending date; its own tax point is the only date it carries."""
        invoice = self._paid_invoice(50000, issuer=ISSUER_SMARTBILL, month=1)
        force_status(invoice, "refunded")
        self._attached_note(self._refund(invoice, 50000, month=3), month=3)

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 3)), -50000, f"dated by its own tax point; got {fiscal}")

    def test_a_refund_without_its_credit_note_yet_moves_cash_but_not_fiscal(self) -> None:
        """Until the correction is issued and sent, nothing fiscal has happened."""
        invoice = self._paid_invoice(50000, month=1)
        force_status(invoice, "refunded")
        self._refund(invoice, 50000, month=3)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 3), 0), 0, f"no credit note, no fiscal correction; got {fiscal}")
        self.assertEqual(cash.get((YEAR, 3)), -50000)

    def test_a_refund_against_an_uncounted_invoice_subtracts_nothing(self) -> None:
        """The refund population has to match the revenue population.

        Requiring only that a refund reference SOME invoice let a completed refund against
        an unissued draft subtract money the report never added - revenue adds 0 and takes
        away 200. Nothing covered it, so the filter could have been loosened back without
        a single test noticing.
        """
        self._paid_invoice(12100, month=2)
        baseline = self._totals()
        self.assertEqual(baseline, (12100, 12100), "a real baseline, or the comparison below is vacuous")
        draft = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=20000,
            tax_cents=0,
            total_cents=20000,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        self._refund(draft, 20000, month=4)

        self.assertEqual(self._totals(), baseline, "a draft was never revenue; its refund subtracts nothing")

    def test_a_credit_note_against_an_uncounted_original_subtracts_nothing(self) -> None:
        """Fiscal sales subtract only the notes that reverse an invoice the report added.

        An issued invoice that was never collected is outside the revenue population; a credit note
        cancelling it must not take money out of a month that never received it.
        """
        unpaid = self._paid_invoice(30000, month=1)
        Invoice.objects.filter(pk=unpaid.pk).update(status="issued")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=unpaid,
            currency=self.currency,
            amount_cents=30000,
            original_amount_cents=30000,
            refund_type="full",
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        self._communicated_note(refund, issued_month=2, sent_month=2)
        self._paid_invoice(12100, month=2)

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 2)), 12100, f"only the counted sale is February's; got {fiscal}")

    def test_the_fiscal_month_is_the_tax_point_not_the_creation_date(self) -> None:
        """A draft created in December and issued in January is January's sale.

        Cash still reads the creation date: that series is unchanged, and the dashboard's cash
        indicator is built on the same basis.
        """
        invoice = self._paid_invoice(40000, month=1)
        Invoice.objects.filter(pk=invoice.pk).update(created_at=local_at(12, year=YEAR - 1))

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 1)), 40000, f"issued in January; got {fiscal}")
        self.assertEqual(fiscal.get((YEAR - 1, 12), 0), 0, f"created is not issued; got {fiscal}")
        self.assertEqual(cash.get((YEAR - 1, 12)), 40000, f"cash keeps its basis; got {cash}")

    def test_the_tax_point_wins_over_the_issue_instant(self) -> None:
        """A tax point on 31 January with the document issued on 1 February declares in January."""
        invoice = self._paid_invoice(40000, month=2, tax=6942)
        Invoice.objects.filter(pk=invoice.pk).update(tax_point_date=date(YEAR, 1, 31), issued_at=local_at(2, 1))

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 1)), 40000, f"the tax point decides; got {fiscal}")
        self.assertEqual(self._vat(1), 6942)
        self.assertEqual(self._vat(2), 0)

    def test_without_a_tax_point_the_issue_date_is_the_romanian_calendar_date(self) -> None:
        """22:30 UTC on 31 January is already 1 February in Bucharest."""
        invoice = self._paid_invoice(40000, month=1, tax=6942)
        Invoice.objects.filter(pk=invoice.pk).update(
            tax_point_date=None, issued_at=datetime(YEAR, 1, 31, 22, 30, tzinfo=ZoneInfo("UTC"))
        )

        fiscal, _cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 2)), 40000, f"the Romanian date is February's; got {fiscal}")
        self.assertEqual(self._vat(2), 6942)
        self.assertEqual(self._vat(1), 0)

    def test_a_collected_invoice_is_revenue(self) -> None:
        """The regression guard: none of this may disturb an ordinary sale."""
        self._paid_invoice(12100, month=5)

        fiscal, cash = self._report()

        self.assertEqual(fiscal.get((YEAR, 5)), 12100)
        self.assertEqual(cash.get((YEAR, 5)), 12100)
        self.assertEqual(self._totals(), (12100, 12100))


class VatPeriodTests(RevenueRecognitionTestCase):
    def test_vat_corrects_a_refund_in_the_month_of_its_credit_note(self) -> None:
        """January keeps the VAT it declared; March carries the reversal.

        The original used to leave the report the moment it became `refunded`, which restated a
        period already filed. Now it stays where it was declared, and the credit note subtracts in
        its own month, once.
        """
        invoice = self._paid_invoice(59500, issuer=ISSUER_SMARTBILL, month=1, tax=9500)
        force_status(invoice, "refunded")
        self._provider_note(self._refund(invoice, 59500, month=3), issued_month=3, sent_month=3, tax=9500)

        self.assertEqual(self._vat(1), 9500, "January's filing is not rewritten by a later refund")
        self.assertEqual(self._vat(3), -9500, "March declares the reversal")
        self.assertEqual(self._vat(2), 0)

    def test_a_refunded_invoice_still_declares_its_vat(self) -> None:
        """Whatever its refund status: VAT is owed when the document is issued."""
        invoice = self._paid_invoice(59500, month=1, tax=9500)
        force_status(invoice, "refunded")

        self.assertEqual(self._vat(1), 9500)

    def test_vat_keeps_an_ordinary_issued_invoice(self) -> None:
        """The regression guard: this must not stop counting VAT that is genuinely owed."""
        self._paid_invoice(59500, month=2, tax=9500)

        self.assertEqual(self._vat(2), 9500)

    def test_an_overdue_invoice_still_owes_vat(self) -> None:
        """Ageing past a due date does not un-declare a filing.

        `overdue` was absent from the VAT population, so a period's VAT fell to zero the
        moment an invoice aged and came back if it was later paid. Nothing covered it.
        """
        invoice = self._paid_invoice(59500, month=6, tax=9500)
        force_status(Invoice.objects.get(pk=invoice.pk), "overdue")

        self.assertEqual(self._vat(6), 9500)

    def test_an_issued_but_unsent_credit_note_declares_in_no_period_yet(self) -> None:
        """Its period is the day it reaches the customer, which has not happened.

        Counting it on its tax point would put the reversal in March and then, once sent in April,
        the D390 would disagree with this screen about which period carries it.
        """
        invoice = self._paid_invoice(59500, month=1, tax=9500)
        force_status(invoice, "refunded")
        refund = self._refund(invoice, 59500, month=3)
        self._issued_correction(refund, self._credit_note(invoice, 59500, month=3, tax=9500))

        self.assertEqual(self._vat(3), 0, "an unsent note has no period yet")
        fiscal, _cash = self._report()
        self.assertEqual(fiscal.get((YEAR, 3), 0), 0, f"nor does it reduce fiscal sales; got {fiscal}")


@SELLER
class BuiltInStornoReportTests(StornoTestCase):
    """The headline case end to end: the worker issues and emails the note, and both reports follow it."""

    def test_a_january_invoice_refunded_in_march_moves_each_month_once(self) -> None:
        with patch("django.utils.timezone.now", return_value=local_at(1, 10)):
            original = self.original()
            payment = self.collected(original, original.total_cents)
        with patch("django.utils.timezone.now", return_value=local_at(3, 20)):
            correction = self.process(self.refund(original, payment, original.total_cents))
        self.assertEqual(correction.state, STATE_COMMUNICATED)
        self.client.force_login(create_admin_user(username="storno_reports"))

        rows = {(row["year"], row["month"]): row for row in self.client.get(reverse("billing:reports")).context["monthly_stats"]}
        january, march = rows.get((YEAR, 1), {}), rows.get((YEAR, 3), {})

        self.assertEqual((january.get("fiscal"), march.get("fiscal")), (12100, -12100), f"fiscal; got {rows}")
        self.assertEqual((january.get("cash"), march.get("cash")), (12100, -12100), f"cash; got {rows}")
        for month, expected in ((1, 2100), (2, 0), (3, -2100)):
            response = self.client.get(
                reverse("billing:vat_report"),
                {"start_date": date(YEAR, month, 1).isoformat(), "end_date": date(YEAR, month, 28).isoformat()},
            )
            self.assertEqual(response.context["total_vat"] or 0, expected, f"VAT in month {month}")
