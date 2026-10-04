"""The reports say when a period is not finished yet.

A completed refund owes a credit note, and the note belongs to the period in which the customer
received it (OPANAF 705/2020). Until that has happened the fiscal figures are short a correction
that is certainly coming, and nothing in the numbers shows it. So both reports count the completed
refunds whose correction is still unsettled, in two groups that need different people:

* **not issued yet**: no correction recorded, or one pending, allocated or failed;
* **issued, not sent**: a numbered credit note exists but has not reached the customer, so it has
  no period at all.

A correction that was sent, attached to a provider credit note, or closed as not required is
settled and never warns.
"""

from __future__ import annotations

import uuid
from datetime import date

from django.urls import reverse

from apps.billing.fiscal_correction_models import REASON_COVERED_BY_COLLECTIONS, FiscalCorrection
from apps.billing.invoice_models import ISSUER_SMARTBILL
from apps.billing.models import Payment
from apps.billing.refund_models import Refund
from tests.billing._revenue_report_helpers import YEAR, RevenueRecognitionTestCase, local_at
from tests.helpers.fsm_helpers import force_status

NOT_ISSUED = "awaiting_issue"
NOT_SENT = "awaiting_communication"


class UndatedCorrectionWarningTests(RevenueRecognitionTestCase):
    def _vat_warning(self, *, end: date | None = None) -> dict[str, int]:
        params = {"start_date": date(YEAR, 1, 1).isoformat(), "end_date": (end or date(YEAR, 12, 31)).isoformat()}
        response = self.client.get(reverse("billing:vat_report"), params)
        self.assertEqual(response.status_code, 200)
        return dict(response.context.get("undated_corrections") or {})

    def _refunded(self, *, month: int = 3) -> Refund:
        invoice = self._paid_invoice(59500, month=1, tax=9500)
        force_status(invoice, "refunded")
        return self._refund(invoice, 59500, month=month)

    def test_a_refund_with_no_correction_yet_is_flagged_as_not_issued(self) -> None:
        self._refunded()

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 1, NOT_SENT: 0})

    def test_a_pending_correction_is_flagged_as_not_issued(self) -> None:
        refund = self._refunded()
        FiscalCorrection.objects.create(original=refund.invoice, source_refund=refund)

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 1, NOT_SENT: 0})

    def test_an_issued_but_unsent_credit_note_is_flagged_and_shown(self) -> None:
        refund = self._refunded()
        assert refund.invoice is not None
        self._issued_correction(refund, self._credit_note(refund.invoice, 59500, month=3, tax=9500))

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 0, NOT_SENT: 1})
        response = self.client.get(
            reverse("billing:vat_report"), {"start_date": f"{YEAR}-01-01", "end_date": f"{YEAR}-12-31"}
        )
        self.assertContains(response, 'data-testid="undated-corrections"')

    def test_a_sent_credit_note_settles_the_period(self) -> None:
        self._communicated_note(self._refunded(), issued_month=3, sent_month=3)

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 0, NOT_SENT: 0})

    def test_an_attached_provider_note_settles_the_period(self) -> None:
        invoice = self._paid_invoice(59500, month=1, tax=9500, issuer=ISSUER_SMARTBILL)
        force_status(invoice, "refunded")
        self._provider_note(self._refund(invoice, 59500, month=3), month=3, tax=9500)

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 0, NOT_SENT: 0})

    def test_a_correction_closed_as_not_required_settles_the_period(self) -> None:
        refund = self._refunded()
        correction = FiscalCorrection.objects.create(original=refund.invoice, source_refund=refund)
        correction.mark_not_required(REASON_COVERED_BY_COLLECTIONS)
        correction.save()

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 0, NOT_SENT: 0})

    def test_tender_legs_answer_to_their_command_correction(self) -> None:
        """Two legs, one command, one sent note: settled, even though neither leg owns a correction."""
        from apps.promotions.models import TenderRefundCommand, TenderRefundLeg  # noqa: PLC0415

        invoice = self._paid_invoice(59500, month=1, tax=9500)
        force_status(invoice, "refunded")
        command = TenderRefundCommand.objects.create(
            invoice=invoice,
            customer=self.customer,
            amount_cents=59500,
            operation_key=f"report-warning-{uuid.uuid4().hex[:8]}",
            reason="test",
        )
        for amount in (40000, 19500):
            payment = Payment.objects.create(
                customer=self.customer,
                invoice=invoice,
                currency=self.currency,
                status="succeeded",
                payment_method="bank_transfer",
                amount_cents=amount,
            )
            leg = self._refund(invoice, amount, month=3)
            TenderRefundLeg.objects.create(command=command, payment=payment, refund=leg, amount_cents=amount)
        credit_note = self._credit_note(invoice, 59500, month=3, tax=9500)
        correction = FiscalCorrection.objects.create(original=invoice, source_command=command)
        correction.allocate(base_cents=50000, tax_cents=9500, discount_cents=0, at=local_at(3))
        correction.save()
        correction.record_issued(credit_note)
        correction.save()
        correction.record_communicated(at=local_at(3), fiscal_date=date(YEAR, 3, 15))
        correction.save()

        self.assertEqual(self._vat_warning(), {NOT_ISSUED: 0, NOT_SENT: 0})

    def test_a_refund_settled_after_the_period_does_not_flag_it(self) -> None:
        """A period that ended before the money went back cannot receive that refund's note."""
        self._refunded(month=6)

        self.assertEqual(self._vat_warning(end=date(YEAR, 5, 31)), {NOT_ISSUED: 0, NOT_SENT: 0})
        self.assertEqual(self._vat_warning(end=date(YEAR, 6, 30)), {NOT_ISSUED: 1, NOT_SENT: 0})

    def test_the_revenue_report_carries_the_same_warning(self) -> None:
        self._refunded()

        response = self.client.get(reverse("billing:reports"))

        self.assertEqual(dict(response.context.get("undated_corrections") or {}), {NOT_ISSUED: 1, NOT_SENT: 0})
        self.assertContains(response, 'data-testid="undated-corrections"')

    def test_nothing_unsettled_shows_no_warning(self) -> None:
        self._paid_invoice(12100, month=2)

        response = self.client.get(reverse("billing:reports"))

        self.assertNotContains(response, 'data-testid="undated-corrections"')
