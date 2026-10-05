"""Every way a document can be dated lands on the right side of a month boundary.

The VAT period is chosen with one indexable condition per dating rule rather than one computed date,
so each rule is pinned here on its own: a document just before midnight on 31 January and one just
after it, both in Bucharest time. VAT amounts are distinct powers of two, so a period's total names
exactly which documents it counted.

- an invoice with a tax point is dated by it;
- without a tax point, by the Romanian date of its issue;
- with neither (rows that never went through `issue()`), by the Romanian date of its creation;
- a sent credit note by the day its correction records it was sent;
- a provider note linked before sending dates existed (`attached`) by its own tax point.

The refund warning has the same boundary on the day the money went back.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from django.urls import reverse

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    DOCUMENT_KIND_INVOICE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Invoice,
)
from apps.billing.refund_models import Refund
from tests.billing._revenue_report_helpers import YEAR, RevenueRecognitionTestCase, local_at

# 23:30 on 31 January and 00:30 on 1 February, Bucharest time. The second is still 31 January in UTC.
LAST_THING_IN_JANUARY = local_at(1, 31, hour=23)
FIRST_THING_IN_FEBRUARY = local_at(2, 1, hour=0)


class VatPeriodBoundaryTests(RevenueRecognitionTestCase):
    def _document(  # noqa: PLR0913  # One keyword per dating field a test places
        self,
        vat: int,
        *,
        tax_point: date | None,
        issued_at: datetime | None,
        created_at: datetime,
        reverses: Invoice | None = None,
        issuer: str = ISSUER_BUILTIN,
    ) -> Invoice:
        """An issued document whose dating fields are exactly the ones given."""
        self._seq += 1
        sign = -1 if reverses is not None else 1
        document = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"BND-{self._seq}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE if reverses is not None else DOCUMENT_KIND_INVOICE,
            reverses_invoice=reverses,
            subtotal_cents=sign * 10000,
            tax_cents=sign * vat,
            total_cents=sign * (10000 + vat),
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        fields: dict[str, Any] = {
            "status": "issued" if reverses is not None else "paid",
            "tax_point_date": tax_point,
            "issued_at": issued_at,
            "created_at": created_at,
        }
        if reverses is not None:
            fields["locked_at"] = created_at
        Invoice.objects.filter(pk=document.pk).update(**fields)
        return Invoice.objects.get(pk=document.pk)

    def _sent_note(self, vat: int, *, sent_on: date, own_tax_point: date) -> Invoice:
        """A sent built-in note whose own tax point sits on the other side of the boundary."""
        original = self._paid_invoice(10000 + vat, month=6, tax=vat)
        refund = self._refund(original, 10000 + vat, month=1)
        note = self._document(
            vat,
            tax_point=own_tax_point,
            issued_at=local_at(own_tax_point.month, own_tax_point.day),
            created_at=local_at(own_tax_point.month, own_tax_point.day),
            reverses=original,
        )
        correction = self._issued_correction(refund, note)
        correction.record_communicated(at=local_at(sent_on.month, sent_on.day), fiscal_date=sent_on)
        correction.save()
        return note

    def _legacy_note(self, vat: int, *, tax_point: date) -> Invoice:
        """A provider note `attached` before sending dates existed: dated by its own tax point."""
        original = self._paid_invoice(10000 + vat, month=6, tax=vat, issuer=ISSUER_SMARTBILL)
        refund = self._refund(original, 10000 + vat, month=1)
        note = self._document(
            vat,
            tax_point=tax_point,
            issued_at=local_at(tax_point.month, tax_point.day),
            created_at=local_at(tax_point.month, tax_point.day),
            reverses=original,
            issuer=ISSUER_SMARTBILL,
        )
        correction = FiscalCorrection.objects.create(original=original, source_refund=refund)
        correction.attach_credit_note(note)
        correction.save()
        return note

    def _period(self, month: int) -> tuple[int, set[str]]:
        last = 31 if month == 1 else 28
        response = self.client.get(
            reverse("billing:vat_report"),
            {"start_date": date(YEAR, month, 1).isoformat(), "end_date": date(YEAR, month, last).isoformat()},
        )
        self.assertEqual(response.status_code, 200)
        return response.context["total_vat"] or 0, {document.number for document in response.context["documents"]}

    def test_each_dating_rule_puts_a_document_on_its_side_of_midnight(self) -> None:
        by_tax_point = (
            self._document(1, tax_point=date(YEAR, 1, 31), issued_at=FIRST_THING_IN_FEBRUARY, created_at=FIRST_THING_IN_FEBRUARY),
            self._document(2, tax_point=date(YEAR, 2, 1), issued_at=LAST_THING_IN_JANUARY, created_at=LAST_THING_IN_JANUARY),
        )
        by_issue = (
            self._document(4, tax_point=None, issued_at=LAST_THING_IN_JANUARY, created_at=FIRST_THING_IN_FEBRUARY),
            self._document(8, tax_point=None, issued_at=FIRST_THING_IN_FEBRUARY, created_at=LAST_THING_IN_JANUARY),
        )
        by_creation = (
            self._document(16, tax_point=None, issued_at=None, created_at=LAST_THING_IN_JANUARY),
            self._document(32, tax_point=None, issued_at=None, created_at=FIRST_THING_IN_FEBRUARY),
        )
        by_sending = (
            self._sent_note(64, sent_on=date(YEAR, 1, 31), own_tax_point=date(YEAR, 2, 1)),
            self._sent_note(128, sent_on=date(YEAR, 2, 1), own_tax_point=date(YEAR, 1, 31)),
        )
        by_own_date = (
            self._legacy_note(256, tax_point=date(YEAR, 1, 31)),
            self._legacy_note(512, tax_point=date(YEAR, 2, 1)),
        )
        pairs = (by_tax_point, by_issue, by_creation, by_sending, by_own_date)

        january, february = self._period(1), self._period(2)

        self.assertEqual(january[1], {january_doc.number for january_doc, _ in pairs})
        self.assertEqual(february[1], {february_doc.number for _, february_doc in pairs})
        self.assertEqual(january[0], 1 + 4 + 16 - 64 - 256)
        self.assertEqual(february[0], 2 + 8 + 32 - 128 - 512)


class WarningPeriodBoundaryTests(RevenueRecognitionTestCase):
    def _settled(self, *, processed_at: datetime | None, created_at: datetime) -> Refund:
        invoice = self._paid_invoice(10000, month=1)
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=10000,
            original_amount_cents=10000,
            refund_type="full",
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        Refund.objects.filter(pk=refund.pk).update(processed_at=processed_at, created_at=created_at)
        return refund

    def _owed_by_end_of_january(self) -> int:
        response = self.client.get(
            reverse("billing:vat_report"), {"start_date": f"{YEAR}-01-01", "end_date": f"{YEAR}-01-31"}
        )
        return int(response.context["undated_corrections"]["awaiting_issue"])

    def test_a_refund_settled_before_midnight_flags_january_and_one_after_does_not(self) -> None:
        self._settled(processed_at=LAST_THING_IN_JANUARY, created_at=LAST_THING_IN_JANUARY)
        self._settled(processed_at=FIRST_THING_IN_FEBRUARY, created_at=LAST_THING_IN_JANUARY)

        self.assertEqual(self._owed_by_end_of_january(), 1)

    def test_without_a_processing_time_the_request_time_decides(self) -> None:
        self._settled(processed_at=None, created_at=LAST_THING_IN_JANUARY)
        self._settled(processed_at=None, created_at=FIRST_THING_IN_FEBRUARY)

        self.assertEqual(self._owed_by_end_of_january(), 1)
