"""Shared fixtures for the revenue and VAT report tests: documents placed on fixed dates of one year."""

from __future__ import annotations

import calendar
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from apps.billing.refund_models import Refund
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user
from tests.helpers.fsm_helpers import force_status

# One fixed past year for every date these tests place, and the same year for every window they
# read. The VAT window used to be a hardcoded 2026 while the documents were placed in "this year",
# so the suite would have started failing on 1 January 2027.
YEAR = 2025
BUCHAREST = ZoneInfo("Europe/Bucharest")


def local_at(month: int, day: int = 15, *, year: int = YEAR, hour: int = 12) -> datetime:
    return datetime(year, month, day, hour, tzinfo=BUCHAREST)


class RevenueRecognitionTestCase(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="revenue_admin"))
        self._seq = 0

    def _paid_invoice(
        self,
        total: int,
        *,
        month: int,
        issuer: str = ISSUER_BUILTIN,
        tax: int = 0,
        currency: Currency | None = None,
    ) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=currency or self.currency,
            number=f"FCT-REV-{self._seq}",
            status="draft",
            subtotal_cents=total - tax,
            tax_cents=tax,
            total_cents=total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=total - tax,
            tax_rate=Decimal("0"),
            tax_cents=tax,
            line_total_cents=total,
        )
        force_status(invoice, "issued")
        force_status(invoice, "paid")
        self._place(invoice, month)
        return invoice

    def _place(self, invoice: Invoice, month: int, *, day: int = 15, locked: bool = False) -> None:
        """Issue the document on a day of `YEAR`: its tax point, its issue instant, and its creation.

        The fiscal series reads the first two; the cash series has always grouped on `created_at`,
        and a document created and issued the same day is the ordinary case. The test that needs
        the two apart moves `created_at` on its own.
        """
        fields: dict[str, Any] = {
            "issued_at": local_at(month, day),
            "tax_point_date": date(YEAR, month, day),
            "created_at": local_at(month, day),
        }
        if locked:
            fields["locked_at"] = local_at(month, day)
        Invoice.objects.filter(pk=invoice.pk).update(**fields)

    def _refund(
        self, invoice: Invoice, amount: int, *, month: int, currency: Currency | None = None
    ) -> Refund:
        self._seq += 1
        refund = Refund.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=currency or self.currency,
            amount_cents=amount,
            original_amount_cents=invoice.total_cents,
            refund_type="full" if amount == invoice.total_cents else "partial",
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        # `processed_at` is what the cash side dates a refund to: when the money went back.
        Refund.objects.filter(pk=refund.pk).update(created_at=local_at(month), processed_at=local_at(month))
        return refund

    def _credit_note(
        self, original: Invoice, total: int, *, month: int, tax: int = 0, issuer: str = ISSUER_BUILTIN
    ) -> Invoice:
        """An issued, numbered credit note whose tax point and issue fall in `month`."""
        self._seq += 1
        credit_note = Invoice.objects.create(
            customer=original.customer,
            currency=original.currency,
            number=f"STORNO-{self._seq}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-(total - tax),
            tax_cents=-tax,
            total_cents=-total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        force_status(credit_note, "issued")
        self._place(credit_note, month, locked=True)
        return Invoice.objects.get(pk=credit_note.pk)

    def _communicated_note(
        self, refund: Refund, *, issued_month: int, sent_month: int, tax: int = 0, sent_day: int = 15
    ) -> Invoice:
        """A built-in storno, issued in one month and received by the customer in another.

        Driven through the correction's own transitions, so every constraint a real note satisfies
        holds here too.
        """
        assert refund.invoice is not None
        credit_note = self._credit_note(refund.invoice, refund.amount_cents, month=issued_month, tax=tax)
        correction = self._issued_correction(refund, credit_note)
        correction.record_communicated(at=local_at(sent_month, sent_day), fiscal_date=date(YEAR, sent_month, sent_day))
        correction.save()
        return credit_note

    def _allocated_correction(self, refund: Refund, credit_note: Invoice) -> FiscalCorrection:
        """The refund's correction, allocated for exactly what `credit_note` carries."""
        correction = FiscalCorrection.objects.create(original=refund.invoice, source_refund=refund)
        correction.allocate(
            base_cents=-credit_note.subtotal_cents,
            tax_cents=-credit_note.tax_cents,
            discount_cents=0,
            at=credit_note.issued_at or timezone.now(),
        )
        correction.save()
        return correction

    def _issued_correction(self, refund: Refund, credit_note: Invoice) -> FiscalCorrection:
        correction = self._allocated_correction(refund, credit_note)
        correction.record_issued(credit_note)
        correction.save()
        return correction

    def _provider_note(
        self, refund: Refund, *, issued_month: int, sent_month: int, tax: int = 0, sent_day: int = 15
    ) -> Invoice:
        """The SmartBill path: a storno staff issued at the provider and recorded with its sending date."""
        assert refund.invoice is not None
        credit_note = self._credit_note(
            refund.invoice, refund.amount_cents, month=issued_month, tax=tax, issuer=ISSUER_SMARTBILL
        )
        correction = self._allocated_correction(refund, credit_note)
        correction.require_manual_issuance()
        correction.save()
        correction.record_provider_document(
            credit_note,
            communicated_at=local_at(sent_month, sent_day),
            fiscal_date=date(YEAR, sent_month, sent_day),
            evidence="sent from the provider, message 42",
        )
        correction.save()
        return credit_note

    def _attached_note(self, refund: Refund, *, month: int, tax: int = 0) -> Invoice:
        """A provider storno linked before corrections carried a sending date: `attached`, no fiscal date."""
        assert refund.invoice is not None
        credit_note = self._credit_note(
            refund.invoice, refund.amount_cents, month=month, tax=tax, issuer=ISSUER_SMARTBILL
        )
        correction = FiscalCorrection.objects.create(original=refund.invoice, source_refund=refund)
        correction.attach_credit_note(credit_note)
        correction.save()
        return credit_note

    def _report(self, currency: str = "RON") -> tuple[dict[tuple[int, int], Any], dict[tuple[int, int], Any]]:
        """The fiscal and the cash series for one currency, keyed by (year, month)."""
        response = self.client.get(reverse("billing:reports"))
        self.assertEqual(response.status_code, 200)
        rows = [row for row in response.context["monthly_stats"] if row["currency"] == currency]
        fiscal = {(row["year"], row["month"]): row.get("fiscal") for row in rows}
        cash = {(row["year"], row["month"]): row.get("cash") for row in rows}
        return fiscal, cash

    def _totals(self, currency: str = "RON") -> tuple[Any, Any]:
        response = self.client.get(reverse("billing:reports"))
        row = next(
            (row for row in response.context["revenue_by_currency"] if row["currency"] == currency),
            {},
        )
        return row.get("fiscal"), row.get("cash")

    def _vat(self, month: int) -> int:
        """VAT declared for one calendar month of `YEAR`."""
        last = calendar.monthrange(YEAR, month)[1]
        response = self.client.get(
            reverse("billing:vat_report"),
            {"start_date": date(YEAR, month, 1).isoformat(), "end_date": date(YEAR, month, last).isoformat()},
        )
        self.assertEqual(response.status_code, 200)
        return response.context["total_vat"] or 0
