"""Revenue counts each money event in its own month, and says the same thing
whichever invoicing system produced the document.

Two rules, and the second is the one that keeps getting broken:

1. The sale is revenue in the month it was collected; the refund subtracts in the month
   the money went back. Neither month is rewritten later, so a January report run in April
   answers exactly as it did in February.

2. The correction is dated to the `Refund`, not to a credit note. A credit note is the
   SmartBill path's FISCAL record of a refund; the built-in path creates none at all, and
   SmartBill refuses a partial storno, so a credit note cannot represent a partial refund
   on either path. `Refund` is written at one site for both. Counting credit notes instead
   made the same refund move revenue differently depending on which issuer was configured,
   and counting them as well as the refund subtracted the same money twice.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

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


class RevenueRecognitionTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="revenue_admin"))
        self._seq = 0

    def _paid_invoice(self, total: int, *, issuer: str = ISSUER_BUILTIN, month: int | None = None) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FCT-REV-{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=total,
            tax_cents=0,
            total_cents=total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=total,
            tax_rate=Decimal("0"),
            tax_cents=0,
            line_total_cents=total,
        )
        force_status(invoice, "issued")
        force_status(invoice, "paid")
        if month is not None:
            self._in_month(invoice, month)
        return invoice

    def _refund(self, invoice: Invoice, amount: int, *, month: int | None = None) -> Refund:
        self._seq += 1
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=amount,
            original_amount_cents=invoice.total_cents,
            refund_type="full" if amount == invoice.total_cents else "partial",
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        if month is not None:
            # `processed_at` is what the report dates the correction to - it is when the
            # money went back, not when someone asked for it.
            when = timezone.now().replace(month=month, day=15)
            Refund.objects.filter(pk=refund.pk).update(created_at=when, processed_at=when)
        return refund

    def _issued_credit_note(self, original: Invoice, total: int, *, month: int | None = None) -> Invoice:
        """The SmartBill path's fiscal document. The built-in path has no equivalent."""
        self._seq += 1
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"STORNO-{self._seq}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-total,
            tax_cents=0,
            total_cents=-total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        force_status(credit_note, "issued")
        if month is not None:
            self._in_month(credit_note, month)
        return credit_note

    def _in_month(self, invoice: Invoice, month: int) -> None:
        """`created_at` is auto_now_add, and the monthly series groups on it."""
        Invoice.objects.filter(pk=invoice.pk).update(created_at=timezone.now().replace(month=month, day=15))

    def _report(self) -> tuple[dict[int, int], int]:
        response = self.client.get(reverse("billing:reports"))
        self.assertEqual(response.status_code, 200)
        monthly = {row["month"]: row["revenue"] for row in response.context["monthly_stats"]}
        return monthly, response.context["total_revenue"] or 0

    def test_the_sale_stays_in_its_month_and_the_refund_lands_in_its_own(self) -> None:
        invoice = self._paid_invoice(50000, month=1)
        force_status(invoice, "refunded")
        self._refund(invoice, 50000, month=3)

        monthly, total = self._report()

        self.assertEqual(monthly.get(1), 50000, f"January must still show the sale; got {monthly}")
        self.assertEqual(monthly.get(3), -50000, f"March must show the money going back; got {monthly}")
        self.assertEqual(total, 0)

    def test_a_partial_refund_subtracts_only_what_was_returned(self) -> None:
        """The case a credit note can never express: SmartBill refuses a partial storno,
        so dating the correction to a credit note would lose this entirely."""
        invoice = self._paid_invoice(50000, month=1)
        self._refund(invoice, 20000, month=2)
        # The status the real flow reaches. Leaving it `paid` is why an earlier version of
        # this test passed while the whole 500 was dropping out of the report.
        force_status(invoice, "partially_refunded")

        monthly, total = self._report()

        self.assertEqual(monthly.get(1), 50000)
        self.assertEqual(monthly.get(2), -20000, f"only the returned part; got {monthly}")
        self.assertEqual(total, 30000)

    def test_both_issuers_report_the_same_numbers(self) -> None:
        """The parity rule: one business event, one answer.

        The SmartBill path additionally produces a credit note. That is a fiscal document,
        not a second refund, so it must not move revenue - otherwise the same sale and the
        same refund would report differently depending only on configuration.
        """
        builtin = self._paid_invoice(50000, issuer=ISSUER_BUILTIN, month=1)
        force_status(builtin, "refunded")
        self._refund(builtin, 50000, month=3)
        builtin_monthly, builtin_total = self._report()

        Refund.objects.all().delete()
        Invoice.objects.all().delete()

        provider = self._paid_invoice(50000, issuer=ISSUER_SMARTBILL, month=1)
        force_status(provider, "refunded")
        self._refund(provider, 50000, month=3)
        self._issued_credit_note(provider, 50000, month=3)
        provider_monthly, provider_total = self._report()

        self.assertEqual(provider_monthly, builtin_monthly, "same event, same monthly series")
        self.assertEqual(provider_total, builtin_total, "same event, same total")

    def test_a_credit_note_does_not_subtract_a_second_time(self) -> None:
        """It is the fiscal record of a refund already counted."""
        invoice = self._paid_invoice(50000, issuer=ISSUER_SMARTBILL, month=1)
        force_status(invoice, "refunded")
        self._refund(invoice, 50000, month=3)
        self._issued_credit_note(invoice, 50000, month=3)

        _monthly, total = self._report()

        self.assertEqual(total, 0, "counting both the refund and its credit note subtracts twice")

    def test_a_collected_invoice_is_revenue(self) -> None:
        """The regression guard: none of this may disturb an ordinary sale."""
        self._paid_invoice(12100, month=5)

        monthly, total = self._report()

        self.assertEqual(monthly.get(5), 12100)
        self.assertEqual(total, 12100)
