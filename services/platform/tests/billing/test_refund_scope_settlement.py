"""Settlement reads refunds through the same scope rule as the fiscal correction.

`refund_order` leaves a refund's own `invoice` NULL by schema, and its payment may name only the
proforma. Sums that read the direct and payment links alone never saw such a refund: the invoice
stayed `paid` after its money went back, so no storno was queued and nothing swept it up, and the
outstanding and refundable balances both overstated what was left.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase, TransactionTestCase

from apps.api.billing.serializers import _invoice_remaining_amounts
from apps.billing.fiscal_correction_models import STATE_ATTACHED, FiscalCorrection
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice
from apps.billing.issuers.base import Issued, PreparedDocument
from apps.billing.issuers.service import issue_storno_for_invoice
from apps.billing.models import Payment, ProformaInvoice, Refund
from apps.billing.refund_service import RefundService
from apps.common.types import Ok
from tests.billing import _fiscal_correction_helpers as h


class SettlementSumsReadTheSharedScopeTests(TestCase):
    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner)
        self.payment = h.paid(self.invoice)
        self.order = h.order_for(self.invoice)

    def _order_refund(self, amount_cents: int, *, payment: Payment | None = None) -> Refund:
        """Settled against the order; the refund's own invoice is NULL by schema."""
        return h.pending_refund(order=self.order, payment=payment, amount_cents=amount_cents, status="completed")

    def test_the_outstanding_balance_counts_a_refund_linked_only_through_its_order(self) -> None:
        self._order_refund(4000)

        self.assertEqual(self.invoice.get_remaining_amount(), 4000)

    def test_a_refund_linked_only_through_its_payment_still_counts(self) -> None:
        """The payment leg on its own: no invoice on the refund, and its order names none."""
        unlinked_order = h.order_for(None, owner=self.owner)
        h.pending_refund(order=unlinked_order, payment=self.payment, amount_cents=4000, status="completed")

        self.assertEqual(self.invoice.get_remaining_amount(), 4000)
        self.assertEqual(RefundService._get_invoice_refunded_amount(self.invoice), 4000)
        self.assertEqual(
            _invoice_remaining_amounts(Invoice.objects.filter(pk=self.invoice.pk)), {self.invoice.pk: 4000}
        )

    def test_the_api_batch_agrees_with_the_per_invoice_balance(self) -> None:
        self._order_refund(4000)

        remaining = _invoice_remaining_amounts(Invoice.objects.filter(pk=self.invoice.pk))

        self.assertEqual(remaining, {self.invoice.pk: 4000})

    def test_the_refundable_balance_counts_an_order_path_refund(self) -> None:
        self._order_refund(4000)

        self.assertEqual(RefundService._get_invoice_refunded_amount(self.invoice), 4000)

    def test_the_projection_marks_an_invoice_refunded_through_its_order(self) -> None:
        self._order_refund(self.invoice.total_cents)

        result = RefundService._project_settled_refunds(self.payment, self.invoice)

        self.assertTrue(result.is_ok(), result)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "refunded")

    def test_a_refund_reached_through_two_links_is_counted_once(self) -> None:
        """Regression guard: the order AND the payment both lead to this invoice.

        A forward-key OR cannot duplicate the row in SQL today, but a sum assembled per link (or
        across a multiplying join) would count 4000 twice. Every reader must say 4000.
        """
        self._order_refund(4000, payment=self.payment)

        self.assertEqual(self.invoice.get_remaining_amount(), 4000)
        self.assertEqual(RefundService._get_invoice_refunded_amount(self.invoice), 4000)
        self.assertEqual(
            _invoice_remaining_amounts(Invoice.objects.filter(pk=self.invoice.pk)), {self.invoice.pk: 4000}
        )
        result = RefundService._project_settled_refunds(self.payment, self.invoice)
        self.assertTrue(result.is_ok(), result)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "partially_refunded")


class OrderRefundAgainstTheProformaTests(TransactionTestCase):
    """The `_submit_reserved_refund` shape: the payment names the proforma, never the invoice."""

    def test_the_invoice_projects_to_refunded_and_its_storno_is_minted(self) -> None:
        owner = h.customer()
        invoice = h.issued_invoice(owner, issuer=ISSUER_SMARTBILL, number="FCT-001000")
        invoice.mark_as_paid()
        invoice.save()
        proforma = ProformaInvoice.objects.create(
            customer=owner,
            currency=invoice.currency,
            number="PRO-SCOPE-1",
            subtotal_cents=invoice.subtotal_cents,
            tax_cents=invoice.tax_cents,
            total_cents=invoice.total_cents,
        )
        order = h.order_for(invoice, proforma=proforma)
        payment = Payment.objects.create(
            customer=owner,
            proforma=proforma,
            currency=invoice.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=invoice.total_cents,
            gateway_txn_id="pi_scope_proforma",
        )
        self.assertIsNone(payment.invoice_id)

        def storno_now(invoice_id: int) -> str:
            result = issue_storno_for_invoice(invoice_id)
            self.assertTrue(result.is_ok(), getattr(result, "error", ""))
            return "inline"

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(12100)),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "001000"}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
                return_value=Issued(number="001001", series="STORNO"),
            ),
            patch("apps.billing.issuers.tasks.queue_invoice_storno", side_effect=storno_now) as queued,
        ):
            result = RefundService.refund_order(
                order.pk, {"refund_type": "full", "amount_cents": 12100, "reason": "customer_request"}
            )

        self.assertTrue(result.is_ok(), result)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        queued.assert_called_once_with(invoice.pk)
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit_note.number, "STORNO-001001")
        self.assertEqual(credit_note.reverses_invoice_id, invoice.pk)
        refund = Refund.objects.get(order=order)
        correction = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(correction.state, STATE_ATTACHED)
        self.assertEqual(correction.credit_note_id, credit_note.pk)
