"""Settlement reads refunds through the same scope rule as the fiscal correction.

`refund_order` leaves a refund's own `invoice` NULL by schema, and its payment may name only the
proforma. Sums that read the direct and payment links alone never saw such a refund: the invoice
stayed `paid` after its money went back, so no storno was queued and nothing swept it up, and the
outstanding and refundable balances both overstated what was left.
"""

from __future__ import annotations

from typing import Any
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
from tests.helpers.fsm_helpers import force_status


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


class OneRefundBelongsToOneInvoiceTests(TestCase):
    """A refund whose links disagree (payment names A, order names B) belongs to ONE of them.

    Gateway convergence can attach a refund to a payment of one invoice and an order of another.
    Counted against both, it returned the same money twice: A's and B's balances both dropped.
    Precedence decides: the refund's own invoice, then its payment's, then its order's.
    """

    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice_a = h.issued_invoice(self.owner)
        self.payment_a = h.paid(self.invoice_a)
        self.invoice_b = h.issued_invoice(self.owner)
        self.payment_b = h.paid(self.invoice_b)
        self.order_b = h.order_for(self.invoice_b)

    def _disagreeing_refund(self, **fields: object) -> Refund:
        return h.pending_refund(order=self.order_b, payment=self.payment_a, amount_cents=4000, **fields)

    def test_only_the_payments_invoice_counts_the_refund(self) -> None:
        self._disagreeing_refund(status="completed")

        self.assertEqual(self.invoice_a.get_remaining_amount(), 4000)
        self.assertEqual(self.invoice_b.get_remaining_amount(), 0)
        self.assertEqual(RefundService._get_invoice_refunded_amount(self.invoice_a), 4000)
        self.assertEqual(RefundService._get_invoice_refunded_amount(self.invoice_b), 0)
        both = Invoice.objects.filter(pk__in=[self.invoice_a.pk, self.invoice_b.pk])
        self.assertEqual(_invoice_remaining_amounts(both), {self.invoice_a.pk: 4000, self.invoice_b.pk: 0})

    def test_the_obligation_follows_the_same_precedence_and_says_so(self) -> None:
        refund = self._disagreeing_refund()

        with self.assertLogs("apps.billing.refund_models", level="WARNING") as logs:
            h.complete(refund)

        correction = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(correction.original_id, self.invoice_a.pk)
        self.assertTrue(any(str(refund.pk) in line for line in logs.output), logs.output)


ONE_HUNDRED = ((10000, "0"),)


class ProjectionFollowsNetCollectedTests(TransactionTestCase):
    """An invoice is refunded when the money it was paid with has gone back, not when refunds add up.

    Returning an overpayment leaves the invoice fully paid. Projecting from refunds alone marked it
    `refunded` and let a whole-document storno credit the customer for a sale they still paid for.
    """

    def setUp(self) -> None:
        self.owner = h.customer()

    def _smartbill_invoice(self, number: str) -> Invoice:
        invoice = h.issued_invoice(self.owner, lines=ONE_HUNDRED, issuer=ISSUER_SMARTBILL, number=number)
        invoice.mark_as_paid()
        invoice.save()
        return invoice

    def _storno_patches(self, number: str) -> Any:
        def storno_now(invoice_id: int) -> str:
            result = issue_storno_for_invoice(invoice_id)
            self.assertTrue(result.is_ok(), getattr(result, "error", ""))
            return "inline"

        return (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": number}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
                return_value=Issued(number=f"{number}9", series="STORNO"),
            ),
            patch("apps.billing.issuers.tasks.queue_invoice_storno", side_effect=storno_now),
        )

    def test_refunding_an_overpayment_leaves_the_invoice_paid_and_unreversed(self) -> None:
        invoice = self._smartbill_invoice("FCT-002000")
        proforma = ProformaInvoice.objects.create(
            customer=self.owner,
            currency=invoice.currency,
            number="PRO-OVERPAID",
            subtotal_cents=10000,
            tax_cents=0,
            total_cents=10000,
        )
        order = h.order_for(invoice, proforma=proforma, subtotal_cents=20000, tax_cents=0, total_cents=20000)
        Payment.objects.create(
            customer=self.owner,
            proforma=proforma,
            currency=invoice.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=20000,
            gateway_txn_id="pi_overpaid",
        )
        prepare, submit, queue = self._storno_patches("002000")

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(10000)),
            prepare,
            submit,
            queue as queued,
        ):
            result = RefundService.refund_order(
                order.pk, {"refund_type": "partial", "amount_cents": 10000, "reason": "duplicate_payment"}
            )

        self.assertTrue(result.is_ok(), result)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid", "100 is still collected against a 100 invoice")
        queued.assert_not_called()
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())

    def test_a_whole_document_storno_is_refused_while_money_is_still_collected(self) -> None:
        invoice = self._smartbill_invoice("FCT-002100")
        Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            status="succeeded",
            payment_method="bank_transfer",
            amount_cents=20000,
        )
        h.pending_refund(invoice=invoice, status="completed", amount_cents=10000)
        force_status(invoice, "refunded")
        prepare, submit, _queue = self._storno_patches("002100")

        with prepare, submit:
            result = issue_storno_for_invoice(invoice.pk)

        self.assertTrue(result.is_err())
        self.assertIn("still collected", result.error)
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())

    def test_a_full_refund_of_a_fully_paid_invoice_is_still_refunded_and_reversed(self) -> None:
        """Regression guard for the net rule: 100 paid, 100 returned, nothing left."""
        invoice = self._smartbill_invoice("FCT-002200")
        Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=10000,
            gateway_txn_id="pi_full_100",
        )
        prepare, submit, queue = self._storno_patches("002200")

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(10000)),
            prepare,
            submit,
            queue as queued,
        ):
            result = RefundService.refund_invoice(
                invoice.pk, {"refund_type": "full", "amount_cents": 10000, "reason": "customer_request"}
            )

        self.assertTrue(result.is_ok(), result)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        queued.assert_called_once_with(invoice.pk)
        self.assertTrue(
            Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE, reverses_invoice=invoice).exists()
        )

    def test_a_partial_refund_of_a_fully_paid_invoice_is_partially_refunded(self) -> None:
        """Regression guard for the net rule: 100 paid, 40 returned, 60 still collected."""
        invoice = self._smartbill_invoice("FCT-002300")
        Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=10000,
            gateway_txn_id="pi_partial_100",
        )

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(4000)):
            result = RefundService.refund_invoice(
                invoice.pk, {"refund_type": "partial", "amount_cents": 4000, "reason": "customer_request"}
            )

        self.assertTrue(result.is_ok(), result)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "partially_refunded")
