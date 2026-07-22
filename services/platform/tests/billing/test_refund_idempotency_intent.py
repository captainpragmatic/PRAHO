"""#342: the refund gateway idempotency key must be invariant to sibling refunds.

Before this fix the key was derived from mutable ledger state (`already_refunded`), so a sibling
refund committing between an attempt and its retry minted a NEW key and the gateway re-executed the
refund → double refund. The fix derives the gateway key deterministically from
`(payment.id, reference)` via a refund intent, so a retry of the same logical refund recomputes the
identical key and the gateway replays. The persisted intent is the durable ledger row for that key
(advanced in place); it does NOT need to survive an outer rollback — the deterministic key does the
work. The TransactionTestCase below proves the end-to-end rollback + retry keeps the key stable.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, Refund
from apps.billing.refund_service import Err, RefundData, RefundService
from apps.customers.models import Customer


class RefundIdempotencyIntentTests(TestCase):
    """Exercise the public refund service with only the gateway boundary mocked."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Refund Intent SRL", customer_type="company", company_name="Refund Intent SRL", status="active"
        )

    def _invoice(self, *, total_cents: int = 10_000) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{uuid.uuid4().hex[:10]}",
            status="paid",
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name=self.customer.company_name,
        )

    def _payment(self, invoice: Invoice, *, txn: str) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=invoice.total_cents,
            gateway_txn_id=txn,
        )

    def _ok_gateway(self, refund_id: str = "re_test") -> MagicMock:
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": refund_id,
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }
        return gateway

    @staticmethod
    def _refund_data(reference: str, amount_cents: int = 10_000) -> RefundData:
        return {
            "refund_type": "full",
            "amount_cents": amount_cents,
            "reason": "customer_request",
            "reference": reference,
        }

    def test_gateway_key_is_stable_across_a_sibling_refund_and_retry(self) -> None:
        """The #342 window at the helper boundary: attempt A, then a sibling refund B commits and
        shifts the refunded balance, then a retry of A (same reference) derives the same gateway key.

        On master the key is `refund:{payment}:{already_refunded}:...`, so B's commit changes it and
        the retry re-executes the refund. Here the key is the DETERMINISTIC `refund:{payment}:{ref}`,
        so it is invariant to sibling refunds. (End-to-end rollback survival is covered by the
        TransactionTestCase below.)
        """
        invoice_a = self._invoice()
        payment_a = self._payment(invoice_a, txn="pi_a")
        gateway = self._ok_gateway("re_a")

        # Simulate the window at the helper boundary: attempt A persists an intent and calls the
        # gateway; its local settlement is then assumed rolled back (intent stays `initiated`); a
        # sibling refund B commits and shifts the balance; a retry of A reuses the surviving intent.
        intent_a = RefundService._get_or_create_refund_intent(
            payment=payment_a,
            order=None,
            invoice=invoice_a,
            amount_cents=10_000,
            original_cents=10_000,
            refund_data=self._refund_data("REF-A"),
            refund_id=uuid.uuid4(),
        ).unwrap()

        with patch(
            "apps.billing.refund_service.PaymentGatewayFactory.create_gateway", return_value=gateway
        ):
            RefundService._execute_gateway_refund(
                payment_a, 10_000, 10_000, idempotency_key=intent_a.idempotency_key
            )
            first_key = gateway.refund_payment.call_args.kwargs["idempotency_key"]

            # A sibling refund B commits, shifting already_refunded on the payment.
            Refund.objects.create(
                customer=self.customer,
                invoice=invoice_a,
                payment=payment_a,
                amount_cents=2_500,
                currency=self.currency,
                original_amount_cents=10_000,
                status="completed",
                reference_number=f"REF-B-{uuid.uuid4().hex[:6]}",
                gateway_refund_id=f"re_b_{uuid.uuid4().hex[:6]}",
            )

            # Retry A with the SAME reference → finds the surviving intent → same key.
            intent_a_retry = RefundService._get_or_create_refund_intent(
                payment=payment_a,
                order=None,
                invoice=invoice_a,
                amount_cents=10_000,
                original_cents=10_000,
                refund_data=self._refund_data("REF-A"),
                refund_id=uuid.uuid4(),
            ).unwrap()
            RefundService._execute_gateway_refund(
                payment_a, 10_000, 10_000, idempotency_key=intent_a_retry.idempotency_key
            )
            retry_key = gateway.refund_payment.call_args.kwargs["idempotency_key"]

        self.assertEqual(first_key, retry_key, "the retry must reuse the original intent's gateway key")
        self.assertEqual(intent_a.id, intent_a_retry.id, "the retry reuses the same persisted intent row")

    def test_intent_is_persisted_as_initiated_and_ignored_by_the_balance(self) -> None:
        """A pre-gateway `initiated` intent must NOT count toward the payment's refunded balance."""
        invoice = self._invoice()
        payment = self._payment(invoice, txn="pi_bal")

        remaining_before = RefundService._get_remaining_payment_refund_amount(payment)

        intent = RefundService._get_or_create_refund_intent(
            payment=payment,
            order=None,
            invoice=invoice,
            amount_cents=10_000,
            original_cents=10_000,
            refund_data=self._refund_data("REF-BAL"),
            refund_id=uuid.uuid4(),
        ).unwrap()

        self.assertEqual(intent.status, "initiated")
        self.assertEqual(intent.idempotency_key, f"refund:{payment.id}:REF-BAL")
        # The initiated intent does not shrink the refundable balance.
        self.assertEqual(RefundService._get_remaining_payment_refund_amount(payment), remaining_before)

    def test_same_reference_different_amount_is_rejected(self) -> None:
        invoice = self._invoice()
        payment = self._payment(invoice, txn="pi_dup")
        RefundService._get_or_create_refund_intent(
            payment=payment, order=None, invoice=invoice, amount_cents=5_000, original_cents=10_000,
            refund_data=self._refund_data("REF-DUP", amount_cents=5_000), refund_id=uuid.uuid4(),
        ).unwrap()

        second = RefundService._get_or_create_refund_intent(
            payment=payment, order=None, invoice=invoice, amount_cents=7_000, original_cents=10_000,
            refund_data=self._refund_data("REF-DUP", amount_cents=7_000), refund_id=uuid.uuid4(),
        )

        self.assertTrue(second.is_err())
        self.assertIn("different amount", second.unwrap_err())

    def test_no_reference_falls_back_to_a_per_call_key(self) -> None:
        """Without a reference, each attempt gets a distinct intent key (previous behaviour)."""
        invoice = self._invoice()
        payment = self._payment(invoice, txn="pi_noref")
        rid1, rid2 = uuid.uuid4(), uuid.uuid4()

        i1 = RefundService._get_or_create_refund_intent(
            payment=payment, order=None, invoice=invoice, amount_cents=10_000, original_cents=10_000,
            refund_data={"refund_type": "full"}, refund_id=rid1,
        ).unwrap()
        i2 = RefundService._get_or_create_refund_intent(
            payment=payment, order=None, invoice=invoice, amount_cents=10_000, original_cents=10_000,
            refund_data={"refund_type": "full"}, refund_id=rid2,
        ).unwrap()

        self.assertNotEqual(i1.idempotency_key, i2.idempotency_key)
        self.assertEqual(i1.idempotency_key, f"refund:{payment.id}:{rid1}")

    def test_full_refund_via_public_path_advances_the_intent_in_place(self) -> None:
        """End-to-end: refund_invoice creates an intent then advances THAT row (no duplicate)."""
        invoice = self._invoice()
        self._payment(invoice, txn="pi_e2e")
        gateway = self._ok_gateway("re_e2e")

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, self._refund_data("REF-E2E"))

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refunds = list(Refund.objects.filter(invoice=invoice))
        self.assertEqual(len(refunds), 1, "the intent row is advanced in place, not duplicated")
        self.assertEqual(refunds[0].idempotency_key, f"refund:{invoice.payments.first().id}:REF-E2E")
        self.assertEqual(refunds[0].gateway_refund_id, "re_e2e")


class RefundRollbackRetryKeyStabilityTests(TransactionTestCase):
    """Real commit semantics (#342): a post-gateway rollback then a retry must hit the gateway with
    the SAME idempotency key — even though the intent row does NOT survive the rollback.

    Uses TransactionTestCase so the outer refund transaction genuinely commits/rolls back (a plain
    TestCase wraps everything in one savepoint and would mask this). This is the test that actually
    proves the window is closed by the deterministic key, not by row persistence.
    """

    reset_sequences = True

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Rollback SRL", customer_type="company", company_name="Rollback SRL", status="active"
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{uuid.uuid4().hex[:10]}",
            status="paid",
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name="Rollback SRL",
        )
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=10_000,
            gateway_txn_id="pi_rollback",
        )

    def _gateway(self) -> MagicMock:
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_rollback",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }
        return gateway

    def test_rollback_then_retry_keeps_the_gateway_key_stable(self) -> None:
        data: RefundData = {"refund_type": "full", "amount_cents": 10_000, "reference": "REF-ROLL"}
        gateway = self._gateway()

        # Attempt A: gateway succeeds, but force the post-gateway settlement to fail so the whole
        # refund transaction rolls back (the intent row is discarded with it).
        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch.object(RefundService, "_advance_refund_status", return_value=Err("forced settlement failure")),
        ):
            result_a = RefundService.refund_invoice(self.invoice.id, data)
        self.assertTrue(result_a.is_err(), "attempt A must fail its local settlement")
        # The rollback wiped the intent — proving row survival is NOT the mechanism.
        self.assertEqual(Refund.objects.filter(payment=self.payment).count(), 0)
        key_a = gateway.refund_payment.call_args.kwargs["idempotency_key"]

        # A distinct sibling refund commits, shifting already_refunded (would change the OLD key).
        Refund.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment=self.payment,
            amount_cents=2_500,
            currency=self.currency,
            original_amount_cents=10_000,
            status="completed",
            reference_number=f"REF-SIB-{uuid.uuid4().hex[:6]}",
            gateway_refund_id=f"re_sib_{uuid.uuid4().hex[:6]}",
        )

        # Retry A with the SAME reference: the deterministic key must be identical to key_a.
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result_b = RefundService.refund_invoice(self.invoice.id, data)
        self.assertTrue(result_b.is_ok(), result_b.unwrap_err() if result_b.is_err() else "")
        key_b = gateway.refund_payment.call_args.kwargs["idempotency_key"]

        self.assertEqual(key_a, key_b, "the retry must reach the gateway with the same idempotency key")
        self.assertEqual(key_a, f"refund:{self.payment.id}:REF-ROLL")

    def tearDown(self) -> None:
        Refund.objects.all().delete()
        Payment.objects.all().delete()
        Invoice.objects.all().delete()
        Customer.objects.all().delete()
