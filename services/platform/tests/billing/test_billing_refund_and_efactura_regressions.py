# ===============================================================================
# TESTS FOR BILLING TODO FIXES
# Tests for: amount_due, update_status_from_payments, proforma PDF/email,
#             gateway refund, e-Factura wiring
# ===============================================================================

import logging
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment, Refund
from apps.billing.proforma_service import generate_proforma_pdf, send_proforma_email
from apps.billing.refund_service import RefundService
from tests.factories.billing_factories import create_currency, create_customer, create_invoice
from tests.helpers.fsm_helpers import force_status

# ===============================================================================
# 1. Invoice amount_due Tests
# ===============================================================================


class InvoiceAmountDueTests(TestCase):
    """Test Invoice.amount_due wiring to get_remaining_amount()"""

    def setUp(self):
        self.customer = create_customer("Amount Due Co")
        self.currency = create_currency("RON")
        self.invoice = create_invoice(self.customer, self.currency, total_cents=10000)

    def test_no_payments_returns_full_total(self):
        """Issued invoice with no payments → amount_due == total_cents"""
        self.assertEqual(self.invoice.amount_due, 10000)

    def test_partial_payment_returns_remainder(self):
        """Partial payment → amount_due == total - paid"""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=3000,
            status="succeeded",
            currency=self.currency,
        )
        self.assertEqual(self.invoice.amount_due, 7000)

    def test_full_payment_returns_zero(self):
        """Full payment → amount_due == 0"""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            status="succeeded",
            currency=self.currency,
        )
        self.assertEqual(self.invoice.amount_due, 0)

    def test_paid_status_fast_path_skips_db(self):
        """Invoice with status='paid' returns 0 without DB query"""
        force_status(self.invoice, "paid")
        with self.assertNumQueries(0):
            self.assertEqual(self.invoice.amount_due, 0)


# ===============================================================================
# 2. update_status_from_payments Tests
# ===============================================================================


class UpdateStatusFromPaymentsTests(TestCase):
    """Test Invoice.update_status_from_payments() logic"""

    def setUp(self):
        self.customer = create_customer("Status Update Co")
        self.currency = create_currency("EUR")
        self.invoice = create_invoice(self.customer, self.currency, total_cents=10000)

    def test_full_payment_marks_paid(self):
        """Full payment → invoice transitions to 'paid'"""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            status="succeeded",
            currency=self.currency,
        )
        self.invoice.update_status_from_payments()
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertIsNotNone(self.invoice.paid_at)

    def test_partial_payment_keeps_issued(self):
        """Partial payment → status stays 'issued', logs partial info"""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=3000,
            status="succeeded",
            currency=self.currency,
        )
        with self.assertLogs("apps.billing", level="INFO") as cm:
            self.invoice.update_status_from_payments()
        self.assertEqual(self.invoice.status, "issued")
        self.assertTrue(any("partially paid" in msg for msg in cm.output))

    def test_terminal_status_not_modified(self):
        """'void' invoice is never changed by payments"""
        force_status(self.invoice, "void")
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            status="succeeded",
            currency=self.currency,
        )
        self.invoice.update_status_from_payments()
        self.assertEqual(self.invoice.status, "void")

    def test_overpayment_still_marks_paid(self):
        """Payment > total_cents → still marks paid (get_remaining_amount floors at 0)"""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=15000,
            status="succeeded",
            currency=self.currency,
        )
        self.invoice.update_status_from_payments()
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")


# ===============================================================================
# 3. Proforma PDF & Email Tests
# ===============================================================================


class ProformaPdfTests(TestCase):
    """Test generate_proforma_pdf() delegation to pdf_generators"""

    def test_generate_delegates_to_pdf_generators(self):
        """generate_proforma_pdf() calls the real ReportLab generator"""
        mock_proforma = MagicMock()
        mock_proforma.number = "PF-001"

        with patch("apps.billing.pdf_generators.generate_proforma_pdf", return_value=b"PDF bytes") as mock_gen:
            result = generate_proforma_pdf(mock_proforma)
            mock_gen.assert_called_once_with(mock_proforma)
            self.assertEqual(result, b"PDF bytes")


class ProformaEmailTests(TestCase):
    """Test send_proforma_email() with PDF attachment"""

    def test_send_email_success(self):
        """Email sent with PDF attachment → returns True"""
        mock_proforma = MagicMock()
        mock_proforma.number = "PF-002"
        mock_proforma.customer.primary_email = "cust@example.com"

        with (
            patch("apps.billing.pdf_generators.generate_proforma_pdf", return_value=b"PDF"),
            patch("apps.notifications.services.EmailService.send_email") as mock_send,
        ):
            result = send_proforma_email(mock_proforma, "test@example.com")
            self.assertTrue(result)
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            attachments = call_kwargs.kwargs.get("attachments") or call_kwargs[1].get("attachments")
            self.assertEqual(len(attachments), 1)
            self.assertIn("proforma_PF-002.pdf", attachments[0][0])

    def test_send_email_pdf_failure_returns_false(self):
        """PDF generation failure → returns False, doesn't raise"""
        mock_proforma = MagicMock()
        mock_proforma.number = "PF-003"
        mock_proforma.customer.primary_email = "cust@example.com"

        with patch("apps.billing.pdf_generators.generate_proforma_pdf", side_effect=Exception("PDF error")):
            result = send_proforma_email(mock_proforma)
            self.assertFalse(result)


# ===============================================================================
# 4. Gateway Refund Tests
# ===============================================================================


class StripeRefundTests(TestCase):
    """Test StripeGateway.refund_payment() — Stripe SDK fully mocked"""

    def _make_gateway(self, mock_stripe):
        with patch("apps.billing.gateways.stripe_gateway.StripeGateway._initialize_stripe"):
            gw = StripeGateway.__new__(StripeGateway)
            gw._stripe = mock_stripe
            gw.logger = logging.getLogger("test")
            return gw

    def test_full_refund_success(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.create.return_value = MagicMock(
            id="re_abc", amount=5000, status="succeeded"
        )
        gw = self._make_gateway(mock_stripe)
        result = gw.refund_payment("pi_123")
        self.assertTrue(result["success"])
        self.assertEqual(result["refund_id"], "re_abc")
        self.assertEqual(result["amount_refunded_cents"], 5000)

    def test_partial_refund_passes_amount(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.create.return_value = MagicMock(
            id="re_def", amount=2000, status="succeeded"
        )
        gw = self._make_gateway(mock_stripe)
        result = gw.refund_payment("pi_123", amount_cents=2000)
        mock_stripe.Refund.create.assert_called_once_with(
            payment_intent="pi_123", amount=2000, reason="requested_by_customer"
        )
        self.assertTrue(result["success"])

    def test_stripe_error_returns_failure(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.Refund.create.side_effect = mock_stripe.error.StripeError("charge already refunded")
        gw = self._make_gateway(mock_stripe)
        result = gw.refund_payment("pi_123")
        self.assertFalse(result["success"])
        self.assertIn("already refunded", result["error"])

    def test_refund_pending_status_is_success(self):
        """Stripe 'pending' refunds are treated as success"""
        mock_stripe = MagicMock()
        mock_stripe.Refund.create.return_value = MagicMock(
            id="re_pend", amount=5000, status="pending"
        )
        gw = self._make_gateway(mock_stripe)
        result = gw.refund_payment("pi_123")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "pending")

    def test_refund_requires_action_status_is_a_created_request(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.create.return_value = MagicMock(
            id="re_action",
            amount=5000,
            status="requires_action",
        )
        result = self._make_gateway(mock_stripe).refund_payment("pi_123")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "requires_action")

    def test_retrieve_refund_returns_normalized_authoritative_facts(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.retrieve.return_value = MagicMock(
            id="re_lookup",
            payment_intent="pi_lookup",
            amount=1234,
            currency="ron",
            status="succeeded",
            reason="requested_by_customer",
            failure_reason="lost_or_stolen_card",
        )

        result = self._make_gateway(mock_stripe).retrieve_refund("re_lookup")

        mock_stripe.Refund.retrieve.assert_called_once_with("re_lookup")
        self.assertEqual(
            result,
            {
                "success": True,
                "refund_id": "re_lookup",
                "payment_intent_id": "pi_lookup",
                "amount_cents": 1234,
                "currency": "ron",
                "status": "succeeded",
                "reason": "requested_by_customer",
                "failure_reason": "lost_or_stolen_card",
                "error": None,
            },
        )

    def test_retrieve_refund_rejects_missing_gateway_identity(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.retrieve.return_value = MagicMock(
            id=None,
            payment_intent="pi_missing_refund_id",
            amount=1234,
            currency="ron",
            status="succeeded",
            reason=None,
        )

        result = self._make_gateway(mock_stripe).retrieve_refund("re_expected")

        self.assertFalse(result["success"])
        self.assertIn("malformed", result["error"].lower())

    def test_list_refunds_normalizes_auto_paged_results(self):
        mock_stripe = MagicMock()
        mock_stripe.Refund.list.return_value.auto_paging_iter.return_value = [
            MagicMock(
                id="re_recent",
                payment_intent=MagicMock(id="pi_recent"),
                amount=987,
                currency="ron",
                status="pending",
                reason=None,
            ),
            MagicMock(
                id="re_older_page",
                payment_intent="pi_older_page",
                amount=321,
                currency="ron",
                status="succeeded",
                reason=None,
            ),
        ]

        result = self._make_gateway(mock_stripe).list_refunds(created_gte=123456, limit=1)

        mock_stripe.Refund.list.assert_called_once_with(created={"gte": 123456}, limit=1)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["refunds"]), 2)
        self.assertEqual(result["refunds"][0]["payment_intent_id"], "pi_recent")
        self.assertEqual(result["refunds"][0]["amount_cents"], 987)

    def test_list_refunds_skips_malformed_refund_without_dropping_valid_ones(self):
        """One malformed refund must not discard the whole discovery page (#339).

        Regression: a list comprehension over `auto_paging_iter()` let a single
        ValueError abort the entire page, returning `success=False, refunds=[]`
        and silently defeating the daily reconciliation safety-net.
        """
        mock_stripe = MagicMock()
        mock_stripe.Refund.list.return_value.auto_paging_iter.return_value = [
            MagicMock(id="re_valid_1", payment_intent="pi_v1", amount=500, currency="ron", status="succeeded", reason=None),
            # payment_intent=None → _normalize_refund raises ValueError
            MagicMock(id="re_malformed", payment_intent=None, amount=700, currency="ron", status="succeeded", reason=None),
            MagicMock(id="re_valid_2", payment_intent="pi_v2", amount=900, currency="ron", status="succeeded", reason=None),
        ]

        result = self._make_gateway(mock_stripe).list_refunds(created_gte=123456, limit=100)

        self.assertTrue(result["success"])
        self.assertEqual([r["refund_id"] for r in result["refunds"]], ["re_valid_1", "re_valid_2"])


# ===============================================================================
# 6. Gateway-First Refund Pattern Tests (Fix #1 + #2)
# ===============================================================================


class GatewayFirstRefundTests(TestCase):
    """Test that payment status is only updated AFTER gateway success."""

    def setUp(self):
        self.customer = create_customer("Refund Co")
        self.currency = create_currency("USD")
        self.invoice = create_invoice(self.customer, self.currency, number="INV-REFUND-001", total_cents=5000)

    def _create_refund_intent(self, payment: Payment, amount_cents: int = 5000) -> Refund:
        return Refund.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment=payment,
            amount_cents=amount_cents,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="full" if amount_cents == payment.amount_cents else "partial",
            status="pending",
            gateway_refund_id="",
        )

    def test_gateway_failure_does_not_update_payment_status(self):
        """When Stripe refund fails, payment.status must remain 'succeeded'."""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="succeeded",
            currency=self.currency,
            payment_method="stripe",
            gateway_txn_id="pi_test_fail",
        )
        refund_intent = self._create_refund_intent(payment)

        mock_gateway = MagicMock()
        mock_gateway.refund_payment.return_value = {
            "success": False,
            "refund_id": None,
            "amount_refunded_cents": 0,
            "status": "error",
            "error": "charge_already_refunded",
        }

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch("apps.common.validators.log_security_event"),
        ):
            result = RefundService._process_payment_refund(
                payment,
                {"refund_type": "full", "amount_cents": 5000, "reason": "requested_by_customer"},
                refund_intent_id=refund_intent.id,
            )

        self.assertTrue(result.is_err())
        # The failure must be a GATEWAY failure, not an earlier validation exit —
        # otherwise this test stops verifying its named scenario (review of #388).
        mock_gateway.refund_payment.assert_called_once()
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")  # NOT "refunded"

    def test_gateway_success_updates_payment_status(self):
        """When Stripe refund succeeds, payment.status should be updated."""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="succeeded",
            currency=self.currency,
            payment_method="stripe",
            gateway_txn_id="pi_test_success",
        )
        refund_intent = self._create_refund_intent(payment)

        mock_gateway = MagicMock()
        mock_gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_123",
            "amount_refunded_cents": 5000,
            "status": "succeeded",
            "error": None,
        }

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch("apps.common.validators.log_security_event"),
        ):
            result = RefundService._process_payment_refund(
                payment,
                refund_data={"refund_type": "full", "amount_cents": 5000},
                refund_amount_cents=5000,
                refund_intent_id=refund_intent.id,
            )

        self.assertTrue(result.is_ok())
        payment.refresh_from_db()
        self.assertEqual(payment.status, "refunded")

    def test_missing_gateway_txn_id_is_hard_error(self):
        """Stripe payment without gateway_txn_id → Result.err, not silent success."""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="succeeded",
            currency=self.currency,
            payment_method="stripe",
            gateway_txn_id="",  # Missing!
        )

        with patch("apps.common.validators.log_security_event"):
            result = RefundService._process_payment_refund(payment)

        self.assertTrue(result.is_err())
        self.assertIn("missing gateway transaction ID", result.error)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")  # Unchanged

    def test_non_gateway_payment_succeeds_locally(self):
        """Bank transfer payment → succeeds locally without gateway call."""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="succeeded",
            currency=self.currency,
            payment_method="bank_transfer",
            gateway_txn_id="",
        )

        with patch("apps.common.validators.log_security_event"):
            result = RefundService._process_payment_refund(
                payment, refund_data={"refund_type": "full", "amount_cents": 5000}
            )

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap()["gateway_refund"], "not_applicable")
        payment.refresh_from_db()
        self.assertEqual(payment.status, "refunded")


# ===============================================================================
# 9. Proforma Email Result Handling Tests (Fix #5)
# ===============================================================================


class ProformaEmailResultTests(TestCase):
    """Test that send_proforma_email respects EmailResult.success."""

    def test_email_service_failure_returns_false(self):
        """EmailService returns success=False → send_proforma_email returns False."""
        mock_proforma = MagicMock()
        mock_proforma.number = "PF-FAIL"
        mock_proforma.customer.primary_email = "cust@example.com"

        mock_email_result = MagicMock()
        mock_email_result.success = False
        mock_email_result.error = "Recipient suppressed"

        with (
            patch("apps.billing.pdf_generators.generate_proforma_pdf", return_value=b"PDF"),
            patch("apps.notifications.services.EmailService.send_email", return_value=mock_email_result),
        ):
            result = send_proforma_email(mock_proforma, "suppressed@example.com")

        self.assertFalse(result)

    def test_email_service_success_returns_true(self):
        """EmailService returns success=True → send_proforma_email returns True."""
        mock_proforma = MagicMock()
        mock_proforma.number = "PF-OK"
        mock_proforma.customer.primary_email = "cust@example.com"

        mock_email_result = MagicMock()
        mock_email_result.success = True

        with (
            patch("apps.billing.pdf_generators.generate_proforma_pdf", return_value=b"PDF"),
            patch("apps.notifications.services.EmailService.send_email", return_value=mock_email_result),
        ):
            result = send_proforma_email(mock_proforma, "ok@example.com")

        self.assertTrue(result)


# ===============================================================================
# 10. Partially Refunded Payments in amount_due Tests (Fix #6)
# ===============================================================================


class PartiallyRefundedPaymentTests(TestCase):
    """Test that partially_refunded payments count toward paid amount."""

    def setUp(self):
        self.customer = create_customer("Partial Refund Co")
        self.currency = create_currency("GBP")
        self.invoice = create_invoice(self.customer, self.currency, number="INV-PR-001", total_cents=10000)

    def test_partially_refunded_payment_counts_as_paid(self):
        """Payment with status='partially_refunded' still counts toward paid amount."""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            status="partially_refunded",
            currency=self.currency,
        )
        # The payment was partially refunded, but the original amount still counts
        self.assertEqual(self.invoice.amount_due, 0)

    def test_mix_of_succeeded_and_partially_refunded(self):
        """Both succeeded and partially_refunded payments count."""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="succeeded",
            currency=self.currency,
        )
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            status="partially_refunded",
            currency=self.currency,
        )
        self.assertEqual(self.invoice.amount_due, 0)

    def test_failed_payment_still_excluded(self):
        """Failed payments are NOT counted."""
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            status="failed",
            currency=self.currency,
        )
        self.assertEqual(self.invoice.amount_due, 10000)
