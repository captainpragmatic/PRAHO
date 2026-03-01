# ===============================================================================
# TESTS FOR BILLING TODO FIXES
# Tests for: amount_due, update_status_from_payments, proforma PDF/email,
#             gateway refund, e-Factura wiring
# ===============================================================================

import logging
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.efactura.client import AuthenticationError, NetworkError
from apps.billing.efactura_service import EFacturaSubmissionService
from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment
from apps.billing.proforma_service import generate_proforma_pdf, send_proforma_email
from apps.billing.refund_service import RefundService
from tests.factories.billing_factories import create_currency, create_customer, create_invoice

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
        self.invoice.status = "paid"
        self.invoice.save()
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
        self.invoice.status = "void"
        self.invoice.save()
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


# ===============================================================================
# 5. e-Factura Wiring Tests
# ===============================================================================


class EFacturaSubmissionTests(TestCase):
    """Test e-Factura submission wiring to EFacturaClient"""

    @patch("apps.billing.efactura.client.EFacturaClient")
    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_calls_client_when_configured(self, mock_from_settings, mock_client_cls):
        """Configured e-Factura → calls client.upload_invoice()"""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = True
        mock_from_settings.return_value = mock_config

        mock_client = MagicMock()
        mock_client.upload_invoice.return_value = MagicMock(
            success=True, upload_index="UI12345", message="OK", errors=[], raw_response={}
        )
        mock_client_cls.return_value = mock_client

        service = EFacturaSubmissionService()
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-001"

        # Mock xml_generator to return valid XML
        mock_xml_result = MagicMock()
        mock_xml_result.is_ok.return_value = True
        mock_xml_result.unwrap.return_value = "<xml/>"
        service.xml_generator = MagicMock()
        service.xml_generator.generate_invoice_xml.return_value = mock_xml_result

        result = service.submit_invoice(mock_invoice)

        self.assertTrue(result.success)
        mock_client.upload_invoice.assert_called_once()

    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_returns_simulated_when_not_configured_in_debug(self, mock_from_settings):
        """Missing credentials + DEBUG=True → simulated result, no API call"""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = False
        mock_from_settings.return_value = mock_config

        service = EFacturaSubmissionService()
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-002"

        # Mock xml_generator to return valid XML
        mock_xml_result = MagicMock()
        mock_xml_result.is_ok.return_value = True
        mock_xml_result.unwrap.return_value = "<xml/>"
        service.xml_generator = MagicMock()
        service.xml_generator.generate_invoice_xml.return_value = mock_xml_result

        with self.settings(DEBUG=True):
            result = service.submit_invoice(mock_invoice)

        self.assertTrue(result.success)
        self.assertIn("simulated", result.message.lower())

    @patch("apps.billing.efactura.client.EFacturaClient")
    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_check_status_delegates_to_client(self, mock_from_settings, mock_client_cls):
        """check_status() calls client.get_upload_status()"""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = True
        mock_from_settings.return_value = mock_config

        mock_client = MagicMock()
        mock_status = MagicMock()
        mock_status.is_accepted = True
        mock_status.is_rejected = False
        mock_status.status = "ok"
        mock_status.raw_response = {}
        mock_client.get_upload_status.return_value = mock_status
        mock_client_cls.return_value = mock_client

        service = EFacturaSubmissionService()
        result = service.check_status("UI12345")

        self.assertTrue(result.success)
        mock_client.get_upload_status.assert_called_once_with("UI12345")


# ===============================================================================
# 6. Gateway-First Refund Pattern Tests (Fix #1 + #2)
# ===============================================================================


class GatewayFirstRefundTests(TestCase):
    """Test that payment status is only updated AFTER gateway success."""

    def setUp(self):
        self.customer = create_customer("Refund Co")
        self.currency = create_currency("USD")
        self.invoice = create_invoice(self.customer, self.currency, number="INV-REFUND-001", total_cents=5000)

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
            result = RefundService._process_payment_refund(payment)

        self.assertTrue(result.is_err())
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
# 7. e-Factura Exception Handling Tests (Fix #3)
# ===============================================================================


class EFacturaExceptionHandlingTests(TestCase):
    """Test that EFacturaClientError exceptions are caught properly."""

    @patch("apps.billing.efactura.client.EFacturaClient")
    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_catches_client_error(self, mock_from_settings, mock_client_cls):
        """AuthenticationError during submit → graceful failure, not 500."""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = True
        mock_from_settings.return_value = mock_config
        mock_client_cls.return_value.upload_invoice.side_effect = AuthenticationError("OAuth token expired")

        service = EFacturaSubmissionService()
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-ERR-001"

        mock_xml_result = MagicMock()
        mock_xml_result.is_ok.return_value = True
        mock_xml_result.unwrap.return_value = "<xml/>"
        service.xml_generator = MagicMock()
        service.xml_generator.generate_invoice_xml.return_value = mock_xml_result

        result = service.submit_invoice(mock_invoice)

        self.assertFalse(result.success)
        self.assertIn("OAuth token expired", result.message)

    @patch("apps.billing.efactura.client.EFacturaClient")
    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_check_status_catches_network_error(self, mock_from_settings, mock_client_cls):
        """NetworkError during check_status → graceful failure."""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = True
        mock_from_settings.return_value = mock_config
        mock_client_cls.return_value.get_upload_status.side_effect = NetworkError("Connection refused")

        service = EFacturaSubmissionService()
        result = service.check_status("UI12345")

        self.assertFalse(result.success)
        self.assertIn("Connection refused", result.message)


# ===============================================================================
# 8. e-Factura Simulation Gating Tests (Fix #4)
# ===============================================================================


class EFacturaSimulationGatingTests(TestCase):
    """Test that simulated success is only returned in DEBUG mode."""

    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_simulates_in_debug_mode(self, mock_from_settings):
        """DEBUG=True + invalid config → simulated success."""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = False
        mock_from_settings.return_value = mock_config

        service = EFacturaSubmissionService()
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-SIM-001"

        mock_xml_result = MagicMock()
        mock_xml_result.is_ok.return_value = True
        mock_xml_result.unwrap.return_value = "<xml/>"
        service.xml_generator = MagicMock()
        service.xml_generator.generate_invoice_xml.return_value = mock_xml_result

        with self.settings(DEBUG=True):
            result = service.submit_invoice(mock_invoice)

        self.assertTrue(result.success)
        self.assertIn("simulated", result.message.lower())

    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_fails_in_production_mode(self, mock_from_settings):
        """DEBUG=False + invalid config → hard failure, NOT simulated success."""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = False
        mock_from_settings.return_value = mock_config

        service = EFacturaSubmissionService()
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-PROD-001"

        mock_xml_result = MagicMock()
        mock_xml_result.is_ok.return_value = True
        mock_xml_result.unwrap.return_value = "<xml/>"
        service.xml_generator = MagicMock()
        service.xml_generator.generate_invoice_xml.return_value = mock_xml_result

        with self.settings(DEBUG=False):
            result = service.submit_invoice(mock_invoice)

        self.assertFalse(result.success)
        self.assertIn("not configured", result.message.lower())

    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_check_status_fails_in_production_mode(self, mock_from_settings):
        """DEBUG=False + invalid config → hard failure for check_status."""
        mock_config = MagicMock()
        mock_config.is_valid.return_value = False
        mock_from_settings.return_value = mock_config

        service = EFacturaSubmissionService()

        with self.settings(DEBUG=False):
            result = service.check_status("UI99999")

        self.assertFalse(result.success)
        self.assertIn("not configured", result.message.lower())


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
