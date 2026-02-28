"""
Comprehensive tests for apps/billing/invoice_service.py.

Coverage targets: BillingAnalyticsService (4 static methods),
generate_invoice_pdf, _generate_placeholder_pdf, generate_e_factura_xml,
send_invoice_email, generate_vat_summary.
"""

from __future__ import annotations

import io
from datetime import datetime
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Invoice
from apps.billing.invoice_service import (
    BillingAnalyticsService,
    _generate_placeholder_pdf,
    generate_e_factura_xml,
    generate_invoice_pdf,
    generate_vat_summary,
    send_invoice_email,
)
from apps.customers.models import Customer
from tests.factories.billing_factories import (
    PaymentCreationRequest,
    create_currency,
    create_customer,
    create_invoice,
    create_payment,
)

# ===============================================================================
# HELPERS
# ===============================================================================


def _make_invoice(  # noqa: PLR0913
    *,
    number: str = "INV-2026-001",
    total_cents: int = 12100,
    subtotal_cents: int = 10000,
    tax_cents: int = 2100,
    status: str = "issued",
    customer_name: str = "Test SRL",
) -> tuple[Customer, Invoice]:
    """Return (customer, invoice) with values satisfying subtotal+tax==total constraint."""
    # Ensure the math holds: subtotal + tax must equal total
    actual_total = subtotal_cents + tax_cents
    customer = create_customer(customer_name)
    currency = create_currency("RON")
    invoice = create_invoice(customer, currency, number=number, total_cents=actual_total)
    if status != "issued":
        invoice.status = status
        invoice.save(update_fields=["status"])
    return customer, invoice


def _make_mock_customer(meta: dict[str, object] | None = None) -> Mock:
    """Return a Mock customer object with configurable meta attribute."""
    customer = Mock()
    customer.id = 42
    customer.meta = meta
    customer.get_display_name.return_value = "Mock Customer SRL"
    customer.primary_email = "mock@example.com"
    customer.vat_number = "RO99999999"
    return customer


# ===============================================================================
# BillingAnalyticsService.update_invoice_metrics
# ===============================================================================


class UpdateInvoiceMetricsPaidTest(TestCase):
    """update_invoice_metrics — 'paid' event calculates payment_time_days."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_paid_event_returns_payment_time_days(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()

        result = BillingAnalyticsService.update_invoice_metrics(invoice, "paid")

        self.assertTrue(result["success"])
        self.assertIn("payment_time_days", result)
        self.assertIsInstance(result["payment_time_days"], int)
        self.assertEqual(result["event_type"], "paid")
        self.assertEqual(result["invoice_number"], invoice.number)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_paid_event_with_no_created_at_gives_zero_days(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()
        invoice.created_at = None

        result = BillingAnalyticsService.update_invoice_metrics(invoice, "paid")

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_time_days"], 0)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_paid_event_audit_log_contains_correct_event_type(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()

        BillingAnalyticsService.update_invoice_metrics(invoice, "paid")

        # Signals also fire log_simple_event so check that our specific call was made
        event_types_logged = [c.kwargs["event_type"] for c in mock_log.call_args_list]
        self.assertIn("invoice_metrics_updated", event_types_logged)

        our_call = next(
            c for c in mock_log.call_args_list if c.kwargs["event_type"] == "invoice_metrics_updated"
        )
        self.assertIsNone(our_call.kwargs["user"])
        self.assertEqual(our_call.kwargs["actor_type"], "system")


class UpdateInvoiceMetricsOverdueTest(TestCase):
    """update_invoice_metrics — 'overdue' event adds overdue_amount."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_overdue_event_returns_overdue_amount(self, mock_log: MagicMock) -> None:
        invoice = Mock()
        invoice.id = "overdue-id"
        invoice.number = "INV-OVER-001"
        invoice.total_cents = 5000
        invoice.created_at = timezone.now()

        result = BillingAnalyticsService.update_invoice_metrics(invoice, "overdue")

        self.assertTrue(result["success"])
        self.assertIn("overdue_amount", result)
        self.assertEqual(result["overdue_amount"], 5000)


class UpdateInvoiceMetricsCreatedTest(TestCase):
    """update_invoice_metrics — 'created' event has no extra fields."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_created_event_has_no_payment_time_or_overdue(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()

        result = BillingAnalyticsService.update_invoice_metrics(invoice, "created")

        self.assertTrue(result["success"])
        self.assertNotIn("payment_time_days", result)
        self.assertNotIn("overdue_amount", result)
        self.assertEqual(result["amount_cents"], invoice.total_cents)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_cancelled_event_has_no_extra_fields(self, mock_log: MagicMock) -> None:
        invoice = Mock()
        invoice.id = "cancel-id"
        invoice.number = "INV-CANCEL-001"
        invoice.total_cents = 8000
        invoice.created_at = timezone.now()

        result = BillingAnalyticsService.update_invoice_metrics(invoice, "cancelled")

        self.assertTrue(result["success"])
        self.assertNotIn("payment_time_days", result)
        self.assertNotIn("overdue_amount", result)


class UpdateInvoiceMetricsExceptionTest(TestCase):
    """update_invoice_metrics — exception path returns error dict."""

    def test_exception_returns_error_dict(self) -> None:
        invoice = Mock()
        invoice.number = "INV-ERR"
        invoice.id = "bad-id"
        invoice.total_cents = 100
        invoice.created_at = timezone.now()

        with patch("apps.audit.services.AuditService.log_simple_event", side_effect=RuntimeError("boom")):
            result = BillingAnalyticsService.update_invoice_metrics(invoice, "created")

        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertIn("boom", result["error"])


# ===============================================================================
# BillingAnalyticsService.update_customer_metrics
# ===============================================================================


class UpdateCustomerMetricsTest(TestCase):
    """update_customer_metrics — aggregates correctly and updates meta."""

    def setUp(self) -> None:
        self.customer = create_customer("Metrics SRL")
        self.currency = create_currency("RON")

    def test_no_invoices_returns_zeros(self) -> None:
        result = BillingAnalyticsService.update_customer_metrics(self.customer, Mock())

        self.assertTrue(result["success"])
        self.assertEqual(result["total_invoiced_cents"], 0)
        self.assertEqual(result["total_paid_cents"], 0)
        self.assertEqual(result["outstanding_cents"], 0)
        self.assertEqual(result["invoice_count"], 0)

    def test_with_invoices_sums_correctly(self) -> None:
        inv1 = create_invoice(self.customer, self.currency, number="INV-M001", total_cents=5000)
        create_invoice(self.customer, self.currency, number="INV-M002", total_cents=3000)

        result = BillingAnalyticsService.update_customer_metrics(self.customer, inv1)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_invoiced_cents"], 8000)
        self.assertEqual(result["invoice_count"], 2)

    def test_with_paid_payments_calculates_outstanding(self) -> None:
        invoice = create_invoice(self.customer, self.currency, number="INV-M003", total_cents=10000)
        req = PaymentCreationRequest(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=6000,
            status="succeeded",
        )
        create_payment(req)

        result = BillingAnalyticsService.update_customer_metrics(self.customer, invoice)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_paid_cents"], 6000)
        self.assertEqual(result["outstanding_cents"], 10000 - 6000)

    def test_paid_invoice_count_tracked(self) -> None:
        inv = create_invoice(self.customer, self.currency, number="INV-M004", total_cents=5000)
        inv.status = "paid"
        inv.save(update_fields=["status"])

        result = BillingAnalyticsService.update_customer_metrics(self.customer, inv)

        self.assertTrue(result["success"])
        self.assertEqual(result["paid_invoice_count"], 1)

    def test_mock_customer_with_meta_dict_gets_billing_metrics_written(self) -> None:
        """Customer with meta dict attribute has billing_metrics written into it."""
        mock_customer = _make_mock_customer(meta={})

        with (
            patch("apps.billing.models.Invoice") as mock_inv,
            patch("apps.billing.models.Payment") as mock_pay,
        ):
            qs_mock = Mock()
            qs_mock.aggregate.return_value = {"total": 5000}
            qs_mock.count.return_value = 2
            qs_mock.filter.return_value.count.return_value = 1
            mock_inv.objects.filter.return_value = qs_mock
            mock_pay.objects.filter.return_value.aggregate.return_value = {"total": 3000}

            result = BillingAnalyticsService.update_customer_metrics(mock_customer, Mock())

        self.assertTrue(result["success"])
        self.assertIn("billing_metrics", mock_customer.meta)

    def test_mock_customer_without_meta_skips_save(self) -> None:
        """Customer without meta attribute still returns success without saving."""
        mock_customer = Mock(spec=[])  # no attributes at all
        mock_customer.id = 99

        with (
            patch("apps.billing.models.Invoice") as mock_inv,
            patch("apps.billing.models.Payment") as mock_pay,
        ):
            qs_mock = Mock()
            qs_mock.aggregate.return_value = {"total": 0}
            qs_mock.count.return_value = 0
            qs_mock.filter.return_value.count.return_value = 0
            mock_inv.objects.filter.return_value = qs_mock
            mock_pay.objects.filter.return_value.aggregate.return_value = {"total": 0}

            result = BillingAnalyticsService.update_customer_metrics(mock_customer, Mock())

        self.assertTrue(result["success"])

    def test_exception_returns_error_dict(self) -> None:
        with patch("apps.billing.models.Invoice") as mock_invoice:
            mock_invoice.objects.filter.side_effect = RuntimeError("db failure")
            result = BillingAnalyticsService.update_customer_metrics(self.customer, Mock())

        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertIn("db failure", result["error"])


# ===============================================================================
# BillingAnalyticsService.record_invoice_refund
# ===============================================================================


class RecordInvoiceRefundTest(TestCase):
    """record_invoice_refund — records refund data and logs audit event."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success_with_customer_returns_correct_data(self, mock_log: MagicMock) -> None:
        customer, invoice = _make_invoice()
        refund_date = timezone.now()

        result = BillingAnalyticsService.record_invoice_refund(invoice, refund_date)

        self.assertTrue(result["success"])
        self.assertEqual(result["invoice_number"], invoice.number)
        self.assertEqual(result["refund_amount_cents"], invoice.total_cents)
        self.assertEqual(result["customer_id"], str(customer.id))

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_audit_log_called_with_refund_event_type(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()

        BillingAnalyticsService.record_invoice_refund(invoice, timezone.now())

        event_types = [c.kwargs["event_type"] for c in mock_log.call_args_list]
        self.assertIn("invoice_refund_recorded", event_types)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success_without_customer(self, mock_log: MagicMock) -> None:
        invoice = Mock()
        invoice.id = "mock-refund-id"
        invoice.number = "INV-REFUND-NO-CUST"
        invoice.total_cents = 9900
        invoice.customer = None

        result = BillingAnalyticsService.record_invoice_refund(invoice, timezone.now())

        self.assertTrue(result["success"])
        self.assertIsNone(result["customer_id"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_refund_date_in_result(self, mock_log: MagicMock) -> None:
        _, invoice = _make_invoice()
        refund_date = datetime(2026, 1, 15, 12, 0, 0)

        result = BillingAnalyticsService.record_invoice_refund(invoice, refund_date)

        self.assertIn("2026-01-15", result["refund_date"])

    def test_exception_returns_error_dict(self) -> None:
        invoice = Mock()
        invoice.id = "err-id"
        invoice.number = "INV-ERR"
        invoice.total_cents = 1000
        invoice.customer = Mock()
        invoice.customer.id = 1

        with patch("apps.audit.services.AuditService.log_simple_event", side_effect=ValueError("audit down")):
            result = BillingAnalyticsService.record_invoice_refund(invoice, timezone.now())

        self.assertFalse(result["success"])
        self.assertIn("audit down", result["error"])


# ===============================================================================
# BillingAnalyticsService.adjust_customer_ltv
# ===============================================================================


class AdjustCustomerLtvTest(TestCase):
    """adjust_customer_ltv — adjusts LTV in meta and logs."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_positive_adjustment_with_empty_meta(self, mock_log: MagicMock) -> None:
        customer = _make_mock_customer(meta={})

        result = BillingAnalyticsService.adjust_customer_ltv(customer, 5000, "first purchase")

        self.assertTrue(result["success"])
        self.assertEqual(result["previous_ltv_cents"], 0)
        self.assertEqual(result["adjustment_cents"], 5000)
        self.assertEqual(result["new_ltv_cents"], 5000)
        self.assertEqual(result["reason"], "first purchase")

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_adjustment_from_existing_ltv(self, mock_log: MagicMock) -> None:
        customer = _make_mock_customer(meta={"lifetime_value_cents": 10000})

        result = BillingAnalyticsService.adjust_customer_ltv(customer, 2000, "renewal")

        self.assertTrue(result["success"])
        self.assertEqual(result["previous_ltv_cents"], 10000)
        self.assertEqual(result["new_ltv_cents"], 12000)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_negative_adjustment_reduces_ltv(self, mock_log: MagicMock) -> None:
        customer = _make_mock_customer(meta={"lifetime_value_cents": 8000})

        result = BillingAnalyticsService.adjust_customer_ltv(customer, -3000, "refund")

        self.assertTrue(result["success"])
        self.assertEqual(result["new_ltv_cents"], 5000)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_meta_is_updated_in_place(self, mock_log: MagicMock) -> None:
        meta: dict[str, object] = {}
        customer = _make_mock_customer(meta=meta)

        BillingAnalyticsService.adjust_customer_ltv(customer, 1500, "test")

        self.assertEqual(meta["lifetime_value_cents"], 1500)
        self.assertIn("ltv_last_adjusted", meta)

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_customer_with_none_meta_skips_save(self, mock_log: MagicMock) -> None:
        """When meta is None, adjustment still succeeds but save is not called."""
        customer = _make_mock_customer(meta=None)

        result = BillingAnalyticsService.adjust_customer_ltv(customer, 500, "reason")

        self.assertTrue(result["success"])
        self.assertEqual(result["new_ltv_cents"], 500)
        customer.save.assert_not_called()

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_audit_log_called_with_customer_ltv_event(self, mock_log: MagicMock) -> None:
        customer = _make_mock_customer(meta={})

        BillingAnalyticsService.adjust_customer_ltv(customer, 1000, "test")

        event_types = [c.kwargs["event_type"] for c in mock_log.call_args_list]
        self.assertIn("customer_ltv_adjusted", event_types)

    def test_exception_returns_error_dict(self) -> None:
        customer = _make_mock_customer(meta={})

        with patch("apps.audit.services.AuditService.log_simple_event", side_effect=Exception("ltv error")):
            result = BillingAnalyticsService.adjust_customer_ltv(customer, 100, "boom")

        self.assertFalse(result["success"])
        self.assertIn("ltv error", result["error"])


# ===============================================================================
# generate_invoice_pdf
# ===============================================================================


class GenerateInvoicePdfTest(TestCase):
    """generate_invoice_pdf — weasyprint unavailable → placeholder; available → real PDF."""

    def test_weasyprint_not_installed_returns_placeholder_bytes(self) -> None:
        _, invoice = _make_invoice()

        # weasyprint is not properly installed in test env; exercises ImportError path
        result = generate_invoice_pdf(invoice)

        self.assertIsInstance(result, bytes)
        self.assertIn(invoice.number.encode(), result)

    def test_weasyprint_available_renders_pdf(self) -> None:
        _, invoice = _make_invoice()

        fake_pdf_bytes = b"%PDF-1.4 fake-content"
        fake_html_instance = Mock()

        def write_to_buf(buf: object) -> None:
            if isinstance(buf, io.BytesIO):
                buf.write(fake_pdf_bytes)

        fake_html_instance.write_pdf.side_effect = write_to_buf
        fake_html_class = Mock(return_value=fake_html_instance)
        fake_weasyprint = Mock()
        fake_weasyprint.HTML = fake_html_class

        with (
            patch.dict("sys.modules", {"weasyprint": fake_weasyprint}),
            patch("apps.billing.invoice_service.render_to_string", return_value="<html><body></body></html>"),
        ):
            result = generate_invoice_pdf(invoice)

        self.assertIsInstance(result, bytes)

    def test_exception_during_rendering_falls_back_to_placeholder(self) -> None:
        _, invoice = _make_invoice()

        fake_html_class = Mock(side_effect=RuntimeError("render exploded"))
        fake_weasyprint = Mock()
        fake_weasyprint.HTML = fake_html_class

        with (
            patch.dict("sys.modules", {"weasyprint": fake_weasyprint}),
            patch("apps.billing.invoice_service.render_to_string", return_value="<html/>"),
        ):
            result = generate_invoice_pdf(invoice)

        self.assertIsInstance(result, bytes)
        self.assertIn(invoice.number.encode(), result)


# ===============================================================================
# _generate_placeholder_pdf
# ===============================================================================


class GeneratePlaceholderPdfTest(TestCase):
    """_generate_placeholder_pdf — returns bytes with invoice number and customer."""

    def test_contains_invoice_number(self) -> None:
        _, invoice = _make_invoice(number="INV-PH-007")

        result = _generate_placeholder_pdf(invoice)

        self.assertIsInstance(result, bytes)
        self.assertIn(b"INV-PH-007", result)

    def test_contains_customer_display_name(self) -> None:
        _, invoice = _make_invoice(customer_name="Placeholder SRL")

        result = _generate_placeholder_pdf(invoice)

        self.assertIn(b"Placeholder SRL", result)

    def test_contains_formatted_amount(self) -> None:
        # total = 10000 + 2100 = 12100 → 121.00
        _, invoice = _make_invoice(subtotal_cents=10000, tax_cents=2100)

        result = _generate_placeholder_pdf(invoice)

        self.assertIn(b"121.00", result)

    def test_customer_none_returns_na(self) -> None:
        invoice = Mock()
        invoice.number = "INV-NO-CUST"
        invoice.customer = None
        invoice.total_cents = 5000
        invoice.created_at = timezone.now()

        result = _generate_placeholder_pdf(invoice)

        self.assertIn(b"N/A", result)

    def test_created_at_none_returns_na_for_date(self) -> None:
        _, invoice = _make_invoice()
        invoice.created_at = None

        result = _generate_placeholder_pdf(invoice)

        self.assertIn(b"N/A", result)


# ===============================================================================
# generate_e_factura_xml
# ===============================================================================


class GenerateEFacturaXmlTest(TestCase):
    """generate_e_factura_xml — returns valid UBL XML string."""

    def test_returns_xml_string(self) -> None:
        _, invoice = _make_invoice(number="INV-XML-001")

        result = generate_e_factura_xml(invoice)

        self.assertIsInstance(result, str)
        self.assertIn("<?xml", result)

    def test_contains_invoice_number(self) -> None:
        _, invoice = _make_invoice(number="INV-XML-002")

        result = generate_e_factura_xml(invoice)

        self.assertIn("INV-XML-002", result)

    def test_contains_currency_code(self) -> None:
        _, invoice = _make_invoice()

        result = generate_e_factura_xml(invoice)

        self.assertIn("RON", result)

    def test_contains_tax_and_total_amounts(self) -> None:
        # Use a Mock invoice with explicit values to avoid DB validation complexity
        customer = _make_mock_customer()
        invoice = Mock()
        invoice.number = "INV-XML-AMOUNTS"
        invoice.customer = customer
        invoice.subtotal_cents = 10000  # 100.00
        invoice.tax_cents = 2100        # 21.00
        invoice.total_cents = 12100     # 121.00
        invoice.created_at = timezone.now()
        invoice.due_date = None

        result = generate_e_factura_xml(invoice)

        self.assertIn("100.00", result)
        self.assertIn("21.00", result)
        self.assertIn("121.00", result)

    def test_contains_company_name_from_settings(self) -> None:
        _, invoice = _make_invoice()

        with patch("apps.billing.invoice_service.settings") as mock_settings:
            mock_settings.COMPANY_NAME = "PragmaticHost SRL"
            mock_settings.COMPANY_VAT_NUMBER = "RO12345678"
            result = generate_e_factura_xml(invoice)

        self.assertIn("PragmaticHost SRL", result)

    def test_contains_customer_name(self) -> None:
        _, invoice = _make_invoice(customer_name="XML Customer SRL")

        result = generate_e_factura_xml(invoice)

        self.assertIn("XML Customer SRL", result)

    def test_contains_ubl_namespace(self) -> None:
        _, invoice = _make_invoice()

        result = generate_e_factura_xml(invoice)

        self.assertIn("urn:oasis:names:specification:ubl", result)

    def test_exception_is_reraised(self) -> None:
        invoice = Mock()
        invoice.number = "INV-FAIL"
        type(invoice).customer = property(lambda self: (_ for _ in ()).throw(RuntimeError("xml boom")))

        with self.assertRaises(RuntimeError):
            generate_e_factura_xml(invoice)


# ===============================================================================
# send_invoice_email
# ===============================================================================


class SendInvoiceEmailTest(TestCase):
    """send_invoice_email — sends email with PDF attachment."""

    def setUp(self) -> None:
        self.customer, self.invoice = _make_invoice()
        self.customer.primary_email = "customer@example.com"
        self.customer.save(update_fields=["primary_email"])

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_sends_with_explicit_recipient_email(self, mock_pdf: MagicMock) -> None:
        with patch("django.core.mail.EmailMessage") as mock_email_cls:
            mock_msg = Mock()
            mock_email_cls.return_value = mock_msg

            result = send_invoice_email(self.invoice, recipient_email="override@example.com")

        self.assertTrue(result)
        mock_msg.send.assert_called_once()
        mock_msg.attach.assert_called_once()

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_sends_with_customer_primary_email(self, mock_pdf: MagicMock) -> None:
        with patch("django.core.mail.EmailMessage") as mock_email_cls:
            mock_msg = Mock()
            mock_email_cls.return_value = mock_msg

            result = send_invoice_email(self.invoice)

        self.assertTrue(result)
        mock_msg.send.assert_called_once()

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_no_customer_no_explicit_email_returns_false(self, mock_pdf: MagicMock) -> None:
        invoice = Mock()
        invoice.number = "INV-NO-EMAIL"
        invoice.customer = None

        result = send_invoice_email(invoice)

        self.assertFalse(result)

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_send_exception_returns_false(self, mock_pdf: MagicMock) -> None:
        with patch("django.core.mail.EmailMessage") as mock_email_cls:
            mock_msg = Mock()
            mock_msg.send.side_effect = Exception("SMTP error")
            mock_email_cls.return_value = mock_msg

            result = send_invoice_email(self.invoice, recipient_email="test@example.com")

        self.assertFalse(result)

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"pdf-bytes")
    def test_email_subject_contains_invoice_number(self, mock_pdf: MagicMock) -> None:
        with patch("django.core.mail.EmailMessage") as mock_email_cls:
            mock_msg = Mock()
            mock_email_cls.return_value = mock_msg

            send_invoice_email(self.invoice, recipient_email="x@x.com")

            call_kwargs = mock_email_cls.call_args
            subject = call_kwargs[1].get("subject", "") or (call_kwargs[0][0] if call_kwargs[0] else "")

        self.assertIn(self.invoice.number, subject)

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_pdf_attached_with_correct_mime_type(self, mock_pdf: MagicMock) -> None:
        with patch("django.core.mail.EmailMessage") as mock_email_cls:
            mock_msg = Mock()
            mock_email_cls.return_value = mock_msg

            send_invoice_email(self.invoice, recipient_email="test@test.com")

        attach_call = mock_msg.attach.call_args
        self.assertEqual(attach_call[0][1], b"fake-pdf")
        self.assertEqual(attach_call[0][2], "application/pdf")

    @patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"fake-pdf")
    def test_empty_primary_email_returns_false(self, mock_pdf: MagicMock) -> None:
        self.customer.primary_email = ""
        self.customer.save(update_fields=["primary_email"])

        result = send_invoice_email(self.invoice)

        self.assertFalse(result)


# ===============================================================================
# generate_vat_summary
# ===============================================================================


class GenerateVatSummaryTest(TestCase):
    """generate_vat_summary — aggregates invoices by period and VAT rate."""

    def setUp(self) -> None:
        self.customer = create_customer("VAT SRL")
        self.currency = create_currency("RON")

    def _create_invoice_for_vat(
        self,
        number: str,
        status: str = "paid",
        subtotal_cents: int = 10000,
        tax_cents: int = 2100,
    ) -> Invoice:
        total = subtotal_cents + tax_cents
        invoice = create_invoice(self.customer, self.currency, number=number, total_cents=total)
        invoice.subtotal_cents = subtotal_cents
        invoice.tax_cents = tax_cents
        invoice.status = status
        invoice.save(update_fields=["subtotal_cents", "tax_cents", "status"])
        return invoice

    def test_no_invoices_returns_zeros(self) -> None:
        result = generate_vat_summary("2026-01-01", "2026-01-31")

        self.assertEqual(result["period_start"], "2026-01-01")
        self.assertEqual(result["period_end"], "2026-01-31")
        self.assertEqual(result["invoice_count"], 0)
        self.assertEqual(result["total_vat"], Decimal("0"))
        self.assertEqual(result["total_sales"], Decimal("0"))
        self.assertEqual(result["total_amount"], Decimal("0"))

    def test_paid_invoice_included_in_summary(self) -> None:
        self._create_invoice_for_vat("INV-VAT-001", status="paid")

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        self.assertGreater(result["invoice_count"], 0)
        self.assertGreater(result["total_sales"], Decimal("0"))
        self.assertGreater(result["total_vat"], Decimal("0"))

    def test_sent_invoice_included_in_summary(self) -> None:
        self._create_invoice_for_vat("INV-VAT-002", status="sent")

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        self.assertGreater(result["invoice_count"], 0)

    def test_issued_invoice_excluded_from_summary(self) -> None:
        self._create_invoice_for_vat("INV-VAT-003", status="issued")

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        self.assertEqual(result["invoice_count"], 0)

    def test_vat_breakdown_uses_default_rate_21(self) -> None:
        self._create_invoice_for_vat("INV-VAT-004")

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        # Default vat_rate getattr fallback is 21
        self.assertIn(21, result["vat_breakdown"])
        breakdown = result["vat_breakdown"][21]
        self.assertGreater(breakdown["count"], 0)
        self.assertIsInstance(breakdown["sales"], Decimal)
        self.assertIsInstance(breakdown["vat"], Decimal)

    def test_invalid_date_format_returns_error_dict(self) -> None:
        result = generate_vat_summary("not-a-date", "2026-01-31")

        self.assertIn("error", result)
        self.assertEqual(result["period_start"], "not-a-date")

    def test_multiple_invoices_totals_are_summed(self) -> None:
        self._create_invoice_for_vat("INV-VAT-005", subtotal_cents=10000, tax_cents=2100)
        self._create_invoice_for_vat("INV-VAT-006", subtotal_cents=5000, tax_cents=1050)

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        self.assertGreaterEqual(result["invoice_count"], 2)
        self.assertGreaterEqual(result["total_sales"], Decimal("150.00"))
        self.assertGreaterEqual(result["total_vat"], Decimal("31.50"))

    def test_generated_at_present_in_result(self) -> None:
        result = generate_vat_summary("2026-01-01", "2026-12-31")

        self.assertIn("generated_at", result)

    def test_totals_correctly_converted_from_cents_to_decimal(self) -> None:
        self._create_invoice_for_vat("INV-VAT-007", subtotal_cents=10000, tax_cents=2100)

        result = generate_vat_summary("2025-01-01", "2027-01-01")

        # 10000 cents = 100.00 decimal
        self.assertEqual(result["total_sales"], Decimal("100.00"))
        # 2100 cents = 21.00 decimal
        self.assertEqual(result["total_vat"], Decimal("21.00"))
