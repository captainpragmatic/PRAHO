# ===============================================================================
# COMPREHENSIVE BILLING VIEWS TESTS - Coverage maximization
# ===============================================================================
"""
Tests for apps/billing/views.py targeting all view functions, error paths,
edge cases, and API endpoints.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceSequence,
    Payment,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


def _add_middleware(request):
    """Add session and message middleware to a RequestFactory request."""
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()
    middleware = MessageMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    return request


class BillingViewsTestBase(TestCase):
    """Base class with common setup for billing views tests."""

    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()
        self.currency = Currency.objects.create(code="RON", symbol="L", decimals=2)

        # Staff user with billing role
        self.staff_user = User.objects.create_user(
            email="billing@test.ro",
            password="testpass123",
            is_staff=True,
            staff_role="billing",
        )

        # Admin user
        self.admin_user = User.objects.create_user(
            email="admin@test.ro",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
            staff_role="admin",
        )

        # Regular user (non-staff)
        self.regular_user = User.objects.create_user(
            email="regular@test.ro",
            password="testpass123",
        )

        # Customer
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            company_name="Test Company SRL",
            primary_email="company@test.ro",
            status="active",
        )

        # Give regular user access to customer
        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role="admin",
        )

        # Create sequences
        ProformaSequence.objects.get_or_create(scope="default")
        InvoiceSequence.objects.get_or_create(scope="default")

    def _create_invoice(self, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"INV-{Invoice.objects.count() + 1:05d}",
            "status": "issued",
            "total_cents": 10000,
            "subtotal_cents": 8403,
            "tax_cents": 1597,
            "due_at": timezone.now() + timedelta(days=14),
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def _create_proforma(self, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"PRO-{ProformaInvoice.objects.count() + 1:05d}",
            "status": "draft",
            "total_cents": 10000,
            "subtotal_cents": 8403,
            "tax_cents": 1597,
            "valid_until": timezone.now() + timedelta(days=30),
            "bill_to_name": "Test Company SRL",
            "bill_to_email": "company@test.ro",
        }
        defaults.update(kwargs)
        return ProformaInvoice.objects.create(**defaults)


# ===============================================================================
# BILLING LIST VIEWS
# ===============================================================================


class BillingListViewTest(BillingViewsTestBase):
    """Tests for billing_list view."""

    def test_billing_list_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_anonymous_redirect(self):
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 302)

    def test_billing_list_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 302)

    def test_billing_list_filter_by_type_proforma(self):
        self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?type=proforma")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_filter_by_type_invoice(self):
        self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?type=invoice")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_search(self):
        self._create_invoice(number="INV-SEARCH-001")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?search=SEARCH")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_pagination(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?page=1")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_documents(self):
        self._create_invoice()
        self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_database_error(self):
        """Test that database errors are handled gracefully."""
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/invoices/")
            self.assertEqual(response.status_code, 200)  # Renders error template


class ProformaListViewTest(BillingViewsTestBase):
    """Tests for proforma_list view."""

    def test_proforma_list_authenticated(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/")
        self.assertEqual(response.status_code, 200)

    def test_proforma_list_with_search(self):
        self._create_proforma(number="PRO-SEARCH-001")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/?search=SEARCH")
        self.assertEqual(response.status_code, 200)

    def test_proforma_list_anonymous_redirect(self):
        response = self.client.get("/billing/proformas/")
        self.assertEqual(response.status_code, 302)

    def test_proforma_list_database_error(self):
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/proformas/")
            self.assertEqual(response.status_code, 200)


class BillingListHtmxViewTest(BillingViewsTestBase):
    """Tests for billing_list_htmx view."""

    def test_htmx_list_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/")
        self.assertEqual(response.status_code, 200)

    def test_htmx_list_filter_by_type(self):
        self._create_proforma()
        self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?type=proforma")
        self.assertEqual(response.status_code, 200)

    def test_htmx_list_with_search(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?search=test")
        self.assertEqual(response.status_code, 200)

    def test_htmx_list_pagination(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?page=1&type=all")
        self.assertEqual(response.status_code, 200)

    def test_htmx_list_database_error(self):
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/invoices/list/")
            self.assertEqual(response.status_code, 200)

    def test_htmx_list_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/invoices/list/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# INVOICE DETAIL / EDIT / PDF / SEND VIEWS
# ===============================================================================


class InvoiceDetailViewTest(BillingViewsTestBase):
    """Tests for invoice_detail view."""

    def test_invoice_detail_with_access(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/")
        self.assertEqual(response.status_code, 200)

    def test_invoice_detail_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/99999/")
        self.assertEqual(response.status_code, 404)

    def test_invoice_detail_access_denied(self):
        """Regular user without membership should be redirected."""
        other_customer = Customer.objects.create(
            name="Other Co",
            customer_type="company",
            company_name="Other Co",
            status="active",
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/")
        self.assertEqual(response.status_code, 302)


class InvoiceEditViewTest(BillingViewsTestBase):
    """Tests for invoice_edit view."""

    def test_invoice_edit_get_draft(self):
        invoice = self._create_invoice(status="draft")
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertEqual(response.status_code, 200)

    def test_invoice_edit_non_draft_redirect(self):
        invoice = self._create_invoice(status="issued")
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertEqual(response.status_code, 302)

    def test_invoice_edit_post_draft(self):
        invoice = self._create_invoice(status="draft")
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertEqual(response.status_code, 302)

    def test_invoice_edit_no_access(self):
        other_customer = Customer.objects.create(
            name="Noaccess Co", customer_type="company", company_name="Noaccess Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer, status="draft")
        # Use a regular user who doesn't have access but has billing role
        _no_access_user = User.objects.create_user(
            email="noaccess@test.ro", password="testpass123", is_staff=True, staff_role="billing"
        )
        # staff can_access_customer returns True for staff users, so test with non-staff
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        # regular_user doesn't have billing_staff_required
        self.assertEqual(response.status_code, 302)


class InvoicePdfViewTest(BillingViewsTestBase):
    """Tests for invoice_pdf view."""

    @patch("apps.billing.views.RomanianInvoicePDFGenerator")
    def test_invoice_pdf_success(self, mock_gen_cls):
        mock_gen = MagicMock()
        mock_gen.generate_response.return_value = HttpResponse(b"%PDF", content_type="application/pdf")
        mock_gen_cls.return_value = mock_gen
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/pdf/")
        self.assertEqual(response.status_code, 200)

    def test_invoice_pdf_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/99999/pdf/")
        self.assertEqual(response.status_code, 404)

    def test_invoice_pdf_access_denied(self):
        other_customer = Customer.objects.create(
            name="PdfDeny Co", customer_type="company", company_name="PdfDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/pdf/")
        self.assertEqual(response.status_code, 302)


class InvoiceSendViewTest(BillingViewsTestBase):
    """Tests for invoice_send view."""

    def test_invoice_send_post(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_invoice_send_get_method_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 405)

    def test_invoice_send_no_access(self):
        other_customer = Customer.objects.create(
            name="SendDeny Co", customer_type="company", company_name="SendDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        # Non-staff user can't pass billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# PROFORMA VIEWS
# ===============================================================================


class ProformaCreateViewTest(BillingViewsTestBase):
    """Tests for proforma_create view."""

    def test_proforma_create_get(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/create/")
        self.assertEqual(response.status_code, 200)

    @patch("apps.billing.views.get_invoice_payment_terms_days", return_value=30)
    def test_proforma_create_post_success(self, _mock):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                "customer": str(self.customer.pk),
                "valid_until": (timezone.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "bill_to_name": "Test Company SRL",
                "bill_to_email": "company@test.ro",
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ProformaInvoice.objects.filter(customer=self.customer).exists())

    def test_proforma_create_post_no_customer(self):
        self.client.force_login(self.admin_user)
        response = self.client.post("/billing/proformas/create/", {})
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_customer(self):
        self.client.force_login(self.admin_user)
        response = self.client.post("/billing/proformas/create/", {"customer": "99999"})
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_date(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                "customer": str(self.customer.pk),
                "valid_until": "not-a-date",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_line_quantity(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "abc",
                "line_0_unit_price": "100",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_unit_price(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "1",
                "line_0_unit_price": "abc",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_vat_rate(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "1",
                "line_0_unit_price": "100",
                "line_0_vat_rate": "abc",
            },
        )
        self.assertEqual(response.status_code, 302)


class ProformaDetailViewTest(BillingViewsTestBase):
    """Tests for proforma_detail view."""

    def test_proforma_detail_with_access(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/")
        self.assertEqual(response.status_code, 200)

    def test_proforma_detail_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/99999/")
        self.assertEqual(response.status_code, 404)


class ProformaEditViewTest(BillingViewsTestBase):
    """Tests for proforma_edit view."""

    def test_proforma_edit_get(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/edit/")
        self.assertEqual(response.status_code, 200)

    def test_proforma_edit_expired(self):
        proforma = self._create_proforma(valid_until=timezone.now() - timedelta(days=1))
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/edit/")
        self.assertEqual(response.status_code, 302)

    def test_proforma_edit_post_success(self):
        proforma = self._create_proforma()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/edit/",
            {
                "customer": str(self.customer.pk),
                "valid_until": (timezone.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "bill_to_name": "Updated Name",
                "bill_to_email": "updated@test.ro",
                "bill_to_tax_id": "RO12345",
                "line_0_description": "Updated service",
                "line_0_quantity": "2",
                "line_0_unit_price": "50.00",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_edit_post_no_customer(self):
        proforma = self._create_proforma()
        self.client.force_login(self.admin_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/edit/", {})
        self.assertEqual(response.status_code, 302)


class ProformaPdfViewTest(BillingViewsTestBase):
    """Tests for proforma_pdf view."""

    @patch("apps.billing.views.RomanianProformaPDFGenerator")
    def test_proforma_pdf_success(self, mock_gen_cls):
        mock_gen = MagicMock()
        mock_gen.generate_response.return_value = HttpResponse(b"%PDF", content_type="application/pdf")
        mock_gen_cls.return_value = mock_gen
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/pdf/")
        self.assertEqual(response.status_code, 200)


class ProformaSendViewTest(BillingViewsTestBase):
    """Tests for proforma_send view."""

    def test_proforma_send_post(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_proforma_send_get(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 405)

    def test_proforma_send_no_access(self):
        other_customer = Customer.objects.create(
            name="NoSend Co", customer_type="company", company_name="NoSend Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        # regular_user can't pass billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 302)


class ProformaToInvoiceViewTest(BillingViewsTestBase):
    """Tests for proforma_to_invoice view."""

    def test_convert_get(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 200)

    def test_convert_post_success(self):
        proforma = self._create_proforma()
        ProformaLine.objects.create(
            proforma=proforma,
            kind="service",
            description="Test Service",
            quantity=1,
            unit_price_cents=8403,
            tax_rate=Decimal("0.19"),
            line_total_cents=10000,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Invoice.objects.filter(converted_from_proforma=proforma).exists())

    def test_convert_expired_proforma(self):
        proforma = self._create_proforma(valid_until=timezone.now() - timedelta(days=1))
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)

    def test_convert_already_converted(self):
        proforma = self._create_proforma()
        self._create_invoice(converted_from_proforma=proforma)
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)

    def test_convert_no_access(self):
        other_customer = Customer.objects.create(
            name="Convert Deny Co", customer_type="company", company_name="Convert Deny Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        # Non-staff fails billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# PAYMENT VIEWS
# ===============================================================================


class PaymentListViewTest(BillingViewsTestBase):
    """Tests for payment_list view."""

    def test_payment_list_authenticated(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/payments/")
        self.assertEqual(response.status_code, 200)

    def test_payment_list_with_status_filter(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/payments/?status=succeeded")
        self.assertEqual(response.status_code, 200)

    def test_payment_list_with_invoice_filter(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/payments/?invoice={invoice.pk}")
        self.assertEqual(response.status_code, 200)

    def test_payment_list_anonymous_redirect(self):
        response = self.client.get("/billing/payments/")
        self.assertEqual(response.status_code, 302)


class ProcessPaymentViewTest(BillingViewsTestBase):
    """Tests for process_payment view."""

    def test_process_payment_post_success(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_process_payment_invalid_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "not-a-number", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 400)

    def test_process_payment_get_method(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/pay/")
        self.assertEqual(response.status_code, 405)

    def test_process_payment_marks_paid(self):
        invoice = self._create_invoice(total_cents=10000)
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "stripe"},
        )
        self.assertEqual(response.status_code, 200)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")

    def test_process_payment_invalid_method_fallback(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bitcoin"},
        )
        self.assertEqual(response.status_code, 200)
        payment = Payment.objects.last()
        self.assertEqual(payment.payment_method, "other")


class ProcessProformaPaymentViewTest(BillingViewsTestBase):
    """Tests for process_proforma_payment view."""

    def test_proforma_payment_post_new_conversion(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_proforma_payment_already_converted(self):
        proforma = self._create_proforma()
        self._create_invoice(converted_from_proforma=proforma)
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"amount": "100.00", "payment_method": "stripe"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_proforma_payment_get_method(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/pay/")
        self.assertEqual(response.status_code, 405)

    def test_proforma_payment_no_access(self):
        other_customer = Customer.objects.create(
            name="PayDeny Co", customer_type="company", company_name="PayDeny Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/pay/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# E-FACTURA VIEWS
# ===============================================================================


class GenerateEFacturaViewTest(BillingViewsTestBase):
    """Tests for generate_e_factura view."""

    def test_generate_efactura_success(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/e-factura/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/xml")

    def test_generate_efactura_no_access(self):
        other_customer = Customer.objects.create(
            name="EFDeny Co", customer_type="company", company_name="EFDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/e-factura/")
        self.assertEqual(response.status_code, 302)


class EFacturaDashboardViewTest(BillingViewsTestBase):
    """Tests for efactura_dashboard view."""

    def test_dashboard_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/e-factura/")
        self.assertEqual(response.status_code, 302)

    def test_dashboard_with_status_filter(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/?status=draft")
        self.assertEqual(response.status_code, 200)


class EFacturaDocumentDetailViewTest(BillingViewsTestBase):
    """Tests for efactura_document_detail view."""

    def test_detail_not_found(self):
        self.client.force_login(self.staff_user)
        fake_uuid = str(uuid.uuid4())
        response = self.client.get(f"/billing/e-factura/{fake_uuid}/")
        self.assertEqual(response.status_code, 404)

    def test_detail_with_document(self):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="draft",
            anaf_upload_index="",
        )
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/e-factura/{doc.pk}/")
        self.assertEqual(response.status_code, 200)


class EFacturaSubmitViewTest(BillingViewsTestBase):
    """Tests for efactura_submit view."""

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_submit_success(self, mock_svc_cls):
        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_svc.submit_invoice.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_submit_failure(self, mock_svc_cls):
        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Validation failed"
        mock_svc.submit_invoice.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 302)

    def test_submit_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 405)


class EFacturaRetryViewTest(BillingViewsTestBase):
    """Tests for efactura_retry view."""

    def test_retry_not_found(self):
        self.client.force_login(self.staff_user)
        fake_uuid = str(uuid.uuid4())
        response = self.client.post(f"/billing/e-factura/{fake_uuid}/retry/")
        self.assertEqual(response.status_code, 404)

    def test_retry_cannot_retry(self):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="accepted",  # Terminal state, can't retry
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_retry_success(self, mock_svc_cls):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_svc.retry_failed_submission.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="error",
            retry_count=0,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_retry_failure(self, mock_svc_cls):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Retry failed"
        mock_svc.retry_failed_submission.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="error",
            retry_count=0,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)


class EFacturaDocumentsHtmxViewTest(BillingViewsTestBase):
    """Tests for efactura_documents_htmx view."""

    def test_htmx_documents_list(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/")
        self.assertEqual(response.status_code, 200)

    def test_htmx_documents_with_status_filter(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/?status=draft")
        self.assertEqual(response.status_code, 200)

    def test_htmx_documents_with_search(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/?q=INV")
        self.assertEqual(response.status_code, 200)


# ===============================================================================
# REPORTS VIEWS
# ===============================================================================


class BillingReportsViewTest(BillingViewsTestBase):
    """Tests for billing_reports view."""

    def test_reports_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 200)

    def test_reports_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 302)

    def test_reports_with_data(self):
        self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 200)


class VatReportViewTest(BillingViewsTestBase):
    """Tests for vat_report view."""

    def test_vat_report_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/vat/")
        self.assertEqual(response.status_code, 200)

    def test_vat_report_with_dates(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/vat/?start_date=2025-01-01&end_date=2025-12-31")
        self.assertEqual(response.status_code, 200)

    def test_vat_report_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/reports/vat/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# INVOICE REFUND VIEWS
# ===============================================================================


class InvoiceRefundViewTest(BillingViewsTestBase):
    """Tests for invoice_refund view."""

    def test_refund_missing_fields(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {"refund_type": "full"},
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_full(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "full",
                "refund_reason": "customer_request",
                "refund_notes": "Customer wants refund",
            },
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        # Refund service not implemented yet
        self.assertFalse(data["success"])

    def test_refund_partial_valid(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "partial",
                "refund_reason": "quality_issue",
                "refund_notes": "Partial refund",
                "refund_amount": "50.00",
            },
        )
        # Returns 400 because RefundService not yet implemented
        self.assertEqual(response.status_code, 400)

    def test_refund_partial_zero_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "partial",
                "refund_reason": "quality_issue",
                "refund_notes": "Partial refund",
                "refund_amount": "0",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_partial_invalid_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "partial",
                "refund_reason": "quality_issue",
                "refund_notes": "Partial refund",
                "refund_amount": "abc",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.get(f"/billing/invoices/{invoice.id}/refund/")
        self.assertEqual(response.status_code, 405)

    def test_refund_no_access(self):
        other_customer = Customer.objects.create(
            name="RefundDeny Co", customer_type="company", company_name="RefundDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/invoices/{invoice.id}/refund/")
        self.assertEqual(response.status_code, 302)


class InvoiceRefundRequestViewTest(BillingViewsTestBase):
    """Tests for invoice_refund_request view."""

    def test_refund_request_success(self):
        """Test refund request - creates a ticket (may fail if SupportCategory schema differs)."""
        from apps.tickets.models import SupportCategory  # noqa: PLC0415

        # Pre-create the category to avoid schema issues in get_or_create defaults
        SupportCategory.objects.get_or_create(name="Billing")

        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {
                "refund_reason": "customer_request",
                "refund_notes": "I want a refund",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_refund_request_not_paid(self):
        invoice = self._create_invoice(status="issued")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {
                "refund_reason": "customer_request",
                "refund_notes": "I want a refund",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_request_missing_fields(self):
        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {"refund_reason": "customer_request"},
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_request_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.id}/refund-request/")
        self.assertEqual(response.status_code, 405)

    def test_refund_request_various_reasons(self):
        """Test different refund reason types."""
        from apps.tickets.models import SupportCategory  # noqa: PLC0415

        SupportCategory.objects.get_or_create(name="Billing")

        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        for reason in ["service_failure", "quality_issue", "duplicate_invoice", "other"]:
            response = self.client.post(
                f"/billing/invoices/{invoice.id}/refund-request/",
                {"refund_reason": reason, "refund_notes": f"Reason: {reason}"},
            )
            self.assertEqual(response.status_code, 200)


# ===============================================================================
# API ENDPOINTS
# ===============================================================================


class ApiCreatePaymentIntentTest(BillingViewsTestBase):
    """Tests for api_create_payment_intent."""

    def _post_json(self, url, data):
        return self.client.post(url, json.dumps(data), content_type="application/json")

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_success(self, mock_create):
        mock_create.return_value = {
            "success": True,
            "payment_intent_id": "pi_test123",
            "client_secret": "cs_test123",
        }
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "order_number": "ORD-001",
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_service_failure(self, mock_create):
        mock_create.return_value = {"success": False, "error": "Stripe error"}
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_order_id(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"amount_cents": 5000, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_amount(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_amount(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": -100, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_customer(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": 5000},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_currency(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "currency": "GBP",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_gateway(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "gateway": "paypal",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_json(self):
        response = self.client.post(
            "/billing/create-payment-intent/",
            "not json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_get_not_allowed(self):
        response = self.client.get("/billing/create-payment-intent/")
        self.assertEqual(response.status_code, 405)

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_exception(self, mock_create):
        mock_create.side_effect = Exception("Unexpected error")
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 500)

    def test_create_intent_order_id_not_string(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": 123, "amount_cents": 5000, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_amount_not_int(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": "5000", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)


class ApiConfirmPaymentTest(BillingViewsTestBase):
    """Tests for api_confirm_payment."""

    def _post_json(self, url, data):
        return self.client.post(url, json.dumps(data), content_type="application/json")

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_success(self, mock_confirm):
        mock_confirm.return_value = {"success": True, "status": "succeeded"}
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_failure(self, mock_confirm):
        mock_confirm.return_value = {"success": False, "error": "Payment failed"}
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe"},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_missing_payment_id(self):
        response = self._post_json("/billing/confirm-payment/", {"gateway": "stripe"})
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_stripe_format(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "invalid_id", "gateway": "stripe"},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_gateway(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "paypal"},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_json(self):
        response = self.client.post(
            "/billing/confirm-payment/",
            "not json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_exception(self, mock_confirm):
        mock_confirm.side_effect = Exception("Unexpected")
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe"},
        )
        self.assertEqual(response.status_code, 500)

    def test_confirm_payment_id_not_string(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": 123, "gateway": "stripe"},
        )
        self.assertEqual(response.status_code, 400)


class ApiCreateSubscriptionTest(BillingViewsTestBase):
    """Tests for api_create_subscription."""

    def _post_json(self, url, data):
        return self.client.post(url, json.dumps(data), content_type="application/json")

    @patch("apps.billing.views.PaymentService.create_subscription")
    def test_create_subscription_success(self, mock_create):
        mock_create.return_value = {
            "success": True,
            "subscription_id": "sub_test123",
            "status": "active",
        }
        response = self._post_json(
            "/billing/create-subscription/",
            {"customer_id": str(self.customer.pk), "price_id": "price_test123"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.create_subscription")
    def test_create_subscription_failure(self, mock_create):
        mock_create.return_value = {"success": False, "error": "Invalid price"}
        response = self._post_json(
            "/billing/create-subscription/",
            {"customer_id": str(self.customer.pk), "price_id": "price_test123"},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_subscription_missing_fields(self):
        response = self._post_json("/billing/create-subscription/", {"customer_id": "123"})
        self.assertEqual(response.status_code, 400)

    def test_create_subscription_invalid_json(self):
        response = self.client.post(
            "/billing/create-subscription/",
            "not json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.PaymentService.create_subscription")
    def test_create_subscription_exception(self, mock_create):
        mock_create.side_effect = Exception("Unexpected")
        response = self._post_json(
            "/billing/create-subscription/",
            {"customer_id": str(self.customer.pk), "price_id": "price_test123"},
        )
        self.assertEqual(response.status_code, 500)


class ApiPaymentMethodsTest(BillingViewsTestBase):
    """Tests for api_payment_methods."""

    @patch("apps.billing.views.PaymentService.get_available_payment_methods")
    def test_payment_methods_success(self, mock_get):
        mock_get.return_value = [{"type": "card", "last4": "4242"}]
        response = self.client.get(f"/billing/payment-methods/{self.customer.pk}/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.get_available_payment_methods")
    def test_payment_methods_exception(self, mock_get):
        mock_get.side_effect = Exception("Stripe error")
        response = self.client.get(f"/billing/payment-methods/{self.customer.pk}/")
        self.assertEqual(response.status_code, 500)

    def test_payment_methods_post_not_allowed(self):
        response = self.client.post(f"/billing/payment-methods/{self.customer.pk}/")
        self.assertEqual(response.status_code, 405)


class ApiProcessRefundTest(BillingViewsTestBase):
    """Tests for api_process_refund."""

    def _post_json(self, url, data):
        return self.client.post(url, json.dumps(data), content_type="application/json")

    def test_process_refund_invalid_payment_id(self):
        """Refund with invalid payment ID format returns 400"""
        response = self._post_json(
            "/billing/process-refund/",
            {"payment_id": "pay_123", "amount_cents": 1000, "reason": "Test"},
        )
        self.assertEqual(response.status_code, 400)

    def test_process_refund_missing_payment_id(self):
        response = self._post_json(
            "/billing/process-refund/",
            {"amount_cents": 1000},
        )
        self.assertEqual(response.status_code, 400)

    def test_process_refund_invalid_json(self):
        response = self.client.post(
            "/billing/process-refund/",
            "not json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.json.loads")
    def test_process_refund_exception(self, mock_loads):
        mock_loads.side_effect = Exception("Unexpected")
        response = self.client.post(
            "/billing/process-refund/",
            json.dumps({"payment_id": "pay_123"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 500)


class ApiStripeConfigTest(BillingViewsTestBase):
    """Tests for api_stripe_config."""

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_enabled(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": True,
            "integrations.stripe_publishable_key": "pk_test_123",
        }.get(key, kwargs.get("default"))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_disabled(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": False,
        }.get(key, kwargs.get("default", False))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 503)

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_no_key(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": True,
            "integrations.stripe_publishable_key": None,
        }.get(key, kwargs.get("default"))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 500)

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_exception(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = Exception("Config error")
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 500)

    def test_stripe_config_post_not_allowed(self):
        response = self.client.post("/billing/stripe-config/")
        self.assertEqual(response.status_code, 405)


# ===============================================================================
# HELPER / INTERNAL FUNCTION TESTS
# ===============================================================================


class ValidateFinancialDocumentAccessTest(BillingViewsTestBase):
    """Tests for _validate_financial_document_access."""

    def test_none_request(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        result = _validate_financial_document_access(None, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 403)

    def test_none_document(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        request = self.factory.get("/")
        request.user = self.staff_user
        result = _validate_financial_document_access(request, None)
        self.assertIsNotNone(result)

    def test_unauthenticated_user(self):
        from django.contrib.auth.models import AnonymousUser  # noqa: PLC0415

        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/")
        request.user = AnonymousUser()
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNotNone(result)

    def test_no_customer_access(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="NoAccess Co", customer_type="company", company_name="NoAccess Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        request = self.factory.get("/")
        request.user = self.regular_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNotNone(result)

    def test_successful_access(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/")
        request.user = self.staff_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNone(result)


class ValidateFinancialDocumentAccessWithRedirectTest(BillingViewsTestBase):
    """Tests for _validate_financial_document_access_with_redirect."""

    def test_successful_access_returns_none(self):
        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = self.staff_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNone(result)

    def test_unauthenticated_redirects_to_login(self):
        from django.contrib.auth.models import AnonymousUser  # noqa: PLC0415

        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = AnonymousUser()
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_no_access_redirects_to_list(self):
        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="Redirect Co", customer_type="company", company_name="Redirect Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = self.regular_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)


class GetAccessibleCustomerIdsTest(BillingViewsTestBase):
    """Tests for _get_accessible_customer_ids."""

    def test_staff_user(self):
        from apps.billing.views import _get_accessible_customer_ids  # noqa: PLC0415

        ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIsInstance(ids, list)

    def test_regular_user(self):
        from apps.billing.views import _get_accessible_customer_ids  # noqa: PLC0415

        ids = _get_accessible_customer_ids(self.regular_user)
        self.assertIsInstance(ids, list)


class ProcessValidUntilDateTest(BillingViewsTestBase):
    """Tests for _process_valid_until_date."""

    def test_none_data(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date(None)
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])

    def test_valid_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": "2026-12-31"})
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])

    def test_invalid_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": "not-a-date"})
        self.assertIsNotNone(valid_until)
        self.assertEqual(len(errors), 1)

    def test_empty_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": ""})
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])


class ValidateCustomerAssignmentTest(BillingViewsTestBase):
    """Tests for _validate_customer_assignment."""

    def test_no_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_invalid_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, "99999", None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_invalid_customer_id_with_proforma_pk(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, "99999", 1)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_valid_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, str(self.customer.pk), None)
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error)

    def test_customer_not_accessible(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="Inaccessible Co", customer_type="company", company_name="Inaccessible Co", status="active"
        )
        customer, error = _validate_customer_assignment(self.regular_user, str(other_customer.pk), None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)


class GetMaxPaymentAmountCentsTest(TestCase):
    """Tests for _get_max_payment_amount_cents."""

    @patch("apps.settings.services.SettingsService")
    def test_returns_setting_value(self, mock_settings_cls):
        from apps.billing.views import _get_max_payment_amount_cents  # noqa: PLC0415

        mock_settings_cls.get_integer_setting.return_value = 50_000_000
        result = _get_max_payment_amount_cents()
        self.assertEqual(result, 50_000_000)
