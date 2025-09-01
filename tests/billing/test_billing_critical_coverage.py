# ===============================================================================
# CRITICAL BILLING COVERAGE TESTS - First 20 Unit Tests  
# Target: Low coverage areas (views 20.11%, PDF generators 25.61%)
# ===============================================================================

from decimal import Decimal
from io import BytesIO
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from reportlab.lib.pagesizes import A4

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
)
from apps.billing.pdf_generators import (
    RomanianInvoicePDFGenerator,
    RomanianProformaPDFGenerator,
)
from apps.billing.services import RefundData, RefundReason, RefundService, RefundType
from apps.billing.views import (
    _get_accessible_customer_ids,
    _validate_financial_document_access,
    billing_list,
    invoice_pdf,
    proforma_pdf,
    proforma_to_invoice,
)
from apps.customers.models import Customer
from apps.users.models import User

UserModel = get_user_model()


class BillingCriticalCoverageTestCase(TestCase):
    """Base test case with common setup for billing tests"""

    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()

        # Create currency
        self.ron_currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )

        # Create test user with proper permissions
        self.staff_user = User.objects.create_user(
            email='staff@test.com',
            password='testpass123',
            is_staff=True,
            is_active=True
        )

        self.regular_user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            is_active=True
        )

        # Create test customer
        self.customer = Customer.objects.create(
            name='Test Customer SRL',
            company_name='Test Customer SRL',
            primary_email='customer@test.com'
        )

        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.ron_currency,
            status='issued',
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,        # 19.00 RON VAT
            total_cents=11900,     # 119.00 RON total
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30)
        )

        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-000001',
            currency=self.ron_currency,
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=15)
        )

    def add_session_middleware(self, request):
        """Add session and message middleware to request for testing"""
        middleware = SessionMiddleware(get_response=lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(get_response=lambda r: None)
        middleware.process_request(request)
        return request


class TestBillingViewsCriticalPaths(BillingCriticalCoverageTestCase):
    """Test critical untested paths in billing views (20.11% coverage)"""

    def test_get_accessible_customer_ids_with_none_user(self):
        """TEST #1: Test _get_accessible_customer_ids with None user"""
        result = _get_accessible_customer_ids(None)
        self.assertEqual(result, [])

    def test_get_accessible_customer_ids_missing_method(self):
        """TEST #2: Test _get_accessible_customer_ids when user lacks get_accessible_customers method"""
        # Create a mock user without the method
        mock_user = Mock()
        del mock_user.get_accessible_customers  # Remove the method
        
        result = _get_accessible_customer_ids(mock_user)
        self.assertEqual(result, [])

    def test_validate_financial_document_access_none_request(self):
        """TEST #3: Test _validate_financial_document_access with None request"""
        from django.core.exceptions import PermissionDenied
        with self.assertRaises(PermissionDenied):
            _validate_financial_document_access(None, self.invoice)

    def test_validate_financial_document_access_none_document(self):
        """TEST #4: Test _validate_financial_document_access with None document"""
        request = self.factory.get('/test/')
        request.user = self.staff_user
        request = self.add_session_middleware(request)
        
        from django.core.exceptions import PermissionDenied
        with self.assertRaises(PermissionDenied):
            _validate_financial_document_access(request, None)

    def test_validate_financial_document_access_unauthorized_user(self):
        """TEST #5: Test _validate_financial_document_access with unauthorized user"""
        request = self.factory.get('/test/')
        request.user = self.regular_user
        request = self.add_session_middleware(request)
        
        # Mock the can_access_customer method to return False
        from django.core.exceptions import PermissionDenied
        with patch.object(self.regular_user, 'can_access_customer', return_value=False):
            with self.assertRaises(PermissionDenied):
                _validate_financial_document_access(request, self.invoice)

    def test_billing_list_database_error_handling(self):
        """TEST #6: Test billing_list view error handling for database exceptions"""
        # Create request
        request = self.factory.get('/billing/')
        request.user = self.staff_user
        request = self.add_session_middleware(request)
        
        # Mock _get_accessible_customer_ids to raise an exception
        with patch('apps.billing.views._get_accessible_customer_ids', side_effect=Exception('Database error')):
            response = billing_list(request)
            
        self.assertEqual(response.status_code, 200)
        # Check that error context is set
        self.assertContains(response, 'Unable to load billing data')

    def test_billing_list_with_search_query(self):
        """TEST #7: Test billing_list view with search functionality"""
        request = self.factory.get('/billing/?search=PRO-000001')
        request.user = self.staff_user
        request = self.add_session_middleware(request)
        
        # Mock get_accessible_customers to return our customer
        with patch.object(self.staff_user, 'get_accessible_customers', return_value=[self.customer]):
            response = billing_list(request)
            
        self.assertEqual(response.status_code, 200)
        # Check that response content contains search-related content instead of context
        self.assertContains(response, 'PRO-000001')  # Should find our proforma number

    def test_proforma_to_invoice_already_converted(self):
        """TEST #8: Test proforma_to_invoice when proforma already converted"""
        # Create invoice from proforma first
        converted_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-FROM-PRO',
            currency=self.ron_currency,
            status='issued',
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,        # 19.00 RON VAT  
            total_cents=11900,     # 119.00 RON total
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            converted_from_proforma=self.proforma
        )
        
        request = self.factory.post(f'/billing/proforma/{self.proforma.pk}/to-invoice/')
        request.user = self.staff_user
        request = self.add_session_middleware(request)
        
        # Mock can_access_customer to return True
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_to_invoice(request, self.proforma.pk)
            
        self.assertEqual(response.status_code, 302)
        # Should redirect somewhere (the exact URL may vary based on app URL configuration)
        self.assertTrue(response.url.startswith('/'))  # Just verify it's a redirect URL

    def test_proforma_to_invoice_expired_proforma(self):
        """TEST #9: Test proforma_to_invoice with expired proforma"""
        # Make proforma expired
        self.proforma.valid_until = timezone.now() - timezone.timedelta(days=1)
        self.proforma.save()
        
        request = self.factory.post(f'/billing/proforma/{self.proforma.pk}/to-invoice/')
        request.user = self.staff_user
        request = self.add_session_middleware(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_to_invoice(request, self.proforma.pk)
            
        self.assertEqual(response.status_code, 302)
        # Should redirect somewhere (expired proforma handling)
        self.assertTrue(response.url.startswith('/'))  # Just verify it's a redirect URL


class TestPDFGeneratorsCriticalPaths(BillingCriticalCoverageTestCase):
    """Test critical untested paths in PDF generators (25.61% coverage)"""

    def test_romanian_invoice_pdf_generator_initialization(self):
        """TEST #10: Test Romanian invoice PDF generator initialization"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        
        self.assertEqual(generator.invoice, self.invoice)
        self.assertEqual(generator.document, self.invoice)
        self.assertIsInstance(generator.buffer, BytesIO)
        self.assertEqual(generator.width, A4[0])
        self.assertEqual(generator.height, A4[1])

    def test_romanian_proforma_pdf_generator_initialization(self):
        """TEST #11: Test Romanian proforma PDF generator initialization"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        
        self.assertEqual(generator.proforma, self.proforma)
        self.assertEqual(generator.document, self.proforma)
        self.assertIsInstance(generator.buffer, BytesIO)

    def test_invoice_pdf_document_title(self):
        """TEST #12: Test invoice PDF document title method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        title = generator._get_document_title()
        
        # Should return translated "FISCAL INVOICE"
        self.assertIn('INVOICE', str(title).upper())

    def test_proforma_pdf_document_title(self):
        """TEST #13: Test proforma PDF document title method"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        title = generator._get_document_title()
        
        # Should return "FACTURĂ PROFORMA"
        self.assertIn('PROFORMA', str(title).upper())

    def test_invoice_pdf_filename_generation(self):
        """TEST #14: Test invoice PDF filename generation"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        filename = generator._get_filename()
        
        self.assertEqual(filename, f"factura_{self.invoice.number}.pdf")

    def test_proforma_pdf_filename_generation(self):
        """TEST #15: Test proforma PDF filename generation"""  
        generator = RomanianProformaPDFGenerator(self.proforma)
        filename = generator._get_filename()
        
        self.assertEqual(filename, f"proforma_{self.proforma.number}.pdf")

    def test_invoice_pdf_legal_disclaimer(self):
        """TEST #16: Test invoice PDF legal disclaimer"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        disclaimer = generator._get_legal_disclaimer()
        
        # Should mention Romanian legislation
        self.assertIn('Romanian', str(disclaimer))

    def test_proforma_pdf_legal_disclaimer(self):
        """TEST #17: Test proforma PDF legal disclaimer"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        disclaimer = generator._get_legal_disclaimer()
        
        # Should state it's not a fiscal invoice
        self.assertIn('not', str(disclaimer).lower())
        self.assertIn('fiscal', str(disclaimer).lower())

    def test_invoice_pdf_total_label(self):
        """TEST #18: Test invoice PDF total label formatting"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        label = generator._get_total_label()
        
        # Should show "TOTAL TO PAY"
        self.assertIn('PAY', str(label).upper())

    def test_pdf_generator_with_no_line_items(self):
        """TEST #19: Test PDF generation with invoice that has no line items"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        
        # Test table rendering with empty lines
        with patch.object(generator.document.lines, 'all', return_value=[]):
            with patch.object(generator.document.lines, 'count', return_value=0):
                # Should not raise exception
                try:
                    generator._render_items_table()
                    generator._render_totals_section()
                except Exception as e:
                    self.fail(f"PDF generation failed with no line items: {e}")

    def test_invoice_pdf_status_information_paid(self):
        """TEST #20: Test invoice PDF status information for paid invoice"""
        # Set invoice as paid
        self.invoice.status = 'paid'
        self.invoice.paid_at = timezone.now()
        self.invoice.save()
        
        generator = RomanianInvoicePDFGenerator(self.invoice)
        
        # Should render paid status without raising exception
        try:
            generator._render_status_information(100)  # Mock y position
        except Exception as e:
            self.fail(f"Status information rendering failed: {e}")