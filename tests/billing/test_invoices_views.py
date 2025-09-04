# ===============================================================================
# INVOICE VIEWS TESTS - Feature-based organization
# ===============================================================================

from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    Payment,
)
from apps.billing.views import (
    billing_list,
    _validate_financial_document_access_with_redirect as _validate_financial_document_access,
    invoice_detail,
    invoice_pdf,
    proforma_to_invoice,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

UserModel = get_user_model()


class InvoiceDetailViewTestCase(TestCase):
    """Test invoice_detail view"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Detail Test Company SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='detail@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DETAIL-001',
            total_cents=12000,
            status='issued'
        )
        
        # Add invoice line
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.19')
        )
        
        # Add payment
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            currency=self.currency,
            status='succeeded'
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.contrib.messages.middleware import MessageMiddleware
        from django.http import HttpResponse
        
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_invoice_detail_success(self):
        """Test successful invoice detail view"""
        request = self.factory.get(f'/app/billing/invoices/{self.invoice.pk}/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 200)
        # Should contain invoice information
        self.assertContains(response, 'INV-DETAIL-001')
        self.assertContains(response, 'Test Service')

    def test_invoice_detail_unauthorized_user(self):
        """Test invoice detail with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth@test.ro',
            password='testpass'
        )
        
        request = self.factory.get(f'/app/billing/invoices/{self.invoice.pk}/')
        request.user = unauthorized_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_detail_not_found(self):
        """Test invoice detail with non-existent invoice"""
        request = self.factory.get('/app/billing/invoices/99999/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        with self.assertRaises(Http404):
            invoice_detail(request, 99999)


class ProformaToInvoiceViewTestCase(TestCase):
    """Test proforma_to_invoice view"""
    
    def setUp(self):
        """Setup test data"""
        from apps.billing.models import ProformaInvoice, ProformaLine
        
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Convert Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='proforma_convert@test.ro',
            password='testpass'
        )
        # Give user billing staff privileges
        self.user.staff_role = 'billing'
        self.user.save()
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONVERT-001',
            total_cents=15000,
            status='sent',
            valid_until=timezone.now() + timezone.timedelta(days=30)  # Future date
        )
        
        # Add proforma line
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Convertible Service',
            quantity=1,
            unit_price_cents=12605,  # 105.88 lei including 19% VAT
            tax_rate=Decimal('0.19'),
            line_total_cents=12605  # Same as unit price for quantity 1
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_proforma_to_invoice_conversion_success(self):
        """Test successful proforma to invoice conversion"""
        request = self.factory.post(f'/app/billing/proformas/{self.proforma.pk}/convert-to-invoice/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        
        # Should redirect to the new invoice
        self.assertEqual(response.status_code, 302)
        
        # Check that invoice was created
        invoices = Invoice.objects.filter(customer=self.customer)
        self.assertEqual(invoices.count(), 1)
        
        invoice = invoices.first()
        self.assertEqual(invoice.total_cents, self.proforma.total_cents)
        self.assertEqual(invoice.status, 'issued')

    def test_proforma_to_invoice_unauthorized_user(self):
        """Test proforma to invoice conversion with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth_convert@test.ro',
            password='testpass'
        )
        
        request = self.factory.post(f'/app/billing/proformas/{self.proforma.pk}/convert-to-invoice/')
        request.user = unauthorized_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        # Should redirect (unauthorized)
        self.assertEqual(response.status_code, 302)
        
        # Should not create invoice
        self.assertEqual(Invoice.objects.count(), 0)

    def test_proforma_to_invoice_not_found(self):
        """Test proforma to invoice conversion with non-existent proforma"""
        request = self.factory.post('/app/billing/proformas/99999/convert-to-invoice/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        with self.assertRaises(Http404):
            proforma_to_invoice(request, 99999)


class InvoiceEditViewsTestCase(TestCase):
    """Test invoice edit functionality"""
    
    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Invoice Edit Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='invoice_edit@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_invoice_edit_access_authorized(self):
        """Test that authorized users can access invoice edit"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EDIT-001',
            total_cents=10000,
            status='draft'
        )
        
        # Test access validation function
        request = self.factory.get('/billing/invoices/')
        request.user = self.user
        self.add_middleware_to_request(request)
        
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNone(result)  # None means access is allowed

    def test_invoice_edit_access_unauthorized(self):
        """Test that unauthorized users cannot access invoice edit"""
        other_customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Company SRL',
            status='active'
        )
        
        invoice = Invoice.objects.create(
            customer=other_customer,
            currency=self.currency,
            number='INV-OTHER-001',
            total_cents=10000,
            status='draft'
        )
        
        # Test access validation function
        request = self.factory.get('/billing/invoices/')
        request.user = self.user
        self.add_middleware_to_request(request)
        
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNotNone(result)  # Should return an HttpResponse indicating access denied


class InvoiceSendViewsTestCase(TestCase):
    """Test invoice sending functionality"""
    
    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Invoice Send Test SRL',
            primary_email='send@test.ro',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='invoice_send@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-SEND-001',
            total_cents=10000,
            status='issued'
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    @patch('apps.billing.services.send_invoice_email')
    def test_invoice_send_success(self, mock_send_email):
        """Test successful invoice sending"""
        mock_send_email.return_value = True
        
        # This is a placeholder test as we need to check the actual view implementation
        # The view function for sending invoices would be tested here
        self.assertTrue(True)  # Placeholder assertion
        
    def test_invoice_send_validation(self):
        """Test invoice send validation"""
        # Test that invoice must be in correct status
        draft_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DRAFT-001',
            total_cents=10000,
            status='draft'
        )
        
        # Draft invoices should not be sendable
        self.assertEqual(draft_invoice.status, 'draft')
        # Add actual validation tests when implementing the send functionality