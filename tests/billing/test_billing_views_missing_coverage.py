# ===============================================================================
# BILLING VIEWS MISSING COVERAGE TESTS - TARGETED FOR 85%+ COVERAGE
# ===============================================================================

from __future__ import annotations

import json
import uuid
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages import get_messages
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpRequest, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing import views
from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceSequence,
    ProformaInvoice,
    ProformaSequence,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class BillingViewsMissingCoverageTestCase(TestCase):
    """
    Comprehensive test suite targeting missing coverage in billing views.py
    Focus on uncovered functions: invoice_send, proforma_send, payment processing, error handling
    """

    def setUp(self) -> None:
        """Set up test fixtures with proper Romanian business data"""
        self.factory = RequestFactory()
        self.client = Client()
        
        # Create currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='RON',
            decimals=2
        )
        
        # Create customer
        self.customer = Customer.objects.create(
            name='Test SRL',
            customer_type='company',
            status='active'
        )
        
        # Create user
        self.user = User.objects.create_user(
            email='admin@example.com',
            password='testpass123',
            is_staff=True
        )
        
        # Create customer membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create sequences
        self.invoice_sequence = InvoiceSequence.objects.create(
            scope='test',
            last_value=0
        )
        
        self.proforma_sequence = ProformaSequence.objects.create(
            scope='test',
            last_value=0
        )
        
        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-001',
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,        # 19.00 RON (19% VAT)
            total_cents=11900,     # 119.00 RON
            currency=self.currency,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            notes='Test proforma',
            status='draft'
        )
        
        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='TST-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            currency=self.currency,
            notes='Test invoice',
            status='issued',
            proforma=self.proforma
        )

    def _add_session_middleware(self, request: HttpRequest) -> None:
        """Add session middleware to request"""
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

    def _add_messages_middleware(self, request: HttpRequest) -> None:
        """Add messages middleware to request"""
        middleware = MessageMiddleware(lambda x: None)
        middleware.process_request(request)

    def test_billing_list_unauthenticated_user(self) -> None:
        """Test billing_list redirects for unauthenticated user (line 75)"""
        request = self.factory.get('/billing/')
        request.user = AnonymousUser()
        
        response = views.billing_list(request)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('users:login', response.url)

    @patch('apps.billing.views._get_accessible_customer_ids')
    def test_billing_list_with_exception(self, mock_get_customers: Mock) -> None:
        """Test billing_list handles exceptions gracefully"""
        mock_get_customers.side_effect = Exception("Database error")
        
        request = self.factory.get('/billing/')
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.billing_list(request)
        
        # Should redirect to dashboard on error
        self.assertEqual(response.status_code, 302)

    def test_handle_proforma_create_post_invalid_customer(self) -> None:
        """Test _handle_proforma_create_post with invalid customer (lines 278-279)"""
        request = self.factory.post('/billing/proformas/create/', {
            'customer_id': '99999',  # Non-existent customer
            'valid_until': '2024-12-31',
            'notes': 'Test notes'
        })
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views._handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(request))
        self.assertTrue(any('customer not found' in str(m).lower() for m in messages))

    def test_handle_proforma_create_post_no_permission(self) -> None:
        """Test _handle_proforma_create_post with no customer permission (line 294)"""
        # Create another customer that user can't access
        other_customer = Customer.objects.create(
            name='Other SRL',
            customer_type='company',
            status='active'
        )
        
        request = self.factory.post('/billing/proformas/create/', {
            'customer_id': str(other_customer.id),
            'valid_until': '2024-12-31',
            'notes': 'Test notes'
        })
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views._handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(request))
        self.assertTrue(any('permission' in str(m).lower() for m in messages))

    def test_handle_proforma_create_post_sequence_error(self) -> None:
        """Test _handle_proforma_create_post with sequence creation error (line 311)"""
        with patch('apps.billing.views._create_proforma_with_sequence') as mock_create:
            mock_create.side_effect = Exception("Sequence error")
            
            request = self.factory.post('/billing/proformas/create/', {
                'customer_id': str(self.customer.id),
                'valid_until': '2024-12-31',
                'notes': 'Test notes'
            })
            request.user = self.user
            self._add_session_middleware(request)
            self._add_messages_middleware(request)
            
            response = views._handle_proforma_create_post(request)
            
            self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_unauthenticated(self) -> None:
        """Test proforma_to_invoice with unauthenticated user (lines 358-359)"""
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/convert/')
        request.user = AnonymousUser()
        
        response = views.proforma_to_invoice(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('users:login', response.url)

    def test_proforma_to_invoice_no_permission(self) -> None:
        """Test proforma_to_invoice with no permission to proforma customer"""
        # Create user without permission to proforma's customer
        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123'
        )
        
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/convert/')
        request.user = other_user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.proforma_to_invoice(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_already_converted(self) -> None:
        """Test proforma_to_invoice with already converted proforma"""
        # Mark proforma as already having an invoice
        self.proforma.invoice_id = self.invoice.id
        self.proforma.save()
        
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/convert/')
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.proforma_to_invoice(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(request))
        self.assertTrue(any('already converted' in str(m).lower() for m in messages))

    def test_process_proforma_payment_unauthenticated(self) -> None:
        """Test process_proforma_payment with unauthenticated user (lines 435-477)"""
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/pay/')
        request.user = AnonymousUser()
        
        response = views.process_proforma_payment(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)

    def test_process_proforma_payment_get_method(self) -> None:
        """Test process_proforma_payment with GET method (not POST)"""
        request = self.factory.get(f'/billing/proformas/{self.proforma.id}/pay/')
        request.user = self.user
        
        response = views.process_proforma_payment(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 405)  # Method not allowed

    def test_validate_customer_assignment_invalid_customer_id(self) -> None:
        """Test _validate_customer_assignment with invalid customer ID (line 502)"""
        result = views._validate_customer_assignment(self.user, 'invalid', None)
        
        customer, error_response = result
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)

    def test_validate_customer_assignment_customer_not_found(self) -> None:
        """Test _validate_customer_assignment with non-existent customer (line 509)"""
        result = views._validate_customer_assignment(self.user, '99999', None)
        
        customer, error_response = result
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_process_valid_until_date_invalid_date(self) -> None:
        """Test _process_valid_until_date with invalid date (lines 537-538)"""
        request_data = {'valid_until': 'invalid-date'}
        
        valid_until, errors = views._process_valid_until_date(request_data)
        
        self.assertTrue(errors)
        self.assertIn('invalid date format', ' '.join(errors).lower())

    @patch('apps.billing.views.RomanianProformaPDFGenerator')
    def test_proforma_pdf_generation_error(self, mock_generator_class: Mock) -> None:
        """Test proforma_pdf with PDF generation error (lines 643-673)"""
        mock_generator = Mock()
        mock_generator.generate_pdf.side_effect = Exception("PDF generation failed")
        mock_generator_class.return_value = mock_generator
        
        request = self.factory.get(f'/billing/proformas/{self.proforma.id}/pdf/')
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.proforma_pdf(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(request))
        self.assertTrue(any('error' in str(m).lower() for m in messages))

    def test_proforma_send_unauthenticated(self) -> None:
        """Test proforma_send with unauthenticated user (lines 742-753)"""
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/send/')
        request.user = AnonymousUser()
        
        response = views.proforma_send(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('users:login', response.url)

    @patch('apps.billing.views.send_mail')
    def test_proforma_send_email_success(self, mock_send_mail: Mock) -> None:
        """Test proforma_send successful email sending"""
        mock_send_mail.return_value = True
        
        request = self.factory.post(f'/billing/proformas/{self.proforma.id}/send/', {
            'recipient_email': 'customer@example.com',
            'subject': 'Your Proforma',
            'message': 'Please find attached your proforma.'
        })
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.proforma_send(request, self.proforma.id)
        
        self.assertEqual(response.status_code, 302)
        mock_send_mail.assert_called_once()

    def test_invoice_edit_unauthenticated(self) -> None:
        """Test invoice_edit with unauthenticated user (lines 761-782)"""
        request = self.factory.get(f'/billing/invoices/{self.invoice.id}/edit/')
        request.user = AnonymousUser()
        
        response = views.invoice_edit(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_pdf_unauthenticated(self) -> None:
        """Test invoice_pdf with unauthenticated user (line 795)"""
        request = self.factory.get(f'/billing/invoices/{self.invoice.id}/pdf/')
        request.user = AnonymousUser()
        
        response = views.invoice_pdf(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_send_unauthenticated(self) -> None:
        """Test invoice_send with unauthenticated user (lines 807-822)"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/send/')
        request.user = AnonymousUser()
        
        response = views.invoice_send(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('users:login', response.url)

    @patch('apps.billing.views.send_mail')
    def test_invoice_send_email_success(self, mock_send_mail: Mock) -> None:
        """Test invoice_send successful email sending"""
        mock_send_mail.return_value = True
        
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/send/', {
            'recipient_email': 'customer@example.com',
            'subject': 'Your Invoice',
            'message': 'Please find attached your invoice.'
        })
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.invoice_send(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)
        mock_send_mail.assert_called_once()

    def test_generate_e_factura_unauthenticated(self) -> None:
        """Test generate_e_factura with unauthenticated user (lines 830-853)"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/e-factura/')
        request.user = AnonymousUser()
        
        response = views.generate_e_factura(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)

    def test_generate_e_factura_not_implemented(self) -> None:
        """Test generate_e_factura returns not implemented message"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/e-factura/')
        request.user = self.user
        self._add_session_middleware(request)
        self._add_messages_middleware(request)
        
        response = views.generate_e_factura(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(request))
        self.assertTrue(any('not implemented' in str(m).lower() for m in messages))

    def test_payment_list_unauthenticated(self) -> None:
        """Test payment_list with unauthenticated user (line 863)"""
        request = self.factory.get('/billing/payments/')
        request.user = AnonymousUser()
        
        response = views.payment_list(request)
        
        self.assertEqual(response.status_code, 302)

    def test_process_payment_unauthenticated(self) -> None:
        """Test process_payment with unauthenticated user (line 880)"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/pay/')
        request.user = AnonymousUser()
        
        response = views.process_payment(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)

    def test_process_payment_get_method(self) -> None:
        """Test process_payment with GET method (not POST) (line 892)"""
        request = self.factory.get(f'/billing/invoices/{self.invoice.id}/pay/')
        request.user = self.user
        
        response = views.process_payment(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 405)  # Method not allowed

    def test_billing_reports_unauthenticated(self) -> None:
        """Test billing_reports with unauthenticated user (line 928)"""
        request = self.factory.get('/billing/reports/')
        request.user = AnonymousUser()
        
        response = views.billing_reports(request)
        
        self.assertEqual(response.status_code, 302)

    def test_vat_report_unauthenticated(self) -> None:
        """Test vat_report with unauthenticated user (line 961)"""
        request = self.factory.get('/billing/reports/vat/')
        request.user = AnonymousUser()
        
        response = views.vat_report(request)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_refund_unauthenticated(self) -> None:
        """Test invoice_refund with unauthenticated user (lines 995-1074)"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/refund/')
        request.user = AnonymousUser()
        
        response = views.invoice_refund(request, uuid.uuid4())
        
        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertFalse(data['success'])
        self.assertIn('permission', data['error'].lower())

    def test_invoice_refund_not_post_method(self) -> None:
        """Test invoice_refund with non-POST method"""
        request = self.factory.get(f'/billing/invoices/{self.invoice.id}/refund/')
        request.user = self.user
        
        response = views.invoice_refund(request, uuid.uuid4())
        
        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertFalse(data['success'])

    def test_invoice_refund_invalid_uuid(self) -> None:
        """Test invoice_refund with invalid UUID format"""
        request = self.factory.post('/billing/invoices/invalid-uuid/refund/')
        request.user = self.user
        
        # This will be caught by URL routing, but test the view directly
        response = views.invoice_refund(request, uuid.uuid4())  # Valid UUID but non-existent
        
        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertFalse(data['success'])

    @patch('apps.billing.services.RefundService.refund_invoice')
    def test_invoice_refund_service_error(self, mock_refund: Mock) -> None:
        """Test invoice_refund when refund service returns error"""
        from apps.common.types import Err
        
        mock_refund.return_value = Err("Refund failed")
        
        # Convert Invoice ID to UUID format for testing
        invoice_uuid = uuid.uuid4()
        with patch('apps.billing.models.Invoice.objects.get') as mock_get:
            mock_get.return_value = self.invoice
            
            request = self.factory.post(f'/billing/invoices/{invoice_uuid}/refund/', {
                'refund_type': 'full',
                'reason': 'customer_request',
                'notes': 'Test refund'
            })
            request.user = self.user
            
            response = views.invoice_refund(request, invoice_uuid)
            
            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertFalse(data['success'])
            self.assertEqual(data['error'], "Refund failed")

    def test_invoice_refund_request_unauthenticated(self) -> None:
        """Test invoice_refund_request with unauthenticated user"""
        request = self.factory.post(f'/billing/invoices/{self.invoice.id}/refund-request/')
        request.user = AnonymousUser()
        
        response = views.invoice_refund_request(request, uuid.uuid4())
        
        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertFalse(data['success'])

    def test_invoice_refund_request_unpaid_invoice(self) -> None:
        """Test invoice_refund_request for unpaid invoice"""
        # Create unpaid invoice
        self.invoice.status = 'issued'
        self.invoice.save()
        
        # Convert to UUID for the view
        invoice_uuid = uuid.uuid4()
        with patch('apps.billing.models.Invoice.objects.get') as mock_get:
            mock_get.return_value = self.invoice
            
            request = self.factory.post(f'/billing/invoices/{invoice_uuid}/refund-request/', {
                'refund_reason': 'customer_request',
                'refund_notes': 'Want to cancel service'
            })
            request.user = self.user
            
            response = views.invoice_refund_request(request, invoice_uuid)
            
            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertFalse(data['success'])
            self.assertIn('paid invoices', data['error'])

    def test_invoice_refund_request_missing_fields(self) -> None:
        """Test invoice_refund_request with missing required fields"""
        # Mark invoice as paid
        self.invoice.status = 'paid'
        self.invoice.save()
        
        invoice_uuid = uuid.uuid4()
        with patch('apps.billing.models.Invoice.objects.get') as mock_get:
            mock_get.return_value = self.invoice
            
            request = self.factory.post(f'/billing/invoices/{invoice_uuid}/refund-request/', {
                'refund_reason': '',  # Missing reason
                'refund_notes': ''    # Missing notes
            })
            request.user = self.user
            
            response = views.invoice_refund_request(request, invoice_uuid)
            
            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertFalse(data['success'])
            self.assertIn('required', data['error'])


class HelperFunctionsCoverageTestCase(TestCase):
    """Test coverage for helper functions that might be missed"""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.currency = Currency.objects.create(
            code='RON',
            symbol='RON',
            decimals=2
        )
        self.customer = Customer.objects.create(
            name='Test SRL',
            customer_type='company',
            status='active'
        )

    def test_get_accessible_customer_ids_with_none_user(self) -> None:
        """Test _get_accessible_customer_ids with None user - should not happen but test edge case"""
        # This shouldn't happen in normal flow, but test defensive programming
        with patch('apps.users.models.User.get_accessible_customers') as mock_get:
            mock_get.return_value = None
            
            result = views._get_accessible_customer_ids(self.user)
            
            self.assertEqual(result, [])

    def test_get_accessible_customer_ids_with_list(self) -> None:
        """Test _get_accessible_customer_ids when returning a list instead of QuerySet"""
        with patch.object(self.user, 'get_accessible_customers') as mock_get:
            mock_get.return_value = [self.customer]
            
            result = views._get_accessible_customer_ids(self.user)
            
            self.assertEqual(result, [self.customer.id])

    def test_validate_pdf_access_unauthorized_user(self) -> None:
        """Test _validate_pdf_access with user who can't access document"""
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.user
        
        # Mock user.can_access_customer to return False
        with patch.object(self.user, 'can_access_customer') as mock_access:
            mock_access.return_value = False
            
            # Add messages framework
            from django.contrib.messages.middleware import MessageMiddleware
            from django.contrib.sessions.middleware import SessionMiddleware
            
            middleware = SessionMiddleware(lambda x: None)
            middleware.process_request(request)
            request.session.save()
            
            msg_middleware = MessageMiddleware(lambda x: None)
            msg_middleware.process_request(request)
            
            # Create a mock document
            mock_document = Mock()
            mock_document.customer = self.customer
            
            response = views._validate_pdf_access(request, mock_document)
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 302)

    def test_validate_pdf_access_authorized_user(self) -> None:
        """Test _validate_pdf_access with authorized user"""
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.user
        
        # Mock user.can_access_customer to return True
        with patch.object(self.user, 'can_access_customer') as mock_access:
            mock_access.return_value = True
            
            mock_document = Mock()
            mock_document.customer = self.customer
            
            response = views._validate_pdf_access(request, mock_document)
            
            self.assertIsNone(response)  # No redirect, access granted
