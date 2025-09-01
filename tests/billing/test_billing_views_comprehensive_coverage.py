# ===============================================================================
# COMPREHENSIVE BILLING VIEWS TEST SUITE - COVERAGE FOCUSED
# ===============================================================================
"""
Comprehensive test suite for billing views targeting 85%+ coverage.
Focuses on all uncovered paths, error conditions, and edge cases.

Priority Areas from Coverage Analysis:
- views.py: 12.28% → 85%+ (PRIMARY TARGET)
- Critical functions: invoice_pdf, invoice_send, proforma_send, payment processing
- Error handling paths, authentication, authorization edge cases
"""

from __future__ import annotations

import json
import uuid
from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.db.models import QuerySet
from django.http import HttpRequest, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse
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
from apps.billing.views import (
    _create_proforma_with_sequence,
    _get_accessible_customer_ids,
    _get_customers_for_edit_form,
    _handle_proforma_create_post,
    _handle_proforma_edit_post,
    _parse_line_quantity,
    _parse_line_unit_price,
    _parse_line_vat_rate,
    _process_proforma_line_items,
    _process_valid_until_date,
    _update_proforma_basic_info,
    _validate_customer_assignment,
    _validate_financial_document_access,
    _validate_proforma_edit_access,
    billing_list,
    billing_reports,
    generate_e_factura,
    invoice_detail,
    invoice_edit,
    invoice_pdf,
    invoice_refund,
    invoice_refund_request,
    invoice_send,
    payment_list,
    process_payment,
    process_proforma_payment,
    proforma_create,
    proforma_detail,
    proforma_edit,
    proforma_pdf,
    proforma_send,
    proforma_to_invoice,
    vat_report,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

UserModel = get_user_model()


class BillingViewsComprehensiveCoverageTestCase(TestCase):
    """
    Comprehensive test suite targeting 85%+ coverage for billing views.
    Organized by function with focus on uncovered lines and edge cases.
    """

    def setUp(self) -> None:
        """Set up test data with proper relationships and authentication."""
        self.factory = RequestFactory()
        self.client = Client()
        
        # Create Currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )
        
        # Create sequences - start at higher value to avoid conflicts with test data
        self.invoice_seq, _ = InvoiceSequence.objects.get_or_create(
            scope='default',
            defaults={'last_value': 1}  # Start at 1 so next number is INV-000002
        )
        self.proforma_seq, _ = ProformaSequence.objects.get_or_create(
            scope='default',
            defaults={'last_value': 0}
        )
        
        # Create test users
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True,
            staff_role='admin'
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='testpass123',
            is_staff=False
        )
        
        # Create test customer
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='customer@test.com',
            status='active'
        )
        
        # Create customer membership for access control
        CustomerMembership.objects.create(
            user=self.staff_user,
            customer=self.customer,
            role='owner'
        )
        
        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role='member'
        )
        
        # Create test invoice and proforma
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.currency,
            status='issued',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            bill_to_name=self.customer.name,
            bill_to_email=self.customer.primary_email,
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30)
        )
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-000001',
            currency=self.currency,
            subtotal_cents=5000,
            tax_cents=950,
            total_cents=5950,
            bill_to_name=self.customer.name,
            bill_to_email=self.customer.primary_email,
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )

    def _add_session_and_messages(self, request: HttpRequest) -> None:
        """Add session and message middleware to request for testing."""
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()
        MessageMiddleware(lambda r: None).process_request(request)

    # ===============================================================================
    # HELPER FUNCTION TESTS - HIGH PRIORITY MISSING COVERAGE
    # ===============================================================================

    def test_get_accessible_customer_ids_with_queryset(self) -> None:
        """Test _get_accessible_customer_ids with QuerySet return (Line 51-52)."""
        # Mock get_accessible_customers returning QuerySet
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_method:
            mock_queryset = Mock(spec=QuerySet)
            mock_queryset.values_list.return_value = [1, 2, 3]
            mock_method.return_value = mock_queryset
            
            result = _get_accessible_customer_ids(self.staff_user)
            
            self.assertEqual(result, [1, 2, 3])
            mock_queryset.values_list.assert_called_once_with('id', flat=True)

    def test_get_accessible_customer_ids_with_list(self) -> None:
        """Test _get_accessible_customer_ids with list return (Line 54)."""
        # Mock get_accessible_customers returning list of objects
        mock_customer1 = Mock()
        mock_customer1.id = 10
        mock_customer2 = Mock()
        mock_customer2.id = 20
        
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_method:
            mock_method.return_value = [mock_customer1, mock_customer2]
            
            result = _get_accessible_customer_ids(self.staff_user)
            
            self.assertEqual(result, [10, 20])

    def test_get_accessible_customer_ids_with_empty_list(self) -> None:
        """Test _get_accessible_customer_ids with empty return (Line 54)."""
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_method:
            mock_method.return_value = []
            
            result = _get_accessible_customer_ids(self.staff_user)
            
            self.assertEqual(result, [])

    def test_validate_financial_document_access_unauthorized_user_type(self) -> None:
        """Test _validate_financial_document_access with wrong user type (Line 63)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()  # Proper anonymous user
        self._add_session_and_messages(request)
        
        response = _validate_financial_document_access(request, self.invoice)
        
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 302)

    def test_validate_financial_document_access_no_permission(self) -> None:
        """Test _validate_financial_document_access with no access to customer (Line 63-65)."""
        # Create user with no access to customer
        unauthorized_user = User.objects.create_user(
            email='unauthorized@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = _validate_financial_document_access(request, self.invoice)
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 302)

    def test_validate_financial_document_access_granted(self) -> None:
        """Test _validate_financial_document_access with valid access (Line 66)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = _validate_financial_document_access(request, self.invoice)
            
            self.assertIsNone(response)

    # ===============================================================================
    # BILLING LIST VIEW TESTS - MISSING ERROR HANDLING
    # ===============================================================================

    def test_billing_list_unauthenticated_user_type(self) -> None:
        """Test billing_list with unauthenticated user (Line 75-76)."""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 302)

    def test_billing_list_database_exception(self) -> None:
        """Test billing_list with database exception (Line 188-211)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        # Mock _get_accessible_customer_ids to raise exception
        with patch('apps.billing.views._get_accessible_customer_ids', side_effect=Exception("DB Error")) as mock_func:
            response = billing_list(request)
            
            # Verify the mock was actually called
            mock_func.assert_called_once()
            
            # Should render with error message displayed via Django messages
            self.assertEqual(response.status_code, 200)
            # Check that error message is in the rendered content as a Django message
            response_content = response.content.decode()
            self.assertIn('Unable to load billing data', response_content)

    def test_billing_list_with_document_type_filter(self) -> None:
        """Test billing_list with document type filtering (Line 83, 110-147)."""
        request = self.factory.get('/?type=proforma')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch('apps.billing.views._get_accessible_customer_ids', return_value=[self.customer.id]):
            response = billing_list(request)
            
            self.assertEqual(response.status_code, 200)
            # Check that proforma filter is active in the rendered content
            response_content = response.content.decode()
            self.assertIn('type=proforma', response_content)

    def test_billing_list_with_search_query(self) -> None:
        """Test billing_list with search functionality (Line 94-102)."""
        request = self.factory.get('/?search=PRO-000001')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch('apps.billing.views._get_accessible_customer_ids', return_value=[self.customer.id]):
            response = billing_list(request)
            
            self.assertEqual(response.status_code, 200)
            # Check that search functionality is present in rendered content
            response_content = response.content.decode()
            self.assertIn('search=PRO-000001', response_content)

    # ===============================================================================
    # INVOICE DETAIL VIEW TESTS
    # ===============================================================================

    def test_invoice_detail_unauthenticated_user_type(self) -> None:
        """Test invoice_detail with wrong user type (Line 222-224)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = invoice_detail(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_detail_no_permission(self) -> None:
        """Test invoice_detail without customer access (Line 222-224)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized2@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = invoice_detail(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA CREATE VIEW TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_create_proforma_with_sequence_success(self) -> None:
        """Test _create_proforma_with_sequence function (Line 242-258)."""
        valid_until = timezone.now() + timezone.timedelta(days=30)
        
        with patch('apps.billing.models.ProformaSequence.objects.get_or_create') as mock_seq:
            mock_sequence = Mock()
            mock_sequence.get_next_number.return_value = 'PRO-000002'
            mock_seq.return_value = (mock_sequence, True)
            
            proforma = _create_proforma_with_sequence(self.customer, valid_until)
            
            self.assertEqual(proforma.customer, self.customer)
            self.assertEqual(proforma.number, 'PRO-000002')
            self.assertEqual(proforma.currency, self.currency)

    def test_handle_proforma_create_post_unauthenticated_user_type(self) -> None:
        """Test _handle_proforma_create_post with wrong user type (Line 264-265)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)

    def test_handle_proforma_create_post_invalid_customer(self) -> None:
        """Test _handle_proforma_create_post with validation error (Line 269-271)."""
        request = self.factory.post('/', {'customer': 'invalid'})
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)

    def test_handle_proforma_create_post_customer_none_after_validation(self) -> None:
        """Test _handle_proforma_create_post with customer None (Line 278-280)."""
        request = self.factory.post('/', {'customer': str(self.customer.id)})
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        # Mock validation to return None customer
        with patch('apps.billing.views._validate_customer_assignment', return_value=(None, None)):
            response = _handle_proforma_create_post(request)
            
            self.assertEqual(response.status_code, 302)

    def test_handle_proforma_create_post_creation_exception(self) -> None:
        """Test _handle_proforma_create_post with creation exception (Line 282-284)."""
        request = self.factory.post('/', {'customer': str(self.customer.id)})
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch('apps.billing.views._validate_customer_assignment', return_value=(self.customer, None)):
            with patch('apps.billing.views._create_proforma_with_sequence', side_effect=Exception("Creation failed")):
                response = _handle_proforma_create_post(request)
                
                self.assertEqual(response.status_code, 302)

    def test_proforma_create_get_unauthenticated_user_type(self) -> None:
        """Test proforma_create GET with wrong user type (Line 311-312)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = proforma_create(request)
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA DETAIL VIEW TESTS
    # ===============================================================================

    def test_proforma_detail_unauthenticated_user_type(self) -> None:
        """Test proforma_detail with wrong user type (Line 331-333)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = proforma_detail(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_detail_no_permission(self) -> None:
        """Test proforma_detail without customer access (Line 331-333)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized3@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = proforma_detail(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA TO INVOICE CONVERSION TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_proforma_to_invoice_unauthenticated_user_type(self) -> None:
        """Test proforma_to_invoice with wrong user type (Line 357-360)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_no_permission(self) -> None:
        """Test proforma_to_invoice without customer access (Line 357-360)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized4@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_expired_proforma(self) -> None:
        """Test proforma_to_invoice with expired proforma (Line 363-365)."""
        # Make proforma expired
        self.proforma.valid_until = timezone.now() - timezone.timedelta(days=1)
        self.proforma.save()
        
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_already_converted(self) -> None:
        """Test proforma_to_invoice with already converted proforma (Line 368-371)."""
        # Create existing invoice linked to proforma
        Invoice.objects.create(
            customer=self.customer,
            number='INV-000002',
            currency=self.currency,
            status='issued',
            total_cents=5950,
            converted_from_proforma=self.proforma
        )
        
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_post_success(self) -> None:
        """Test proforma_to_invoice POST success path (Line 373-421)."""
        # Create proforma lines
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.19'),
            line_total_cents=5950
        )
        
        request = self.factory.post('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            # Verify invoice was created
            self.assertTrue(Invoice.objects.filter(converted_from_proforma=self.proforma).exists())

    # ===============================================================================
    # PROCESS PROFORMA PAYMENT TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_process_proforma_payment_unauthenticated_user_type(self) -> None:
        """Test process_proforma_payment with wrong user type (Line 439-440)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)  # @billing_staff_required decorator redirects to login

    def test_process_proforma_payment_no_permission(self) -> None:
        """Test process_proforma_payment without customer access (Line 439-440)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized5@example.com',
            password='testpass123'
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = process_proforma_payment(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)  # Redirect from @billing_staff_required decorator

    def test_process_proforma_payment_success(self) -> None:
        """Test process_proforma_payment successful processing (Line 442-476)."""
        request = self.factory.post('/', {
            'amount': '59.50',
            'payment_method': 'bank_transfer'
        })
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            # The view creates invoice directly, so just call it
            response = process_proforma_payment(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.content)
            self.assertTrue(response_data['success'])
            
            # Verify an invoice was created from the proforma
            invoice = Invoice.objects.filter(converted_from_proforma=self.proforma).first()
            self.assertIsNotNone(invoice)

    def test_process_proforma_payment_conversion_failed(self) -> None:
        """Test process_proforma_payment when conversion fails (Line 475-476)."""
        request = self.factory.post('/', {
            'amount': '59.50',
            'payment_method': 'bank_transfer'
        })
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            # Mock Invoice.objects.create to raise an exception during conversion
            with patch('apps.billing.models.Invoice.objects.create', side_effect=Exception("Database error")):
                # The view doesn't currently have exception handling, so expect the exception to be raised
                with self.assertRaises(Exception) as context:
                    process_proforma_payment(request, self.proforma.pk)
                
                self.assertEqual(str(context.exception), "Database error")

    def test_process_proforma_payment_get_method(self) -> None:
        """Test process_proforma_payment with GET method (Line 478)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        
        response = process_proforma_payment(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # VALIDATION HELPER FUNCTIONS TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_validate_customer_assignment_no_customer_id(self) -> None:
        """Test _validate_customer_assignment with no customer ID (Line 496-497)."""
        customer, error_response = _validate_customer_assignment(self.staff_user, None, None)
        
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)

    def test_validate_customer_assignment_invalid_customer_id(self) -> None:
        """Test _validate_customer_assignment with invalid customer ID (Line 500-505)."""
        customer, error_response = _validate_customer_assignment(
            self.staff_user, 'invalid_id', self.proforma.pk
        )
        
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)

    def test_validate_customer_assignment_customer_not_found(self) -> None:
        """Test _validate_customer_assignment with non-existent customer (Line 500-505)."""
        customer, error_response = _validate_customer_assignment(
            self.staff_user, '99999', None
        )
        
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)

    def test_validate_customer_assignment_no_access(self) -> None:
        """Test _validate_customer_assignment without access (Line 508-512)."""
        with patch('apps.billing.views._get_accessible_customer_ids', return_value=[]):
            customer, error_response = _validate_customer_assignment(
                self.staff_user, str(self.customer.id), None
            )
            
            self.assertIsNone(customer)
            self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_success(self) -> None:
        """Test _validate_customer_assignment with valid data (Line 514)."""
        with patch('apps.billing.views._get_accessible_customer_ids', return_value=[self.customer.id]):
            customer, error_response = _validate_customer_assignment(
                self.staff_user, str(self.customer.id), None
            )
            
            self.assertEqual(customer, self.customer)
            self.assertIsNone(error_response)

    # ===============================================================================
    # PROFORMA UPDATE/EDIT FUNCTIONS TESTS
    # ===============================================================================

    def test_update_proforma_basic_info(self) -> None:
        """Test _update_proforma_basic_info function (Line 518-530)."""
        request_data = {
            'bill_to_name': 'Updated Name',
            'bill_to_email': 'updated@example.com',
            'bill_to_tax_id': 'RO12345678'
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        self.assertEqual(self.proforma.bill_to_name, 'Updated Name')
        self.assertEqual(self.proforma.bill_to_email, 'updated@example.com')
        self.assertEqual(self.proforma.bill_to_tax_id, 'RO12345678')

    def test_update_proforma_basic_info_empty_values(self) -> None:
        """Test _update_proforma_basic_info with empty values (Line 520, 524, 528)."""
        original_name = self.proforma.bill_to_name
        request_data = {
            'bill_to_name': '',
            'bill_to_email': '  ',
            'bill_to_tax_id': None
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        # Values should not change for empty inputs
        self.assertEqual(self.proforma.bill_to_name, original_name)

    def test_process_valid_until_date_none_data(self) -> None:
        """Test _process_valid_until_date with None data (Line 537-539)."""
        valid_until, errors = _process_valid_until_date(None)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_process_valid_until_date_invalid_format(self) -> None:
        """Test _process_valid_until_date with invalid date format (Line 548-551)."""
        request_data = {'valid_until': 'invalid-date'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid date format', errors[0])

    def test_process_valid_until_date_empty_string(self) -> None:
        """Test _process_valid_until_date with empty date string (Line 552-554)."""
        request_data = {'valid_until': ''}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_process_valid_until_date_valid_format(self) -> None:
        """Test _process_valid_until_date with valid date format (Line 544-547)."""
        request_data = {'valid_until': '2024-12-31'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)
        self.assertEqual(valid_until.date().year, 2024)
        self.assertEqual(valid_until.date().month, 12)
        self.assertEqual(valid_until.date().day, 31)

    # ===============================================================================
    # LINE ITEM PROCESSING TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_parse_line_quantity_invalid_value(self) -> None:
        """Test _parse_line_quantity with invalid value (Line 611-613)."""
        request_data = {'line_0_quantity': 'invalid'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('0'))
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid quantity', errors[0])

    def test_parse_line_quantity_valid_value(self) -> None:
        """Test _parse_line_quantity with valid value (Line 609-610)."""
        request_data = {'line_0_quantity': '5.50'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('5.50'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_unit_price_invalid_value(self) -> None:
        """Test _parse_line_unit_price with invalid value (Line 623-625)."""
        request_data = {'line_0_unit_price': 'invalid'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('0'))
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid unit price', errors[0])

    def test_parse_line_unit_price_valid_value(self) -> None:
        """Test _parse_line_unit_price with valid value (Line 621-622)."""
        request_data = {'line_0_unit_price': '100.00'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('100.00'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_invalid_value(self) -> None:
        """Test _parse_line_vat_rate with invalid value (Line 635-637)."""
        request_data = {'line_0_vat_rate': 'invalid'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid VAT rate', errors[0])

    def test_parse_line_vat_rate_valid_value(self) -> None:
        """Test _parse_line_vat_rate with valid value (Line 633-634)."""
        request_data = {'line_0_vat_rate': '10.0'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('10.0'))
        self.assertEqual(len(errors), 0)

    def test_process_proforma_line_items(self) -> None:
        """Test _process_proforma_line_items function (Line 559-602)."""
        request_data = {
            'line_0_description': 'Test Service',
            'line_0_quantity': '2',
            'line_0_unit_price': '50.00',
            'line_0_vat_rate': '19',
            'line_1_description': 'Another Service',
            'line_1_quantity': '1',
            'line_1_unit_price': '30.00',
            'line_1_vat_rate': '19'
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        self.assertEqual(len(errors), 0)
        self.assertEqual(self.proforma.lines.count(), 2)
        # Function updates totals in memory but doesn't save - save explicitly for testing
        self.proforma.save()
        self.proforma.refresh_from_db()
        # Total should be: (2*50.00 + 1*30.00) * 1.19 = 154.70
        self.assertEqual(self.proforma.total_cents, 15470)

    # ===============================================================================
    # PDF GENERATION TESTS - HIGH PRIORITY MISSING COVERAGE
    # ===============================================================================

    def test_invoice_pdf_generation(self) -> None:
        """Test invoice_pdf function (Line 787-800)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.RomanianInvoicePDFGenerator') as mock_generator:
                mock_pdf = Mock()
                mock_pdf.generate_response.return_value = Mock(status_code=200)
                mock_generator.return_value = mock_pdf
                
                response = invoice_pdf(request, self.invoice.pk)
                
                mock_generator.assert_called_once_with(self.invoice)
                mock_pdf.generate_response.assert_called_once()
                # The response should be the mocked PDF response
                self.assertEqual(response.status_code, 200)

    def test_proforma_pdf_generation(self) -> None:
        """Test proforma_pdf function (Line 722-735)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.RomanianProformaPDFGenerator') as mock_generator:
                mock_pdf = Mock()
                mock_pdf.generate_response.return_value = Mock(status_code=200)
                mock_generator.return_value = mock_pdf
                
                response = proforma_pdf(request, self.proforma.pk)
                
                mock_generator.assert_called_once_with(self.proforma)
                mock_pdf.generate_response.assert_called_once()
                # The response should be the mocked PDF response
                self.assertEqual(response.status_code, 200)

    # ===============================================================================
    # EMAIL SENDING TESTS - HIGH PRIORITY MISSING COVERAGE
    # ===============================================================================

    def test_proforma_send_unauthenticated_user_type(self) -> None:
        """Test proforma_send with wrong user type (Line 746-747)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = proforma_send(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)  # @billing_staff_required decorator redirects to login

    def test_proforma_send_no_permission(self) -> None:
        """Test proforma_send without customer access (Line 746-747)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized6@example.com',
            password='testpass123'
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = proforma_send(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)  # Redirect from @billing_staff_required decorator

    def test_proforma_send_success(self) -> None:
        """Test proforma_send successful email sending (Line 749-752)."""
        request = self.factory.post('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = proforma_send(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.content)
            self.assertTrue(response_data['success'])

    def test_proforma_send_get_method(self) -> None:
        """Test proforma_send with GET method (Line 754)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        response = proforma_send(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 405)

    def test_invoice_send_unauthenticated_user_type(self) -> None:
        """Test invoice_send with wrong user type (Line 811-812)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = invoice_send(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)  # login_required redirects

    def test_invoice_send_no_permission(self) -> None:
        """Test invoice_send without customer access (Line 811-812)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized7@example.com',
            password='testpass123'
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = invoice_send(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)  # Redirect from @billing_staff_required decorator

    def test_invoice_send_success(self) -> None:
        """Test invoice_send successful email sending (Line 814-821)."""
        request = self.factory.post('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_send(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.content)
            self.assertTrue(response_data['success'])
            
            # Verify invoice was marked as sent
            self.invoice.refresh_from_db()
            self.assertIsNotNone(self.invoice.sent_at)

    def test_invoice_send_get_method(self) -> None:
        """Test invoice_send with GET method (Line 823)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        response = invoice_send(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # E-FACTURA GENERATION TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_generate_e_factura_unauthenticated_user_type(self) -> None:
        """Test generate_e_factura with wrong user type (Line 834-836)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = generate_e_factura(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_generate_e_factura_no_permission(self) -> None:
        """Test generate_e_factura without customer access (Line 834-836)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized8@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = generate_e_factura(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_generate_e_factura_success(self) -> None:
        """Test generate_e_factura successful XML generation (Line 841-854)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = generate_e_factura(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response['Content-Type'], 'application/xml')
            self.assertIn('e_factura_INV-000001.xml', response['Content-Disposition'])

    # ===============================================================================
    # PAYMENT PROCESSING TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_payment_list_unauthenticated_user_type(self) -> None:
        """Test payment_list with wrong user type (Line 863-864)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = payment_list(request)
        
        self.assertEqual(response.status_code, 302)

    def test_process_payment_unauthenticated_user_type(self) -> None:
        """Test process_payment with wrong user type (Line 892-893)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = process_payment(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)  # @billing_staff_required decorator redirects to login

    def test_process_payment_no_permission(self) -> None:
        """Test process_payment without customer access (Line 892-893)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized9@example.com',
            password='testpass123'
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = process_payment(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)  # Redirect from @billing_staff_required decorator

    def test_process_payment_success_partial(self) -> None:
        """Test process_payment with partial payment (Line 895-917)."""
        request = self.factory.post('/', {
            'amount': '50.00',
            'payment_method': 'stripe'
        })
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch.object(self.invoice, 'get_remaining_amount', return_value=Decimal('69.50')):
                response = process_payment(request, self.invoice.pk)
                
                self.assertEqual(response.status_code, 200)
                response_data = json.loads(response.content)
                self.assertTrue(response_data['success'])
                
                # Verify payment was created
                payment = Payment.objects.filter(invoice=self.invoice).first()
                self.assertIsNotNone(payment)
                self.assertEqual(payment.amount_cents, 5000)
                self.assertEqual(payment.payment_method, 'stripe')

    def test_process_payment_success_full(self) -> None:
        """Test process_payment with full payment (Line 911-914)."""
        request = self.factory.post('/', {
            'amount': '119.00',
            'payment_method': 'bank'
        })
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch.object(self.invoice, 'get_remaining_amount', return_value=Decimal('0')):
                response = process_payment(request, self.invoice.pk)
                
                self.assertEqual(response.status_code, 200)
                
                # Verify invoice marked as paid
                self.invoice.refresh_from_db()
                self.assertEqual(self.invoice.status, 'paid')
                self.assertIsNotNone(self.invoice.paid_at)

    def test_process_payment_get_method(self) -> None:
        """Test process_payment with GET method (Line 919)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        response = process_payment(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # REPORTING VIEWS TESTS - HIGH PRIORITY
    # ===============================================================================

    def test_billing_reports_unauthenticated_user_type(self) -> None:
        """Test billing_reports with wrong user type (Line 928-929)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = billing_reports(request)
        
        self.assertEqual(response.status_code, 302)

    def test_vat_report_unauthenticated_user_type(self) -> None:
        """Test vat_report with wrong user type (Line 961-962)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = vat_report(request)
        
        self.assertEqual(response.status_code, 302)

    def test_vat_report_with_date_params(self) -> None:
        """Test vat_report with date parameters (Line 967-968)."""
        self.client.force_login(self.staff_user)
        
        with patch('apps.billing.views._get_accessible_customer_ids', return_value=[self.customer.id]):
            response = self.client.get('/app/billing/reports/vat/?start_date=2024-01-01&end_date=2024-12-31')
            
            self.assertEqual(response.status_code, 200)
            self.assertIn('start_date', response.context)
            self.assertIn('end_date', response.context)

    # ===============================================================================
    # INVOICE REFUND TESTS - HIGH PRIORITY COMPLEX LOGIC
    # ===============================================================================

    def test_invoice_refund_unauthenticated_user_type(self) -> None:
        """Test invoice_refund with wrong user type (Line 1011-1012)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = invoice_refund(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)  # @staff_required decorator redirects to login

    def test_invoice_refund_no_permission(self) -> None:
        """Test invoice_refund without customer access (Line 1011-1012)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized10@example.com',
            password='testpass123',
            is_staff=True  # Must be staff to pass @staff_required decorator
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = invoice_refund(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_missing_fields(self) -> None:
        """Test invoice_refund with missing required fields (Line 1022-1023)."""
        request = self.factory.post('/', {})
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_refund(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_invalid_reason(self) -> None:
        """Test invoice_refund with invalid refund reason (Line 1031-1032)."""
        request = self.factory.post('/', {
            'refund_type': 'full',
            'refund_reason': 'invalid_reason',
            'refund_notes': 'Test refund'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_refund(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_invalid_amount(self) -> None:
        """Test invoice_refund with invalid partial amount (Line 1042-1043)."""
        request = self.factory.post('/', {
            'refund_type': 'partial',
            'refund_reason': 'customer_request',
            'refund_notes': 'Test refund',
            'refund_amount': 'invalid'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_refund(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_zero_amount(self) -> None:
        """Test invoice_refund with zero partial amount (Line 1039-1040)."""
        request = self.factory.post('/', {
            'refund_type': 'partial',
            'refund_reason': 'customer_request',
            'refund_notes': 'Test refund',
            'refund_amount': '0'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_refund(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_success(self) -> None:
        """Test invoice_refund successful processing (Line 1056-1065)."""
        request = self.factory.post('/', {
            'refund_type': 'full',
            'refund_reason': 'customer_request',
            'refund_notes': 'Full refund requested',
            'process_payment_refund': 'false'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.RefundService.refund_invoice') as mock_refund:
                mock_result = Mock()
                mock_result.is_ok.return_value = True
                mock_result.unwrap.return_value = {'refund_id': uuid.uuid4()}
                mock_refund.return_value = mock_result
                
                response = invoice_refund(request, self.invoice.id)
                
                self.assertEqual(response.status_code, 200)
                response_data = json.loads(response.content)
                self.assertTrue(response_data['success'])

    def test_invoice_refund_service_error(self) -> None:
        """Test invoice_refund with service error (Line 1067-1071)."""
        request = self.factory.post('/', {
            'refund_type': 'full',
            'refund_reason': 'customer_request',
            'refund_notes': 'Full refund requested'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.RefundService.refund_invoice') as mock_refund:
                mock_result = Mock()
                mock_result.is_ok.return_value = False
                mock_result.error = "Refund failed"
                mock_refund.return_value = mock_result
                
                response = invoice_refund(request, self.invoice.id)
                
                self.assertEqual(response.status_code, 400)  # json_error returns 400
                response_data = json.loads(response.content)
                self.assertFalse(response_data['success'])

    def test_invoice_refund_unexpected_exception(self) -> None:
        """Test invoice_refund with unexpected exception (Line 1073-1075)."""
        request = self.factory.post('/', {
            'refund_type': 'full',
            'refund_reason': 'customer_request',
            'refund_notes': 'Full refund requested'
        })
        request.user = self.staff_user
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.RefundService.refund_invoice', side_effect=Exception("Unexpected error")):
                response = invoice_refund(request, self.invoice.id)
                
                self.assertEqual(response.status_code, 400)  # json_error returns 400
                response_data = json.loads(response.content)
                self.assertFalse(response_data['success'])

    # ===============================================================================
    # INVOICE REFUND REQUEST TESTS - CUSTOMER FACING
    # ===============================================================================

    def test_invoice_refund_request_unauthenticated_user_type(self) -> None:
        """Test invoice_refund_request with wrong user type (Line 1094-1095)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = invoice_refund_request(request, self.invoice.id)
        
        self.assertEqual(response.status_code, 302)  # @login_required decorator redirects to login

    def test_invoice_refund_request_no_permission(self) -> None:
        """Test invoice_refund_request without customer access (Line 1094-1095)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized11@example.com',
            password='testpass123'
        )
        
        request = self.factory.post('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = invoice_refund_request(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_request_unpaid_invoice(self) -> None:
        """Test invoice_refund_request with unpaid invoice (Line 1098-1099)."""
        # Set invoice status to issued (not paid)
        self.invoice.status = 'issued'
        self.invoice.save()
        
        request = self.factory.post('/')
        request.user = self.regular_user
        self._add_session_and_messages(request)
        
        with patch.object(self.regular_user, 'can_access_customer', return_value=True):
            response = invoice_refund_request(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_request_missing_fields(self) -> None:
        """Test invoice_refund_request with missing fields (Line 1105-1106)."""
        # Set invoice as paid
        self.invoice.status = 'paid'
        self.invoice.save()
        
        request = self.factory.post('/', {})
        request.user = self.regular_user
        self._add_session_and_messages(request)
        
        with patch.object(self.regular_user, 'can_access_customer', return_value=True):
            response = invoice_refund_request(request, self.invoice.id)
            
            self.assertEqual(response.status_code, 400)  # json_error returns 400
            response_data = json.loads(response.content)
            self.assertFalse(response_data['success'])

    def test_invoice_refund_request_success(self) -> None:
        """Test invoice_refund_request successful ticket creation (Line 1137-1176)."""
        # Set invoice as paid
        self.invoice.status = 'paid'
        self.invoice.save()
        
        request = self.factory.post('/', {
            'refund_reason': 'service_failure',
            'refund_notes': 'Service did not work as expected'
        })
        request.user = self.regular_user
        
        with patch.object(self.regular_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.Ticket.objects.create') as mock_create:
                mock_ticket = Mock()
                mock_ticket.ticket_number = 'TICKET-001'
                mock_create.return_value = mock_ticket
                
                with patch('apps.billing.views.SupportCategory.objects.get_or_create') as mock_category:
                    mock_category.return_value = (Mock(), True)
                    
                    response = invoice_refund_request(request, self.invoice.id)
                    
                    self.assertEqual(response.status_code, 200)
                    response_data = json.loads(response.content)
                    self.assertTrue(response_data['success'])
                    self.assertEqual(response_data['data']['ticket_number'], 'TICKET-001')

    def test_invoice_refund_request_exception(self) -> None:
        """Test invoice_refund_request with unexpected exception (Line 1179-1181)."""
        # Set invoice as paid
        self.invoice.status = 'paid'
        self.invoice.save()
        
        request = self.factory.post('/', {
            'refund_reason': 'service_failure',
            'refund_notes': 'Service did not work as expected'
        })
        request.user = self.regular_user
        
        with patch.object(self.regular_user, 'can_access_customer', return_value=True):
            with patch('apps.billing.views.SupportCategory.objects.get_or_create', side_effect=Exception("DB Error")):
                response = invoice_refund_request(request, self.invoice.id)
                
                self.assertEqual(response.status_code, 400)  # json_error returns 400
                response_data = json.loads(response.content)
                self.assertFalse(response_data['success'])

    # ===============================================================================
    # PROFORMA EDIT TESTS
    # ===============================================================================

    def test_handle_proforma_edit_post_unauthenticated_user_type(self) -> None:
        """Test _handle_proforma_edit_post with wrong user type (Line 644-645)."""
        request = self.factory.post('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = _handle_proforma_edit_post(request, self.proforma)
        
        self.assertEqual(response.status_code, 302)

    def test_validate_proforma_edit_access_no_permission(self) -> None:
        """Test _validate_proforma_edit_access without customer access (Line 483-485)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized12@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = _validate_proforma_edit_access(unauthorized_user, self.proforma, request)
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 302)

    def test_validate_proforma_edit_access_expired_proforma(self) -> None:
        """Test _validate_proforma_edit_access with expired proforma (Line 487-489)."""
        # Make proforma expired
        self.proforma.valid_until = timezone.now() - timezone.timedelta(days=1)
        self.proforma.save()
        
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = _validate_proforma_edit_access(self.staff_user, self.proforma, request)
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 302)

    def test_validate_proforma_edit_access_granted(self) -> None:
        """Test _validate_proforma_edit_access with valid access (Line 491)."""
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = _validate_proforma_edit_access(self.staff_user, self.proforma, request)
            
            self.assertIsNone(response)

    def test_proforma_edit_unauthenticated_user_type(self) -> None:
        """Test proforma_edit with wrong user type (Line 700-701)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = proforma_edit(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_get_customers_for_edit_form_with_queryset(self) -> None:
        """Test _get_customers_for_edit_form with QuerySet (Line 680-681)."""
        mock_queryset = Mock()
        mock_queryset.select_related.return_value = mock_queryset
        
        with patch.object(self.staff_user, 'get_accessible_customers', return_value=mock_queryset):
            result = _get_customers_for_edit_form(self.staff_user)
            
            mock_queryset.select_related.assert_called_once_with('tax_profile', 'billing_profile')
            # Should return the processed queryset
            self.assertEqual(result, mock_queryset)

    def test_get_customers_for_edit_form_with_list(self) -> None:
        """Test _get_customers_for_edit_form with list (Line 682-685)."""
        mock_customer = Mock()
        mock_customer.id = self.customer.id
        
        with patch.object(self.staff_user, 'get_accessible_customers', return_value=[mock_customer]):
            with patch('apps.customers.models.Customer.objects.filter') as mock_filter:
                mock_filter.return_value.select_related.return_value = 'filtered_queryset'
                
                result = _get_customers_for_edit_form(self.staff_user)
                
                self.assertEqual(result, 'filtered_queryset')

    def test_get_customers_for_edit_form_fallback(self) -> None:
        """Test _get_customers_for_edit_form fallback case (Line 687-688)."""
        mock_fallback_queryset = Mock()
        mock_fallback_queryset.select_related.return_value = mock_fallback_queryset
        
        with patch.object(self.staff_user, 'get_accessible_customers', return_value=mock_fallback_queryset):
            result = _get_customers_for_edit_form(self.staff_user)
            
            mock_fallback_queryset.select_related.assert_called_once_with('tax_profile', 'billing_profile')
            # Should return the fallback queryset
            self.assertEqual(result, mock_fallback_queryset)

    # ===============================================================================
    # INVOICE EDIT TESTS
    # ===============================================================================

    def test_invoice_edit_unauthenticated_user_type(self) -> None:
        """Test invoice_edit with wrong user type (Line 765-767)."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        self._add_session_and_messages(request)
        
        response = invoice_edit(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_edit_no_permission(self) -> None:
        """Test invoice_edit without customer access (Line 765-767)."""
        unauthorized_user = User.objects.create_user(
            email='unauthorized13@example.com',
            password='testpass123'
        )
        
        request = self.factory.get('/')
        request.user = unauthorized_user
        self._add_session_and_messages(request)
        
        with patch.object(unauthorized_user, 'can_access_customer', return_value=False):
            response = invoice_edit(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_invoice_edit_not_draft(self) -> None:
        """Test invoice_edit with non-draft invoice (Line 769-771)."""
        # Set invoice to issued status
        self.invoice.status = 'issued'
        self.invoice.save()
        
        request = self.factory.get('/')
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_edit(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_invoice_edit_post_success(self) -> None:
        """Test invoice_edit POST success (Line 773-776)."""
        # Set invoice to draft status
        self.invoice.status = 'draft'
        self.invoice.save()
        
        request = self.factory.post('/', {})
        request.user = self.staff_user
        self._add_session_and_messages(request)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = invoice_edit(request, self.invoice.pk)
            
            self.assertEqual(response.status_code, 302)

    def test_invoice_edit_get_success(self) -> None:
        """Test invoice_edit GET success (Line 778-782)."""
        # Set invoice to draft status
        self.invoice.status = 'draft'
        self.invoice.save()
        
        # Login and use Django test client for context access
        self.client.force_login(self.staff_user)
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = self.client.get(reverse('billing:invoice_edit', kwargs={'pk': self.invoice.pk}))
            
            self.assertEqual(response.status_code, 200)
            self.assertIn('invoice', response.context)
