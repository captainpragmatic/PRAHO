# ===============================================================================
# COMPLETE BILLING VIEWS TESTS - WORKING 85%+ COVERAGE
# ===============================================================================

from decimal import Decimal
from typing import Any
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    ProformaInvoice,
    ProformaLine,
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
    invoice_detail,
    invoice_pdf,
    proforma_detail,
    proforma_pdf,
    proforma_to_invoice,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class CompleteBillingViewsTestCase(TestCase):
    """Complete test case for billing views focused on working 85%+ coverage"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.client = Client()
        
        # Create currency
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        # Create customer
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Complete Test Company SRL',
            primary_email='complete@company.ro',
            status='active'
        )
        
        # Create another customer for testing no-access scenarios
        self.other_customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Company SRL',
            primary_email='other@company.ro',
            status='active'
        )
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='completestaff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        # Create regular user with customer access
        self.user = User.objects.create_user(
            email='completeuser@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create user without access
        self.no_access_user = User.objects.create_user(
            email='completenoaccess@test.ro',
            password='testpass'
        )
        
        # Create test proforma with lines
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-COMPLETE-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Complete Test Company SRL',
            bill_to_email='complete@company.ro'
        )
        
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.19'),
            line_total_cents=10000
        )
        
        # Create expired proforma for testing
        self.expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-001',
            total_cents=10000,
            valid_until=timezone.now() - timezone.timedelta(days=1)
        )
        
        # Create test invoice with lines
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-COMPLETE-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            status='issued'
        )
        
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.19'),
            line_total_cents=10000
        )
        
        # Create draft invoice for edit testing
        self.draft_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DRAFT-001',
            status='draft'
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    # ===============================================================================
    # HELPER FUNCTION TESTS - COMPREHENSIVE COVERAGE
    # ===============================================================================

    def test_get_accessible_customer_ids_with_staff_user(self):
        """Test _get_accessible_customer_ids with staff user"""
        customer_ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIn(self.customer.id, customer_ids)
        self.assertIn(self.other_customer.id, customer_ids)

    def test_get_accessible_customer_ids_with_regular_user(self):
        """Test _get_accessible_customer_ids with regular user"""
        customer_ids = _get_accessible_customer_ids(self.user)
        self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_with_no_access(self):
        """Test _get_accessible_customer_ids with no access user"""
        customer_ids = _get_accessible_customer_ids(self.no_access_user)
        self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_with_list_return(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns list"""
        with patch.object(self.user, 'get_accessible_customers', return_value=[self.customer]):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_with_empty_list(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns empty list"""
        with patch.object(self.user, 'get_accessible_customers', return_value=[]):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_with_none(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns None"""
        with patch.object(self.user, 'get_accessible_customers', return_value=None):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])

    def test_validate_financial_document_access_success(self):
        """Test _validate_financial_document_access with authorized user"""
        request = self.factory.get('/test/')
        request.user = self.user
        
        result = _validate_financial_document_access(request, self.invoice)
        self.assertIsNone(result)

    def test_validate_financial_document_access_denied(self):
        """Test _validate_financial_document_access with unauthorized user"""
        request = self.factory.get('/test/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        result = _validate_financial_document_access(request, self.invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_validate_financial_document_access_non_user_type(self):
        """Test _validate_financial_document_access with non-User instance"""
        request = self.factory.get('/test/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        result = _validate_financial_document_access(request, self.invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_create_proforma_with_sequence(self):
        """Test _create_proforma_with_sequence helper"""
        valid_until = timezone.now() + timezone.timedelta(days=30)
        
        proforma = _create_proforma_with_sequence(self.customer, valid_until)
        
        self.assertIsInstance(proforma, ProformaInvoice)
        self.assertEqual(proforma.customer, self.customer)
        self.assertTrue(proforma.number.startswith('PRO-'))
        self.assertEqual(proforma.valid_until, valid_until)

    def test_validate_customer_assignment_success(self):
        """Test _validate_customer_assignment with valid customer"""
        customer, error_response = _validate_customer_assignment(
            self.user, str(self.customer.pk), None
        )
        
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error_response)

    def test_validate_customer_assignment_no_customer_id(self):
        """Test _validate_customer_assignment with no customer_id"""
        customer, error_response = _validate_customer_assignment(self.user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_invalid_id(self):
        """Test _validate_customer_assignment with invalid customer ID"""
        customer, error_response = _validate_customer_assignment(self.user, '99999', None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_invalid_id_with_proforma_pk(self):
        """Test _validate_customer_assignment with invalid ID and proforma_pk"""
        customer, error_response = _validate_customer_assignment(
            self.user, 'invalid', self.proforma.pk
        )
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)

    def test_validate_customer_assignment_no_access_with_proforma_pk(self):
        """Test _validate_customer_assignment no access with proforma_pk"""
        customer, error_response = _validate_customer_assignment(
            self.no_access_user, str(self.other_customer.pk), self.proforma.pk
        )
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_no_access_without_proforma_pk(self):
        """Test _validate_customer_assignment no access without proforma_pk"""
        customer, error_response = _validate_customer_assignment(
            self.no_access_user, str(self.other_customer.pk), None
        )
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_process_valid_until_date_valid(self):
        """Test _process_valid_until_date with valid date"""
        request_data = {'valid_until': '2024-12-31'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_process_valid_until_date_invalid(self):
        """Test _process_valid_until_date with invalid date"""
        request_data = {'valid_until': 'invalid-date'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertGreater(len(errors), 0)

    def test_process_valid_until_date_empty(self):
        """Test _process_valid_until_date with empty date"""
        request_data = {'valid_until': ''}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_process_valid_until_date_missing_key(self):
        """Test _process_valid_until_date with missing key"""
        valid_until, errors = _process_valid_until_date({})
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_parse_line_quantity_valid(self):
        """Test _parse_line_quantity with valid input"""
        request_data = {'line_0_quantity': '2.5'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('2.5'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_quantity_invalid(self):
        """Test _parse_line_quantity with invalid input"""
        request_data = {'line_0_quantity': 'invalid'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('0'))
        self.assertGreater(len(errors), 0)

    def test_parse_line_quantity_empty(self):
        """Test _parse_line_quantity with empty input"""
        request_data = {'line_0_quantity': ''}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('0'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_unit_price_valid(self):
        """Test _parse_line_unit_price with valid input"""
        request_data = {'line_0_unit_price': '99.99'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('99.99'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_unit_price_invalid(self):
        """Test _parse_line_unit_price with invalid input"""
        request_data = {'line_0_unit_price': 'invalid'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('0'))
        self.assertGreater(len(errors), 0)

    def test_parse_line_unit_price_empty(self):
        """Test _parse_line_unit_price with empty input"""
        request_data = {'line_0_unit_price': ''}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('0'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_valid(self):
        """Test _parse_line_vat_rate with valid input"""
        request_data = {'line_0_vat_rate': '19'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_invalid(self):
        """Test _parse_line_vat_rate with invalid input"""
        request_data = {'line_0_vat_rate': 'invalid'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        self.assertGreater(len(errors), 0)

    def test_parse_line_vat_rate_empty(self):
        """Test _parse_line_vat_rate with empty input"""
        request_data = {'line_0_vat_rate': ''}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_missing_key(self):
        """Test _parse_line_vat_rate with missing key"""
        vat_rate, errors = _parse_line_vat_rate({}, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        self.assertEqual(len(errors), 0)

    def test_process_proforma_line_items(self):
        """Test _process_proforma_line_items processing"""
        request_data = {
            'line_0_description': 'Test Service',
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        self.assertEqual(len(errors), 0)
        self.assertEqual(self.proforma.lines.count(), 1)

    def test_process_proforma_line_items_invalid_data(self):
        """Test _process_proforma_line_items with invalid data"""
        request_data = {
            'line_0_description': 'Test Service',
            'line_0_quantity': 'invalid',
            'line_0_unit_price': 'invalid',
            'line_0_vat_rate': 'invalid',
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        # Should have errors but still process what it can
        self.assertGreater(len(errors), 0)

    def test_process_proforma_line_items_empty_description(self):
        """Test _process_proforma_line_items with empty description"""
        request_data = {
            'line_0_description': '',  # Empty description should skip line
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        # Should not create line with empty description
        self.assertEqual(len(errors), 0)  # Empty description is not an error, just skipped  
        self.assertEqual(self.proforma.lines.count(), 0)  # No lines because description was empty

    def test_process_proforma_line_items_zero_quantity(self):
        """Test _process_proforma_line_items with zero quantity"""
        request_data = {
            'line_0_description': 'Test Service',
            'line_0_quantity': '0',  # Zero quantity should skip line
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        # Should not create line with zero quantity  
        self.assertEqual(len(errors), 0)  # Zero quantity is not an error, just skipped
        self.assertEqual(self.proforma.lines.count(), 0)  # No lines because quantity was zero

    def test_update_proforma_basic_info(self):
        """Test _update_proforma_basic_info utility"""
        request_data = {
            'bill_to_name': 'Updated Company Name',
            'bill_to_email': 'updated@company.ro',
            'bill_to_tax_id': 'RO12345678'
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        self.assertEqual(self.proforma.bill_to_name, 'Updated Company Name')
        self.assertEqual(self.proforma.bill_to_email, 'updated@company.ro')
        self.assertEqual(self.proforma.bill_to_tax_id, 'RO12345678')

    def test_update_proforma_basic_info_empty_values(self):
        """Test _update_proforma_basic_info with empty values"""
        original_name = self.proforma.bill_to_name
        
        request_data = {
            'bill_to_name': '',  # Empty value should not update
            'bill_to_email': 'new@email.com',  # Non-empty should update
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        # Empty value should not update
        self.assertEqual(self.proforma.bill_to_name, original_name)
        self.assertEqual(self.proforma.bill_to_email, 'new@email.com')

    def test_validate_proforma_edit_access_success(self):
        """Test _validate_proforma_edit_access with valid access"""
        request = self.factory.get('/test/')
        result = _validate_proforma_edit_access(self.user, self.proforma, request)
        
        self.assertIsNone(result)

    def test_validate_proforma_edit_access_no_customer_access(self):
        """Test _validate_proforma_edit_access with no customer access"""
        request = self.factory.get('/test/')
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.no_access_user, self.proforma, request)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_validate_proforma_edit_access_expired(self):
        """Test _validate_proforma_edit_access with expired proforma"""
        request = self.factory.get('/test/')
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.user, self.expired_proforma, request)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_get_customers_for_edit_form_with_queryset(self):
        """Test _get_customers_for_edit_form with QuerySet result"""
        customers = _get_customers_for_edit_form(self.user)
        
        self.assertIn(self.customer, customers)

    def test_get_customers_for_edit_form_with_list(self):
        """Test _get_customers_for_edit_form when get_accessible_customers returns list"""
        with patch.object(self.user, 'get_accessible_customers', return_value=[self.customer]):
            customers = _get_customers_for_edit_form(self.user)
            
            self.assertIn(self.customer, customers)

    def test_get_customers_for_edit_form_fallback(self):
        """Test _get_customers_for_edit_form fallback case"""
        # Mock to return neither QuerySet nor list
        mock_result = Mock()
        mock_result.select_related.return_value = Customer.objects.filter(id=self.customer.id)
        
        with patch.object(self.user, 'get_accessible_customers', return_value=mock_result):
            customers = _get_customers_for_edit_form(self.user)
            
            self.assertIn(self.customer, customers)

    # ===============================================================================
    # VIEW FUNCTION TESTS
    # ===============================================================================

    def test_billing_list_authenticated(self):
        """Test billing_list with authenticated user"""
        request = self.factory.get('/billing/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_unauthenticated_redirect(self):
        """Test billing_list redirects unauthenticated users"""
        request = self.factory.get('/billing/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 302)

    def test_billing_list_with_search(self):
        """Test billing_list with search parameter"""
        request = self.factory.get('/billing/?search=COMPLETE')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_type_filter_all(self):
        """Test billing_list with type=all filter"""
        request = self.factory.get('/billing/?type=all')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_type_filter_proforma(self):
        """Test billing_list with type=proforma filter"""
        request = self.factory.get('/billing/?type=proforma')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_type_filter_invoice(self):
        """Test billing_list with type=invoice filter"""
        request = self.factory.get('/billing/?type=invoice')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_empty_results(self):
        """Test billing_list with no matching documents"""
        # Create user with no customer access
        empty_user = User.objects.create_user(
            email='empty@test.ro',
            password='testpass'
        )
        
        request = self.factory.get('/billing/')
        request.user = empty_user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_invoice_detail_success(self):
        """Test invoice_detail with authorized user"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_invoice_detail_unauthorized(self):
        """Test invoice_detail with unauthorized user"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_invoice_detail_not_found(self):
        """Test invoice_detail with non-existent invoice"""
        request = self.factory.get('/invoice/99999/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        with self.assertRaises(Http404):
            invoice_detail(request, 99999)

    def test_proforma_detail_success(self):
        """Test proforma_detail with authorized user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_detail_unauthorized(self):
        """Test proforma_detail with unauthorized user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_get(self):
        """Test proforma_to_invoice GET request"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_to_invoice_unauthorized(self):
        """Test proforma_to_invoice with unauthorized user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_expired(self):
        """Test proforma_to_invoice with expired proforma"""
        request = self.factory.post(f'/proforma/{self.expired_proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.expired_proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_already_converted(self):
        """Test proforma_to_invoice with already converted proforma"""
        # Create existing invoice from proforma
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EXISTING-001',
            status='issued',
            total_cents=self.proforma.total_cents,
            converted_from_proforma=self.proforma
        )
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_post_success(self):
        """Test successful proforma to invoice conversion"""
        test_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONVERT-002',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Convert Test Company SRL',
            bill_to_email='convert@test.ro'
        )
        
        # Add line to proforma
        ProformaLine.objects.create(
            proforma=test_proforma,
            kind='service',
            description='Convert Service',
            quantity=2,
            unit_price_cents=5000,
            tax_rate=Decimal('0.19'),
            line_total_cents=10000
        )
        
        request = self.factory.post(f'/proforma/{test_proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, test_proforma.pk)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify invoice was created with all details
        invoice = Invoice.objects.filter(converted_from_proforma=test_proforma).first()
        self.assertIsNotNone(invoice)
        self.assertEqual(invoice.total_cents, test_proforma.total_cents)
        self.assertEqual(invoice.status, 'issued')
        self.assertEqual(invoice.bill_to_name, 'Convert Test Company SRL')
        
        # Verify line items were copied
        self.assertEqual(invoice.lines.count(), 1)
        line = invoice.lines.first()
        self.assertEqual(line.description, 'Convert Service')
        self.assertEqual(line.quantity, 2)

    # ===============================================================================
    # PDF GENERATION TESTS
    # ===============================================================================

    @patch('apps.billing.views.RomanianProformaPDFGenerator')
    def test_proforma_pdf_success(self, mock_pdf_generator):
        """Test successful proforma PDF generation"""
        mock_generator_instance = Mock()
        mock_response = Mock()
        mock_generator_instance.generate_response.return_value = mock_response
        mock_pdf_generator.return_value = mock_generator_instance
        
        request = self.factory.get(f'/proforma/{self.proforma.pk}/pdf/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = proforma_pdf(request, self.proforma.pk)
        
        mock_pdf_generator.assert_called_once_with(self.proforma)
        self.assertEqual(response, mock_response)

    @patch('apps.billing.views.RomanianInvoicePDFGenerator')
    def test_invoice_pdf_success(self, mock_pdf_generator):
        """Test successful invoice PDF generation"""
        mock_generator_instance = Mock()
        mock_response = Mock()
        mock_generator_instance.generate_response.return_value = mock_response
        mock_pdf_generator.return_value = mock_generator_instance
        
        request = self.factory.get(f'/invoice/{self.invoice.pk}/pdf/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = invoice_pdf(request, self.invoice.pk)
        
        mock_pdf_generator.assert_called_once_with(self.invoice)
        self.assertEqual(response, mock_response)

    # ===============================================================================
    # HANDLE PROFORMA CREATE POST TESTS
    # ===============================================================================

    def test_handle_proforma_create_post_success(self):
        """Test successful proforma creation via POST"""
        post_data = {
            'customer': str(self.customer.pk),
            'valid_until': '2024-12-31',
            'bill_to_name': 'Test Company SRL',
            'bill_to_email': 'test@company.ro',
            'line_0_description': 'Test Service',
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        request = self.factory.post('/proforma/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)

    def test_handle_proforma_create_post_no_customer(self):
        """Test _handle_proforma_create_post with no customer"""
        post_data: dict[str, Any] = {}
        
        request = self.factory.post('/proforma/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # HANDLE PROFORMA EDIT POST TESTS
    # ===============================================================================

    def test_handle_proforma_edit_post_success(self):
        """Test successful proforma edit via POST"""
        post_data = {
            'customer': str(self.customer.pk),
            'valid_until': '2024-12-31',
            'bill_to_name': 'Updated Company SRL',
            'line_0_description': 'Updated Service',
            'line_0_quantity': '2',
            'line_0_unit_price': '150.00',
            'line_0_vat_rate': '19',
        }
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/edit/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_edit_post(request, self.proforma)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify proforma was updated
        self.proforma.refresh_from_db()
        self.assertEqual(self.proforma.bill_to_name, 'Updated Company SRL')

    def test_handle_proforma_edit_post_no_customer(self):
        """Test proforma edit POST with no customer"""
        post_data: dict[str, Any] = {}
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/edit/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_edit_post(request, self.proforma)
        
        self.assertEqual(response.status_code, 302)

    def test_handle_proforma_edit_post_customer_none_after_validation(self):
        """Test proforma edit POST when customer validation returns None"""
        post_data = {
            'customer': str(self.customer.pk),
            'valid_until': '2024-12-31',
        }
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/edit/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        # Mock _validate_customer_assignment to return None customer
        with patch('apps.billing.views._validate_customer_assignment', return_value=(None, None)):
            response = _handle_proforma_edit_post(request, self.proforma)
            
            self.assertEqual(response.status_code, 302)
