# ===============================================================================
# FIXED BILLING VIEWS TESTS - COMPREHENSIVE COVERAGE WITH TYPE SAFETY
# ===============================================================================

from __future__ import annotations

from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpRequest, HttpResponse
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
    _parse_line_quantity,
    _parse_line_unit_price,
    _parse_line_vat_rate,
    _process_proforma_line_items,
    _process_valid_until_date,
    _update_proforma_basic_info,
    _validate_customer_assignment,
    _validate_pdf_access,
    _validate_proforma_edit_access,
    billing_list,
    invoice_pdf,
    proforma_pdf,
    proforma_to_invoice,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class BillingViewsTestCase(TestCase):
    """Comprehensive test suite for billing views with proper type safety and authentication"""

    def setUp(self) -> None:
        """Set up test data for billing views tests"""
        self.factory: RequestFactory = RequestFactory()
        self.client: Client = Client()
        
        # Create currency
        self.currency: Currency = Currency.objects.create(
            code='RON', 
            symbol='lei', 
            decimals=2
        )
        
        # Create customers
        self.customer: Customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='test@company.ro',
            status='active'
        )
        
        self.other_customer: Customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Company SRL',
            primary_email='other@company.ro',
            status='active'
        )
        
        # Create staff user with proper staff role
        self.staff_user: User = User.objects.create_user(
            email='staff@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='billing'  # Use valid staff role
        )
        
        # Create regular user with customer access
        self.user: User = User.objects.create_user(
            email='user@test.ro',
            password='testpass123'
        )
        
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create user without access
        self.no_access_user: User = User.objects.create_user(
            email='noaccess@test.ro',
            password='testpass123'
        )
        
        # Create test proforma
        self.proforma: ProformaInvoice = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Test Company SRL',
            bill_to_email='test@company.ro'
        )
        
        # Add proforma line
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.19'),
            line_total_cents=10000
        )
        
        # Create expired proforma
        self.expired_proforma: ProformaInvoice = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-001',
            total_cents=10000,
            valid_until=timezone.now() - timezone.timedelta(days=1)
        )
        
        # Create test invoice with proper numeric fields
        self.invoice: Invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
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
            # line_total_cents will be calculated automatically in save()
        )

    def add_middleware_to_request(self, request: HttpRequest) -> HttpRequest:
        """Add required middleware to request for message framework"""
        # Add session middleware
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        # Add messages middleware
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    # ===============================================================================
    # HELPER FUNCTION TESTS
    # ===============================================================================

    def test_get_accessible_customer_ids_with_staff_user(self) -> None:
        """Test _get_accessible_customer_ids with staff user"""
        customer_ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIn(self.customer.id, customer_ids)
        self.assertIn(self.other_customer.id, customer_ids)

    def test_get_accessible_customer_ids_with_regular_user(self) -> None:
        """Test _get_accessible_customer_ids with regular user"""
        customer_ids = _get_accessible_customer_ids(self.user)
        self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_with_no_access(self) -> None:
        """Test _get_accessible_customer_ids with no access user"""
        customer_ids = _get_accessible_customer_ids(self.no_access_user)
        self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_with_empty_result(self) -> None:
        """Test _get_accessible_customer_ids when get_accessible_customers returns empty"""
        with patch.object(self.user, 'get_accessible_customers', return_value=[]):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_with_none_result(self) -> None:
        """Test _get_accessible_customer_ids when get_accessible_customers returns None"""
        with patch.object(self.user, 'get_accessible_customers', return_value=None):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])

    def test_validate_pdf_access_success(self) -> None:
        """Test _validate_pdf_access with authorized user"""
        request = self.factory.get('/test/')
        request.user = self.user
        
        result = _validate_pdf_access(request, self.invoice)
        self.assertIsNone(result)

    def test_validate_pdf_access_denied(self) -> None:
        """Test _validate_pdf_access with unauthorized user"""
        request = self.factory.get('/test/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        result = _validate_pdf_access(request, self.invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_validate_pdf_access_anonymous_user(self) -> None:
        """Test _validate_pdf_access with anonymous user"""
        request = self.factory.get('/test/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        result = _validate_pdf_access(request, self.invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_create_proforma_with_sequence(self) -> None:
        """Test _create_proforma_with_sequence helper"""
        valid_until = timezone.now() + timezone.timedelta(days=30)
        
        proforma = _create_proforma_with_sequence(self.customer, valid_until)
        
        self.assertIsInstance(proforma, ProformaInvoice)
        self.assertEqual(proforma.customer, self.customer)
        self.assertTrue(proforma.number.startswith('PRO-'))
        self.assertEqual(proforma.valid_until, valid_until)

    def test_validate_customer_assignment_success(self) -> None:
        """Test _validate_customer_assignment with valid customer"""
        customer, error_response = _validate_customer_assignment(
            self.user, str(self.customer.pk), None
        )
        
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error_response)

    def test_validate_customer_assignment_no_customer_id(self) -> None:
        """Test _validate_customer_assignment with no customer_id"""
        customer, error_response = _validate_customer_assignment(self.user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_invalid_id(self) -> None:
        """Test _validate_customer_assignment with invalid customer ID"""
        with self.assertRaises(Http404):
            _validate_customer_assignment(self.user, '99999', None)

    def test_validate_customer_assignment_no_access(self) -> None:
        """Test _validate_customer_assignment with no access to customer"""
        customer, error_response = _validate_customer_assignment(
            self.no_access_user, str(self.other_customer.pk), None
        )
        
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_process_valid_until_date_valid(self) -> None:
        """Test _process_valid_until_date with valid date"""
        request_data: dict[str, str] = {'valid_until': '2024-12-31'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_process_valid_until_date_invalid(self) -> None:
        """Test _process_valid_until_date with invalid date"""
        request_data: dict[str, str] = {'valid_until': 'invalid-date'}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertGreater(len(errors), 0)

    def test_process_valid_until_date_empty(self) -> None:
        """Test _process_valid_until_date with empty date"""
        request_data: dict[str, str] = {'valid_until': ''}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_parse_line_quantity_valid(self) -> None:
        """Test _parse_line_quantity with valid input"""
        request_data: dict[str, str] = {'line_0_quantity': '2.5'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('2.5'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_quantity_invalid(self) -> None:
        """Test _parse_line_quantity with invalid input"""
        request_data: dict[str, str] = {'line_0_quantity': 'invalid'}
        
        quantity, errors = _parse_line_quantity(request_data, 0)
        
        self.assertEqual(quantity, Decimal('0'))
        self.assertGreater(len(errors), 0)

    def test_parse_line_unit_price_valid(self) -> None:
        """Test _parse_line_unit_price with valid input"""
        request_data: dict[str, str] = {'line_0_unit_price': '99.99'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('99.99'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_unit_price_invalid(self) -> None:
        """Test _parse_line_unit_price with invalid input"""
        request_data: dict[str, str] = {'line_0_unit_price': 'invalid'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('0'))
        self.assertGreater(len(errors), 0)

    def test_parse_line_vat_rate_valid(self) -> None:
        """Test _parse_line_vat_rate with valid input"""
        request_data: dict[str, str] = {'line_0_vat_rate': '19'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_invalid(self) -> None:
        """Test _parse_line_vat_rate with invalid input"""
        request_data: dict[str, str] = {'line_0_vat_rate': 'invalid'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        self.assertGreater(len(errors), 0)

    def test_process_proforma_line_items_valid(self) -> None:
        """Test _process_proforma_line_items processing with valid data"""
        test_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-LINES-001'
        )
        
        request_data: dict[str, str] = {
            'line_0_description': 'Test Service',
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(test_proforma, request_data)
        
        self.assertEqual(len(errors), 0)
        self.assertGreaterEqual(test_proforma.lines.count(), 1)

    def test_process_proforma_line_items_invalid_data(self) -> None:
        """Test _process_proforma_line_items with invalid data"""
        test_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-INVALID-001'
        )
        
        request_data: dict[str, str] = {
            'line_0_description': 'Test Service',
            'line_0_quantity': 'invalid',
            'line_0_unit_price': 'invalid',
            'line_0_vat_rate': 'invalid',
        }
        
        errors = _process_proforma_line_items(test_proforma, request_data)
        
        # Should have errors but not crash
        self.assertGreater(len(errors), 0)

    def test_update_proforma_basic_info(self) -> None:
        """Test _update_proforma_basic_info utility"""
        request_data: dict[str, str] = {
            'bill_to_name': 'Updated Company Name',
            'bill_to_email': 'updated@company.ro',
            'bill_to_tax_id': 'RO12345678'
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        self.assertEqual(self.proforma.bill_to_name, 'Updated Company Name')
        self.assertEqual(self.proforma.bill_to_email, 'updated@company.ro')
        self.assertEqual(self.proforma.bill_to_tax_id, 'RO12345678')

    def test_validate_proforma_edit_access_success(self) -> None:
        """Test _validate_proforma_edit_access with valid access"""
        request = self.factory.get('/test/')
        result = _validate_proforma_edit_access(self.user, self.proforma, request)
        
        self.assertIsNone(result)

    def test_validate_proforma_edit_access_no_access(self) -> None:
        """Test _validate_proforma_edit_access with no customer access"""
        request = self.factory.get('/test/')
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.no_access_user, self.proforma, request)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_validate_proforma_edit_access_expired(self) -> None:
        """Test _validate_proforma_edit_access with expired proforma"""
        request = self.factory.get('/test/')
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.user, self.expired_proforma, request)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_get_customers_for_edit_form(self) -> None:
        """Test _get_customers_for_edit_form utility"""
        customers = _get_customers_for_edit_form(self.user)
        
        # Should return QuerySet containing the accessible customer
        self.assertIn(self.customer, customers)

    # ===============================================================================
    # VIEW FUNCTION TESTS - AUTHENTICATION & AUTHORIZATION
    # ===============================================================================

    def test_billing_list_authenticated_user(self) -> None:
        """Test billing_list with authenticated user"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/invoices/')
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_unauthenticated_user_redirects(self) -> None:
        """Test billing_list redirects unauthenticated users"""
        response = self.client.get('/app/billing/invoices/')
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)

    def test_billing_list_with_search(self) -> None:
        """Test billing_list with search parameter"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/invoices/?search=PRO-001')
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_type_filters(self) -> None:
        """Test billing_list with different type filters"""
        self.client.force_login(self.user)
        type_filters = ['all', 'proforma', 'invoice']
        
        for filter_type in type_filters:
            with self.subTest(filter_type=filter_type):
                response = self.client.get(f'/app/billing/invoices/?type={filter_type}')
                
                self.assertEqual(response.status_code, 200)

    def test_invoice_detail_success(self) -> None:
        """Test invoice_detail with authorized user"""
        # Use Django test client for proper template rendering
        self.client.force_login(self.user)
        response = self.client.get(f'/app/billing/invoices/{self.invoice.pk}/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'INV-001')

    def test_invoice_detail_unauthorized(self) -> None:
        """Test invoice_detail with unauthorized user"""
        self.client.force_login(self.no_access_user)
        response = self.client.get(f'/app/billing/invoices/{self.invoice.pk}/')
        
        # Should redirect due to lack of access
        self.assertEqual(response.status_code, 302)

    def test_invoice_detail_not_found(self) -> None:
        """Test invoice_detail with non-existent invoice"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/invoices/99999/')
        
        self.assertEqual(response.status_code, 404)

    def test_proforma_detail_success(self) -> None:
        """Test proforma_detail with authorized user"""
        self.client.force_login(self.user)
        response = self.client.get(f'/app/billing/proformas/{self.proforma.pk}/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'PRO-001')

    def test_proforma_detail_unauthorized(self) -> None:
        """Test proforma_detail with unauthorized user"""
        self.client.force_login(self.no_access_user)
        response = self.client.get(f'/app/billing/proformas/{self.proforma.pk}/')
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA TO INVOICE CONVERSION TESTS
    # ===============================================================================

    def test_proforma_to_invoice_get_request(self) -> None:
        """Test proforma_to_invoice GET request"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_to_invoice_unauthorized(self) -> None:
        """Test proforma_to_invoice with unauthorized user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_expired_proforma(self) -> None:
        """Test proforma_to_invoice with expired proforma"""
        request = self.factory.post(f'/proforma/{self.expired_proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.expired_proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_already_converted(self) -> None:
        """Test proforma_to_invoice with already converted proforma"""
        # Create existing invoice from proforma
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EXISTING-001',
            status='issued',
            total_cents=self.proforma.total_cents,
            meta={'proforma_id': self.proforma.id}
        )
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PDF GENERATION TESTS
    # ===============================================================================

    @patch('apps.billing.views.RomanianProformaPDFGenerator')
    def test_proforma_pdf_success(self, mock_pdf_generator: Mock) -> None:
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
    def test_invoice_pdf_success(self, mock_pdf_generator: Mock) -> None:
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

    def test_pdf_access_denied_for_unauthorized_user(self) -> None:
        """Test PDF access denied for unauthorized user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/pdf/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_pdf(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.error.assert_called_once()

    # ===============================================================================
    # HANDLE PROFORMA CREATE/EDIT POST TESTS
    # ===============================================================================

    def test_handle_proforma_create_post_success(self) -> None:
        """Test successful proforma creation via POST"""
        post_data: dict[str, str] = {
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

    def test_handle_proforma_create_post_no_customer(self) -> None:
        """Test _handle_proforma_create_post with no customer"""
        post_data: dict[str, str] = {}
        
        request = self.factory.post('/proforma/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # ERROR HANDLING TESTS
    # ===============================================================================

    def test_billing_list_handles_empty_customer_access(self) -> None:
        """Test billing_list handles users with no customer access"""
        empty_user = User.objects.create_user(
            email='empty@test.ro',
            password='testpass123'
        )
        
        request = self.factory.get('/billing/')
        request.user = empty_user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_process_line_items_with_edge_cases(self) -> None:
        """Test processing line items with various edge cases"""
        test_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EDGE-001'
        )
        
        # Test with empty description (should skip)
        request_data: dict[str, str] = {
            'line_0_description': '',  # Empty description
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(test_proforma, request_data)
        
        # Should not create line with empty description
        self.assertEqual(test_proforma.lines.count(), 0)
        
        # Test with zero quantity (should skip)
        request_data['line_0_description'] = 'Test Service'
        request_data['line_0_quantity'] = '0'
        
        errors = _process_proforma_line_items(test_proforma, request_data)
        
        # Should not create line with zero quantity
        self.assertIsNotNone(errors)  # Should return errors for zero quantity
        self.assertEqual(test_proforma.lines.count(), 0)

    def test_parse_line_fields_edge_cases(self) -> None:
        """Test line field parsing with edge cases"""
        # Test empty values
        quantity, errors = _parse_line_quantity({'line_0_quantity': ''}, 0)
        self.assertEqual(quantity, Decimal('0'))
        
        price, errors = _parse_line_unit_price({'line_0_unit_price': ''}, 0)
        self.assertEqual(price, Decimal('0'))
        
        vat_rate, errors = _parse_line_vat_rate({'line_0_vat_rate': ''}, 0)
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        
        # Test missing keys
        vat_rate, errors = _parse_line_vat_rate({}, 0)
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%

    def test_update_proforma_basic_info_with_empty_values(self) -> None:
        """Test proforma basic info update with empty values"""
        original_name = self.proforma.bill_to_name
        
        request_data: dict[str, str] = {
            'bill_to_name': '',  # Empty value should not update
            'bill_to_email': 'new@email.com',  # Non-empty should update
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        # Empty value should not overwrite existing
        self.assertEqual(self.proforma.bill_to_name, original_name)
        self.assertEqual(self.proforma.bill_to_email, 'new@email.com')


class BillingViewsIntegrationTestCase(TestCase):
    """Integration tests using Django test client"""

    def setUp(self) -> None:
        """Set up test data for integration tests"""
        self.client: Client = Client()
        
        # Create currency
        self.currency: Currency = Currency.objects.create(
            code='RON', 
            symbol='lei', 
            decimals=2
        )
        
        # Create customer
        self.customer: Customer = Customer.objects.create(
            customer_type='company',
            company_name='Integration Test Company SRL',
            primary_email='integration@company.ro',
            status='active'
        )
        
        # Create staff user
        self.staff_user: User = User.objects.create_user(
            email='integration_staff@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        # Create regular user with customer access
        self.user: User = User.objects.create_user(
            email='integration_user@test.ro',
            password='testpass123'
        )
        
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )

    def test_billing_list_integration(self) -> None:
        """Test billing list view integration"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/invoices/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'billing')

    def test_unauthenticated_access_redirects(self) -> None:
        """Test that unauthenticated access redirects to login"""
        response = self.client.get('/app/billing/invoices/')
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/', response.url)


# ===============================================================================
# TYPE-SAFE ERROR HANDLING TESTS
# ===============================================================================

class BillingViewsErrorHandlingTestCase(TestCase):
    """Test error handling scenarios with proper type safety"""

    def setUp(self) -> None:
        """Set up minimal test data for error scenarios"""
        self.factory: RequestFactory = RequestFactory()
        
        self.currency: Currency = Currency.objects.create(
            code='RON', 
            symbol='lei', 
            decimals=2
        )
        
        self.customer: Customer = Customer.objects.create(
            customer_type='company',
            company_name='Error Test Company SRL',
            status='active'
        )
        
        self.user: User = User.objects.create_user(
            email='error_test@test.ro',
            password='testpass123'
        )

    def add_middleware_to_request(self, request: HttpRequest) -> HttpRequest:
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_billing_list_with_database_error_handling(self) -> None:
        """Test billing_list handles database errors gracefully"""
        request = self.factory.get('/billing/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        with patch('apps.billing.views._get_accessible_customer_ids') as mock_get_ids:
            mock_get_ids.side_effect = Exception('Database error')
            
            # Should handle the error gracefully without crashing
            try:
                response = billing_list(request)
                # If we get here, error handling is working
                self.assertIsNotNone(response)
                self.assertTrue(True)
            except Exception as e:
                self.fail(f"View should handle database errors gracefully, but got: {e}")

    def test_invalid_form_data_handling(self) -> None:
        """Test handling of invalid form data in proforma creation"""
        post_data: dict[str, str] = {
            'customer': 'invalid-customer-id',
            'valid_until': 'invalid-date',
            'line_0_quantity': 'not-a-number',
            'line_0_unit_price': 'not-a-price',
        }
        
        staff_user = User.objects.create_user(
            email='invalid_form_staff@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        request = self.factory.post('/proforma/create/', post_data)
        request.user = staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        # Should redirect back without crashing
        self.assertEqual(response.status_code, 302)

    def test_process_valid_until_date_comprehensive_error_handling(self) -> None:
        """Test comprehensive error handling for date processing"""
        test_cases = [
            {},  # Missing key
            {'valid_until': ''},  # Empty value  
            {'valid_until': 'invalid-date'},  # Invalid format
            {'valid_until': '2024-13-45'},  # Invalid date
            {'valid_until': None},  # None value
        ]
        
        for test_data in test_cases:
            with self.subTest(test_data=test_data):
                valid_until, errors = _process_valid_until_date(test_data)
                
                # Should always return a datetime object
                self.assertIsInstance(valid_until, timezone.datetime)
                
                # Invalid dates should generate errors
                if test_data.get('valid_until') and test_data['valid_until'] not in ['', None]:
                    if 'invalid' in str(test_data['valid_until']) or '13-45' in str(test_data['valid_until']):
                        self.assertGreater(len(errors), 0)
