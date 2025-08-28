# ===============================================================================
# COMPREHENSIVE BILLING VIEWS TESTS - COVERAGE FOCUSED
# ===============================================================================

import json
from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    Payment,
    ProformaInvoice,
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
    _validate_pdf_access,
    _validate_proforma_edit_access,
    billing_list,
    billing_reports,
    generate_e_factura,
    invoice_detail,
    invoice_edit,
    invoice_pdf,
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


class BillingViewsComprehensiveTestCase(TestCase):
    """Comprehensive test case for billing views to achieve 85%+ coverage"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.client = Client()
        
        # Create currency
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        # Create customer
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='test@company.ro',
            status='active'
        )
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        # Create regular user with customer access
        self.user = User.objects.create_user(
            email='user@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create user without access
        self.no_access_user = User.objects.create_user(
            email='noaccess@test.ro',
            password='testpass'
        )
        
        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-TEST-001',
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )
        
        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-TEST-001',
            total_cents=15000,
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

    # ===============================================================================
    # HELPER FUNCTION TESTS
    # ===============================================================================

    def test_get_accessible_customer_ids_staff_user(self):
        """Test _get_accessible_customer_ids with staff user"""
        customer_ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIn(self.customer.id, customer_ids)

    def test_get_accessible_customer_ids_regular_user(self):
        """Test _get_accessible_customer_ids with regular user"""
        customer_ids = _get_accessible_customer_ids(self.user)
        self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_no_access(self):
        """Test _get_accessible_customer_ids with no access user"""
        customer_ids = _get_accessible_customer_ids(self.no_access_user)
        self.assertEqual(customer_ids, [])

    def test_validate_pdf_access_success(self):
        """Test _validate_pdf_access with authorized user"""
        request = self.factory.get('/test/')
        request.user = self.user
        
        result = _validate_pdf_access(request, self.invoice)
        self.assertIsNone(result)

    def test_validate_pdf_access_denied(self):
        """Test _validate_pdf_access with unauthorized user"""
        request = self.factory.get('/test/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        result = _validate_pdf_access(request, self.invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_create_proforma_with_sequence(self):
        """Test _create_proforma_with_sequence helper"""
        valid_until = timezone.now() + timezone.timedelta(days=30)
        
        proforma = _create_proforma_with_sequence(self.customer, valid_until)
        
        self.assertIsInstance(proforma, ProformaInvoice)
        self.assertEqual(proforma.customer, self.customer)
        self.assertTrue(proforma.number.startswith('PRO-'))

    def test_validate_customer_assignment_success(self):
        """Test _validate_customer_assignment with valid customer"""
        customer, error_response = _validate_customer_assignment(
            self.user, str(self.customer.pk), None
        )
        
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error_response)

    def test_validate_customer_assignment_invalid_id(self):
        """Test _validate_customer_assignment with invalid customer ID"""
        with self.assertRaises(Http404):
            _validate_customer_assignment(self.user, '99999', None)

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

    def test_parse_line_unit_price_valid(self):
        """Test _parse_line_unit_price with valid input"""
        request_data = {'line_0_unit_price': '99.99'}
        
        unit_price, errors = _parse_line_unit_price(request_data, 0)
        
        self.assertEqual(unit_price, Decimal('99.99'))
        self.assertEqual(len(errors), 0)

    def test_parse_line_vat_rate_invalid(self):
        """Test _parse_line_vat_rate with invalid input"""
        request_data = {'line_0_vat_rate': 'invalid'}
        
        vat_rate, errors = _parse_line_vat_rate(request_data, 0)
        
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        self.assertGreater(len(errors), 0)

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

    def test_validate_proforma_edit_access_success(self):
        """Test _validate_proforma_edit_access with valid access"""
        request = self.factory.get('/test/')
        result = _validate_proforma_edit_access(self.user, self.proforma, request)
        
        self.assertIsNone(result)

    def test_validate_proforma_edit_access_expired(self):
        """Test _validate_proforma_edit_access with expired proforma"""
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-001',
            valid_until=timezone.now() - timezone.timedelta(days=1)
        )
        
        request = self.factory.get('/test/')
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.user, expired_proforma, request)
        
        self.assertIsNotNone(result)

    def test_get_customers_for_edit_form(self):
        """Test _get_customers_for_edit_form utility"""
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

    def test_billing_list_unauthenticated(self):
        """Test billing_list with unauthenticated user"""
        request = self.factory.get('/billing/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 302)

    def test_billing_list_with_search(self):
        """Test billing_list with search parameter"""
        request = self.factory.get('/billing/?search=TEST')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_list_with_type_filter(self):
        """Test billing_list with type filter"""
        request = self.factory.get('/billing/?type=proforma')
        request.user = self.user
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

    def test_proforma_create_get(self):
        """Test proforma_create GET request"""
        request = self.factory.get('/proforma/create/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_create(request)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_create_post_success(self):
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

    def test_proforma_to_invoice_get(self):
        """Test proforma_to_invoice GET request"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_to_invoice_post_success(self):
        """Test successful proforma to invoice conversion"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify invoice was created
        invoice = Invoice.objects.filter(meta__proforma_id=self.proforma.id).first()
        self.assertIsNotNone(invoice)

    def test_proforma_to_invoice_expired(self):
        """Test conversion of expired proforma"""
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-002',
            total_cents=10000,
            valid_until=timezone.now() - timezone.timedelta(days=1)
        )
        
        request = self.factory.post(f'/proforma/{expired_proforma.pk}/convert/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, expired_proforma.pk)
        
        self.assertEqual(response.status_code, 302)

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
    # PAYMENT PROCESSING TESTS
    # ===============================================================================

    def test_process_payment_success(self):
        """Test successful payment processing"""
        post_data = {
            'amount': '150.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/invoice/{self.invoice.pk}/payment/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        
        self.assertIsInstance(response, JsonResponse)
        
        # Verify payment was created
        payment = Payment.objects.filter(invoice=self.invoice).first()
        self.assertIsNotNone(payment)

    @patch('apps.billing.views.messages')
    def test_process_proforma_payment_success(self, mock_messages):
        """Test successful proforma payment processing"""
        post_data = {
            'amount': '119.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/payment/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        
        self.assertIsInstance(response, JsonResponse)

    # ===============================================================================
    # EMAIL SENDING TESTS
    # ===============================================================================

    def test_proforma_send_success(self):
        """Test successful proforma send"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_send(request, self.proforma.pk)
        
        self.assertIsInstance(response, JsonResponse)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])

    def test_proforma_send_get_method(self):
        """Test proforma send with GET method (should fail)"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_send(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 405)

    def test_invoice_send_success(self):
        """Test successful invoice send"""
        request = self.factory.post(f'/invoice/{self.invoice.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_send(request, self.invoice.pk)
        
        self.assertIsInstance(response, JsonResponse)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        
        # Verify sent_at timestamp was updated
        self.invoice.refresh_from_db()
        self.assertIsNotNone(self.invoice.sent_at)

    # ===============================================================================
    # ROMANIAN E-FACTURA TESTS
    # ===============================================================================

    def test_generate_e_factura(self):
        """Test e-Factura XML generation"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/e-factura/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = generate_e_factura(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/xml')
        self.assertIn('e_factura_', response['Content-Disposition'])

    # ===============================================================================
    # REPORTS TESTS
    # ===============================================================================

    def test_payment_list_success(self):
        """Test payment list view"""
        # Create a test payment
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            currency=self.currency,
            status='succeeded'
        )
        
        request = self.factory.get('/payments/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = payment_list(request)
        
        self.assertEqual(response.status_code, 200)

    def test_billing_reports_success(self):
        """Test billing reports view"""
        request = self.factory.get('/billing/reports/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = billing_reports(request)
        
        self.assertEqual(response.status_code, 200)

    def test_vat_report_success(self):
        """Test VAT report view"""
        request = self.factory.get('/billing/vat-report/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = vat_report(request)
        
        self.assertEqual(response.status_code, 200)

    def test_vat_report_with_date_range(self):
        """Test VAT report with date range parameters"""
        request = self.factory.get('/billing/vat-report/?start_date=2024-01-01&end_date=2024-12-31')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = vat_report(request)
        
        self.assertEqual(response.status_code, 200)

    # ===============================================================================
    # INVOICE EDITING TESTS
    # ===============================================================================

    def test_invoice_edit_draft_success(self):
        """Test editing draft invoice"""
        draft_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DRAFT-001',
            status='draft'
        )
        
        request = self.factory.get(f'/invoice/{draft_invoice.pk}/edit/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_edit(request, draft_invoice.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_invoice_edit_issued_fails(self):
        """Test editing issued invoice should fail"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/edit/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_edit(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA EDITING TESTS
    # ===============================================================================

    def test_proforma_edit_get(self):
        """Test proforma edit GET request"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/edit/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_edit(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)

    def test_proforma_edit_post_success(self):
        """Test proforma edit POST request"""
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

    # ===============================================================================
    # ERROR HANDLING TESTS
    # ===============================================================================

    def test_process_line_items_with_invalid_data(self):
        """Test processing line items with invalid data"""
        request_data = {
            'line_0_description': 'Valid Description',
            'line_0_quantity': 'not-a-number',
            'line_0_unit_price': 'also-not-a-number',
            'line_0_vat_rate': 'invalid-rate',
        }
        
        errors = _process_proforma_line_items(self.proforma, request_data)
        
        # Should have errors for invalid numeric fields
        self.assertGreater(len(errors), 0)

    def test_edge_case_parsing(self):
        """Test edge cases in line parsing functions"""
        # Test empty values
        quantity, errors = _parse_line_quantity({'line_0_quantity': ''}, 0)
        self.assertEqual(quantity, Decimal('0'))
        
        # Test None values  
        price, errors = _parse_line_unit_price({}, 0)
        self.assertEqual(price, Decimal('0'))
        
        # Test VAT rate defaults
        vat_rate, errors = _parse_line_vat_rate({'line_0_vat_rate': ''}, 0)
        self.assertEqual(vat_rate, Decimal('19'))
