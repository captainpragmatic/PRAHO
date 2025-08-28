# ===============================================================================
# FINAL BILLING VIEWS TESTS - TARGET 85%+ COVERAGE
# ===============================================================================

from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    Payment,
    ProformaInvoice,
    ProformaLine,
)
from apps.billing.views import (
    _get_accessible_customer_ids,
    _handle_proforma_create_post,
    _process_valid_until_date,
    _update_proforma_basic_info,
    _validate_customer_assignment,
    billing_list,
    billing_reports,
    generate_e_factura,
    invoice_detail,
    invoice_pdf,
    invoice_send,
    payment_list,
    process_payment,
    process_proforma_payment,
    proforma_detail,
    proforma_pdf,
    proforma_send,
    proforma_to_invoice,
    vat_report,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class BillingViewsFinalTestCase(TestCase):
    """Final comprehensive test case targeting 85%+ coverage"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.client = Client()
        
        # Create currency
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        # Create customer
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Final Test Company SRL',
            primary_email='final@company.ro',
            status='active'
        )
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='finalstaff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing_manager'
        self.staff_user.save()
        
        # Create regular user with customer access
        self.user = User.objects.create_user(
            email='finaluser@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create user without access
        self.no_access_user = User.objects.create_user(
            email='finalnoaccess@test.ro',
            password='testpass'
        )
        
        # Create test proforma with lines
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-FINAL-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Final Test Company SRL',
            bill_to_email='final@company.ro'
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
        
        # Create test invoice with lines
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-FINAL-001',
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

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    # ===============================================================================
    # CORE VIEW TESTS - TARGET MISSING LINES
    # ===============================================================================

    def test_billing_list_unauthenticated(self):
        """Test billing_list with None user (line 74)"""
        request = self.factory.get('/billing/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        self.assertEqual(response.status_code, 302)

    def test_billing_list_type_all(self):
        """Test billing_list with type=all (line 107)"""
        request = self.factory.get('/billing/?type=all')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        self.assertEqual(response.status_code, 200)

    def test_billing_list_type_invoice_only(self):
        """Test billing_list with type=invoice (line 127)"""
        request = self.factory.get('/billing/?type=invoice')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        self.assertEqual(response.status_code, 200)

    def test_invoice_detail_unauthenticated(self):
        """Test invoice_detail with None user"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        self.assertEqual(response.status_code, 302)

    def test_proforma_detail_unauthenticated(self):
        """Test proforma_detail with None user"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # PROFORMA CREATE TESTS
    # ===============================================================================

    @patch('apps.billing.views.messages')
    def test_handle_proforma_create_post_unauthenticated(self, mock_messages):
        """Test _handle_proforma_create_post with None user (line 237)"""
        request = self.factory.post('/proforma/create/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        self.assertEqual(response.status_code, 302)

    @patch('apps.billing.views.messages')
    def test_handle_proforma_create_post_no_customer(self, mock_messages):
        """Test _handle_proforma_create_post with no customer (line 251-252)"""
        request = self.factory.post('/proforma/create/', {})
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        self.assertEqual(response.status_code, 302)

    @patch('apps.billing.views.messages')
    def test_handle_proforma_create_post_exception(self, mock_messages):
        """Test _handle_proforma_create_post with exception (line 254-256)"""
        post_data = {
            'customer': str(self.customer.pk),
            'valid_until': '2024-12-31',
        }
        
        request = self.factory.post('/proforma/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        # Mock Currency.objects.get to raise exception
        with patch('apps.billing.views.Currency.objects.get', side_effect=Exception('Test error')):
            response = _handle_proforma_create_post(request)
            self.assertEqual(response.status_code, 302)
            mock_messages.error.assert_called()

    # ===============================================================================
    # PROFORMA TO INVOICE CONVERSION TESTS
    # ===============================================================================

    def test_proforma_to_invoice_unauthenticated(self):
        """Test proforma_to_invoice with None user (line 330)"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_unauthorized_user(self):
        """Test proforma_to_invoice with unauthorized user (line 332)"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/convert/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_to_invoice(request, self.proforma.pk)
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_expired(self):
        """Test proforma_to_invoice with expired proforma (line 335-337)"""
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

    def test_proforma_to_invoice_already_converted(self):
        """Test proforma_to_invoice with already converted proforma (line 340-343)"""
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

    def test_proforma_to_invoice_post_success(self):
        """Test successful proforma to invoice conversion (lines 345-400)"""
        test_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONVERT-001',
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
        invoice = Invoice.objects.filter(meta__proforma_id=test_proforma.id).first()
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
    # PAYMENT PROCESSING TESTS
    # ===============================================================================

    def test_process_proforma_payment_unauthenticated(self):
        """Test process_proforma_payment with None user (line 411)"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/payment/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        self.assertEqual(response.status_code, 403)

    def test_process_proforma_payment_unauthorized(self):
        """Test process_proforma_payment with unauthorized user (line 412)"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/payment/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        self.assertEqual(response.status_code, 403)

    def test_process_proforma_payment_success(self):
        """Test successful proforma payment processing (lines 414-449)"""
        post_data = {
            'amount': '119.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/payment/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        self.assertEqual(response.status_code, 200)
        
        # Verify invoice was created from proforma
        invoice = Invoice.objects.filter(meta__proforma_id=self.proforma.id).first()
        self.assertIsNotNone(invoice)
        self.assertEqual(invoice.status, 'paid')
        
        # Verify payment was created
        payment = Payment.objects.filter(invoice=invoice).first()
        self.assertIsNotNone(payment)
        self.assertEqual(payment.status, 'succeeded')

    def test_process_proforma_payment_no_invoice_created(self):
        """Test process_proforma_payment when conversion fails (line 447-448)"""
        post_data = {
            'amount': '119.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/proforma/{self.proforma.pk}/payment/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        # Mock proforma_to_invoice to not create invoice
        with patch('apps.billing.views.proforma_to_invoice') as mock_convert:
            mock_convert.return_value = None
            response = process_proforma_payment(request, self.proforma.pk)
            self.assertEqual(response.status_code, 400)

    def test_process_proforma_payment_invalid_method(self):
        """Test process_proforma_payment with invalid method (line 450)"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/payment/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_proforma_payment(request, self.proforma.pk)
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # PAYMENT LIST TESTS - FIX FIELD NAME BUG
    # ===============================================================================

    def test_payment_list_success(self):
        """Test payment_list view with correct field name"""
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

    def test_payment_list_unauthenticated(self):
        """Test payment_list with None user (line 830)"""
        request = self.factory.get('/payments/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = payment_list(request)
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # STAFF-REQUIRED VIEW TESTS
    # ===============================================================================

    def test_process_payment_unauthenticated(self):
        """Test process_payment with None user"""
        request = self.factory.post(f'/invoice/{self.invoice.pk}/payment/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        self.assertEqual(response.status_code, 302)

    def test_process_payment_unauthorized(self):
        """Test process_payment with unauthorized user (line 858-859)"""
        request = self.factory.post(f'/invoice/{self.invoice.pk}/payment/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        self.assertEqual(response.status_code, 403)

    def test_process_payment_success(self):
        """Test successful payment processing (lines 861-884)"""
        post_data = {
            'amount': '150.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/invoice/{self.invoice.pk}/payment/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        self.assertEqual(response.status_code, 200)
        
        # Verify payment was created
        payment = Payment.objects.filter(invoice=self.invoice).first()
        self.assertIsNotNone(payment)
        self.assertEqual(payment.amount_cents, 15000)

    def test_process_payment_invalid_method(self):
        """Test process_payment with invalid method (line 885)"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/payment/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # REPORTS TESTS
    # ===============================================================================

    def test_billing_reports_unauthenticated(self):
        """Test billing_reports with None user (lines 894-895)"""
        request = self.factory.get('/billing/reports/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = billing_reports(request)
        self.assertEqual(response.status_code, 302)

    def test_billing_reports_success(self):
        """Test billing reports view (lines 897-918)"""
        # Create paid invoice for reporting
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-REPORT-001',
            status='paid',
            total_cents=20000
        )
        
        request = self.factory.get('/billing/reports/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = billing_reports(request)
        self.assertEqual(response.status_code, 200)

    def test_vat_report_unauthenticated(self):
        """Test vat_report with None user (lines 927-928)"""
        request = self.factory.get('/billing/vat-report/')
        request.user = None
        request = self.add_middleware_to_request(request)
        
        response = vat_report(request)
        self.assertEqual(response.status_code, 302)

    def test_vat_report_success(self):
        """Test VAT report view (lines 930-953)"""
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
    # EDGE CASE TESTS FOR HELPER FUNCTIONS
    # ===============================================================================

    def test_validate_customer_assignment_no_customer_id(self):
        """Test _validate_customer_assignment with no customer_id (line 469)"""
        customer, error_response = _validate_customer_assignment(self.user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_with_proforma_pk(self):
        """Test _validate_customer_assignment error with proforma_pk (lines 474-477)"""
        customer, error_response = _validate_customer_assignment(self.user, '99999', self.proforma.pk)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_validate_customer_assignment_no_access_with_proforma_pk(self):
        """Test _validate_customer_assignment no access with proforma_pk (lines 481-484)"""
        other_customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Company SRL',
            status='active'
        )
        
        customer, error_response = _validate_customer_assignment(
            self.no_access_user, str(other_customer.pk), self.proforma.pk
        )
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

    def test_update_proforma_basic_info_empty_values(self):
        """Test _update_proforma_basic_info with empty values (lines 492-495)"""
        original_name = self.proforma.bill_to_name
        
        request_data = {
            'bill_to_name': '',  # Empty value should not update
            'bill_to_email': 'new@email.com',  # Non-empty should update
        }
        
        _update_proforma_basic_info(self.proforma, request_data)
        
        self.assertEqual(self.proforma.bill_to_name, original_name)  # Should remain unchanged
        self.assertEqual(self.proforma.bill_to_email, 'new@email.com')  # Should be updated

    def test_process_valid_until_date_no_key(self):
        """Test _process_valid_until_date with missing key (line 520)"""
        valid_until, errors = _process_valid_until_date({})
        
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    # ===============================================================================
    # PDF AND EMAIL TESTS
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

    def test_proforma_send_success(self):
        """Test successful proforma send (lines 715-718)"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_send(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])

    def test_proforma_send_unauthorized(self):
        """Test proforma send with unauthorized user (line 713)"""
        request = self.factory.post(f'/proforma/{self.proforma.pk}/send/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_send(request, self.proforma.pk)
        self.assertEqual(response.status_code, 403)

    def test_proforma_send_invalid_method(self):
        """Test proforma send with invalid method (line 720)"""
        request = self.factory.get(f'/proforma/{self.proforma.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_send(request, self.proforma.pk)
        self.assertEqual(response.status_code, 405)

    def test_invoice_send_success(self):
        """Test successful invoice send (lines 780-787)"""
        request = self.factory.post(f'/invoice/{self.invoice.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_send(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        # Verify sent_at timestamp was updated
        self.invoice.refresh_from_db()
        self.assertIsNotNone(self.invoice.sent_at)

    def test_invoice_send_unauthorized(self):
        """Test invoice send with unauthorized user (line 777-778)"""
        request = self.factory.post(f'/invoice/{self.invoice.pk}/send/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_send(request, self.invoice.pk)
        self.assertEqual(response.status_code, 403)

    def test_invoice_send_invalid_method(self):
        """Test invoice send with invalid method (line 789)"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/send/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = invoice_send(request, self.invoice.pk)
        self.assertEqual(response.status_code, 405)

    # ===============================================================================
    # E-FACTURA TESTS
    # ===============================================================================

    def test_generate_e_factura_success(self):
        """Test e-Factura XML generation (lines 797-820)"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/e-factura/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = generate_e_factura(request, self.invoice.pk)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/xml')
        self.assertIn('e_factura_', response['Content-Disposition'])
        
        # Verify XML content contains invoice information
        content = response.content.decode('utf-8')
        self.assertIn('INV-FINAL-001', content)
        self.assertIn('<?xml version="1.0" encoding="UTF-8"?>', content)

    def test_generate_e_factura_unauthorized(self):
        """Test e-Factura generation with unauthorized user (lines 800-802)"""
        request = self.factory.get(f'/invoice/{self.invoice.pk}/e-factura/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        response = generate_e_factura(request, self.invoice.pk)
        self.assertEqual(response.status_code, 302)

    # ===============================================================================
    # ADDITIONAL HELPER FUNCTION TESTS
    # ===============================================================================

    def test_get_accessible_customer_ids_empty_queryset(self):
        """Test _get_accessible_customer_ids with empty queryset result"""
        # Create user with no customer access
        empty_user = User.objects.create_user(
            email='empty@test.ro',
            password='testpass'
        )
        
        customer_ids = _get_accessible_customer_ids(empty_user)
        self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_list_result(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns list"""
        # Mock get_accessible_customers to return a list instead of QuerySet
        with patch.object(self.user, 'get_accessible_customers', return_value=[self.customer]):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_empty_list_result(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns empty list"""
        with patch.object(self.user, 'get_accessible_customers', return_value=[]):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])

    def test_get_accessible_customer_ids_none_result(self):
        """Test _get_accessible_customer_ids when get_accessible_customers returns None"""
        with patch.object(self.user, 'get_accessible_customers', return_value=None):
            customer_ids = _get_accessible_customer_ids(self.user)
            self.assertEqual(customer_ids, [])
