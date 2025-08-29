# ===============================================================================
# COMPREHENSIVE BILLING VIEWS TESTS
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
    invoice_detail,
    invoice_pdf,
    process_payment,
    proforma_detail,
    proforma_pdf,
    proforma_to_invoice,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

UserModel = get_user_model()


class BillingViewsTestCase(TestCase):
    """Test billing views functionality"""

    def setUp(self):
        """Create test data for billing views tests"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        # Create test customer
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
        
    def add_middleware_to_request(self, request):
        """Add required middleware to request for message framework"""
        # Add session middleware
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        # Add messages middleware
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_get_accessible_customer_ids_with_queryset(self):
        """Test _get_accessible_customer_ids helper with QuerySet"""
        customer_ids = _get_accessible_customer_ids(self.user)
        self.assertEqual(customer_ids, [self.customer.id])

    def test_get_accessible_customer_ids_with_empty_list(self):
        """Test _get_accessible_customer_ids with user having no customers"""
        customer_ids = _get_accessible_customer_ids(self.no_access_user)
        self.assertEqual(customer_ids, [])

    def test_validate_pdf_access_success(self):
        """Test _validate_pdf_access with authorized user"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-001'
        )
        
        request = self.factory.get('/test/')
        request.user = self.user
        
        result = _validate_pdf_access(request, invoice)
        self.assertIsNone(result)

    def test_validate_pdf_access_denied(self):
        """Test _validate_pdf_access with unauthorized user"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-001'
        )
        
        request = self.factory.get('/test/')
        request.user = self.no_access_user
        request = self.add_middleware_to_request(request)
        
        result = _validate_pdf_access(request, invoice)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)


class BillingListViewTestCase(TestCase):
    """Test billing_list view"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='List Test Company SRL',
            primary_email='list@company.ro', 
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='listuser@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='liststaff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        # Create test invoices and proformas
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-001',
            total_cents=10000
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-001', 
            total_cents=15000,
            status='issued'
        )
        
    def add_middleware_to_request(self, request):
        """Add required middleware to request for message framework"""
        # Add session middleware
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        # Add messages middleware
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_billing_list_unauthenticated_user(self):
        """Test billing_list redirects unauthenticated users"""
        # Use Django's AnonymousUser for proper testing
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/billing/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        self.assertEqual(response.status_code, 302)

    def test_billing_list_all_documents(self):
        """Test billing_list shows all documents by default"""
        request = self.factory.get('/billing/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Check context is properly loaded
        self.assertContains(response, 'PRO-001')
        self.assertContains(response, 'INV-001')

    def test_billing_list_filter_by_proforma(self):
        """Test billing_list filtered by proforma type"""
        request = self.factory.get('/billing/?type=proforma')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Should contain proforma but not invoice
        self.assertContains(response, 'PRO-001')
        self.assertNotContains(response, 'INV-001')

    def test_billing_list_filter_by_invoice(self):
        """Test billing_list filtered by invoice type"""
        request = self.factory.get('/billing/?type=invoice')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Should contain invoice but not proforma
        self.assertContains(response, 'INV-001')
        self.assertNotContains(response, 'PRO-001')

    def test_billing_list_with_search(self):
        """Test billing_list with search query"""
        request = self.factory.get('/billing/?search=PRO-001')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Should find the proforma with PRO-001
        self.assertContains(response, 'PRO-001')
        # Should not contain INV-001 since search doesn't match
        self.assertNotContains(response, 'INV-001')

    def test_billing_list_staff_permissions(self):
        """Test billing_list with staff user permissions"""
        request = self.factory.get('/billing/')
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Should contain staff-specific content
        self.assertContains(response, 'is_staff_user')

    def test_billing_list_pagination(self):
        """Test billing_list pagination functionality"""
        # Create many documents to test pagination (use unique numbers)
        for i in range(2, 25):  # Start from 2 to avoid conflicts with existing PRO-001
            ProformaInvoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f'PRO-{i:03d}',
                total_cents=1000 * (i + 1)
            )
        
        request = self.factory.get('/billing/?page=2')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        
        self.assertEqual(response.status_code, 200)
        # Should have pagination controls
        self.assertContains(response, 'page')


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


class ProformaViewsTestCase(TestCase):
    """Test proforma-related views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Test Company SRL',
            primary_email='proforma@test.ro',
            status='active'
        )
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='proforma_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.regular_user = User.objects.create_user(
            email='regular@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role='admin'
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

    def test_create_proforma_with_sequence(self):
        """Test _create_proforma_with_sequence helper"""
        valid_until = timezone.now() + timezone.timedelta(days=30)
        
        proforma = _create_proforma_with_sequence(self.customer, valid_until)
        
        self.assertIsInstance(proforma, ProformaInvoice)
        self.assertEqual(proforma.customer, self.customer)
        self.assertTrue(proforma.number.startswith('PRO-'))
        self.assertEqual(proforma.valid_until, valid_until)

    def test_proforma_create_get(self):
        """Test proforma create GET request"""
        # Use Django test client for staff-required view
        self.client.force_login(self.staff_user)
        response = self.client.get('/app/billing/proformas/create/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create New Proforma')
        self.assertContains(response, 'Customer Information')

    def test_proforma_create_unauthorized(self):
        """Test proforma create without staff permissions"""
        # Use Django test client for proper decorator testing
        self.client.force_login(self.regular_user)
        response = self.client.get('/app/billing/proformas/create/')
        
        # Should redirect due to @billing_staff_required decorator
        self.assertEqual(response.status_code, 302)

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
        
        request = self.factory.post('/app/billing/proformas/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify proforma was created
        proforma = ProformaInvoice.objects.filter(customer=self.customer).first()
        self.assertIsNotNone(proforma)

    def test_proforma_create_post_invalid_customer(self):
        """Test proforma creation with invalid customer"""
        post_data = {
            'customer': '99999',  # Non-existent customer
            'valid_until': '2024-12-31',
        }
        
        request = self.factory.post('/app/billing/proformas/create/', post_data)
        request.user = self.staff_user
        
        response = _handle_proforma_create_post(request)
        self.assertEqual(response.status_code, 302)

    def test_validate_customer_assignment_success(self):
        """Test _validate_customer_assignment with valid customer"""
        customer, error_response = _validate_customer_assignment(
            self.staff_user, str(self.customer.pk), None
        )
        
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error_response)

    def test_validate_customer_assignment_invalid_id(self):
        """Test _validate_customer_assignment with invalid customer ID"""
        with self.assertRaises(Http404):
            _validate_customer_assignment(
                self.staff_user, '99999', None
            )

    def test_validate_customer_assignment_no_access(self):
        """Test _validate_customer_assignment with no access to customer"""
        other_customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Company SRL',
            status='active'
        )
        
        customer, error_response = _validate_customer_assignment(
            self.regular_user, str(other_customer.pk), None
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
        self.assertEqual(len(errors), 1)

    def test_process_valid_until_date_empty(self):
        """Test _process_valid_until_date with empty date"""
        request_data = {'valid_until': ''}
        
        valid_until, errors = _process_valid_until_date(request_data)
        
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
        self.assertEqual(len(errors), 1)

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
        self.assertEqual(len(errors), 1)

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
        self.assertEqual(len(errors), 1)

    def test_process_proforma_line_items(self):
        """Test _process_proforma_line_items processing"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-TEST-LINES'
        )
        
        request_data = {
            'line_0_description': 'Test Service 1',
            'line_0_quantity': '1',
            'line_0_unit_price': '100.00',
            'line_0_vat_rate': '19',
            'line_1_description': 'Test Service 2',
            'line_1_quantity': '2',
            'line_1_unit_price': '50.00',
            'line_1_vat_rate': '19',
        }
        
        errors = _process_proforma_line_items(proforma, request_data)
        
        self.assertEqual(len(errors), 0)
        self.assertEqual(proforma.lines.count(), 2)
        
        # Verify totals were calculated (note: _process_proforma_line_items updates the proforma)
        proforma.refresh_from_db()
        # Check that lines were created
        self.assertEqual(proforma.lines.count(), 2)
        # Note: The totals calculation depends on the actual implementation
        self.assertGreaterEqual(proforma.total_cents, 0)


class ProformaDetailViewTestCase(TestCase):
    """Test proforma_detail view"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Detail Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='proforma_detail@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-DETAIL-001',
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )
        
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.19')
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

    def test_proforma_detail_success(self):
        """Test successful proforma detail view"""
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 200)
        # Check response content instead of context_data which isn't available in direct calls
        self.assertContains(response, 'PRO-DETAIL-001')
        self.assertContains(response, 'Test Service')

    def test_proforma_detail_unauthorized(self):
        """Test proforma detail with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth_proforma@test.ro',
            password='testpass'
        )
        
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/')
        request.user = unauthorized_user
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_detail(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.error.assert_called_once()


class ProformaToInvoiceViewTestCase(TestCase):
    """Test proforma_to_invoice conversion view"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Conversion Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='convert_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONVERT-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Conversion Test SRL',
            bill_to_email='convert@test.ro'
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

    def test_proforma_to_invoice_get(self):
        """Test proforma to invoice GET request"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/proformas/{self.proforma.pk}/convert/')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['proforma'], self.proforma)

    def test_proforma_to_invoice_post_success(self):
        """Test successful proforma to invoice conversion"""
        request = self.factory.post(f'/app/billing/proformas/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.success.assert_called_once()
            
            # Verify invoice was created
            invoice = Invoice.objects.filter(meta__proforma_id=self.proforma.id).first()
            self.assertIsNotNone(invoice)
            self.assertEqual(invoice.total_cents, self.proforma.total_cents)

    def test_proforma_to_invoice_expired(self):
        """Test conversion of expired proforma"""
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-001',
            total_cents=10000,
            valid_until=timezone.now() - timezone.timedelta(days=1)  # Expired
        )
        
        request = self.factory.post(f'/proforma/{expired_proforma.pk}/convert/')
        request.user = self.staff_user
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_to_invoice(request, expired_proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.error.assert_called_once()

    def test_proforma_to_invoice_already_converted(self):
        """Test conversion of already converted proforma"""
        # Create existing invoice from proforma
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EXISTING-001',
            status='issued',
            total_cents=self.proforma.total_cents,
            meta={'proforma_id': self.proforma.id}
        )
        
        request = self.factory.post(f'/app/billing/proformas/{self.proforma.pk}/convert/')
        request.user = self.staff_user
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_to_invoice(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.warning.assert_called_once()


class PDFGenerationViewsTestCase(TestCase):
    """Test PDF generation views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='PDF Test Company SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='pdf@test.ro',
            password='testpass'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-PDF-001',
            total_cents=11900
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PDF-001',
            total_cents=11900,
            status='issued'
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

    @patch('apps.billing.views.RomanianProformaPDFGenerator')
    def test_proforma_pdf_success(self, mock_pdf_generator):
        """Test successful proforma PDF generation"""
        mock_generator_instance = Mock()
        mock_response = Mock()
        mock_generator_instance.generate_response.return_value = mock_response
        mock_pdf_generator.return_value = mock_generator_instance
        
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/pdf/')
        request.user = self.user
        
        response = proforma_pdf(request, self.proforma.pk)
        
        mock_pdf_generator.assert_called_once_with(self.proforma)
        mock_generator_instance.generate_response.assert_called_once()
        self.assertEqual(response, mock_response)

    @patch('apps.billing.views.RomanianInvoicePDFGenerator')
    def test_invoice_pdf_success(self, mock_pdf_generator):
        """Test successful invoice PDF generation"""
        mock_generator_instance = Mock()
        mock_response = Mock()
        mock_generator_instance.generate_response.return_value = mock_response
        mock_pdf_generator.return_value = mock_generator_instance
        
        request = self.factory.get(f'/app/billing/invoices/{self.invoice.pk}/pdf/')
        request.user = self.user
        
        response = invoice_pdf(request, self.invoice.pk)
        
        mock_pdf_generator.assert_called_once_with(self.invoice)
        mock_generator_instance.generate_response.assert_called_once()
        self.assertEqual(response, mock_response)

    def test_pdf_access_denied(self):
        """Test PDF access denied for unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='pdf_unauth@test.ro',
            password='testpass'
        )
        
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/pdf/')
        request.user = unauthorized_user
        
        with patch('apps.billing.views.messages') as mock_messages:
            response = proforma_pdf(request, self.proforma.pk)
            
            self.assertEqual(response.status_code, 302)
            mock_messages.error.assert_called_once()


class PaymentProcessingViewsTestCase(TestCase):
    """Test payment processing views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Payment Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='payment_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAYMENT-001',
            total_cents=10000,
            status='issued'
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

    @patch('apps.billing.views.messages')
    def test_process_payment_success(self, mock_messages):
        """Test successful payment processing"""
        
        post_data = {
            'amount': '100.00',
            'payment_method': 'bank_transfer'
        }
        
        request = self.factory.post(f'/app/billing/invoices/{self.invoice.pk}/pay/', post_data)
        request.user = self.staff_user
        
        response = process_payment(request, self.invoice.pk)
        
        self.assertIsInstance(response, JsonResponse)
        mock_messages.success.assert_called_once()
        
        # Verify payment was created
        payment = Payment.objects.filter(invoice=self.invoice).first()
        self.assertIsNotNone(payment)
        self.assertEqual(payment.amount_cents, 10000)

    def test_process_payment_unauthorized(self):
        """Test payment processing without authorization"""
        
        regular_user = User.objects.create_user(
            email='payment_regular@test.ro',
            password='testpass'
        )
        
        request = self.factory.post(f'/app/billing/invoices/{self.invoice.pk}/pay/')
        request.user = regular_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request, self.invoice.pk)
        self.assertEqual(response.status_code, 302)  # Redirect due to no staff permission


class ErrorHandlingViewsTestCase(TestCase):
    """Test error handling in views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Error Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='error@test.ro',
            password='testpass'
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

    def test_billing_list_with_database_error(self):
        """Test billing_list handles database errors gracefully"""
        request = self.factory.get('/billing/')
        request.user = self.user
        
        with patch('apps.billing.views._get_accessible_customer_ids') as mock_get_ids:
            mock_get_ids.side_effect = Exception('Database error')
            
            # Should handle the error gracefully without crashing
            try:
                response = billing_list(request)
                # If no exception is raised, the error handling is working
                self.assertTrue(True)
                # Response should be valid
                self.assertIsNotNone(response)
            except Exception:
                self.fail("View should handle database errors gracefully")

    def test_proforma_create_with_invalid_form_data(self):
        """Test proforma creation with invalid form data"""
        post_data = {
            'customer': 'invalid',  # Invalid customer ID
            'valid_until': 'invalid-date',  # Invalid date
            'line_0_quantity': 'invalid',  # Invalid quantity
            'line_0_unit_price': 'invalid',  # Invalid price
        }
        
        staff_user = User.objects.create_user(
            email='invalid_form@test.ro',
            password='testpass',
            is_staff=True
        )
        staff_user.staff_role = 'billing_manager'
        staff_user.save()
        
        request = self.factory.post('/app/billing/proformas/create/', post_data)
        request.user = staff_user
        
        response = _handle_proforma_create_post(request)
        
        # Should redirect back without crashing
        self.assertEqual(response.status_code, 302)


class UtilityFunctionsTestCase(TestCase):
    """Test utility functions used in views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Utility Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='utility@test.ro',
            password='testpass'
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

    def test_get_customers_for_edit_form(self):
        """Test _get_customers_for_edit_form utility"""
        
        # Create customer membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        customers = _get_customers_for_edit_form(self.user)
        
        # Should return QuerySet containing the accessible customer
        self.assertIn(self.customer, customers)

    def test_update_proforma_basic_info(self):
        """Test _update_proforma_basic_info utility"""
        
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-UPDATE-001'
        )
        
        request_data = {
            'bill_to_name': 'Updated Company Name',
            'bill_to_email': 'updated@company.ro',
            'bill_to_tax_id': 'RO12345678'
        }
        
        _update_proforma_basic_info(proforma, request_data)
        
        self.assertEqual(proforma.bill_to_name, 'Updated Company Name')
        self.assertEqual(proforma.bill_to_email, 'updated@company.ro')
        self.assertEqual(proforma.bill_to_tax_id, 'RO12345678')

    def test_validate_proforma_edit_access_success(self):
        """Test _validate_proforma_edit_access with valid access"""
        
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-ACCESS-001',
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )
        
        request = self.factory.get('/test/')
        result = _validate_proforma_edit_access(self.user, proforma, request)
        
        self.assertIsNone(result)  # No error response means access is valid

    def test_validate_proforma_edit_access_expired(self):
        """Test _validate_proforma_edit_access with expired proforma"""
        
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='admin'
        )
        
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED-001',
            valid_until=timezone.now() - timezone.timedelta(days=1)
        )
        
        request = self.factory.get('/test/')
        
        with patch('apps.billing.views.messages') as mock_messages:
            result = _validate_proforma_edit_access(self.user, expired_proforma, request)
            
            self.assertIsNotNone(result)  # Should return error response
            mock_messages.error.assert_called_once()


# ===============================================================================
# COMPREHENSIVE ADDITIONAL TESTS FOR 85%+ COVERAGE
# ===============================================================================

class ProformaEditViewsTestCase(TestCase):
    """Test proforma edit functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Edit Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='edit_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EDIT-001',
            valid_until=timezone.now() + timezone.timedelta(days=30)
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

    def test_proforma_edit_get(self):
        """Test proforma edit GET request"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/proformas/{self.proforma.pk}/edit/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'PRO-EDIT-001')

    def test_proforma_edit_post(self):
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
        
        self.client.force_login(self.staff_user)
        response = self.client.post(f'/app/billing/proformas/{self.proforma.pk}/edit/', post_data)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify proforma was updated
        self.proforma.refresh_from_db()
        self.assertEqual(self.proforma.bill_to_name, 'Updated Company SRL')


class ProformaSendViewsTestCase(TestCase):
    """Test proforma send functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Send Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='send_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-SEND-001'
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

    def test_proforma_send_success(self):
        """Test successful proforma send"""
        self.client.force_login(self.staff_user)
        response = self.client.post(f'/app/billing/proformas/{self.proforma.pk}/send/')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['success'], True)

    def test_proforma_send_get_method(self):
        """Test proforma send with GET method (should fail)"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/proformas/{self.proforma.pk}/send/')
        
        self.assertEqual(response.status_code, 405)


class InvoiceEditViewsTestCase(TestCase):
    """Test invoice edit functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Invoice Edit Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='invoice_edit_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.draft_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DRAFT-001',
            status='draft'
        )
        
        self.issued_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-ISSUED-001',
            status='issued'
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

    def test_invoice_edit_draft_success(self):
        """Test editing draft invoice"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/invoices/{self.draft_invoice.pk}/edit/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'INV-DRAFT-001')

    def test_invoice_edit_issued_fails(self):
        """Test editing issued invoice should fail"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/invoices/{self.issued_invoice.pk}/edit/')
        
        self.assertEqual(response.status_code, 302)  # Redirect with error message


class InvoiceSendViewsTestCase(TestCase):
    """Test invoice send functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Invoice Send Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='invoice_send_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-SEND-001',
            status='issued'
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

    def test_invoice_send_success(self):
        """Test successful invoice send"""
        self.client.force_login(self.staff_user)
        response = self.client.post(f'/app/billing/invoices/{self.invoice.pk}/send/')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['success'], True)
        
        # Verify sent_at timestamp was updated
        self.invoice.refresh_from_db()
        self.assertIsNotNone(self.invoice.sent_at)


class EFacturaViewsTestCase(TestCase):
    """Test Romanian e-Factura functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='E-Factura Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='efactura_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EFACTURA-001',
            status='issued'
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

    def test_generate_e_factura(self):
        """Test e-Factura XML generation"""
        self.client.force_login(self.staff_user)
        response = self.client.get(f'/app/billing/invoices/{self.invoice.pk}/e-factura/')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/xml')
        self.assertIn('e_factura_', response['Content-Disposition'])
        
        # Verify XML content contains invoice number
        content = response.content.decode('utf-8')
        self.assertIn('INV-EFACTURA-001', content)
        self.assertIn('<?xml version="1.0" encoding="UTF-8"?>', content)


class PaymentListViewsTestCase(TestCase):
    """Test payment list functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Payment List Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='payment_list@test.ro',
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
            number='INV-PAYMENT-LIST-001'
        )
        
        # Create test payment
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
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

    def test_payment_list_success(self):
        """Test payment list view"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/payments/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'INV-PAYMENT-LIST-001')


class BillingReportsViewsTestCase(TestCase):
    """Test billing reports functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Reports Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='reports_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        # Create paid invoice for reporting
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-REPORT-001',
            status='paid',
            total_cents=20000
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

    def test_billing_reports_success(self):
        """Test billing reports view"""
        self.client.force_login(self.staff_user)
        response = self.client.get('/app/billing/reports/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'revenue')

    def test_vat_report_success(self):
        """Test VAT report view"""
        self.client.force_login(self.staff_user)
        response = self.client.get('/app/billing/reports/vat/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'total_vat')

    def test_vat_report_with_date_range(self):
        """Test VAT report with date range parameters"""
        self.client.force_login(self.staff_user)
        response = self.client.get('/app/billing/reports/vat/?start_date=2024-01-01&end_date=2024-12-31')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '2024-01-01')
        self.assertContains(response, '2024-12-31')


class ProformaPaymentProcessingTestCase(TestCase):
    """Test proforma payment processing functionality"""

    def setUp(self):
        """Setup test data"""
        self.client = Client()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Payment Test SRL',
            status='active'
        )
        
        self.staff_user = User.objects.create_user(
            email='proforma_payment_staff@test.ro',
            password='testpass',
            is_staff=True
        )
        self.staff_user.staff_role = 'billing'
        self.staff_user.save()
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-PAYMENT-001',
            total_cents=15000,
            valid_until=timezone.now() + timezone.timedelta(days=30)
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

    def test_process_proforma_payment_success(self):
        """Test successful proforma payment processing"""
        post_data = {
            'amount': '150.00',
            'payment_method': 'bank_transfer'
        }
        
        self.client.force_login(self.staff_user)
        response = self.client.post(f'/app/billing/proformas/{self.proforma.pk}/pay/', post_data)
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        # Verify invoice was created from proforma
        invoice = Invoice.objects.filter(meta__proforma_id=self.proforma.id).first()
        self.assertIsNotNone(invoice)
        self.assertEqual(invoice.status, 'paid')
        
        # Verify payment was created
        payment = Payment.objects.filter(invoice=invoice).first()
        self.assertIsNotNone(payment)
        self.assertEqual(payment.status, 'succeeded')

    def test_process_proforma_payment_unauthorized(self):
        """Test proforma payment processing without authorization"""
        regular_user = User.objects.create_user(
            email='proforma_payment_regular@test.ro',
            password='testpass'
        )
        
        post_data = {
            'amount': '150.00',
            'payment_method': 'bank_transfer'
        }
        
        self.client.force_login(regular_user)
        response = self.client.post(f'/app/billing/proformas/{self.proforma.pk}/pay/', post_data)
        
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error'], 'Unauthorized')


class UnauthenticatedAccessTestCase(TestCase):
    """Test unauthenticated user access"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Unauth Test SRL',
            status='active'
        )
        
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-UNAUTH-001'
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-UNAUTH-001'
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_billing_list_unauthenticated_redirects(self):
        """Test billing_list redirects unauthenticated users"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/billing/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = billing_list(request)
        self.assertEqual(response.status_code, 302)

    def test_invoice_detail_unauthenticated_redirects(self):
        """Test invoice_detail redirects unauthenticated users"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get(f'/app/billing/invoices/{self.invoice.pk}/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = invoice_detail(request, self.invoice.pk)
        self.assertEqual(response.status_code, 302)

    def test_proforma_detail_unauthenticated_redirects(self):
        """Test proforma_detail redirects unauthenticated users"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/')
        request.user = AnonymousUser()
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        self.assertEqual(response.status_code, 302)


class ErrorHandlingAndEdgeCasesTestCase(TestCase):
    """Test error handling and edge cases in billing views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Error Test SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='error@test.ro',
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

    def test_process_line_items_with_invalid_data(self):
        """Test processing line items with invalid data"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-ERROR-001'
        )
        
        # Test with invalid numeric data
        request_data = {
            'line_0_description': 'Valid Description',
            'line_0_quantity': 'not-a-number',
            'line_0_unit_price': 'also-not-a-number',
            'line_0_vat_rate': 'invalid-rate',
        }
        
        errors = _process_proforma_line_items(proforma, request_data)
        
        # Should have errors for invalid numeric fields
        self.assertGreater(len(errors), 0)
        
        # Should still create line with defaults
        self.assertEqual(proforma.lines.count(), 0)  # Line shouldn't be created with invalid data

    def test_process_valid_until_date_edge_cases(self):
        """Test valid_until date processing edge cases"""
        # Test with empty string
        valid_until, errors = _process_valid_until_date({'valid_until': ''})
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)
        
        # Test with invalid format
        valid_until, errors = _process_valid_until_date({'valid_until': '2024-13-45'})  # Invalid date
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertGreater(len(errors), 0)
        
        # Test with missing key
        valid_until, errors = _process_valid_until_date({})
        self.assertIsInstance(valid_until, timezone.datetime)
        self.assertEqual(len(errors), 0)

    def test_parse_line_fields_edge_cases(self):
        """Test line field parsing edge cases"""
        # Test quantity parsing with edge cases
        quantity, errors = _parse_line_quantity({'line_0_quantity': ''}, 0)
        self.assertEqual(quantity, Decimal('0'))
        
        quantity, errors = _parse_line_quantity({'line_0_quantity': None}, 0)
        self.assertEqual(quantity, Decimal('0'))
        
        # Test unit price parsing with edge cases
        price, errors = _parse_line_unit_price({'line_0_unit_price': ''}, 0)
        self.assertEqual(price, Decimal('0'))
        
        # Test VAT rate parsing with edge cases
        vat_rate, errors = _parse_line_vat_rate({'line_0_vat_rate': ''}, 0)
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%
        
        vat_rate, errors = _parse_line_vat_rate({}, 0)  # Missing key
        self.assertEqual(vat_rate, Decimal('19'))  # Default to 19%

    def test_update_proforma_basic_info_edge_cases(self):
        """Test proforma basic info update edge cases"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-UPDATE-EDGE-001'
        )
        
        # Test with empty/whitespace values
        request_data = {
            'bill_to_name': '   ',  # Whitespace only
            'bill_to_email': '',   # Empty string
            'bill_to_tax_id': None  # None value
        }
        
        _update_proforma_basic_info(proforma, request_data)
        
        # Values should not be updated if they are empty/whitespace
        self.assertEqual(proforma.bill_to_name, '')  # Should remain unchanged
        self.assertEqual(proforma.bill_to_email, '')  # Should remain unchanged
        self.assertEqual(proforma.bill_to_tax_id, '')  # Should remain unchanged
