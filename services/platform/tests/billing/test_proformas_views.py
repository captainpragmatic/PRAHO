# ===============================================================================
# PROFORMA VIEWS TESTS - Feature-based organization
# ===============================================================================

from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, JsonResponse
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    ProformaInvoice,
    ProformaLine,
)
from apps.billing.views import (
    _create_proforma_with_sequence,
    _get_accessible_customer_ids,
    _get_customers_for_edit_form,
    _handle_proforma_create_post,
    _validate_financial_document_access_with_redirect as _validate_financial_document_access,
    _validate_proforma_edit_access,
    proforma_detail,
    proforma_pdf,
)
# Note: Some helper functions may have been moved to services or removed in refactoring
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

UserModel = get_user_model()


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
        response = self.client.get('/billing/proformas/create/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create New Proforma')
        self.assertContains(response, 'Customer Information')

    def test_proforma_create_unauthorized(self):
        """Test proforma create without staff permissions"""
        # Use Django test client for proper decorator testing
        self.client.force_login(self.regular_user)
        response = self.client.get('/billing/proformas/create/')
        
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
        
        request = self.factory.post('/billing/proformas/create/', post_data)
        request.user = self.staff_user
        request = self.add_middleware_to_request(request)
        
        response = _handle_proforma_create_post(request)
        
        self.assertEqual(response.status_code, 302)
        
        # Verify proforma was created
        proforma = ProformaInvoice.objects.get(customer=self.customer)
        self.assertEqual(proforma.bill_to_name, 'Test Company SRL')
        self.assertEqual(proforma.bill_to_email, 'test@company.ro')


class ProformaDetailViewTestCase(TestCase):
    """Test proforma_detail view"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Detail Test SRL',
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
            total_cents=15000,
            valid_until=timezone.now().date()
        )
        
        # Add proforma line
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Detail Test Service',
            quantity=1,
            unit_price_cents=12605,
            tax_rate=Decimal('0.19')
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
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
        self.assertContains(response, 'PRO-DETAIL-001')
        self.assertContains(response, 'Detail Test Service')

    def test_proforma_detail_unauthorized_user(self):
        """Test proforma detail with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth_detail@test.ro',
            password='testpass'
        )
        
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/')
        request.user = unauthorized_user
        request = self.add_middleware_to_request(request)
        
        response = proforma_detail(request, self.proforma.pk)
        
        self.assertEqual(response.status_code, 302)

    def test_proforma_detail_not_found(self):
        """Test proforma detail with non-existent proforma"""
        request = self.factory.get('/app/billing/proformas/99999/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        with self.assertRaises(Http404):
            proforma_detail(request, 99999)


class ProformaEditViewsTestCase(TestCase):
    """Test proforma edit functionality"""
    
    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Edit Test SRL',
        )
        
        self.user = User.objects.create_user(
            email='proforma_edit@test.ro',
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
            number='PRO-EDIT-001',
            total_cents=10000,
            valid_until=timezone.now() + timezone.timedelta(days=30)  # Future date
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_proforma_edit_access_authorized(self):
        """Test that authorized users can access proforma edit"""
        request = self.factory.get(f'/app/billing/proformas/{self.proforma.pk}/edit/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        result = _validate_proforma_edit_access(self.user, self.proforma, request)
        self.assertIsNone(result)  # None means access is allowed

    def test_proforma_edit_access_unauthorized(self):
        """Test that unauthorized users cannot access proforma edit"""
        other_customer = Customer.objects.create(
            customer_type='company',
            company_name='Other Edit Company SRL',
        )
        
        other_proforma = ProformaInvoice.objects.create(
            customer=other_customer,
            currency=self.currency,
            number='PRO-OTHER-001',
            total_cents=10000,
            valid_until=timezone.now().date()
        )
        
        request = self.factory.get(f'/app/billing/proformas/{other_proforma.pk}/edit/')
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        # Should return error response, not None
        error_response = _validate_proforma_edit_access(self.user, other_proforma, request)
        self.assertIsNotNone(error_response)
        self.assertEqual(error_response.status_code, 302)  # Redirect response

    def test_update_proforma_basic_info(self):
        """Test updating proforma basic information"""
        from apps.billing.proforma_service import ProformaService
        
        update_data = {
            'bill_to_name': 'Updated Company Name',
            'bill_to_email': 'updated@test.ro',
            'notes': 'Updated notes'
        }
        
        result = ProformaService.update_proforma(self.proforma, update_data, self.user)
        
        if result.is_err():
            self.fail(f"ProformaService.update_proforma failed: {result.unwrap_err()}")
        
        self.assertTrue(result.is_ok())
        self.proforma.refresh_from_db()
        self.assertEqual(self.proforma.bill_to_name, 'Updated Company Name')
        self.assertEqual(self.proforma.bill_to_email, 'updated@test.ro')
        self.assertEqual(self.proforma.notes, 'Updated notes')


class ProformaSendViewsTestCase(TestCase):
    """Test proforma sending functionality"""
    
    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Send Test SRL',
            primary_email='send@test.ro',
        )
        
        self.user = User.objects.create_user(
            email='proforma_send@test.ro',
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
            number='PRO-SEND-001',
            total_cents=10000,
            valid_until=timezone.now().date()
        )

    @patch('apps.billing.services.send_proforma_email')
    def test_proforma_send_success(self, mock_send_email):
        """Test successful proforma sending"""
        mock_send_email.return_value = True
        
        # This is a placeholder test as we need to check the actual view implementation
        # The view function for sending proformas would be tested here
        self.assertTrue(True)  # Placeholder assertion
        
    def test_proforma_send_validation(self):
        """Test proforma send validation"""
        # Test that only certain statuses allow sending
        self.assertEqual(self.proforma.status, 'draft')
        # Add actual validation tests when implementing the send functionality


class ProformaPaymentProcessingTestCase(TestCase):
    """Test proforma payment processing views"""
    
    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma Payment Test SRL',
        )
        
        self.user = User.objects.create_user(
            email='proforma_payment@test.ro',
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
            number='PRO-PAYMENT-001',
            total_cents=20000,
            valid_until=timezone.now().date(),
            status='sent'  # Set to sent for payment processing tests
        )

    def test_proforma_payment_processing_setup(self):
        """Test proforma payment processing setup"""
        # Test that proforma is ready for payment processing
        self.assertEqual(self.proforma.status, 'sent')
        self.assertEqual(self.proforma.total_cents, 20000)
        
    def test_proforma_payment_link_generation(self):
        """Test payment link generation for proforma"""
        # This would test the payment link generation functionality
        # when it's implemented in the views
        self.assertTrue(True)  # Placeholder assertion