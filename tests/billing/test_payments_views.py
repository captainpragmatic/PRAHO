# ===============================================================================
# PAYMENT VIEWS TESTS - Feature-based organization
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
from apps.billing.payment_views import (
    process_payment,
)
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

UserModel = get_user_model()


class PaymentProcessingViewsTestCase(TestCase):
    """Test payment processing views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Payment Test Company SRL',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='payment@test.ro',
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
            number='INV-PAYMENT-001',
            total_cents=15000,
            status='issued'
        )
        
        # Add invoice line
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Payment Test Service',
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

    @patch('apps.billing.views.stripe.PaymentIntent.create')
    def test_process_payment_success(self, mock_payment_create):
        """Test successful payment processing"""
        mock_payment_create.return_value = Mock(
            id='pi_test_123',
            client_secret='pi_test_123_secret',
            status='requires_payment_method'
        )
        
        post_data = {
            'invoice_id': str(self.invoice.pk),
            'amount': '150.00',
            'payment_method': 'stripe'
        }
        
        request = self.factory.post('/app/billing/process-payment/', post_data)
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request)
        
        # Should return JSON response with payment intent
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, JsonResponse)

    def test_process_payment_unauthorized(self):
        """Test payment processing with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth_payment@test.ro',
            password='testpass'
        )
        
        post_data = {
            'invoice_id': str(self.invoice.pk),
            'amount': '150.00',
            'payment_method': 'stripe'
        }
        
        request = self.factory.post('/app/billing/process-payment/', post_data)
        request.user = unauthorized_user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request)
        
        # Should return error or redirect
        self.assertIn(response.status_code, [302, 403])

    def test_process_payment_invalid_amount(self):
        """Test payment processing with invalid amount"""
        post_data = {
            'invoice_id': str(self.invoice.pk),
            'amount': 'invalid_amount',
            'payment_method': 'stripe'
        }
        
        request = self.factory.post('/app/billing/process-payment/', post_data)
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request)
        
        # Should return error response
        self.assertIn(response.status_code, [400, 422])

    def test_process_payment_missing_invoice(self):
        """Test payment processing with missing invoice"""
        post_data = {
            'invoice_id': '99999',
            'amount': '150.00',
            'payment_method': 'stripe'
        }
        
        request = self.factory.post('/app/billing/process-payment/', post_data)
        request.user = self.user
        request = self.add_middleware_to_request(request)
        
        response = process_payment(request)
        
        # Should return 404 or error response
        self.assertIn(response.status_code, [404, 400])


class PaymentListViewsTestCase(TestCase):
    """Test payment list views"""

    def setUp(self):
        """Setup test data"""
        self.factory = RequestFactory()
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
        
        # Create invoice for payments
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-LIST-001',
            total_cents=10000,
            status='issued'
        )
        
        # Create test payments
        self.payment1 = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=5000,
            currency=self.currency,
            status='succeeded',
            created_at=timezone.now() - timezone.timedelta(days=1)
        )
        
        self.payment2 = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=3000,
            currency=self.currency,
            status='succeeded',
            created_at=timezone.now()
        )
        
        self.payment3 = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=2000,
            currency=self.currency,
            status='failed',
            created_at=timezone.now()
        )

    def add_middleware_to_request(self, request):
        """Add required middleware to request"""
        middleware = SessionMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        
        middleware = MessageMiddleware(lambda req: HttpResponse())
        middleware.process_request(request)
        return request

    def test_payment_list_success(self):
        """Test successful payment list view"""
        # Use Django test client for easier testing of list views
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/payments/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Payments')
        
        # Should show all payments for the customer
        payments = response.context['payments']
        self.assertEqual(len(payments), 3)

    def test_payment_list_filtering_by_status(self):
        """Test payment list filtering by status"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/payments/?status=succeeded')
        
        self.assertEqual(response.status_code, 200)
        
        # Should only show succeeded payments
        payments = response.context['payments']
        self.assertEqual(len(payments), 2)
        for payment in payments:
            self.assertEqual(payment.status, 'succeeded')

    def test_payment_list_filtering_by_invoice(self):
        """Test payment list filtering by invoice"""
        self.client.force_login(self.user)
        response = self.client.get(f'/app/billing/payments/?invoice={self.invoice.pk}')
        
        self.assertEqual(response.status_code, 200)
        
        # Should show all payments for the specific invoice
        payments = response.context['payments']
        self.assertEqual(len(payments), 3)
        for payment in payments:
            self.assertEqual(payment.invoice, self.invoice)

    def test_payment_list_unauthorized(self):
        """Test payment list with unauthorized user"""
        unauthorized_user = User.objects.create_user(
            email='unauth_list@test.ro',
            password='testpass'
        )
        
        self.client.force_login(unauthorized_user)
        response = self.client.get('/app/billing/payments/')
        
        self.assertEqual(response.status_code, 200)
        
        # Should show empty list for unauthorized user
        payments = response.context['payments']
        self.assertEqual(len(payments), 0)

    def test_payment_list_ordering(self):
        """Test payment list default ordering"""
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/payments/')
        
        self.assertEqual(response.status_code, 200)
        
        payments = list(response.context['payments'])
        # Should be ordered by created_at desc (newest first)
        self.assertTrue(payments[0].created_at >= payments[1].created_at)
        self.assertTrue(payments[1].created_at >= payments[2].created_at)

    def test_payment_list_pagination(self):
        """Test payment list pagination"""
        # Create many payments to test pagination
        for i in range(25):
            Payment.objects.create(
                customer=self.customer,
                invoice=self.invoice,
                amount_cents=1000 + i,
                currency=self.currency,
                status='succeeded'
            )
        
        self.client.force_login(self.user)
        response = self.client.get('/app/billing/payments/')
        
        self.assertEqual(response.status_code, 200)
        
        # Should show paginated results
        payments = response.context['payments']
        # Assuming 20 per page pagination
        self.assertLessEqual(len(payments), 20)