"""
Comprehensive access control tests for PRAHO Platform security audit fixes.
Tests that customers cannot access staff-only functionality and data.
"""

from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, Invoice, ProformaInvoice
from apps.common.decorators import billing_staff_required, staff_required  # For testing decorator behavior
from apps.customers.models import Customer
from apps.provisioning.models import Server, Service, ServicePlan
from apps.tickets.models import Ticket, TicketComment
from apps.users.models import CustomerMembership

User = get_user_model()


class ComprehensiveAccessControlTestCase(TestCase):
    """Test comprehensive access control across the PRAHO platform"""

    def setUp(self):
        """Set up test data"""
        # Create currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )

        # Create staff user
        self.staff_user = User.objects.create_user(
            email='staff@praho.ro',
            password='staffpass123',
            first_name='Staff',
            last_name='Member',
            is_staff=True,
            staff_role='admin'
        )

        # Create customer user
        self.customer_user = User.objects.create_user(
            email='customer@example.com',
            password='customerpass123',
            first_name='Customer',
            last_name='User'
        )

        # Create customer organization
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company Ltd',
            primary_email='customer@example.com'
        )

        # Link customer user to customer organization
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

        # Create another customer that our customer user shouldn't access
        self.other_customer = Customer.objects.create(
            name='Other Customer',
            company_name='Other Company Ltd',
            primary_email='other@example.com'
        )

        # Create test invoice and proforma
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-001',
            currency=self.currency,
            status='issued',
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,        # 19.00 RON
            total_cents=11900,     # 119.00 RON
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30)
        )

        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-2024-001',
            currency=self.currency,
            subtotal_cents=15000,  # 150.00 RON
            tax_cents=2850,        # 28.50 RON
            total_cents=17850,     # 178.50 RON
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )

        # Create service plan and service
        self.service_plan = ServicePlan.objects.create(
            name='Basic Hosting',
            plan_type='shared_hosting',
            price_monthly=Decimal('50.00'),
            is_active=True
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name='Test Hosting Service',
            domain='example.com',
            username='testuser123',
            price=Decimal('50.00'),
            status='active'
        )

        # Create server
        self.server = Server.objects.create(
            name='srv-01',
            hostname='srv-01.praho.ro',
            server_type='shared',
            primary_ip='192.168.1.100',
            location='Bucharest',
            datacenter='DC1',
            cpu_model='Intel Xeon E5-2690',
            cpu_cores=8,
            ram_gb=32,
            disk_type='SSD',
            disk_capacity_gb=500,
            status='active'
        )

        # Create ticket
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            title='Test support ticket',
            description='This is a test ticket',
            priority='medium',
            status='open',
            created_by=self.customer_user
        )

        self.client = Client()

    def test_proforma_editing_restricted_to_staff(self):
        """Test that customers cannot edit proformas"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access proforma edit page
        url = reverse('billing:proforma_edit', args=[self.proforma.pk])
        response = self.client.get(url)

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

        # Check error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('staff privileges required' in str(msg).lower() for msg in messages))

    def test_proforma_creation_restricted_to_staff(self):
        """Test that customers cannot create proformas"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access proforma create page
        url = reverse('billing:proforma_create')
        response = self.client.get(url)

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_proforma_to_invoice_conversion_restricted_to_staff(self):
        """Test that customers cannot convert proformas to invoices"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access proforma conversion page
        url = reverse('billing:proforma_to_invoice', args=[self.proforma.pk])
        response = self.client.get(url)

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_payment_processing_restricted_to_staff(self):
        """Test that customers cannot manually process payments"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to process payment
        url = reverse('billing:process_payment', args=[self.invoice.pk])
        response = self.client.post(url, {
            'amount': '100.00',
            'payment_method': 'bank_transfer'
        })

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_customer_creation_restricted_to_staff(self):
        """Test that customers cannot create new customer records"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access customer creation page
        url = reverse('customers:create')
        response = self.client.get(url)

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_customer_deletion_restricted_to_staff(self):
        """Test that customers cannot delete customer records"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access customer deletion page
        url = reverse('customers:delete', args=[self.customer.id])
        response = self.client.get(url)

        # Should be redirected to dashboard with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_service_management_restricted_to_staff(self):
        """Test that customers cannot create, edit, or manage services"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to create service
        url = reverse('provisioning:service_create')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # Try to edit service
        url = reverse('provisioning:service_edit', args=[self.service.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # Try to suspend service
        url = reverse('provisioning:service_suspend', args=[self.service.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_server_infrastructure_restricted_to_staff(self):
        """Test that customers cannot view server infrastructure"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access server list
        url = reverse('provisioning:servers')
        response = self.client.get(url)

        # Should return 403 due to staff_required decorator
        self.assertEqual(response.status_code, 403)

    def test_financial_reports_restricted_to_staff(self):
        """Test that customers cannot access financial reports"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access billing reports
        url = reverse('billing:reports')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

        # Try to access VAT report
        url = reverse('billing:vat_report')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)

    def test_internal_ticket_notes_restricted_to_staff(self):
        """Test that customers cannot create internal notes on tickets"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to create internal note using reply_action (the view reads reply_action, not is_internal)
        url = reverse('tickets:reply', args=[self.ticket.pk])
        response = self.client.post(url, {
            'reply': 'This is an internal note',
            'reply_action': 'internal_note'
        })

        # Should be redirected back to ticket with error message
        self.assertEqual(response.status_code, 302)

        # Verify no internal note was created
        internal_comments = TicketComment.objects.filter(
            ticket=self.ticket,
            comment_type='internal'
        )
        self.assertEqual(internal_comments.count(), 0)

    def test_customer_can_only_access_own_data(self):
        """Test that customers can only access their own customer data"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Try to access another customer's detail page
        url = reverse('customers:detail', args=[self.other_customer.id])
        response = self.client.get(url)

        # Should get 404 to prevent enumeration attacks
        self.assertEqual(response.status_code, 404)

    def test_staff_has_access_to_restricted_functions(self):
        """Test that staff users can access all restricted functions"""
        # Login as staff
        self.client.login(email='staff@praho.ro', password='staffpass123')

        # Test proforma editing
        url = reverse('billing:proforma_edit', args=[self.proforma.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Test customer creation
        url = reverse('customers:create')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Test service management
        url = reverse('provisioning:service_create')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Test server infrastructure
        url = reverse('provisioning:servers')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Test financial reports
        url = reverse('billing:reports')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_proforma_edit_buttons_hidden_from_customers(self):
        """Test that proforma edit buttons are not shown to customers"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Access proforma detail page
        url = reverse('billing:proforma_detail', args=[self.proforma.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Check that can_edit is False in context
        self.assertFalse(response.context['can_edit'])
        self.assertFalse(response.context['can_convert'])

        # Check that edit buttons are not in the HTML
        self.assertNotIn(f'href="/billing/proformas/{self.proforma.pk}/edit/"', response.content.decode())

    def test_ticket_internal_note_checkbox_hidden_from_customers(self):
        """Test that internal note checkbox is not shown to customers in ticket forms"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')

        # Access ticket detail page
        url = reverse('tickets:detail', args=[self.ticket.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # Check that internal note checkbox is not in the HTML
        self.assertNotIn('name="is_internal"', response.content.decode())
        self.assertNotIn('Internal note', response.content.decode())

    def test_staff_can_create_internal_ticket_notes(self):
        """Test that staff users can create internal notes on tickets"""
        # Login as staff
        self.client.login(email='staff@praho.ro', password='staffpass123')

        # Create internal note using reply_action (the view reads reply_action, not is_internal)
        url = reverse('tickets:reply', args=[self.ticket.pk])
        response = self.client.post(url, {
            'reply': 'This is a staff internal note',
            'reply_action': 'internal_note'
        })

        # Should be successful (redirect or success response)
        self.assertIn(response.status_code, [200, 302])

        # Verify internal note was created
        internal_comments = TicketComment.objects.filter(
            ticket=self.ticket,
            comment_type='internal'
        )
        self.assertEqual(internal_comments.count(), 1)
        self.assertEqual(internal_comments.first().content, 'This is a staff internal note')

    def tearDown(self):
        """Clean up test data"""
        # Clean up is handled by Django's TestCase automatically


class SecurityDecoratorsTestCase(TestCase):
    """Test the security decorators directly"""

    def setUp(self):
        """Set up test users"""
        self.staff_user = User.objects.create_user(
            email='staff@praho.ro',
            password='staffpass123',
            is_staff=True,
            staff_role='admin'
        )

        self.customer_user = User.objects.create_user(
            email='customer@example.com',
            password='customerpass123'
        )

        self.client = Client()

    def test_staff_required_decorator_allows_staff(self):
        """Test that staff_required decorator allows staff users"""
        # Create a simple view with staff_required decorator
        @staff_required
        def test_view(request):
            return HttpResponse('success')

        # Test with staff user
        self.client.login(email='staff@praho.ro', password='staffpass123')
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.staff_user

        response = test_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'success')

    def test_billing_staff_required_decorator_blocks_customers(self):
        """Test that billing_staff_required decorator blocks customer users"""
        # Create a simple view with billing_staff_required decorator
        @billing_staff_required
        def test_view(request):
            return HttpResponse('success')

        # Test with customer user - should be blocked
        self.client.login(email='customer@example.com', password='customerpass123')
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.customer_user

        # Add message storage to the request
        request.session = {}
        request._messages = FallbackStorage(request)

        response = test_view(request)
        self.assertEqual(response.status_code, 302)  # Redirect
        self.assertIn('/dashboard/', response.url)


if __name__ == '__main__':
    pytest.main([__file__])
