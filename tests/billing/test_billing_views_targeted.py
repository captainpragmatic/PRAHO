"""
Targeted tests for specific uncovered lines in apps/billing/views.py

This test file focuses on achieving 85%+ coverage by targeting specific uncovered lines
using Django test client with proper authentication and minimal dependencies.

Current coverage: 59.96%
Target coverage: 85%+
Missing lines focus: 278-292, 327-400, 408-450, 894-918, 927-953
"""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.http import HttpResponse
from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency, Invoice, ProformaInvoice
from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


class BillingViewsTargetedTestCase(TestCase):
    """Targeted tests for specific uncovered lines"""

    def setUp(self):
        """Set up minimal test data"""
        # Create staff user with billing role (working authentication)
        self.staff_user = User.objects.create_user(
            email='staff@test.com',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        # Create regular user
        self.regular_user = User.objects.create_user(
            email='user@test.com',
            password='testpass123'
        )
        
        # Create EUR currency (required by models)
        self.eur_currency = Currency.objects.create(
            code='EUR',
            symbol='€',
            decimals=2
        )
        
        # Create customer (minimal setup)
        self.customer = Customer.objects.create(
            name='Test Business SRL',
            company_name='Test Business SRL',
            customer_type='company',
            status='active',
            primary_email='business@test.com'
        )
        
        # Create customer membership for regular user
        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role='admin'
        )
        
        self.client = Client()

    def test_proforma_create_get_lines_278_292(self):
        """Test proforma_create GET request - Lines 278-292"""
        self.client.force_login(self.staff_user)
        
        with patch('apps.billing.views._get_customers_for_edit_form') as mock_customers:
            mock_customers.return_value = [self.customer]
            
            url = reverse('billing:proforma_create')
            response = self.client.get(url)
            
            # Should hit lines 281-292 (GET branch)
            self.assertEqual(response.status_code, 200)
            mock_customers.assert_called_once()

    def test_proforma_create_post_lines_278_279(self):
        """Test proforma_create POST request - Lines 278-279"""
        self.client.force_login(self.staff_user)
        
        with patch('apps.billing.views._handle_proforma_create_post') as mock_handle:
            mock_handle.return_value = HttpResponse('OK')
            
            url = reverse('billing:proforma_create')
            response = self.client.post(url, {'customer': self.customer.id})
            
            # Should hit lines 278-279 (POST branch)
            mock_handle.assert_called_once()
            self.assertEqual(response.content, b'OK')

    def test_proforma_create_unauthenticated_redirect_lines_283_284(self):
        """Test proforma_create with unauthenticated user - Lines 283-284"""
        # Don't log in user
        url = reverse('billing:proforma_create')
        response = self.client.get(url)
        
        # Should redirect to login (decorator handles this)
        self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_lines_327_344(self):
        """Test proforma_to_invoice view setup - Lines 327-344"""
        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-2024-001',
            currency=self.eur_currency,
            subtotal_cents=100000,  # €1000.00
            tax_cents=19000,        # €190.00 (19% VAT)
            total_cents=119000      # €1190.00
        )
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:proforma_to_invoice', kwargs={'pk': proforma.pk})
        
        # Mock the user access check
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = self.client.get(url)
            
            # Should hit lines 327-344 (basic setup and checks)
            self.assertEqual(response.status_code, 200)

    def test_proforma_to_invoice_no_permission_lines_330_332(self):
        """Test proforma_to_invoice with no permission - Lines 330-332"""
        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-2024-002',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        # Login as regular user without access
        other_user = User.objects.create_user(
            email='other@test.com',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        self.client.force_login(other_user)
        url = reverse('billing:proforma_to_invoice', kwargs={'pk': proforma.pk})
        
        # Mock the access check to return False
        with patch.object(other_user, 'can_access_customer', return_value=False):
            response = self.client.get(url)
            
            # Should hit lines 330-332 (no permission redirect)
            self.assertEqual(response.status_code, 302)
            messages = list(get_messages(response.wsgi_request))
            self.assertTrue(any('permission' in str(message).lower() for message in messages))

    def test_proforma_to_invoice_already_converted_lines_340_343(self):
        """Test proforma_to_invoice when already converted - Lines 340-343"""
        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-2024-003',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        # Create existing invoice with proforma metadata
        existing_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-001',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000,
            meta={'proforma_id': proforma.id}
        )
        # Verify existing invoice was created
        self.assertIsNotNone(existing_invoice)
        self.assertEqual(existing_invoice.meta['proforma_id'], proforma.id)
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:proforma_to_invoice', kwargs={'pk': proforma.pk})
        
        with patch.object(self.staff_user, 'can_access_customer', return_value=True):
            response = self.client.get(url)
            
            # Should hit lines 340-343 (already converted redirect)
            self.assertEqual(response.status_code, 302)

    def test_proforma_to_invoice_post_success_lines_345_400(self):
        """Test proforma_to_invoice POST success - Lines 345-400"""
        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-2024-004',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:proforma_to_invoice', kwargs={'pk': proforma.pk})
        
        # Mock all the dependencies for successful conversion
        with patch.object(self.staff_user, 'can_access_customer', return_value=True), \
             patch('apps.billing.models.InvoiceSequence.objects.get_or_create') as mock_seq, \
             patch('apps.billing.models.Invoice.objects.create') as mock_invoice:
            
            # Mock sequence
            mock_sequence = Mock()
            mock_sequence.get_next_number.return_value = 'INV-2024-005'
            mock_seq.return_value = (mock_sequence, True)
            
            # Mock invoice creation
            mock_invoice_obj = Mock()
            mock_invoice_obj.pk = 123
            mock_invoice.return_value = mock_invoice_obj
            
            response = self.client.post(url)
            
            # Should hit lines 345-400 (POST processing)
            self.assertEqual(response.status_code, 302)  # Redirect after success

    @patch('apps.billing.views.process_payment')
    def test_process_payment_view_lines_408_450(self, mock_process):
        """Test process_payment view - Lines 408-450"""
        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-TEST',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        mock_process.return_value = {'success': True, 'payment_id': 456}
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:process_payment', kwargs={'pk': invoice.pk})
        
        response = self.client.post(url, {
            'amount': '1190.00',
            'payment_method': 'bank_transfer'
        })
        
        # Should hit lines 408-450
        self.assertEqual(response.status_code, 302)  # Redirect on success
        self.assertTrue(mock_process.called)

    @patch('apps.billing.views.generate_payment_collection_report')
    def test_billing_reports_lines_894_918(self, mock_report):
        """Test billing_reports view - Lines 894-918"""
        mock_report.return_value = {
            'total_collected': 500000,  # €5000.00
            'pending_amount': 250000,   # €2500.00
            'report_data': []
        }
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:reports')
        
        response = self.client.get(url, {
            'start_date': '2024-01-01',
            'end_date': '2024-12-31',
            'report_type': 'summary'
        })
        
        # Should hit lines 894-918
        self.assertEqual(response.status_code, 200)
        mock_report.assert_called_once()

    def test_vat_report_lines_927_953(self):
        """Test vat_report view - Lines 927-953"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:vat_report')
        
        with patch('apps.billing.views.generate_vat_summary') as mock_vat, \
             patch('django.shortcuts.render') as mock_render:
            
            mock_vat.return_value = {
                'total_vat_collected': 95000,  # €950.00
                'invoices_count': 5,
                'period': '2024-Q4'
            }
            
            mock_render.return_value = HttpResponse('VAT Report')
            
            response = self.client.get(url, {
                'quarter': '2024-Q4'
            })
            
            # Should hit lines 927-953
            self.assertEqual(response.status_code, 200)
            mock_vat.assert_called_once()
            mock_render.assert_called_once()

    def test_payment_list_with_filters_lines_662_684(self):
        """Test payment_list view with filters - Lines 662-684"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:payment_list')
        
        # Test various filter combinations to hit different branches
        test_cases = [
            {'status': 'completed'},
            {'start_date': '2024-01-01', 'end_date': '2024-12-31'},
            {'customer_id': self.customer.id},
            {'amount_min': '100.00', 'amount_max': '1000.00'}
        ]
        
        for filters in test_cases:
            response = self.client.get(url, filters)
            self.assertEqual(response.status_code, 200)

    def test_proforma_pdf_generation_lines_829_847(self):
        """Test proforma PDF generation - Lines 829-847"""
        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-PDF-001',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:proforma_pdf', kwargs={'pk': proforma.pk})
        
        with patch('apps.billing.services.generate_proforma_pdf') as mock_pdf:
            mock_pdf.return_value = b'%PDF-1.4 fake pdf content'
            
            response = self.client.get(url)
            
            # Should hit lines 829-847
            self.assertEqual(response.status_code, 200)
            mock_pdf.assert_called_once()

    def test_invoice_pdf_generation_lines_855_885(self):
        """Test invoice PDF generation - Lines 855-885"""
        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-PDF-001',
            currency=self.eur_currency,
            subtotal_cents=100000,
            tax_cents=19000,
            total_cents=119000
        )
        
        self.client.force_login(self.staff_user)
        url = reverse('billing:invoice_pdf', kwargs={'pk': invoice.pk})
        
        with patch('apps.billing.services.generate_invoice_pdf') as mock_pdf:
            mock_pdf.return_value = b'%PDF-1.4 fake invoice pdf'
            
            response = self.client.get(url)
            
            # Should hit lines 855-885
            self.assertEqual(response.status_code, 200)
            mock_pdf.assert_called_once()

    def test_edge_cases_and_error_handling(self):
        """Test various edge cases to hit remaining missing lines"""
        self.client.force_login(self.staff_user)
        
        # Test with invalid proforma ID (404 handling)
        url = reverse('billing:proforma_to_invoice', kwargs={'pk': 99999})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        
        # Test with invalid invoice ID
        url = reverse('billing:process_payment', kwargs={'pk': 99999})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 404)


class BillingViewsHelperFunctionsTestCase(TestCase):
    """Tests for helper functions to increase coverage"""
    
    def setUp(self):
        """Set up for helper function tests"""
        self.staff_user = User.objects.create_user(
            email='helper@test.com',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        self.customer = Customer.objects.create(
            name='Helper Test SRL',
            customer_type='company',
            status='active',
            primary_email='helper@test.com'
        )

    def test_helper_function_edge_cases(self):
        """Test helper functions with edge cases"""
        from apps.billing.views import _get_accessible_customer_ids, _validate_pdf_access
        
        # Test _get_accessible_customer_ids with None user
        result = _get_accessible_customer_ids(None)
        self.assertEqual(result, [])
        
        # Test _validate_pdf_access with invalid parameters
        result = _validate_pdf_access(None, None)
        self.assertFalse(result)
        
        # Test with authenticated user
        result = _get_accessible_customer_ids(self.staff_user)
        self.assertIsNotNone(result)
