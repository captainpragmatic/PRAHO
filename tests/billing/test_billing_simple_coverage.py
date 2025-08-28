"""
Simple test to verify billing views coverage setup works
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

User = get_user_model()


class SimpleBillingCoverageTest(TestCase):
    """Simple test to verify basic setup"""

    def setUp(self):
        """Set up basic test data"""
        # Create staff user with billing role
        self.staff_user = User.objects.create_user(
            email='staff@test.com',
            password='testpass123',
            is_staff=True,
            staff_role='billing'
        )
        
        # Don't create complex objects, just test view access
        
        self.client = Client()

    def test_billing_list_with_staff(self):
        """Test basic billing list access"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:invoice_list')
        response = self.client.get(url)
        
        # Just check we can access the view
        self.assertEqual(response.status_code, 200)

    def test_proforma_create_get(self):
        """Test proforma create GET"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:proforma_create')
        response = self.client.get(url)
        
        # Should be accessible by billing staff
        self.assertEqual(response.status_code, 200)

    def test_billing_reports_access(self):
        """Test billing reports access"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:reports')
        response = self.client.get(url)
        
        # Should be accessible
        self.assertEqual(response.status_code, 200)

    def test_vat_report_access(self):
        """Test VAT report access"""
        self.client.force_login(self.staff_user)
        url = reverse('billing:vat_report')
        response = self.client.get(url)
        
        # Should be accessible
        self.assertEqual(response.status_code, 200)
