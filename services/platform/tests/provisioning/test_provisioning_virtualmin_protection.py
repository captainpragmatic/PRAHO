# ===============================================================================
# 🧪 VIRTUALMIN PROTECTION TESTS
# ===============================================================================
"""
Tests for Virtualmin account deletion protection system.

🚨 Coverage Target: ≥90% for protection-related methods
📊 Query Budget: Tests with minimal database operations
🔒 Security: Tests deletion protection mechanisms
"""

from decimal import Decimal
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import ServicePlan, Service
from apps.provisioning.virtualmin_models import VirtualminServer, VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService

User = get_user_model()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def create_test_user(email: str, **kwargs) -> User:
    """Helper to create test users"""
    defaults = {
        'first_name': 'Test',
        'last_name': 'User',
        'password': 'testpass123'
    }
    defaults.update(kwargs)
    return User.objects.create_user(email=email, **defaults)


def create_test_customer(name: str, admin_user: User, **kwargs) -> Customer:
    """Helper to create test customers with all required profiles"""
    defaults = {
        'customer_type': 'company',
        'company_name': name,
        'primary_email': f'contact@{name.lower().replace(" ", "")}.ro',
        'primary_phone': '+40721123456',
        'data_processing_consent': True,
        'created_by': admin_user
    }
    defaults.update(kwargs)
    customer = Customer.objects.create(**defaults)

    # Create required profiles
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui='RO12345678',
        vat_number='RO12345678',
        registration_number='J40/1234/2023',
        is_vat_payer=True,
        vat_rate=Decimal('19.00')
    )

    CustomerBillingProfile.objects.create(
        customer=customer,
        payment_terms=30,
        credit_limit=Decimal('5000.00'),
        preferred_currency='RON'
    )

    CustomerAddress.objects.create(
        customer=customer,
        address_type='legal',
        address_line1='Str. Test Nr. 1',
        city='București',
        county='Sector 1',
        postal_code='010101',
        country='România',
        is_current=True
    )

    return customer


def create_test_service_plan(**kwargs) -> ServicePlan:
    """Helper to create test service plans"""
    defaults = {
        'name': 'Test Hosting Plan',
        'plan_type': 'shared_hosting',
        'description': 'Test hosting plan for unit tests',
        'price_monthly': Decimal('50.00'),
        'setup_fee': Decimal('0.00'),
        'is_active': True,
        'is_public': True,
        'sort_order': 1,
        'auto_provision': True,
    }
    defaults.update(kwargs)
    return ServicePlan.objects.create(**defaults)


def create_test_virtualmin_server(**kwargs) -> VirtualminServer:
    """Helper to create test Virtualmin servers"""
    defaults = {
        'name': 'Test Virtualmin Server',
        'hostname': 'test-vm.example.com',
        'api_username': 'test_api_user',
        'api_port': 10000,
        'status': 'active',
        'max_domains': 1000,
    }
    defaults.update(kwargs)
    server = VirtualminServer.objects.create(**defaults)
    # Set a test password
    server.set_api_password('test_password')
    server.save()
    return server


# ===============================================================================
# VIRTUALMIN PROTECTION TESTS
# ===============================================================================

class VirtualminAccountProtectionTestCase(TestCase):
    """Test Virtualmin account deletion protection functionality"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.service_plan = create_test_service_plan()
        self.virtualmin_server = create_test_virtualmin_server()
        
        # Create a PRAHO service
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name='Test Hosting Service',
            domain='test.example.com',
            username='test_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )
        
        # Create Virtualmin account
        self.virtualmin_account = VirtualminAccount.objects.create(
            domain='test.example.com',
            service=self.service,
            server=self.virtualmin_server,
            virtualmin_username='testuser',
            template_name='Default',
            status='active',
            protected_from_deletion=True,  # Protected by default
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )
        self.virtualmin_account.set_password('test_password')
        self.virtualmin_account.save()

    def test_cannot_delete_protected_virtualmin_account(self):
        """Test that a protected VirtualMin account cannot be deleted"""
        # Verify account is protected
        self.assertTrue(self.virtualmin_account.protected_from_deletion)
        self.assertEqual(self.virtualmin_account.status, 'active')
        
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(self.virtualmin_server)
        
        # Attempt to delete protected account
        result = provisioning_service.delete_account(self.virtualmin_account)
        
        # Verify deletion was blocked
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()
        self.assertIn('protected from deletion', error_message.lower())
        self.assertIn('disable protection first', error_message.lower())
        
        # Verify account still exists and is unchanged
        self.virtualmin_account.refresh_from_db()
        self.assertEqual(self.virtualmin_account.status, 'active')
        self.assertTrue(self.virtualmin_account.protected_from_deletion)

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    def test_can_enable_protection_on_virtualmin_account(self, mock_gateway_class):
        """Test that protection can be enabled on a VirtualMin account"""
        # Create a separate service for the unprotected account
        unprotected_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name='Unprotected Hosting Service',
            domain='unprotected.example.com',
            username='unprotected_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='active'
        )
        
        # Create an unprotected account
        unprotected_account = VirtualminAccount.objects.create(
            domain='unprotected.example.com',
            service=unprotected_service,
            server=self.virtualmin_server,
            virtualmin_username='unprotected_user',
            template_name='Default',
            status='active',
            protected_from_deletion=False,  # Start unprotected
            praho_customer_id=self.customer.id,
            praho_service_id=unprotected_service.id,
        )
        unprotected_account.set_password('test_password')
        unprotected_account.save()
        
        # Verify account is initially unprotected
        self.assertFalse(unprotected_account.protected_from_deletion)
        self.assertTrue(unprotected_account.can_be_deleted)
        
        # Enable protection
        unprotected_account.protected_from_deletion = True
        unprotected_account.save()
        
        # Verify protection is now enabled
        unprotected_account.refresh_from_db()
        self.assertTrue(unprotected_account.protected_from_deletion)
        self.assertFalse(unprotected_account.can_be_deleted)
        
        # Verify deletion is now blocked
        provisioning_service = VirtualminProvisioningService(self.virtualmin_server)
        result = provisioning_service.delete_account(unprotected_account)
        
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()
        self.assertIn('protected from deletion', error_message.lower())

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    def test_can_disable_protection_on_virtualmin_account(self, mock_gateway_class):
        """Test that protection can be disabled on a VirtualMin account"""
        # Mock the gateway and its methods
        mock_gateway = Mock()
        mock_response = Mock()
        mock_response.success = True
        mock_response.data = {'message': 'Domain deleted successfully'}
        mock_gateway.call.return_value.is_ok.return_value = True
        mock_gateway.call.return_value.unwrap.return_value = mock_response
        mock_gateway_class.return_value = mock_gateway
        
        # Verify account starts protected
        self.assertTrue(self.virtualmin_account.protected_from_deletion)
        self.assertFalse(self.virtualmin_account.can_be_deleted)
        
        # Disable protection
        self.virtualmin_account.protected_from_deletion = False
        self.virtualmin_account.save()
        
        # Verify protection is now disabled
        self.virtualmin_account.refresh_from_db()
        self.assertFalse(self.virtualmin_account.protected_from_deletion)
        self.assertTrue(self.virtualmin_account.can_be_deleted)
        
        # Set account to terminated status (required for deletion)
        self.virtualmin_account.status = 'terminated'
        self.virtualmin_account.save()
        
        # Verify deletion is now allowed
        provisioning_service = VirtualminProvisioningService(self.virtualmin_server)
        result = provisioning_service.delete_account(self.virtualmin_account)
        
        self.assertTrue(result.is_ok())
        
        # Verify account was marked as terminated
        self.virtualmin_account.refresh_from_db()
        self.assertEqual(self.virtualmin_account.status, 'terminated')

    def test_protection_property_methods(self):
        """Test protection-related property methods on VirtualMin account"""
        # Test can_be_deleted property with protected account
        protected_account = self.virtualmin_account
        self.assertTrue(protected_account.protected_from_deletion)
        self.assertFalse(protected_account.can_be_deleted)
        
        # Test can_be_deleted property with unprotected account
        protected_account.protected_from_deletion = False
        protected_account.save()
        
        protected_account.refresh_from_db()
        self.assertFalse(protected_account.protected_from_deletion)
        self.assertTrue(protected_account.can_be_deleted)

    def test_delete_url_property_respects_protection(self):
        """Test that delete_url property returns empty string for protected accounts"""
        # Test protected account
        self.assertTrue(self.virtualmin_account.protected_from_deletion)
        self.assertEqual(self.virtualmin_account.delete_url, "")
        
        # Test unprotected account
        self.virtualmin_account.protected_from_deletion = False
        self.virtualmin_account.save()
        
        # Should now return actual delete URL
        delete_url = self.virtualmin_account.delete_url
        self.assertNotEqual(delete_url, "")
        self.assertIn('delete', delete_url)

    def test_toggle_protection_url_property(self):
        """Test toggle_protection_url property returns correct URL"""
        url = self.virtualmin_account.toggle_protection_url
        self.assertIn('toggle-protection', url)
        self.assertIn(str(self.virtualmin_account.id), url)

    def test_protection_status_with_different_account_statuses(self):
        """Test protection works with accounts in different statuses"""
        # Test with suspended account
        self.virtualmin_account.status = 'suspended'
        self.virtualmin_account.save()
        
        provisioning_service = VirtualminProvisioningService(self.virtualmin_server)
        result = provisioning_service.delete_account(self.virtualmin_account)
        
        # Should still be protected regardless of status
        self.assertTrue(result.is_err())
        self.assertIn('protected from deletion', result.unwrap_err())
        
        # Test with error status
        self.virtualmin_account.status = 'error'
        self.virtualmin_account.save()
        
        result = provisioning_service.delete_account(self.virtualmin_account)
        
        # Should still be protected
        self.assertTrue(result.is_err())
        self.assertIn('protected from deletion', result.unwrap_err())

    def test_protection_default_value(self):
        """Test that new VirtualMin accounts are protected by default"""
        # Create a separate service for the new account
        new_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name='New Test Hosting Service',
            domain='new-test.example.com',
            username='newtest_user',
            billing_cycle='monthly',
            price=Decimal('25.00'),
            status='active'
        )
        
        # Create new account without explicitly setting protection
        new_account = VirtualminAccount.objects.create(
            domain='new-test.example.com',
            service=new_service,
            server=self.virtualmin_server,
            virtualmin_username='newtest_user',
            template_name='Default',
            status='provisioning',
            praho_customer_id=self.customer.id,
            praho_service_id=new_service.id,
        )
        new_account.set_password('test_password')
        new_account.save()
        
        # Should be protected by default
        self.assertTrue(new_account.protected_from_deletion)
        self.assertFalse(new_account.can_be_deleted)

    def test_account_status_validation_for_deletion(self):
        """Test that accounts must be terminated or error status before deletion"""
        # Disable protection first
        self.virtualmin_account.protected_from_deletion = False
        self.virtualmin_account.save()
        
        provisioning_service = VirtualminProvisioningService(self.virtualmin_server)
        
        # Test with active account (should be blocked)
        self.virtualmin_account.status = 'active'
        self.virtualmin_account.save()
        
        result = provisioning_service.delete_account(self.virtualmin_account)
        self.assertTrue(result.is_err())
        self.assertIn('must be terminated or in error state before deletion', result.unwrap_err())

        # Test with suspended account (should be blocked)
        self.virtualmin_account.status = 'suspended'
        self.virtualmin_account.save()

        result = provisioning_service.delete_account(self.virtualmin_account)
        self.assertTrue(result.is_err())
        self.assertIn('must be terminated or in error state before deletion', result.unwrap_err())