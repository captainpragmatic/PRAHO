# ===============================================================================
# 🧪 PROVISIONING SERVICES TESTS
# ===============================================================================
"""
Tests for Provisioning Services focusing on business logic and service operations.

🚨 Coverage Target: ≥90% for provisioning service methods
📊 Query Budget: Tests include integration validation
🔒 Security: Tests service activation and suspension logic
"""

from decimal import Decimal
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.billing.models import Invoice
from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.services import ServiceActivationService

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


# ===============================================================================
# SERVICE ACTIVATION SERVICE TESTS
# ===============================================================================

class ServiceActivationServiceTestCase(TestCase):
    """Test ServiceActivationService methods and business logic"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        # Create a mock invoice for testing
        self.mock_invoice = Mock(spec=Invoice)
        self.mock_invoice.number = 'INV-2025-001'
        self.mock_invoice.customer = self.customer
        self.mock_invoice.total_amount = Decimal('59.50')  # 50.00 + 19% VAT
        self.mock_invoice.is_paid = True

    @patch('apps.provisioning.provisioning_service.logger')
    def test_activate_services_for_invoice_logs_message(self, mock_logger):
        """Test that activate_services_for_invoice logs appropriate message"""
        ServiceActivationService.activate_services_for_invoice(self.mock_invoice)
        
        # Verify the log message was called
        mock_logger.info.assert_called_once_with(
            f"⚙️ [Provisioning] Would activate services for paid invoice {self.mock_invoice.number}"
        )

    @patch('apps.provisioning.provisioning_service.logger')
    def test_suspend_services_for_customer_logs_message(self, mock_logger):
        """Test that suspend_services_for_customer logs appropriate message"""
        customer_id = self.customer.id
        reason = 'payment_overdue'
        
        ServiceActivationService.suspend_services_for_customer(customer_id, reason)
        
        # Verify the log message was called
        mock_logger.info.assert_called_once_with(
            f"⚙️ [Provisioning] Would suspend services for customer {customer_id} - {reason}"
        )

    @patch('apps.provisioning.provisioning_service.logger')
    def test_suspend_services_for_customer_default_reason(self, mock_logger):
        """Test that suspend_services_for_customer uses default reason"""
        customer_id = self.customer.id
        
        ServiceActivationService.suspend_services_for_customer(customer_id)
        
        # Verify the log message was called with default reason
        mock_logger.info.assert_called_once_with(
            f"⚙️ [Provisioning] Would suspend services for customer {customer_id} - payment_overdue"
        )

    @patch('apps.provisioning.provisioning_service.logger')
    def test_reactivate_services_for_customer_logs_message(self, mock_logger):
        """Test that reactivate_services_for_customer logs appropriate message"""
        customer_id = self.customer.id
        reason = 'payment_received'
        
        ServiceActivationService.reactivate_services_for_customer(customer_id, reason)
        
        # Verify the log message was called
        mock_logger.info.assert_called_once_with(
            f"⚙️ [Provisioning] Would reactivate services for customer {customer_id} - {reason}"
        )

    @patch('apps.provisioning.provisioning_service.logger')
    def test_reactivate_services_for_customer_default_reason(self, mock_logger):
        """Test that reactivate_services_for_customer uses default reason"""
        customer_id = self.customer.id
        
        ServiceActivationService.reactivate_services_for_customer(customer_id)
        
        # Verify the log message was called with default reason
        mock_logger.info.assert_called_once_with(
            f"⚙️ [Provisioning] Would reactivate services for customer {customer_id} - payment_received"
        )

    def test_activate_services_for_invoice_handles_none_invoice(self):
        """Test that activate_services_for_invoice handles None invoice gracefully"""
        # This should not raise an exception
        try:
            ServiceActivationService.activate_services_for_invoice(None)
        except Exception as e:
            self.fail(f"activate_services_for_invoice raised an exception with None: {e}")

    def test_suspend_services_for_customer_handles_invalid_customer_id(self):
        """Test that suspend_services_for_customer handles invalid customer ID"""
        invalid_customer_id = 999999
        
        # This should not raise an exception
        try:
            ServiceActivationService.suspend_services_for_customer(invalid_customer_id)
        except Exception as e:
            self.fail(f"suspend_services_for_customer raised an exception with invalid ID: {e}")

    def test_reactivate_services_for_customer_handles_invalid_customer_id(self):
        """Test that reactivate_services_for_customer handles invalid customer ID"""
        invalid_customer_id = 999999
        
        # This should not raise an exception
        try:
            ServiceActivationService.reactivate_services_for_customer(invalid_customer_id)
        except Exception as e:
            self.fail(f"reactivate_services_for_customer raised an exception with invalid ID: {e}")

    def test_service_activation_service_static_methods(self):
        """Test that all methods are static and can be called without instance"""
        # Test that we can call methods without creating an instance
        customer_id = self.customer.id
        
        # These should all work without creating a ServiceActivationService instance
        ServiceActivationService.activate_services_for_invoice(self.mock_invoice)
        ServiceActivationService.suspend_services_for_customer(customer_id)
        ServiceActivationService.reactivate_services_for_customer(customer_id)
        
        # If we get here without exceptions, the static methods work correctly
        self.assertTrue(True)

    def test_service_activation_service_with_special_characters_in_reason(self):
        """Test service methods handle special characters in reason strings"""
        customer_id = self.customer.id
        special_reason = "Suspendare pentru întârziere la plată (30+ zile)"
        
        # Should handle Romanian characters and special symbols
        try:
            ServiceActivationService.suspend_services_for_customer(customer_id, special_reason)
            ServiceActivationService.reactivate_services_for_customer(customer_id, special_reason)
        except Exception as e:
            self.fail(f"Service methods failed with special characters: {e}")

    @patch('apps.provisioning.provisioning_service.logger')
    def test_service_activation_service_logging_format(self, mock_logger):
        """Test that logging follows PRAHO Platform format standards"""
        customer_id = self.customer.id
        
        ServiceActivationService.suspend_services_for_customer(customer_id, 'test_reason')
        
        # Get the actual log call
        call_args = mock_logger.info.call_args[0][0]
        
        # Verify log format includes emoji and [Provisioning] scope
        self.assertIn('⚙️ [Provisioning]', call_args)
        self.assertIn('Would suspend services', call_args)
        self.assertIn(str(customer_id), call_args)
        self.assertIn('test_reason', call_args)

    def test_service_activation_service_type_hints(self):
        """Test that service methods work with proper type hints"""
        # Test with correct types
        customer_id: int = self.customer.id
        reason: str = 'payment_overdue'
        
        # These should work with type checkers
        ServiceActivationService.suspend_services_for_customer(customer_id, reason)
        ServiceActivationService.reactivate_services_for_customer(customer_id, reason)
        
        # Test with None invoice (type hint allows this)
        invoice = None
        ServiceActivationService.activate_services_for_invoice(invoice)


# ===============================================================================
# SERVICE ACTIVATION INTEGRATION TESTS
# ===============================================================================

class ServiceActivationIntegrationTestCase(TestCase):
    """Integration tests for service activation with real models"""

    def setUp(self):
        """Set up test data with real models"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Integration Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        # Create real services for integration testing
        self.service1 = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Test Service 1',
            domain='test1.example.com',
            username='test1_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='pending'
        )
        
        self.service2 = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Test Service 2',
            domain='test2.example.com',
            username='test2_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='active'
        )

    def test_service_activation_with_real_customer_data(self):
        """Test service activation methods work with real customer data"""
        customer_id = self.customer.id
        
        # Verify customer has services
        services_count = Service.objects.filter(customer=self.customer).count()
        self.assertEqual(services_count, 2)
        
        # Test suspend operation with real customer ID
        ServiceActivationService.suspend_services_for_customer(customer_id, 'payment_test')
        
        # Test reactivate operation
        ServiceActivationService.reactivate_services_for_customer(customer_id, 'payment_received')
        
        # Services should still exist (placeholder implementation doesn't modify)
        services_after = Service.objects.filter(customer=self.customer).count()
        self.assertEqual(services_after, 2)

    def test_service_activation_with_different_service_statuses(self):
        """Test service activation handles services in different statuses"""
        # Create services with different statuses
        suspended_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Suspended Service',
            domain='suspended.example.com',
            username='suspended_user',
            billing_cycle='monthly',
            price=Decimal('25.00'),
            status='suspended'
        )
        
        expired_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Expired Service',
            domain='expired.example.com',
            username='expired_user',
            billing_cycle='monthly',
            price=Decimal('15.00'),
            status='expired'
        )
        
        customer_id = self.customer.id
        
        # Should handle customer with services in various statuses
        try:
            ServiceActivationService.suspend_services_for_customer(customer_id)
            ServiceActivationService.reactivate_services_for_customer(customer_id)
        except Exception as e:
            self.fail(f"Service activation failed with mixed service statuses: {e}")

    def test_service_activation_with_empty_customer(self):
        """Test service activation with customer that has no services"""
        empty_customer = create_test_customer('Empty Customer', self.admin_user)
        
        # Verify customer has no services
        services_count = Service.objects.filter(customer=empty_customer).count()
        self.assertEqual(services_count, 0)
        
        # Should handle customer with no services gracefully
        try:
            ServiceActivationService.suspend_services_for_customer(empty_customer.id)
            ServiceActivationService.reactivate_services_for_customer(empty_customer.id)
        except Exception as e:
            self.fail(f"Service activation failed with empty customer: {e}")

    @patch('apps.provisioning.provisioning_service.logger')
    def test_service_activation_logging_with_real_data(self, mock_logger):
        """Test logging works correctly with real customer data"""
        customer_id = self.customer.id
        customer_name = self.customer.get_display_name()
        
        ServiceActivationService.suspend_services_for_customer(customer_id, 'integration_test')
        
        # Verify log was called
        self.assertTrue(mock_logger.info.called)
        
        # Get the log message
        log_message = mock_logger.info.call_args[0][0]
        
        # Should contain customer ID
        self.assertIn(str(customer_id), log_message)
        self.assertIn('integration_test', log_message)