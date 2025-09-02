"""
Test billing signal handlers with cross-app integration
"""

from decimal import Decimal
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from django.contrib.auth.models import User

from apps.billing.models import Currency, Invoice, Payment
from apps.billing.signals import _handle_payment_success, _trigger_virtualmin_provisioning_on_payment
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan


class BillingProvisioningIntegrationTest(TestCase):
    """Test billing signal integration with provisioning system"""

    def setUp(self):
        """Set up test data for billing integration tests"""
        # Create currency
        self.currency = Currency.objects.create(
            code='EUR',
            symbol='€',
            decimals=2
        )
        
        # Create user
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        
        # Create customer
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="company",
            company_name="Test Company Ltd",
            status="active"
        )
        
        # Create service plan
        self.service_plan = ServicePlan.objects.create(
            name="Shared Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
            features={"disk_space": "10GB", "bandwidth": "100GB"}
        )
        
        # Create service
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting Service",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99"),
            status="pending_payment"
        )
        
        # Create invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-2024-001",
            total_cents=2999,  # €29.99 in cents
            status="issued"
        )

    @patch('apps.billing.signals.provision_virtualmin_account.delay')
    def test_payment_triggers_virtualmin_provisioning(self, mock_provision):
        """Test that successful payment triggers Virtualmin provisioning for hosting services"""
        # Create successful payment
        payment = Payment.objects.create(
            invoice=self.invoice,
            amount_cents=2999,  # €29.99 in cents
            status="completed",
            payment_method="card",
            reference="txn_123"
        )
        
        # Mock the service method
        with patch.object(self.service, 'requires_hosting_account', return_value=True):
            # Mock order items relationship
            with patch.object(self.invoice, 'get_order_items') as mock_get_items:
                mock_order_item = MagicMock()
                mock_order_item.service = self.service
                mock_get_items.return_value = [mock_order_item]
                
                # Trigger payment success handler
                _handle_payment_success(payment)
        
        # Verify Virtualmin provisioning was triggered
        mock_provision.assert_called_once()
        
        # Verify call arguments
        call_args = mock_provision.call_args[1]  # kwargs
        self.assertEqual(call_args['service_id'], self.service.id)
        self.assertEqual(call_args['customer_id'], self.customer.id)
        self.assertEqual(call_args['payment_id'], payment.id)

    @patch('apps.billing.signals.provision_virtualmin_account.delay')
    def test_payment_only_triggers_hosting_provisioning(self, mock_provision):
        """Test that payment only triggers provisioning for hosting services"""
        # Create non-hosting service plan
        domain_plan = ServicePlan.objects.create(
            name="Domain Registration",
            plan_type="domain",
            price_monthly=Decimal("15.00")
        )
        
        # Create domain service
        domain_service = Service.objects.create(
            customer=self.customer,
            service_plan=domain_plan,
            service_name="Domain Registration",
            domain="example.org",
            username="testuser",
            price=Decimal("15.00"),
            status="pending_payment"
        )
        
        # Create payment
        payment = Payment.objects.create(
            invoice=self.invoice,
            amount_cents=4499,  # €44.99 in cents
            status="completed",
            payment_method="card",
            reference="txn_124"
        )
        
        # Mock services
        with patch.object(self.service, 'requires_hosting_account', return_value=True):
            with patch.object(domain_service, 'requires_hosting_account', return_value=False):
                # Mock order items relationship
                with patch.object(self.invoice, 'get_order_items') as mock_get_items:
                    mock_hosting_item = MagicMock()
                    mock_hosting_item.service = self.service
                    mock_domain_item = MagicMock()
                    mock_domain_item.service = domain_service
                    mock_get_items.return_value = [mock_hosting_item, mock_domain_item]
                    
                    # Trigger payment success handler
                    _handle_payment_success(payment)
        
        # Should only be called once for the hosting service, not domain
        mock_provision.assert_called_once()
        call_args = mock_provision.call_args[1]
        self.assertEqual(call_args['service_id'], self.service.id)  # hosting service

    @patch('apps.billing.signals.provision_virtualmin_account.delay')
    def test_partial_payment_no_provisioning(self, mock_provision):
        """Test that partial payments don't trigger provisioning"""
        # Create partial payment
        payment = Payment.objects.create(
            invoice=self.invoice,
            amount_cents=1500,  # €15.00 - Less than invoice amount
            status="completed",
            payment_method="card",
            reference="txn_125"
        )
        
        # Mock order items
        with patch.object(self.invoice, 'get_order_items') as mock_get_items:
            mock_get_items.return_value = []
            
            # Trigger payment success handler
            _handle_payment_success(payment)
        
        # Verify no provisioning was triggered
        mock_provision.assert_not_called()

    @patch('apps.billing.signals.provision_virtualmin_account.delay')
    @patch('apps.billing.signals.logger')
    def test_provisioning_trigger_error_handling(self, mock_logger, mock_provision):
        """Test that provisioning trigger errors are handled gracefully"""
        # Make provisioning task raise an exception
        mock_provision.side_effect = Exception("Celery task error")
        
        # Create payment
        payment = Payment.objects.create(
            invoice=self.invoice,
            amount_cents=2999,
            status="completed",
            payment_method="card",
            reference="txn_126"
        )
        
        # Mock service and order items
        with patch.object(self.service, 'requires_hosting_account', return_value=True):
            with patch.object(self.invoice, 'get_order_items') as mock_get_items:
                mock_order_item = MagicMock()
                mock_order_item.service = self.service
                mock_get_items.return_value = [mock_order_item]
                
                # Should not raise exception
                _handle_payment_success(payment)
        
        # Verify error was logged
        mock_logger.error.assert_called_once()

    def test_trigger_virtualmin_provisioning_helper(self):
        """Test the Virtualmin provisioning trigger helper function"""
        # Mock service method
        with patch.object(self.service, 'requires_hosting_account', return_value=True):
            with patch('apps.billing.signals.provision_virtualmin_account.delay') as mock_provision:
                # Mock order item
                mock_order_item = MagicMock()
                mock_order_item.service = self.service
                
                # Call helper function
                _trigger_virtualmin_provisioning_on_payment(mock_order_item, 123)
                
                # Verify provisioning was triggered
                mock_provision.assert_called_once_with(
                    service_id=self.service.id,
                    customer_id=self.customer.id,
                    payment_id=123
                )

    def test_no_provisioning_for_non_hosting_services(self):
        """Test that non-hosting services don't trigger provisioning"""
        # Mock service to not require hosting
        with patch.object(self.service, 'requires_hosting_account', return_value=False):
            with patch('apps.billing.signals.provision_virtualmin_account.delay') as mock_provision:
                # Mock order item
                mock_order_item = MagicMock()
                mock_order_item.service = self.service
                
                # Call helper function
                _trigger_virtualmin_provisioning_on_payment(mock_order_item, 123)
                
                # Verify no provisioning was triggered
                mock_provision.assert_not_called()


class BillingSignalsTest(TestCase):
    """Test other billing signal handlers"""

    def setUp(self):
        """Set up test data"""
        # Create currency
        self.currency = Currency.objects.create(
            code='EUR',
            symbol='€',
            decimals=2
        )
        
        # Create customer
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="company",
            company_name="Test Company Ltd",
            status="active"
        )

    @patch('apps.billing.signals.BillingAuditService.log_invoice_event')
    def test_invoice_creation_audit_logging(self, mock_audit):
        """Test that invoice creation triggers audit logging"""
        # Create invoice (should trigger signal)
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-2024-002",
            total_cents=10000,  # €100.00
            status="issued"
        )
        
        # Verify audit logging was called
        mock_audit.assert_called()

    @patch('apps.billing.signals.BillingAuditService.log_payment_event')
    def test_payment_success_audit_logging(self, mock_audit):
        """Test that successful payments trigger audit logging"""
        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-2024-003",
            total_cents=5000,  # €50.00
            status="issued"
        )
        
        # Clear invoice creation signals
        mock_audit.reset_mock()
        
        # Create successful payment (should trigger signal)
        Payment.objects.create(
            invoice=invoice,
            amount_cents=5000,
            status="completed",
            payment_method="bank_transfer",
            reference="txn_128"
        )
        
        # Verify audit logging was called
        mock_audit.assert_called()
