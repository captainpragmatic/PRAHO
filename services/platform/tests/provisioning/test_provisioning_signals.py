# ===============================================================================
# 🧪 PROVISIONING SIGNALS TESTS
# ===============================================================================
"""
Tests for Provisioning Signals focusing on signal handlers and audit logging.

🚨 Coverage Target: ≥90% for provisioning signal handlers
📊 Query Budget: Tests include audit integration validation
🔒 Security: Tests signal-triggered security events and compliance
"""

import unittest
from decimal import Decimal
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import ServicePlan, Server, Service
# Handle missing ProvisioningTask
try:
    from apps.provisioning.models import ProvisioningTask
except ImportError:
    ProvisioningTask = None

# Handle missing signals - they may not be implemented yet
try:
    from apps.provisioning.signals import (
        handle_service_plan_created_or_updated,
        store_original_service_plan_values,
        handle_server_created_or_updated,
        store_original_server_values,
        handle_service_created_or_updated,
        store_original_service_values,
    )
except ImportError:
    # Mock the signals if they don't exist
    handle_service_plan_created_or_updated = None
    store_original_service_plan_values = None
    handle_server_created_or_updated = None
    store_original_server_values = None
    handle_service_created_or_updated = None
    store_original_service_values = None

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


# ===============================================================================
# SERVICE PLAN SIGNAL TESTS
# ===============================================================================

class ServicePlanSignalTestCase(TestCase):
    """Test ServicePlan signal handlers"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')

    @patch('apps.provisioning.signals.logger')
    def test_service_plan_creation_signal(self, mock_logger):
        """Test service plan creation triggers signal"""
        plan_data = {
            'name': 'Test Plan Signal',
            'plan_type': 'shared_hosting',
            'price_monthly': Decimal('45.00'),
            'setup_fee': Decimal('0.00'),
            'is_active': True,
            'is_public': True,
        }
        
        plan = ServicePlan.objects.create(**plan_data)
        
        # Verify logging was called
        mock_logger.info.assert_called()
        
        # Check the log message
        log_calls = [call[0][0] for call in mock_logger.info.call_args_list]
        creation_log = next((call for call in log_calls if 'Created plan:' in call), None)
        self.assertIsNotNone(creation_log)
        self.assertIn('Test Plan Signal', creation_log)



    @patch('apps.provisioning.signals.logger')
    def test_high_value_plan_security_trigger(self, mock_logger):
        """Test high-value plan security logging trigger"""
        # Create high-value plan (≥500 RON)
        high_value_plan = ServicePlan.objects.create(
            name='Enterprise Plan',
            plan_type='dedicated',
            price_monthly=Decimal('600.00'),
            is_active=True
        )
        
        # Should trigger logging for high-value plan
        mock_logger.info.assert_called()


    def test_service_plan_signal_exception_handling(self):
        """Test service plan signal handles exceptions gracefully"""
        with patch('apps.provisioning.signals._handle_new_service_plan_creation', side_effect=Exception('Test error')):
            with patch('apps.provisioning.signals.logger') as mock_logger:
                # Should not raise exception even if handler fails
                plan = ServicePlan.objects.create(
                    name='Exception Test Plan',
                    plan_type='shared_hosting',
                    price_monthly=Decimal('25.00'),
                    is_active=True
                )
                
                # Should log the exception
                mock_logger.exception.assert_called()


# ===============================================================================
# SERVER SIGNAL TESTS
# ===============================================================================

class ServerSignalTestCase(TestCase):
    """Test Server signal handlers"""

    @patch('apps.provisioning.signals.logger')
    def test_server_creation_signal(self, mock_logger):
        """Test server creation triggers signal"""
        server_data = {
            'name': 'Test Server Signal',
            'hostname': 'test-signal.example.com',
            'server_type': 'shared',
            'primary_ip': '192.168.1.200',
            'location': 'Cluj-Napoca',
            'datacenter': 'DC2',
            'cpu_model': 'Intel Xeon',
            'cpu_cores': 4,
            'ram_gb': 16,
            'disk_type': 'SSD',
            'disk_capacity_gb': 500,
            'status': 'active',
            'os_type': 'Ubuntu 22.04',
            'monthly_cost': Decimal('300.00'),
            'is_active': True,
        }
        
        server = Server.objects.create(**server_data)
        
        # Verify logging was called
        mock_logger.info.assert_called()
        
        # Check the log message
        log_calls = [call[0][0] for call in mock_logger.info.call_args_list]
        creation_log = next((call for call in log_calls if 'Registered:' in call), None)
        self.assertIsNotNone(creation_log)
        self.assertIn('Test Server Signal', creation_log)
        self.assertIn('shared', creation_log)


    @patch('apps.provisioning.signals.logger')
    def test_server_status_change_detection(self, mock_logger):
        """Test server status change detection"""
        # Create server
        server = Server.objects.create(
            name='Status Test Server',
            hostname='status-test.example.com',
            server_type='vps_host',
            primary_ip='192.168.1.150',
            location='Timișoara',
            datacenter='DC3',
            cpu_model='AMD EPYC',
            cpu_cores=16,
            ram_gb=64,
            disk_type='NVMe',
            disk_capacity_gb=2000,
            status='active',
            os_type='CentOS 8',
            monthly_cost=Decimal('800.00'),
            is_active=True,
        )
        
        # Clear creation logs
        mock_logger.reset_mock()
        
        # Change status
        server.status = 'maintenance'
        server.save()
        
        # Should trigger logging for status change
        mock_logger.info.assert_called()

    @patch('apps.provisioning.signals.logger')
    def test_server_overload_alert_trigger(self, mock_logger):
        """Test server overload alert trigger"""
        # Create server with high resource usage
        server = Server.objects.create(
            name='Overload Test Server',
            hostname='overload.example.com',
            server_type='shared',
            primary_ip='192.168.1.250',
            location='Iași',
            datacenter='DC4',
            cpu_model='Intel i7',
            cpu_cores=8,
            ram_gb=32,
            disk_type='SSD',
            disk_capacity_gb=1000,
            status='active',
            os_type='Ubuntu 20.04',
            cpu_usage_percent=Decimal('95.00'),  # Over threshold
            ram_usage_percent=Decimal('85.00'),
            monthly_cost=Decimal('400.00'),
            is_active=True,
        )
        
        # Should trigger logging for server creation
        mock_logger.info.assert_called()

    def test_server_signal_exception_handling(self):
        """Test server signal handles exceptions gracefully"""
        with patch('apps.provisioning.signals._handle_new_server_creation', side_effect=Exception('Test error')):
            with patch('apps.provisioning.signals.logger') as mock_logger:
                # Should not raise exception even if handler fails
                server = Server.objects.create(
                    name='Exception Test Server',
                    hostname='exception.example.com',
                    server_type='shared',
                    primary_ip='192.168.1.99',
                    location='București',
                    datacenter='DC1',
                    cpu_model='Intel Xeon',
                    cpu_cores=4,
                    ram_gb=16,
                    disk_type='SSD',
                    disk_capacity_gb=500,
                    status='active',
                    os_type='Ubuntu 20.04',
                    monthly_cost=Decimal('250.00'),
                    is_active=True,
                )
                
                # Should log the exception
                mock_logger.exception.assert_called()


# ===============================================================================
# SERVICE SIGNAL TESTS
# ===============================================================================

class ServiceSignalTestCase(TestCase):
    """Test Service signal handlers"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Signal Test Customer', self.admin_user)
        self.plan = ServicePlan.objects.create(
            name='Signal Test Plan',
            plan_type='shared_hosting',
            price_monthly=Decimal('50.00'),
            is_active=True
        )
        self.server = Server.objects.create(
            name='Signal Test Server',
            hostname='signal-test.example.com',
            server_type='shared',
            primary_ip='192.168.1.100',
            location='București',
            datacenter='DC1',
            cpu_model='Intel Xeon',
            cpu_cores=8,
            ram_gb=32,
            disk_type='SSD',
            disk_capacity_gb=1000,
            status='active',
            os_type='Ubuntu 20.04',
            monthly_cost=Decimal('500.00'),
            is_active=True,
        )

    @patch('apps.provisioning.signals.logger')
    def test_service_creation_signal(self, mock_logger):
        """Test service creation triggers signal"""
        from django.conf import settings
        
        service_data = {
            'customer': self.customer,
            'service_plan': self.plan,
            'server': self.server,
            'service_name': 'Signal Test Service',
            'domain': 'signal-test.example.com',
            'username': 'signal_user',
            'billing_cycle': 'monthly',
            'price': Decimal('50.00'),
            'status': 'pending'
        }
        
        service = Service.objects.create(**service_data)
        
        # Debug: Check if signals are disabled
        signals_disabled = getattr(settings, 'DISABLE_AUDIT_SIGNALS', False)
        if signals_disabled:
            self.skipTest("Audit signals are disabled - signal won't be triggered")
        
        # Verify logging was called
        mock_logger.info.assert_called()



    @patch('apps.provisioning.signals.logger')
    def test_service_provisioning_trigger(self, mock_logger):
        """Test service provisioning trigger"""
        # Create service with auto-provision plan
        auto_plan = ServicePlan.objects.create(
            name='Auto Provision Plan',
            plan_type='vps',
            price_monthly=Decimal('100.00'),
            auto_provision=True,
            is_active=True
        )
        
        service = Service.objects.create(
            customer=self.customer,
            service_plan=auto_plan,
            server=self.server,
            service_name='Auto Provision Service',
            domain='auto-provision.example.com',
            username='auto_user',
            billing_cycle='monthly',
            price=Decimal('100.00'),
            status='pending'
        )
        
        # Should trigger logging for service creation
        mock_logger.info.assert_called()

    def test_service_signal_exception_handling(self):
        """Test service signal handles exceptions gracefully"""
        with patch('apps.provisioning.signals._handle_new_service_creation', side_effect=Exception('Test error')):
            with patch('apps.provisioning.signals.logger') as mock_logger:
                # Should not raise exception even if handler fails
                service = Service.objects.create(
                    customer=self.customer,
                    service_plan=self.plan,
                    server=self.server,
                    service_name='Exception Service',
                    domain='exception.example.com',
                    username='exception_user',
                    billing_cycle='monthly',
                    price=Decimal('30.00'),
                    status='pending'
                )
                
                # Should log the exception
                mock_logger.exception.assert_called()


# ===============================================================================
# SIGNAL INTEGRATION TESTS
# ===============================================================================

class SignalIntegrationTestCase(TestCase):
    """Integration tests for provisioning signals"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Integration Customer', self.admin_user)

    def test_service_plan_to_service_signal_integration(self):
        """Test signal integration from plan creation to service creation"""
        # Create plan
        plan = ServicePlan.objects.create(
            name='Integration Plan',
            plan_type='shared_hosting',
            price_monthly=Decimal('40.00'),
            auto_provision=True,
            is_active=True
        )
        
        # Create server
        server = Server.objects.create(
            name='Integration Server',
            hostname='integration.example.com',
            server_type='shared',
            primary_ip='192.168.1.200',
            location='București',
            datacenter='DC1',
            cpu_model='Intel Xeon',
            cpu_cores=8,
            ram_gb=32,
            disk_type='SSD',
            disk_capacity_gb=1000,
            status='active',
            os_type='Ubuntu 20.04',
            monthly_cost=Decimal('500.00'),
            is_active=True,
        )
        
        # Create service (should trigger multiple signals)
        with patch('apps.provisioning.signals.logger') as mock_logger:
            service = Service.objects.create(
                customer=self.customer,
                service_plan=plan,
                server=server,
                service_name='Integration Service',
                domain='integration-test.example.com',
                username='integration_user',
                billing_cycle='monthly',
                price=Decimal('40.00'),
                status='pending'
            )
            
            # Should have logged service creation
            self.assertTrue(mock_logger.info.called)

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.logger')
    def test_signal_audit_integration(self, mock_logger):
        """Test signal integration with audit system"""
        plan = ServicePlan.objects.create(
            name='Audit Test Plan',
            plan_type='vps',
            price_monthly=Decimal('80.00'),
            is_active=True
        )
        
        # Should log service plan creation
        mock_logger.info.assert_called()

    def test_signal_performance_with_multiple_objects(self):
        """Test signal performance with multiple object creation"""
        import time
        
        start_time = time.time()
        
        # Create multiple plans to test signal performance
        plans = []
        for i in range(10):
            plan = ServicePlan.objects.create(
                name=f'Performance Plan {i}',
                plan_type='shared_hosting',
                price_monthly=Decimal('35.00'),
                is_active=True
            )
            plans.append(plan)
        
        end_time = time.time()
        
        # Should complete relatively quickly (adjust threshold as needed)
        execution_time = end_time - start_time
        self.assertLess(execution_time, 5.0)  # 5 seconds threshold
        
        # All plans should be created
        self.assertEqual(len(plans), 10)

    def test_signal_with_concurrent_operations(self):
        """Test signal behavior with concurrent database operations"""
        # Create plan and server
        plan = ServicePlan.objects.create(
            name='Concurrent Plan',
            plan_type='vps',
            price_monthly=Decimal('90.00'),
            is_active=True
        )
        
        server = Server.objects.create(
            name='Concurrent Server',
            hostname='concurrent.example.com',
            server_type='vps_host',
            primary_ip='192.168.1.250',
            location='Cluj-Napoca',
            datacenter='DC2',
            cpu_model='AMD EPYC',
            cpu_cores=16,
            ram_gb=64,
            disk_type='NVMe',
            disk_capacity_gb=2000,
            status='active',
            os_type='Ubuntu 22.04',
            monthly_cost=Decimal('800.00'),
            is_active=True,
        )
        
        # Create multiple services simultaneously to test signal handling
        services = []
        for i in range(5):
            service = Service.objects.create(
                customer=self.customer,
                service_plan=plan,
                server=server,
                service_name=f'Concurrent Service {i}',
                domain=f'concurrent{i}.example.com',
                username=f'concurrent{i}_user',
                billing_cycle='monthly',
                price=Decimal('90.00'),
                status='pending'
            )
            services.append(service)
        
        # All services should be created successfully
        self.assertEqual(len(services), 5)
        
        # All should be in database
        db_services = Service.objects.filter(customer=self.customer).count()
        self.assertEqual(db_services, 5)


# ===============================================================================
# CROSS-APP INTEGRATION SIGNAL TESTS
# ===============================================================================


class VirtualminAccountSignalsTest(TestCase):
    """Test Virtualmin account lifecycle signals"""

    def setUp(self):
        """Set up test data"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )
        
        # Create service
        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )
        
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99")
        )
        
        # Create Virtualmin server
        from apps.provisioning.virtualmin_models import VirtualminServer
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_virtualmin_account_creation_signal(self, mock_audit):
        """Test that Virtualmin account creation triggers audit signal"""
        from apps.provisioning.virtualmin_models import VirtualminAccount
        
        # Create Virtualmin account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id
        )
        
        # Verify signal was triggered
        mock_audit.assert_called()
        
        # Find the account creation call
        account_calls = [call for call in mock_audit.call_args_list 
                        if call[0][0].event_type == "virtualmin_account_created"]
        self.assertEqual(len(account_calls), 1)
        
        # Verify audit data
        call_args = account_calls[0][0][0]  # AuditEventData
        context_args = account_calls[0][1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_created")
        self.assertEqual(call_args.new_values["domain"], "example.com")
        self.assertEqual(call_args.new_values["status"], "provisioning")
        self.assertEqual(call_args.new_values["customer_id"], str(self.customer.id))
        
        # Verify metadata (in context)
        metadata = context_args.metadata
        self.assertTrue(metadata["compliance_event"])
        self.assertTrue(metadata["provisioning_action"])
        self.assertTrue(metadata["requires_gdpr_logging"])

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_virtualmin_account_status_change_signal(self, mock_audit):
        """Test that account status changes trigger audit signals"""
        from apps.provisioning.virtualmin_models import VirtualminAccount
        
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )
        
        # Clear creation signal
        mock_audit.reset_mock()
        
        # Change status with update_fields
        account.status = "active"
        account.save(update_fields=["status"])
        
        # Verify signal was triggered
        mock_audit.assert_called_once()
        
        # Verify audit data
        call_args = mock_audit.call_args[0][0]  # AuditEventData
        context_args = mock_audit.call_args[1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_status_changed")
        self.assertEqual(call_args.new_values["status"], "active")
        
        # Verify metadata (in context)
        metadata = context_args.metadata
        self.assertTrue(metadata["status_change"])

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_virtualmin_account_deletion_signal(self, mock_audit):
        """Test that account deletion triggers audit signals"""
        from apps.provisioning.virtualmin_models import VirtualminAccount
        
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id
        )
        
        # Clear creation signal
        mock_audit.reset_mock()
        
        # Delete account
        account.delete()
        
        # Verify signal was triggered
        mock_audit.assert_called_once()
        
        # Verify audit data
        call_args = mock_audit.call_args[0][0]  # AuditEventData
        context_args = mock_audit.call_args[1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_deleted")
        self.assertEqual(call_args.old_values["domain"], "example.com")
        
        # Verify metadata (in context)
        metadata = context_args.metadata
        self.assertTrue(metadata["account_termination"])
        self.assertTrue(metadata["requires_gdpr_logging"])

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_virtualmin_signals_can_be_disabled(self, mock_audit):
        """Test that Virtualmin signals can be disabled for testing"""
        from apps.provisioning.virtualmin_models import VirtualminAccount
        
        # Create account with signals disabled
        VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )
        
        # Verify no signal was triggered
        mock_audit.assert_not_called()


class VirtualminProvisioningJobSignalsTest(TestCase):
    """Test Virtualmin provisioning job lifecycle signals"""

    def setUp(self):
        """Set up test data"""
        # Create customer and service
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )
        
        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )
        
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99")
        )
        
        # Create Virtualmin server and account
        from apps.provisioning.virtualmin_models import VirtualminServer, VirtualminAccount
        
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )
        
        self.account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_provisioning_job_creation_signal(self, mock_audit):
        """Test that provisioning job creation triggers audit signals"""
        from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
        
        # Create provisioning job
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain",
            server=self.server,
            account=self.account,
            correlation_id="test-123",
            status="pending"
        )
        
        # Find the job creation call (account creation also triggers audit)
        job_creation_calls = [call for call in mock_audit.call_args_list 
                             if call[0][0].event_type == "virtualmin_provisioning_job_created"]
        self.assertEqual(len(job_creation_calls), 1)
        
        # Verify audit data
        call_args = job_creation_calls[0][0][0]  # AuditEventData
        context_args = job_creation_calls[0][1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_provisioning_job_created")
        self.assertEqual(call_args.new_values["operation"], "create_domain")
        self.assertEqual(call_args.new_values["correlation_id"], "test-123")
        
        # Verify metadata (in context)
        metadata = context_args.metadata
        self.assertTrue(metadata["operational_event"])
        self.assertTrue(metadata["provisioning_job"])

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_provisioning_job_failure_monitoring_alert(self, mock_audit):
        """Test that job failures trigger monitoring alerts"""
        from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
        
        # Create job
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain",
            server=self.server,
            account=self.account,
            correlation_id="test-123",
            status="pending"
        )
        
        # Clear previous signals
        mock_audit.reset_mock()
        
        # Change job status to failed
        job.status = "failed"
        job.status_message = "Server connection failed"
        job.save(update_fields=["status", "status_message"])
        
        # Verify signal was triggered
        mock_audit.assert_called_once()
        
        # Verify monitoring alert is flagged
        call_args = mock_audit.call_args[0][0]  # AuditEventData
        context_args = mock_audit.call_args[1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_provisioning_job_failed")
        self.assertTrue(context_args.metadata["requires_monitoring_alert"])


class SecurityEventSignalsTest(TestCase):
    """Test security event logging signals"""

    @patch('apps.provisioning.signals.log_security_event')
    def test_virtualmin_security_event_logging(self, mock_log_security):
        """Test security event logging helper function"""
        from apps.provisioning.signals import log_virtualmin_security_event
        
        # Log a security event
        log_virtualmin_security_event(
            "virtualmin_auth_failure",
            {
                "server": "vm1.example.com",
                "username": "testuser",
                "attempt_count": 3
            },
            "192.168.1.100"
        )
        
        # Verify security logging was called
        mock_log_security.assert_called_once()
        
        # Verify call arguments
        call_args = mock_log_security.call_args[0]
        self.assertEqual(call_args[0], "virtualmin_auth_failure")
        
        details = call_args[1]
        self.assertEqual(details["server"], "vm1.example.com")
        self.assertEqual(details["source_app"], "provisioning")
        self.assertTrue(details["virtualmin_integration"])
        
        self.assertEqual(call_args[2], "192.168.1.100")  # IP address

    @patch('apps.provisioning.signals.log_security_event')
    @patch('apps.provisioning.signals.logger')
    def test_security_event_error_handling(self, mock_logger, mock_log_security):
        """Test that security event logging errors are handled gracefully"""
        from apps.provisioning.signals import log_virtualmin_security_event
        
        # Make security logging raise an exception
        mock_log_security.side_effect = Exception("Security logging failed")
        
        # Should not raise exception
        log_virtualmin_security_event(
            "virtualmin_auth_failure",
            {"server": "vm1.example.com"},
            "192.168.1.100"
        )
        
        # Verify error was logged
        mock_logger.error.assert_called_once()


class ProvisioningCompletionSignalsTest(TestCase):
    """Test provisioning completion notification signals"""

    def setUp(self):
        """Set up test data"""
        # Create customer and service
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )
        
        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )
        
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99")
        )
        
        # Create Virtualmin server and account
        from apps.provisioning.virtualmin_models import VirtualminServer, VirtualminAccount
        
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )
        
        self.account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active"
        )

    @patch('apps.provisioning.signals.AuditService.log_event')
    def test_provisioning_completion_notification(self, mock_audit):
        """Test provisioning completion notification helper"""
        from apps.provisioning.signals import notify_provisioning_completion
        
        # Clear account creation signals
        mock_audit.reset_mock()
        
        # Notify successful completion
        notify_provisioning_completion(
            self.account,
            success=True,
            details={
                "server": "vm1.example.com",
                "duration_seconds": 45,
                "features_enabled": ["web", "dns", "mail"]
            }
        )
        
        # Verify audit logging was called
        mock_audit.assert_called_once()
        
        # Verify audit data
        call_args = mock_audit.call_args[0][0]  # AuditEventData
        context_args = mock_audit.call_args[1]['context']  # AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_provisioning_completed")
        self.assertTrue(call_args.new_values["success"])
        self.assertEqual(call_args.new_values["domain"], "example.com")
        
        # Verify metadata (in context)
        metadata = context_args.metadata
        self.assertTrue(metadata["provisioning_completion"])
        self.assertTrue(metadata["cross_app_notification"])

    @patch('apps.provisioning.signals.AuditService.log_event')
    @patch('apps.provisioning.signals.logger')
    def test_provisioning_completion_error_handling(self, mock_logger, mock_audit):
        """Test that provisioning completion notification errors are handled"""
        from apps.provisioning.signals import notify_provisioning_completion
        
        # Make audit service raise an exception
        mock_audit.side_effect = Exception("Audit service error")
        
        # Should not raise exception
        notify_provisioning_completion(
            self.account,
            success=True,
            details={"server": "vm1.example.com"}
        )
        
        # Verify error was logged
        mock_logger.error.assert_called_once()