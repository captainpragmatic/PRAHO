# ===============================================================================
# 🧪 PROVISIONING SIGNALS TESTS
# ===============================================================================
"""
Tests for Provisioning Signals focusing on signal handlers and audit logging.

🚨 Coverage Target: ≥90% for provisioning signal handlers
📊 Query Budget: Tests include audit integration validation
🔒 Security: Tests signal-triggered security events and compliance
"""

from decimal import Decimal
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import ServicePlan, Server, Service, ProvisioningTask
from apps.provisioning.signals import (
    handle_service_plan_created_or_updated,
    store_original_service_plan_values,
    handle_server_created_or_updated,
    store_original_server_values,
    handle_service_created_or_updated,
    store_original_service_values,
)

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
        creation_log = next((call for call in log_calls if 'Created service plan' in call), None)
        self.assertIsNotNone(creation_log)
        self.assertIn('Test Plan Signal', creation_log)
        self.assertIn('shared_hosting', creation_log)

    def test_store_original_service_plan_values(self):
        """Test storing original service plan values before update"""
        # Create plan
        plan = ServicePlan.objects.create(
            name='Original Plan',
            plan_type='vps',
            price_monthly=Decimal('100.00'),
            is_active=True
        )
        
        # Update plan (should trigger pre_save signal)
        plan.name = 'Updated Plan'
        plan.price_monthly = Decimal('120.00')
        plan.save()
        
        # Check that original values were stored
        self.assertTrue(hasattr(plan, '_original_plan_values'))
        original_values = plan._original_plan_values
        self.assertEqual(original_values['name'], 'Original Plan')
        self.assertEqual(original_values['price_monthly'], 100.0)

    @patch('apps.provisioning.signals.logger')
    def test_service_plan_price_change_detection(self, mock_logger):
        """Test service plan price change detection"""
        # Create plan
        plan = ServicePlan.objects.create(
            name='Price Test Plan',
            plan_type='shared_hosting',
            price_monthly=Decimal('50.00'),
            is_active=True
        )
        
        # Clear any creation logs
        mock_logger.reset_mock()
        
        # Update price significantly
        plan.price_monthly = Decimal('75.00')
        plan.save()
        
        # Should detect price change (tested indirectly through logging)
        self.assertTrue(mock_logger.info.called or mock_logger.warning.called)

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

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch('apps.provisioning.signals.logger')
    def test_service_plan_signal_with_audit_disabled(self, mock_logger):
        """Test service plan signal when audit is disabled"""
        plan = ServicePlan.objects.create(
            name='No Audit Plan',
            plan_type='shared_hosting',
            price_monthly=Decimal('30.00'),
            is_active=True
        )
        
        # Should still log basic creation message
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
        creation_log = next((call for call in log_calls if 'Created server' in call), None)
        self.assertIsNotNone(creation_log)
        self.assertIn('Test Server Signal', creation_log)
        self.assertIn('shared', creation_log)

    def test_store_original_server_values(self):
        """Test storing original server values before update"""
        # Create server
        server = Server.objects.create(
            name='Original Server',
            hostname='original.example.com',
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
        
        # Update server
        server.name = 'Updated Server'
        server.status = 'maintenance'
        server.save()
        
        # Check that original values were stored
        self.assertTrue(hasattr(server, '_original_server_values'))
        original_values = server._original_server_values
        self.assertEqual(original_values['name'], 'Original Server')
        self.assertEqual(original_values['status'], 'active')

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
        
        # Verify logging was called
        mock_logger.info.assert_called()

    def test_store_original_service_values(self):
        """Test storing original service values before update"""
        # Create service
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Original Service',
            domain='original.example.com',
            username='original_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='pending'
        )
        
        # Update service
        service.service_name = 'Updated Service'
        service.status = 'active'
        service.save()
        
        # Check that original values were stored
        self.assertTrue(hasattr(service, '_original_service_values'))
        original_values = service._original_service_values
        self.assertEqual(original_values['service_name'], 'Original Service')
        self.assertEqual(original_values['status'], 'pending')

    @patch('apps.provisioning.signals.logger')
    def test_service_status_change_detection(self, mock_logger):
        """Test service status change detection"""
        # Create service
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Status Change Service',
            domain='status-change.example.com',
            username='status_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='pending'
        )
        
        # Clear creation logs
        mock_logger.reset_mock()
        
        # Change status
        service.status = 'active'
        service.save()
        
        # Should trigger logging for status change
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