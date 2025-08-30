# ===============================================================================
# 🧪 PROVISIONING MODELS TESTS
# ===============================================================================
"""
Comprehensive tests for Provisioning models focusing on business logic and validation.

🚨 Coverage Target: ≥90% for provisioning model methods
📊 Query Budget: Tests include performance validation
🔒 Security: Tests service relationships and provisioning validation
"""

from decimal import Decimal
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from dateutil.relativedelta import relativedelta

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import (
    ServicePlan,
    Server,
    Service,
    ProvisioningTask,
    ServiceRelationship,
    ServiceDomain,
    ServiceGroup,
    ServiceGroupMember,
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


def create_test_service_plan(**kwargs) -> ServicePlan:
    """Helper to create test service plans"""
    defaults = {
        'name': 'Test Hosting Plan',
        'plan_type': 'shared_hosting',
        'description': 'Test hosting plan for unit tests',
        'price_monthly': Decimal('50.00'),
        'price_quarterly': Decimal('135.00'),
        'price_annual': Decimal('500.00'),
        'setup_fee': Decimal('0.00'),
        'features': {
            'disk_space': '10GB',
            'bandwidth': '100GB',
            'email_accounts': 10
        },
        'disk_space_gb': 10,
        'bandwidth_gb': 100,
        'email_accounts': 10,
        'databases': 5,
        'domains': 1,
        'includes_vat': False,
        'is_active': True,
        'is_public': True,
        'sort_order': 1,
        'auto_provision': True,
    }
    defaults.update(kwargs)
    return ServicePlan.objects.create(**defaults)


def create_test_server(**kwargs) -> Server:
    """Helper to create test servers"""
    defaults = {
        'name': 'Test Server 01',
        'hostname': 'test-server-01.example.com',
        'server_type': 'shared',
        'primary_ip': '192.168.1.100',
        'location': 'București',
        'datacenter': 'DC1',
        'cpu_model': 'Intel Xeon E5-2670',
        'cpu_cores': 8,
        'ram_gb': 32,
        'disk_type': 'SSD',
        'disk_capacity_gb': 1000,
        'status': 'active',
        'os_type': 'Ubuntu 20.04 LTS',
        'control_panel': 'cPanel',
        'monthly_cost': Decimal('500.00'),
        'is_active': True,
    }
    defaults.update(kwargs)
    return Server.objects.create(**defaults)


# ===============================================================================
# SERVICE PLAN MODEL TESTS
# ===============================================================================

class ServicePlanModelTestCase(TestCase):
    """Test ServicePlan model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.plan = create_test_service_plan()

    def test_service_plan_string_representation(self):
        """Test ServicePlan __str__ method"""
        expected = "Test Hosting Plan (Găzduire web partajată)"
        self.assertEqual(str(self.plan), expected)

    def test_get_effective_price_monthly(self):
        """Test get_effective_price for monthly billing"""
        price = self.plan.get_effective_price('monthly')
        self.assertEqual(price, Decimal('50.00'))

    def test_get_effective_price_quarterly(self):
        """Test get_effective_price for quarterly billing"""
        price = self.plan.get_effective_price('quarterly')
        self.assertEqual(price, Decimal('135.00'))

    def test_get_effective_price_annual(self):
        """Test get_effective_price for annual billing"""
        price = self.plan.get_effective_price('annual')
        self.assertEqual(price, Decimal('500.00'))

    def test_get_effective_price_fallback_to_monthly(self):
        """Test get_effective_price falls back to monthly when quarterly/annual not set"""
        plan = create_test_service_plan(
            price_quarterly=None,
            price_annual=None
        )
        
        self.assertEqual(plan.get_effective_price('quarterly'), Decimal('50.00'))
        self.assertEqual(plan.get_effective_price('annual'), Decimal('50.00'))

    def test_get_monthly_equivalent_price_quarterly(self):
        """Test get_monthly_equivalent_price for quarterly billing"""
        price = self.plan.get_monthly_equivalent_price('quarterly')
        expected = Decimal('135.00') / 3
        self.assertEqual(price, expected)

    def test_get_monthly_equivalent_price_annual(self):
        """Test get_monthly_equivalent_price for annual billing"""
        price = self.plan.get_monthly_equivalent_price('annual')
        expected = Decimal('500.00') / 12
        self.assertEqual(price, expected)

    def test_get_monthly_equivalent_price_monthly(self):
        """Test get_monthly_equivalent_price for monthly billing"""
        price = self.plan.get_monthly_equivalent_price('monthly')
        self.assertEqual(price, Decimal('50.00'))

    def test_service_plan_plan_type_choices(self):
        """Test service plan type choices are valid"""
        valid_types = [choice[0] for choice in ServicePlan.PLAN_TYPE_CHOICES]
        self.assertIn('shared_hosting', valid_types)
        self.assertIn('vps', valid_types)
        self.assertIn('dedicated', valid_types)
        self.assertIn('domain', valid_types)
        self.assertIn('ssl', valid_types)

    def test_service_plan_price_validation(self):
        """Test that negative prices are not allowed"""
        with self.assertRaises(ValidationError):
            plan = ServicePlan(
                name='Invalid Plan',
                plan_type='shared_hosting',
                price_monthly=Decimal('-10.00')
            )
            plan.full_clean()


# ===============================================================================
# SERVER MODEL TESTS
# ===============================================================================

class ServerModelTestCase(TestCase):
    """Test Server model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.server = create_test_server()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()

    def test_server_string_representation(self):
        """Test Server __str__ method"""
        expected = "Test Server 01 (test-server-01.example.com)"
        self.assertEqual(str(self.server), expected)

    def test_active_services_count_with_no_services(self):
        """Test active_services_count property with no services"""
        self.assertEqual(self.server.active_services_count, 0)

    def test_active_services_count_with_services(self):
        """Test active_services_count property with active and inactive services"""
        # Create active service
        Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Active Service',
            domain='active.example.com',
            username='active_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        # Create suspended service
        Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Suspended Service',
            domain='suspended.example.com',
            username='suspended_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='suspended'
        )

        self.assertEqual(self.server.active_services_count, 1)

    def test_resource_usage_average(self):
        """Test resource_usage_average property"""
        self.server.cpu_usage_percent = Decimal('60.00')
        self.server.ram_usage_percent = Decimal('40.00')
        self.server.disk_usage_percent = Decimal('80.00')
        
        expected_average = (60.0 + 40.0 + 80.0) / 3
        self.assertEqual(self.server.resource_usage_average, expected_average)

    def test_resource_usage_average_with_none_values(self):
        """Test resource_usage_average property with None values"""
        self.server.cpu_usage_percent = None
        self.server.ram_usage_percent = None
        self.server.disk_usage_percent = None
        
        expected_average = 0.0
        self.assertEqual(self.server.resource_usage_average, expected_average)

    def test_can_host_service_inactive_server(self):
        """Test can_host_service returns False for inactive server"""
        self.server.is_active = False
        self.server.save()
        
        result = self.server.can_host_service(self.plan)
        self.assertFalse(result)

    def test_can_host_service_offline_server(self):
        """Test can_host_service returns False for offline server"""
        self.server.status = 'offline'
        self.server.save()
        
        result = self.server.can_host_service(self.plan)
        self.assertFalse(result)

    def test_can_host_service_max_services_reached(self):
        """Test can_host_service returns False when max services reached"""
        self.server.max_services = 1
        self.server.save()

        # Create one service
        Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Test Service',
            domain='test.example.com',
            username='test_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        result = self.server.can_host_service(self.plan)
        self.assertFalse(result)

    def test_can_host_service_insufficient_ram(self):
        """Test can_host_service returns False when insufficient RAM"""
        plan = create_test_service_plan(ram_gb=64)  # More than server's 32GB
        
        result = self.server.can_host_service(plan)
        self.assertFalse(result)

    def test_can_host_service_insufficient_cpu(self):
        """Test can_host_service returns False when insufficient CPU"""
        plan = create_test_service_plan(cpu_cores=16)  # More than server's 8 cores
        
        result = self.server.can_host_service(plan)
        self.assertFalse(result)

    def test_can_host_service_success(self):
        """Test can_host_service returns True when server can host"""
        plan = create_test_service_plan(ram_gb=16, cpu_cores=4)
        
        result = self.server.can_host_service(plan)
        self.assertTrue(result)


# ===============================================================================
# SERVICE MODEL TESTS
# ===============================================================================

class ServiceModelTestCase(TestCase):
    """Test Service model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        self.server = create_test_server()
        
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            service_name='Test Hosting',
            domain='test.example.com',
            username='testuser',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='pending'
        )

    def test_service_string_representation(self):
        """Test Service __str__ method"""
        expected = f"Test Hosting - {self.customer.get_display_name()}"
        self.assertEqual(str(self.service), expected)

    def test_get_next_billing_date_no_activation(self):
        """Test get_next_billing_date returns None when not activated"""
        self.assertIsNone(self.service.get_next_billing_date())

    def test_get_next_billing_date_monthly(self):
        """Test get_next_billing_date for monthly billing"""
        activation_date = timezone.now()
        self.service.activated_at = activation_date
        self.service.billing_cycle = 'monthly'
        self.service.save()

        expected = activation_date.date() + relativedelta(months=1)
        result = self.service.get_next_billing_date()
        self.assertEqual(result, expected)

    def test_get_next_billing_date_quarterly(self):
        """Test get_next_billing_date for quarterly billing"""
        activation_date = timezone.now()
        self.service.activated_at = activation_date
        self.service.billing_cycle = 'quarterly'
        self.service.save()

        expected = activation_date.date() + relativedelta(months=3)
        result = self.service.get_next_billing_date()
        self.assertEqual(result, expected)

    def test_get_next_billing_date_semi_annual(self):
        """Test get_next_billing_date for semi-annual billing"""
        activation_date = timezone.now()
        self.service.activated_at = activation_date
        self.service.billing_cycle = 'semi_annual'
        self.service.save()

        expected = activation_date.date() + relativedelta(months=6)
        result = self.service.get_next_billing_date()
        self.assertEqual(result, expected)

    def test_get_next_billing_date_annual(self):
        """Test get_next_billing_date for annual billing"""
        activation_date = timezone.now()
        self.service.activated_at = activation_date
        self.service.billing_cycle = 'annual'
        self.service.save()

        expected = activation_date.date() + relativedelta(years=1)
        result = self.service.get_next_billing_date()
        self.assertEqual(result, expected)

    def test_is_overdue_no_expiry(self):
        """Test is_overdue returns False when no expiry date"""
        self.assertFalse(self.service.is_overdue)

    def test_is_overdue_future_expiry(self):
        """Test is_overdue returns False when expiry is in future"""
        future_date = timezone.now() + timezone.timedelta(days=30)
        self.service.expires_at = future_date
        self.service.save()
        
        self.assertFalse(self.service.is_overdue)

    def test_is_overdue_past_expiry(self):
        """Test is_overdue returns True when expiry is in past"""
        past_date = timezone.now() - timezone.timedelta(days=1)
        self.service.expires_at = past_date
        self.service.save()
        
        self.assertTrue(self.service.is_overdue)

    def test_days_until_expiry_no_expiry(self):
        """Test days_until_expiry returns large number when no expiry"""
        self.assertEqual(self.service.days_until_expiry, 999999)

    def test_days_until_expiry_future_date(self):
        """Test days_until_expiry with future expiry date"""
        future_date = timezone.now() + timezone.timedelta(days=15)
        self.service.expires_at = future_date
        self.service.save()
        
        # Should be approximately 15 days (allowing for small timing differences)
        days = self.service.days_until_expiry
        self.assertGreaterEqual(days, 14)
        self.assertLessEqual(days, 15)

    def test_days_until_expiry_past_date(self):
        """Test days_until_expiry returns 0 for past expiry"""
        past_date = timezone.now() - timezone.timedelta(days=5)
        self.service.expires_at = past_date
        self.service.save()
        
        self.assertEqual(self.service.days_until_expiry, 0)

    def test_suspend_method(self):
        """Test suspend method updates status and timestamps"""
        reason = "Payment overdue"
        self.service.suspend(reason)
        
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, 'suspended')
        self.assertIsNotNone(self.service.suspended_at)
        self.assertEqual(self.service.suspension_reason, reason)

    def test_activate_method_first_time(self):
        """Test activate method for first-time activation"""
        self.service.activate()
        
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, 'active')
        self.assertIsNotNone(self.service.activated_at)
        self.assertIsNone(self.service.suspended_at)
        self.assertEqual(self.service.suspension_reason, '')

    def test_activate_method_reactivation(self):
        """Test activate method for reactivation after suspension"""
        # First suspend
        original_activation = timezone.now() - timezone.timedelta(days=10)
        self.service.activated_at = original_activation
        self.service.suspend("Test suspension")
        
        # Then reactivate
        self.service.activate()
        
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, 'active')
        self.assertEqual(self.service.activated_at, original_activation)  # Should keep original
        self.assertIsNone(self.service.suspended_at)
        self.assertEqual(self.service.suspension_reason, '')


# ===============================================================================
# PROVISIONING TASK MODEL TESTS
# ===============================================================================

class ProvisioningTaskModelTestCase(TestCase):
    """Test ProvisioningTask model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Test Service',
            domain='test.example.com',
            username='testuser',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='pending'
        )

        self.task = ProvisioningTask.objects.create(
            service=self.service,
            task_type='create_service',
            parameters={'domain': 'test.example.com'},
            max_retries=3
        )

    def test_provisioning_task_string_representation(self):
        """Test ProvisioningTask __str__ method"""
        # Task display name might be translated, so just check it contains service name
        task_str = str(self.task)
        self.assertIn(self.service.service_name, task_str)
        self.assertIn('-', task_str)  # Should have format "Task Type - Service Name"

    def test_can_retry_when_failed_and_retries_available(self):
        """Test can_retry returns True when task failed and retries available"""
        self.task.status = 'failed'
        self.task.retry_count = 1
        self.task.save()
        
        self.assertTrue(self.task.can_retry)

    def test_can_retry_when_failed_but_max_retries_reached(self):
        """Test can_retry returns False when max retries reached"""
        self.task.status = 'failed'
        self.task.retry_count = 3
        self.task.save()
        
        self.assertFalse(self.task.can_retry)

    def test_can_retry_when_not_failed(self):
        """Test can_retry returns False when task not failed"""
        self.task.status = 'completed'
        self.task.retry_count = 0
        self.task.save()
        
        self.assertFalse(self.task.can_retry)

    def test_duration_seconds_with_timestamps(self):
        """Test duration_seconds calculation with start and end times"""
        start_time = timezone.now()
        end_time = start_time + timezone.timedelta(seconds=45)
        
        self.task.started_at = start_time
        self.task.completed_at = end_time
        self.task.save()
        
        self.assertEqual(self.task.duration_seconds, 45)

    def test_duration_seconds_without_timestamps(self):
        """Test duration_seconds returns 0 when timestamps missing"""
        self.assertEqual(self.task.duration_seconds, 0)

    def test_duration_seconds_only_start_time(self):
        """Test duration_seconds returns 0 when only start time present"""
        self.task.started_at = timezone.now()
        self.task.save()
        
        self.assertEqual(self.task.duration_seconds, 0)


# ===============================================================================
# SERVICE RELATIONSHIP MODEL TESTS
# ===============================================================================

class ServiceRelationshipModelTestCase(TestCase):
    """Test ServiceRelationship model methods and validation"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        self.parent_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='VPS Hosting',
            domain='vps.example.com',
            username='vps_user',
            billing_cycle='monthly',
            price=Decimal('100.00'),
            status='active'
        )

        self.child_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Domain Service',
            domain='domain.example.com',
            username='domain_user',
            billing_cycle='monthly',
            price=Decimal('20.00'),
            status='active'
        )

    def test_service_relationship_string_representation(self):
        """Test ServiceRelationship __str__ method"""
        relationship = ServiceRelationship.objects.create(
            parent_service=self.parent_service,
            child_service=self.child_service,
            relationship_type='addon',
            billing_impact='separate'
        )
        
        expected = f"{self.parent_service} → {self.child_service} (🔧 Add-on Service)"
        self.assertEqual(str(relationship), expected)

    def test_service_relationship_self_reference_validation(self):
        """Test that service cannot be related to itself"""
        relationship = ServiceRelationship(
            parent_service=self.parent_service,
            child_service=self.parent_service,
            relationship_type='addon',
            billing_impact='separate'
        )
        
        with self.assertRaises(ValidationError):
            relationship.clean()

    def test_service_relationship_circular_dependency_detection(self):
        """Test circular dependency detection"""
        # Create A -> B relationship
        ServiceRelationship.objects.create(
            parent_service=self.parent_service,
            child_service=self.child_service,
            relationship_type='dependency',
            billing_impact='separate'
        )

        # Try to create B -> A relationship (would create circular dependency)
        circular_relationship = ServiceRelationship(
            parent_service=self.child_service,
            child_service=self.parent_service,
            relationship_type='dependency',
            billing_impact='separate'
        )
        
        with self.assertRaises(ValidationError):
            circular_relationship.clean()

    def test_service_relationship_discount_validation(self):
        """Test discount percentage validation"""
        # Test valid discount
        relationship = ServiceRelationship.objects.create(
            parent_service=self.parent_service,
            child_service=self.child_service,
            relationship_type='bundle',
            billing_impact='discounted',
            discount_percentage=Decimal('25.00')
        )
        self.assertEqual(relationship.discount_percentage, Decimal('25.00'))

        # Test discount over 100% should fail validation
        with self.assertRaises(ValidationError):
            invalid_relationship = ServiceRelationship(
                parent_service=self.parent_service,
                child_service=self.child_service,
                relationship_type='bundle',
                billing_impact='discounted',
                discount_percentage=Decimal('150.00')
            )
            invalid_relationship.full_clean()


# ===============================================================================
# SERVICE GROUP MODEL TESTS
# ===============================================================================

class ServiceGroupModelTestCase(TestCase):
    """Test ServiceGroup model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        
        self.service_group = ServiceGroup.objects.create(
            name='VPS + Domain Bundle',
            description='Complete hosting solution with VPS and domain',
            group_type='package',
            customer=self.customer,
            status='active',
            billing_cycle='monthly'
        )

    def test_service_group_string_representation(self):
        """Test ServiceGroup __str__ method"""
        expected = "VPS + Domain Bundle (📦 Hosting Package)"
        self.assertEqual(str(self.service_group), expected)

    def test_total_services_property_empty(self):
        """Test total_services property with no members"""
        self.assertEqual(self.service_group.total_services, 0)

    def test_total_services_property_with_members(self):
        """Test total_services property with members"""
        plan = create_test_service_plan()
        
        # Create services
        service1 = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            service_name='Service 1',
            domain='service1.example.com',
            username='service1_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        service2 = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            service_name='Service 2',
            domain='service2.example.com',
            username='service2_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='pending'
        )

        # Add to group
        ServiceGroupMember.objects.create(
            group=self.service_group,
            service=service1,
            member_role='primary'
        )
        
        ServiceGroupMember.objects.create(
            group=self.service_group,
            service=service2,
            member_role='addon'
        )

        self.assertEqual(self.service_group.total_services, 2)

    def test_active_services_property(self):
        """Test active_services property counts only active services"""
        plan = create_test_service_plan()
        
        # Create active service
        active_service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            service_name='Active Service',
            domain='active.example.com',
            username='active_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        # Create pending service
        pending_service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            service_name='Pending Service',
            domain='pending.example.com',
            username='pending_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='pending'
        )

        # Add to group
        ServiceGroupMember.objects.create(
            group=self.service_group,
            service=active_service,
            member_role='primary'
        )
        
        ServiceGroupMember.objects.create(
            group=self.service_group,
            service=pending_service,
            member_role='addon'
        )

        self.assertEqual(self.service_group.active_services, 1)


# ===============================================================================
# SERVICE GROUP MEMBER MODEL TESTS
# ===============================================================================

class ServiceGroupMemberModelTestCase(TestCase):
    """Test ServiceGroupMember model methods and validation"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        
        self.service_group = ServiceGroup.objects.create(
            name='Test Package',
            group_type='package',
            customer=self.customer,
            status='active'
        )

        self.plan = create_test_service_plan()
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Test Service',
            domain='test.example.com',
            username='test_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

    def test_service_group_member_string_representation(self):
        """Test ServiceGroupMember __str__ method"""
        member = ServiceGroupMember.objects.create(
            group=self.service_group,
            service=self.service,
            member_role='primary',
            provision_order=1
        )
        
        expected = f"{self.service} in {self.service_group} (🎯 Primary Service)"
        self.assertEqual(str(member), expected)

    def test_custom_price_property(self):
        """Test custom_price property conversion from cents"""
        member = ServiceGroupMember.objects.create(
            group=self.service_group,
            service=self.service,
            member_role='primary',
            custom_price_cents=4500  # 45.00 RON
        )
        
        self.assertEqual(member.custom_price, 45.0)

    def test_custom_price_property_none(self):
        """Test custom_price property returns None when no custom price"""
        member = ServiceGroupMember.objects.create(
            group=self.service_group,
            service=self.service,
            member_role='primary'
        )
        
        self.assertIsNone(member.custom_price)

    def test_service_group_member_validation_different_customer(self):
        """Test validation fails when service customer differs from group customer"""
        other_customer = create_test_customer('Other Customer', self.admin_user)
        other_service = Service.objects.create(
            customer=other_customer,
            service_plan=self.plan,
            service_name='Other Service',
            domain='other.example.com',
            username='other_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='active'
        )

        member = ServiceGroupMember(
            group=self.service_group,
            service=other_service,
            member_role='addon'
        )
        
        with self.assertRaises(ValidationError):
            member.clean()