# ===============================================================================
# 🧪 PROVISIONING VIEWS TESTS
# ===============================================================================
"""
Tests for Provisioning Views focusing on authentication, authorization, and functionality.

🚨 Coverage Target: ≥90% for provisioning view methods
📊 Query Budget: Tests include performance validation
🔒 Security: Tests access control and permission validation
"""

from decimal import Decimal
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase, Client
from django.urls import reverse

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.provisioning.models import ServicePlan, Server, Service
from apps.users.models import CustomerMembership

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


def create_test_server(**kwargs) -> Server:
    """Helper to create test servers"""
    import time
    import random
    
    # Generate unique hostname if not provided
    if 'hostname' not in kwargs:
        suffix = int(time.time() * 1000000) + random.randint(1, 1000)
        hostname = f'test-server-{suffix}.example.com'
        kwargs['hostname'] = hostname
    
    defaults = {
        'name': 'Test Server 01',
        'hostname': 'test-server-01.example.com',  # Will be overridden above
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
# SERVICE LIST VIEW TESTS
# ===============================================================================

class ServiceListViewTestCase(TestCase):
    """Test service_list view functionality and security"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin', is_staff=True)
        self.customer_user = create_test_user('customer@test.ro')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        # Create customer membership
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role='owner'
        )

        # Create test services
        self.active_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Active Service',
            domain='active.example.com',
            username='active_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        self.pending_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Pending Service',
            domain='pending.example.com',
            username='pending_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='pending'
        )

    def test_service_list_requires_login(self):
        """Test that service list view requires authentication"""
        response = self.client.get(reverse('provisioning:services'))
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_service_list_customer_user_access(self):
        """Test service list view for customer user"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:services'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Active Service')
        self.assertContains(response, 'Pending Service')

    def test_service_list_admin_user_access(self):
        """Test service list view for admin user"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:services'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Active Service')
        self.assertTrue(response.context['can_manage_services'])

    def test_service_list_status_filter(self):
        """Test service list view with status filter"""
        self.client.force_login(self.customer_user)
        
        # Filter by active status
        response = self.client.get(reverse('provisioning:services'), {'status': 'active'})
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Active Service')
        self.assertNotContains(response, 'Pending Service')

    def test_service_list_pagination(self):
        """Test service list view pagination"""
        self.client.force_login(self.customer_user)
        
        # Test that pagination context is present
        response = self.client.get(reverse('provisioning:services'))
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('services', response.context)
        self.assertTrue(hasattr(response.context['services'], 'has_next'))

    def test_service_list_unauthorized_customer_access(self):
        """Test that users can only see services for their customers"""
        # Create another user and customer
        other_user = create_test_user('other@test.ro')
        other_customer = create_test_customer('Other Customer', self.admin_user)
        
        CustomerMembership.objects.create(
            user=other_user,
            customer=other_customer,
            role='owner'
        )

        # Create service for other customer
        other_service = Service.objects.create(
            customer=other_customer,
            service_plan=self.plan,
            service_name='Other Service',
            domain='other.example.com',
            username='other_user',
            billing_cycle='monthly',
            price=Decimal('25.00'),
            status='active'
        )

        # Login as first customer user
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:services'))
        
        # Should see own services but not other customer's services
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Active Service')
        self.assertNotContains(response, 'Other Service')


# ===============================================================================
# SERVICE DETAIL VIEW TESTS
# ===============================================================================

class ServiceDetailViewTestCase(TestCase):
    """Test service_detail view functionality and security"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin', is_staff=True)
        self.customer_user = create_test_user('customer@test.ro')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()
        
        # Create customer membership
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role='owner'
        )

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

    def test_service_detail_requires_login(self):
        """Test that service detail view requires authentication"""
        response = self.client.get(reverse('provisioning:service_detail', args=[self.service.pk]))
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_service_detail_customer_user_access(self):
        """Test service detail view for customer user"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:service_detail', args=[self.service.pk]))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Service')
        self.assertContains(response, 'test.example.com')
        self.assertFalse(response.context['can_manage'])

    def test_service_detail_admin_user_access(self):
        """Test service detail view for admin user"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:service_detail', args=[self.service.pk]))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Service')
        self.assertTrue(response.context['can_manage'])

    def test_service_detail_unauthorized_access(self):
        """Test service detail view denies access to unauthorized users"""
        other_user = create_test_user('other@test.ro')
        self.client.force_login(other_user)
        
        response = self.client.get(reverse('provisioning:service_detail', args=[self.service.pk]))
        
        # Should redirect back to services list with error
        self.assertEqual(response.status_code, 302)
        self.assertIn('services', response.url)

    def test_service_detail_nonexistent_service(self):
        """Test service detail view with nonexistent service returns 404"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:service_detail', args=[99999]))
        
        self.assertEqual(response.status_code, 404)


# ===============================================================================
# SERVICE CREATE VIEW TESTS
# ===============================================================================

class ServiceCreateViewTestCase(TestCase):
    """Test service_create view functionality and security"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin', is_staff=True)
        self.customer_user = create_test_user('customer@test.ro')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()

        # Create customer membership for admin user
        CustomerMembership.objects.create(
            user=self.admin_user,
            customer=self.customer,
            role='admin'
        )

    def test_service_create_requires_staff(self):
        """Test that service create view requires staff access"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:service_create'))
        
        # Should redirect due to staff_required decorator
        self.assertEqual(response.status_code, 302)

    def test_service_create_get_admin_access(self):
        """Test service create GET view for admin user"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:service_create'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'customers')
        self.assertContains(response, 'Test Hosting Plan')  # Check for the plan name in dropdown

    def test_service_create_post_success(self):
        """Test successful service creation"""
        self.client.force_login(self.admin_user)
        
        post_data = {
            'customer_id': self.customer.id,
            'plan_id': self.plan.id,
            'domain': 'newservice.example.com'
        }
        
        response = self.client.post(reverse('provisioning:service_create'), post_data)
        
        # Should create service and redirect
        self.assertEqual(response.status_code, 302)
        
        # Verify service was created
        service = Service.objects.filter(domain='newservice.example.com').first()
        self.assertIsNotNone(service)
        self.assertEqual(service.customer, self.customer)
        self.assertEqual(service.service_plan, self.plan)

    def test_service_create_post_missing_fields(self):
        """Test service creation with missing required fields"""
        self.client.force_login(self.admin_user)
        
        post_data = {
            'customer_id': self.customer.id,
            # Missing plan_id and domain
        }
        
        response = self.client.post(reverse('provisioning:service_create'), post_data)
        
        # Should stay on form with error
        self.assertEqual(response.status_code, 200)
        
        # Should not create service
        self.assertFalse(Service.objects.filter(customer=self.customer).exists())

    def test_service_create_unauthorized_customer_access(self):
        """Test service creation for unauthorized customer"""
        # Create another customer that admin doesn't have access to
        other_customer = create_test_customer('Other Customer', self.admin_user)
        
        self.client.force_login(self.admin_user)
        
        post_data = {
            'customer_id': other_customer.id,
            'plan_id': self.plan.id,
            'domain': 'unauthorized.example.com'
        }
        
        response = self.client.post(reverse('provisioning:service_create'), post_data)
        
        # Should redirect with error message
        self.assertEqual(response.status_code, 302)
        self.assertIn('services', response.url)


# ===============================================================================
# SERVICE SUSPEND/ACTIVATE VIEW TESTS
# ===============================================================================

class ServiceSuspendActivateViewTestCase(TestCase):
    """Test service suspend and activate view functionality"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin', is_staff=True)
        self.customer_user = create_test_user('customer@test.ro')
        self.customer = create_test_customer('Test Customer', self.admin_user)
        self.plan = create_test_service_plan()

        # Create customer membership
        CustomerMembership.objects.create(
            user=self.admin_user,
            customer=self.customer,
            role='admin'
        )

        self.active_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Active Service',
            domain='active.example.com',
            username='active_user',
            billing_cycle='monthly',
            price=Decimal('50.00'),
            status='active'
        )

        self.suspended_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name='Suspended Service',
            domain='suspended.example.com',
            username='suspended_user',
            billing_cycle='monthly',
            price=Decimal('30.00'),
            status='suspended'
        )

    def test_service_suspend_requires_staff(self):
        """Test that service suspend requires staff access"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:service_suspend', args=[self.active_service.pk]))
        
        # Should redirect due to staff_required decorator
        self.assertEqual(response.status_code, 302)

    def test_service_suspend_get(self):
        """Test service suspend GET view"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:service_suspend', args=[self.active_service.pk]))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Active Service')

    def test_service_suspend_post_success(self):
        """Test successful service suspension"""
        self.client.force_login(self.admin_user)
        response = self.client.post(reverse('provisioning:service_suspend', args=[self.active_service.pk]))
        
        # Should redirect to service detail
        self.assertEqual(response.status_code, 302)
        self.assertIn(f'/provisioning/services/{self.active_service.pk}/', response.url)
        
        # Verify service was suspended
        self.active_service.refresh_from_db()
        self.assertEqual(self.active_service.status, 'suspended')

    def test_service_activate_success(self):
        """Test successful service activation"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:service_activate', args=[self.suspended_service.pk]))
        
        # Should redirect to service detail
        self.assertEqual(response.status_code, 302)
        self.assertIn(f'/provisioning/services/{self.suspended_service.pk}/', response.url)
        
        # Verify service was activated
        self.suspended_service.refresh_from_db()
        self.assertEqual(self.suspended_service.status, 'active')

    def test_service_suspend_unauthorized_customer(self):
        """Test service suspension for unauthorized customer"""
        other_user = create_test_user('other@test.ro', staff_role='admin', is_staff=True)
        self.client.force_login(other_user)
        
        response = self.client.post(reverse('provisioning:service_suspend', args=[self.active_service.pk]))
        
        # Should redirect with error
        self.assertEqual(response.status_code, 302)
        self.assertIn('services', response.url)


# ===============================================================================
# PLAN LIST VIEW TESTS
# ===============================================================================

class PlanListViewTestCase(TestCase):
    """Test plan_list view functionality"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = create_test_user('user@test.ro')
        self.plan1 = create_test_service_plan(name='Basic Plan', price_monthly=Decimal('25.00'))
        self.plan2 = create_test_service_plan(name='Premium Plan', price_monthly=Decimal('75.00'))
        self.inactive_plan = create_test_service_plan(name='Inactive Plan', is_active=False)

    def test_plan_list_requires_login(self):
        """Test that plan list view requires authentication"""
        response = self.client.get(reverse('provisioning:plans'))
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_plan_list_shows_active_plans_only(self):
        """Test plan list view shows only active plans"""
        self.client.force_login(self.user)
        response = self.client.get(reverse('provisioning:plans'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Basic Plan')
        self.assertContains(response, 'Premium Plan')
        self.assertNotContains(response, 'Inactive Plan')

    def test_plan_list_ordering(self):
        """Test plan list view ordering by price"""
        self.client.force_login(self.user)
        response = self.client.get(reverse('provisioning:plans'))
        
        self.assertEqual(response.status_code, 200)
        
        # Should be ordered by price (Basic Plan first)
        plans = response.context['plans']
        plan_names = [plan.name for plan in plans]
        self.assertEqual(plan_names.index('Basic Plan'), 0)


# ===============================================================================
# SERVER LIST VIEW TESTS
# ===============================================================================

class ServerListViewTestCase(TestCase):
    """Test server_list view functionality and staff access"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin', is_staff=True)
        self.customer_user = create_test_user('customer@test.ro')
        self.server1 = create_test_server(name='Server 1')
        self.server2 = create_test_server(name='Server 2', status='maintenance')

    def test_server_list_requires_staff(self):
        """Test that server list view requires staff access"""
        self.client.force_login(self.customer_user)
        response = self.client.get(reverse('provisioning:servers'))
        
        # Should redirect due to staff_required decorator
        self.assertEqual(response.status_code, 302)

    def test_server_list_admin_access(self):
        """Test server list view for admin user"""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse('provisioning:servers'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Server 1')
        self.assertContains(response, 'Server 2')
        
        # Check context data
        self.assertEqual(response.context['active_servers'], 1)  # Only Server 1 is active
        self.assertEqual(response.context['total_servers'], 2)