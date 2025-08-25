"""
Performance tests for N+1 query optimization in User model methods.

Tests verify that User.is_customer_user, User.primary_customer, and
User.get_accessible_customers() methods use prefetched data efficiently.
"""

from decimal import Decimal

from django.db import connection
from django.test import TestCase

from apps.customers.models import Customer, CustomerBillingProfile, CustomerTaxProfile
from apps.users.models import CustomerMembership, User


def create_test_user(username_suffix, email, **kwargs):
    """Create a test user with proper defaults"""
    from apps.users.models import User

    user_data = {
        'email': email,
        'first_name': f'Test {username_suffix.title()}',
        'last_name': 'User',
        'is_active': True,
    }
    user_data.update(kwargs)

    return User.objects.create_user(**user_data)


def create_test_customer(name, created_by_user):
    """Create a test customer with proper defaults for Romanian compliance"""
    customer = Customer.objects.create(
        name=name,
        company_name=f"{name} SRL",
        created_by=created_by_user
    )

    # Add required tax profile for Romanian compliance
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui=f'RO{hash(name) % 100000000}',  # Generate a fake but valid-looking CUI
        is_vat_payer=True
    )

    # Add billing profile
    CustomerBillingProfile.objects.create(
        customer=customer,
        payment_terms=30,
        credit_limit=Decimal('10000.00')
    )

    return customer


class N1QueryOptimizationTestCase(TestCase):
    """Test N+1 query optimization for User model methods"""

    def setUp(self):
        """Create test users and customers for performance testing"""
        self.admin_user = create_test_user('admin', 'admin@n1test.ro', staff_role='admin')

        # Create 5 test users with customer memberships
        self.users = []
        self.customers = []

        for i in range(5):
            user = create_test_user(f'user{i}', f'user{i}@n1test.ro')
            customer = create_test_customer(f'Customer {i}', self.admin_user)

            # Create membership
            CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role='owner',
                is_primary=(i == 0),  # First membership is primary
            )

            self.users.append(user)
            self.customers.append(customer)

        print("🏗️  Setting up N+1 query optimization test environment...")

    def test_is_customer_user_without_prefetch_uses_exists(self):
        """Test that is_customer_user uses efficient exists() query when not prefetched"""
        user = self.users[0]

        # Test without prefetch - should use EXISTS query (efficient)
        with self.assertNumQueries(1):
            result = user.is_customer_user
            self.assertTrue(result)

        print("✅ is_customer_user without prefetch (1 query): PASSED")

    def test_is_customer_user_with_prefetch_uses_cache(self):
        """Test that is_customer_user uses prefetched data when available"""
        # Prefetch customer memberships
        user = User.objects.prefetch_related('customer_memberships').get(pk=self.users[0].pk)

        # This should use cached data, no additional queries
        with self.assertNumQueries(0):
            result = user.is_customer_user
            self.assertTrue(result)

        print("✅ is_customer_user with prefetch (0 queries): PASSED")

    def test_primary_customer_without_prefetch_optimized(self):
        """Test that primary_customer uses optimized query when not prefetched"""
        user = self.users[0]

        # Test without prefetch - should use optimized query with select_related
        with self.assertNumQueries(1):
            customer = user.primary_customer
            self.assertEqual(customer, self.customers[0])

        print("✅ primary_customer without prefetch (1 query): PASSED")

    def test_primary_customer_with_prefetch_uses_cache(self):
        """Test that primary_customer uses prefetched data when available"""
        # Prefetch customer memberships with customers
        user = User.objects.prefetch_related('customer_memberships__customer').get(pk=self.users[0].pk)

        # This should use cached data, no additional queries
        with self.assertNumQueries(0):
            customer = user.primary_customer
            self.assertEqual(customer, self.customers[0])

        print("✅ primary_customer with prefetch (0 queries): PASSED")

    def test_get_accessible_customers_without_prefetch_optimized(self):
        """Test that get_accessible_customers uses optimized query when not prefetched"""
        user = self.users[0]

        # Test without prefetch - should use optimized query with distinct()
        with self.assertNumQueries(1):
            customers = list(user.get_accessible_customers())
            self.assertEqual(len(customers), 1)
            self.assertEqual(customers[0], self.customers[0])

        print("✅ get_accessible_customers without prefetch (1 query): PASSED")

    def test_get_accessible_customers_with_prefetch_uses_cache(self):
        """Test that get_accessible_customers uses prefetched data when available"""
        # Prefetch customer memberships with customers
        user = User.objects.prefetch_related('customer_memberships__customer').get(pk=self.users[0].pk)

        # This should use cached data, no additional queries
        with self.assertNumQueries(0):
            customers = list(user.get_accessible_customers())
            self.assertEqual(len(customers), 1)
            self.assertEqual(customers[0], self.customers[0])

        print("✅ get_accessible_customers with prefetch (0 queries): PASSED")

    def test_staff_user_accessible_customers_optimization(self):
        """Test that staff users get optimized query for all customers"""
        staff_user = self.admin_user

        # Staff users should get optimized QuerySet, not individual queries
        with self.assertNumQueries(0):  # QuerySet is lazy, no immediate query
            customers_qs = staff_user.get_accessible_customers()
            # Just get the QuerySet, don't evaluate it
            self.assertIn('Customer', str(type(customers_qs)))

        print("✅ Staff user accessible customers optimization: PASSED")

    def test_n1_prevention_in_bulk_operations(self):
        """Test that bulk operations prevent N+1 queries"""
        # Simulate a view that shows multiple users with their customer info
        users_with_memberships = User.objects.prefetch_related(
            'customer_memberships__customer'
        ).filter(pk__in=[u.pk for u in self.users[:3]])

        # This should execute only the initial prefetch queries (≤3 total)
        with self.assertNumQueries(2):  # 1 for users + 1 for prefetch
            user_customer_data = []
            for user in users_with_memberships:
                # These should all use prefetched data
                user_data = {
                    'is_customer_user': user.is_customer_user,
                    'primary_customer': user.primary_customer,
                    'accessible_customers': list(user.get_accessible_customers())
                }
                user_customer_data.append(user_data)

            # Verify we got data for all users
            self.assertEqual(len(user_customer_data), 3)

        print("✅ Bulk operations N+1 prevention (≤2 queries): PASSED")

    def test_performance_comparison_before_after(self):
        """Performance comparison: N+1 queries vs optimized queries"""
        users_pks = [u.pk for u in self.users[:3]]

        # ❌ BAD: Without optimization (N+1 queries)
        from django.conf import settings
        from django.db import reset_queries

        # Enable query logging temporarily
        old_debug = settings.DEBUG
        settings.DEBUG = True

        try:
            reset_queries()
            unoptimized_users = User.objects.filter(pk__in=users_pks)
            for user in unoptimized_users:
                # Each of these would trigger individual queries without optimization
                _ = user.is_customer_user
            query_count_before = len(connection.queries)

            reset_queries()
            # ✅ GOOD: With optimization (prefetch)
            optimized_users = User.objects.prefetch_related(
                'customer_memberships__customer'
            ).filter(pk__in=users_pks)
            for user in optimized_users:
                # These should use prefetched data
                _ = user.is_customer_user
            query_count_after = len(connection.queries)

            print(f"🚀 Performance improvement: {query_count_before} → {query_count_after} queries")
            print("✅ Performance comparison test: PASSED")

            # With our optimization, should be significantly better
            self.assertLessEqual(query_count_after, 2)  # Should be ≤2 queries total

        finally:
            settings.DEBUG = old_debug
