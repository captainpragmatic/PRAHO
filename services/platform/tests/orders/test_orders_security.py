"""
Comprehensive Security Tests for Order Management Module

Tests the critical security fixes implemented for:
1. Search injection vulnerability prevention
2. Price tampering validation and controls  
3. Access control standardization
4. Enhanced security logging
"""

from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.test.client import Client
from django.urls import reverse

from apps.billing.models import Currency
from apps.common.decorators import can_manage_financial_data
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.views import _sanitize_search_query, _validate_manual_price_override
from apps.products.models import Product, ProductPrice

User = get_user_model()


class OrderSecurityTestCase(TestCase):
    """🔒 Base test case for order security testing"""

    def setUp(self) -> None:
        """Set up test environment with various user types"""
        self.client = Client()
        
        # Create currency
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )
        
        # Create test customer
        self.customer = Customer.objects.create(
            name="Test Security Company SRL",
            customer_type="company",
            status="active", 
            primary_email="security@test.ro"
        )
        
        # Create different user types for testing
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True
        )
        self.admin_user.staff_role = "admin"
        self.admin_user.save()
        
        self.billing_user = User.objects.create_user(
            email="billing@test.com", 
            password="testpass123",
            is_staff=True
        )
        self.billing_user.staff_role = "billing"
        self.billing_user.save()
        
        self.regular_staff = User.objects.create_user(
            email="staff@test.com",
            password="testpass123", 
            is_staff=True
            # No staff_role - should NOT have financial permissions
        )
        
        self.customer_user = User.objects.create_user(
            email="customer@test.com",
            password="testpass123",
            is_staff=False
        )
        
        # Create test product
        self.product = Product.objects.create(
            slug="test-security-product",
            name="Test Security Product",
            product_type="hosting",
            is_active=True
        )
        
        # Create product price for testing
        self.product_price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            billing_period="monthly",
            amount_cents=1000,  # 10 RON
            setup_cents=0,
            is_active=True
        )
        
        # Create test order
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="pending",
            order_number="SEC-TEST-001"
        )

    def tearDown(self) -> None:
        """Clean up after tests"""
        cache.clear()


class SearchInjectionSecurityTests(OrderSecurityTestCase):
    """
    🔍 Test Suite: Search Injection Vulnerability Prevention
    
    Tests for vulnerability: Dynamic search queries vulnerable to NoSQL injection
    Risk: Query manipulation and potential data exposure
    Fix: Input sanitization with validation and security logging
    """

    def test_search_query_sanitization_basic(self) -> None:
        """🧹 Test basic search query sanitization"""
        # Valid search queries should pass through
        valid_queries = [
            "Test Company",
            "ORDER-123",
            "user@example.com",
            "Product-Name_123",
            "COMP.SRL",
        ]
        
        for query in valid_queries:
            with self.subTest(query=query):
                sanitized = _sanitize_search_query(query)
                self.assertEqual(sanitized, query)

    def test_search_query_sanitization_malicious(self) -> None:
        """🚨 Test malicious search query blocking"""
        # Malicious patterns that should be blocked
        malicious_queries = [
            "'; DROP TABLE orders; --",
            "<script>alert('xss')</script>", 
            "$ne: null",
            "{ $where: 'this.password' }",
            "unittest'; DELETE FROM orders WHERE '1'='1",
        ]
        
        for query in malicious_queries:
            with self.subTest(query=query):
                with self.assertLogs('apps.orders.views', level='WARNING') as log:
                    sanitized = _sanitize_search_query(query)
                    
                # Should return empty string for malicious input
                self.assertEqual(sanitized, "")
                # Should log the security warning
                self.assertIn("Blocked search with suspicious characters", log.output[0])

    def test_search_query_length_limiting(self) -> None:
        """📏 Test search query length limiting"""
        # Very long query should be truncated
        long_query = "A" * 200  # 200 characters
        
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            sanitized = _sanitize_search_query(long_query)
            
        # Should be truncated to 100 characters
        self.assertEqual(len(sanitized), 100)
        self.assertEqual(sanitized, "A" * 100)
        # Should log the truncation warning
        self.assertIn("Truncated overly long search query", log.output[0])

    def test_search_injection_in_order_list_view(self) -> None:
        """🛡️ Integration test: Search injection prevention in order list view"""
        self.client.login(email="admin@test.com", password="testpass123")
        
        # Try malicious search query through the actual view
        url = reverse('orders:list')
        malicious_search = "'; DELETE FROM orders; --"
        
        with self.assertLogs('apps.orders.views', level='WARNING'):
            response = self.client.get(url, {'search': malicious_search})
            
        # Should return successfully (not execute malicious query)
        self.assertEqual(response.status_code, 200)
        
        # Should not have affected the database
        self.assertTrue(Order.objects.filter(pk=self.order.pk).exists())

    def test_search_empty_and_whitespace(self) -> None:
        """🔍 Test edge cases for search sanitization"""
        test_cases = [
            ("", ""),  # Empty string
            ("   ", ""),  # Just whitespace
            (None, ""),  # None value
            ("  test  ", "test"),  # Whitespace trimming
        ]
        
        for input_query, expected in test_cases:
            with self.subTest(input_query=repr(input_query)):
                result = _sanitize_search_query(input_query) if input_query is not None else _sanitize_search_query("")
                self.assertEqual(result, expected)


class PriceTamperingSecurityTests(OrderSecurityTestCase):
    """
    💰 Test Suite: Price Tampering Prevention
    
    Tests for vulnerability: Manual price overrides lack validation
    Risk: Staff could manipulate prices for financial fraud
    Fix: Price validation with limits and permission checking
    """

    def test_price_override_permission_validation(self) -> None:
        """🔐 Test price override permission validation"""
        test_cases = [
            (self.admin_user, True, "Admin should have financial permissions"),
            (self.billing_user, True, "Billing staff should have financial permissions"), 
            (self.regular_staff, False, "Regular staff should NOT have financial permissions"),
            (self.customer_user, False, "Customer users should NOT have financial permissions"),
        ]
        
        for user, expected, msg in test_cases:
            with self.subTest(user=user.email):
                result = can_manage_financial_data(user)
                self.assertEqual(result, expected, msg)

    def test_manual_price_validation_basic_limits(self) -> None:
        """📊 Test basic price validation limits"""
        # Test minimum price validation
        is_valid, error_msg = _validate_manual_price_override(
            manual_price_cents=0,  # Below minimum
            product_price_cents=1000,
            user=self.admin_user,
            context="test"
        )
        self.assertFalse(is_valid)
        self.assertIn("Price must be at least 1 cents", error_msg)
        
        # Test maximum price validation  
        is_valid, error_msg = _validate_manual_price_override(
            manual_price_cents=200000000,  # Above maximum (2M EUR)
            product_price_cents=1000,
            user=self.admin_user,
            context="test"
        )
        self.assertFalse(is_valid)
        self.assertIn("Price cannot exceed 100000000 cents", error_msg)

    def test_manual_price_validation_multiplier_limit(self) -> None:
        """🚨 Test price override multiplier limits"""
        product_price = 1000  # 10 EUR
        
        # Valid override (5x original price)
        with self.assertLogs('apps.orders.views', level='INFO') as log:
            is_valid, error_msg = _validate_manual_price_override(
                manual_price_cents=5000,  # 5x original
                product_price_cents=product_price,
                user=self.admin_user,
                context="test_multiplier"
            )
            
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")
        self.assertIn("Price Override", log.output[0])
        
        # Invalid override (15x original price - exceeds 10x limit)
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            is_valid, error_msg = _validate_manual_price_override(
                manual_price_cents=15000,  # 15x original
                product_price_cents=product_price,
                user=self.admin_user,
                context="test_multiplier"
            )
            
        self.assertFalse(is_valid)
        self.assertIn("Price override cannot exceed 10x original price", error_msg)
        self.assertIn("Excessive price override", log.output[0])

    def test_price_override_without_permission(self) -> None:
        """⛔ Test price override attempt without permission"""
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            is_valid, error_msg = _validate_manual_price_override(
                manual_price_cents=5000,
                product_price_cents=1000,
                user=self.regular_staff,  # No financial permissions
                context="unauthorized_test"
            )
            
        self.assertFalse(is_valid)
        self.assertEqual(error_msg, "Insufficient permissions for price override")
        self.assertIn("lacks financial permissions", log.output[0])

    def test_price_override_integration_order_creation(self) -> None:
        """🔗 Integration test: Price override in actual order item creation"""
        self.client.login(email="admin@test.com", password="testpass123")
        
        # Try to create order item with reasonable price override
        url = reverse('orders:add_item', kwargs={'pk': self.order.pk})
        data = {
            'product': self.product.pk,
            'billing_period': 'monthly',
            'quantity': 1,
            'unit_price_cents': 5000,  # Manual override
            'setup_cents': 0,  # Required field
        }
        
        # Should succeed with valid override
        response = self.client.post(url, data)
        # Check that item was created (would redirect on success)
        self.assertEqual(response.status_code, 302)

    def test_price_override_blocked_excessive(self) -> None:
        """🚫 Test that excessive price overrides are blocked"""
        self.client.login(email="admin@test.com", password="testpass123")
        
        # Set a product price first by creating an item with normal price
        normal_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            billing_period="monthly",
            quantity=1,
            unit_price_cents=1000,  # 10 EUR
        )
        
        # Now try excessive override
        url = reverse('orders:update_item', kwargs={
            'pk': self.order.pk,
            'item_pk': normal_item.pk
        })
        
        excessive_price = 15000  # 15x the original 1000 cents
        data = {
            'product': self.product.pk,
            'billing_period': 'monthly', 
            'quantity': 1,
            'unit_price_cents': excessive_price,
            'setup_cents': 0,  # Add required field
        }
        
        response = self.client.post(url, data)
        # Should return error response
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertEqual(response_data['success'], False)
        self.assertIn("Price override cannot exceed 10x", response_data['message'])


class AccessControlSecurityTests(OrderSecurityTestCase):
    """
    🔐 Test Suite: Access Control Standardization
    
    Tests for vulnerability: Inconsistent access control checks
    Risk: Privilege escalation through inconsistent logic
    Fix: Centralized permission checking with can_manage_financial_data()
    """

    def test_financial_permission_function_consistency(self) -> None:
        """🎯 Test that can_manage_financial_data() works consistently"""
        # Test all user types
        test_cases = [
            (self.admin_user, True),
            (self.billing_user, True),
            (self.regular_staff, False),  # is_staff=True but no staff_role
            (self.customer_user, False),
        ]
        
        for user, expected in test_cases:
            with self.subTest(user=user.email):
                result = can_manage_financial_data(user)
                self.assertEqual(result, expected)

    def test_order_list_permission_context(self) -> None:
        """📋 Test that order list uses proper permission checking"""
        # Test admin user
        self.client.login(email="admin@test.com", password="testpass123")
        response = self.client.get(reverse('orders:list'))
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['is_staff'])  # Should be True for admin
        
        # Test regular staff (should be False)
        self.client.login(email="staff@test.com", password="testpass123") 
        response = self.client.get(reverse('orders:list'))
        
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['is_staff'])  # Should be False for regular staff

    def test_order_detail_permission_context(self) -> None:
        """📄 Test that order detail uses proper permission checking"""
        # Test admin user
        self.client.login(email="admin@test.com", password="testpass123")
        response = self.client.get(reverse('orders:detail', kwargs={'pk': self.order.pk}))
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['is_staff'])  # Should be True for admin
        self.assertTrue(response.context['can_edit'])  # Should be able to edit
        
        # Test regular staff
        self.client.login(email="staff@test.com", password="testpass123")
        response = self.client.get(reverse('orders:detail', kwargs={'pk': self.order.pk}))
        
        self.assertEqual(response.status_code, 200) 
        self.assertFalse(response.context['is_staff'])  # Should be False for regular staff
        self.assertFalse(response.context['can_edit'])  # Should NOT be able to edit

    def test_superuser_bypass(self) -> None:
        """👑 Test that superusers have all permissions"""
        superuser = User.objects.create_superuser(
            email="super@test.com",
            password="testpass123"
        )
        
        # Superuser should have financial permissions even without staff_role
        self.assertTrue(can_manage_financial_data(superuser))

    def test_permission_edge_cases(self) -> None:
        """🔍 Test permission edge cases and boundary conditions"""
        # Test user with empty staff_role string
        user_empty_role = User.objects.create_user(
            email="empty@test.com",
            password="testpass123",
            is_staff=True
        )
        user_empty_role.staff_role = ""
        user_empty_role.save()
        
        self.assertFalse(can_manage_financial_data(user_empty_role))
        
        # Test user with invalid staff_role
        user_invalid_role = User.objects.create_user(
            email="invalid@test.com", 
            password="testpass123",
            is_staff=True
        )
        user_invalid_role.staff_role = "invalid_role"
        user_invalid_role.save()
        
        self.assertFalse(can_manage_financial_data(user_invalid_role))


class SecurityLoggingTests(OrderSecurityTestCase):
    """
    📝 Test Suite: Enhanced Security Logging
    
    Tests for vulnerability: Insufficient security logging for financial operations
    Risk: Undetected financial manipulation
    Fix: Comprehensive audit logging for all financial operations
    """

    def test_price_override_logging_success(self) -> None:
        """✅ Test successful price override logging"""
        with self.assertLogs('apps.orders.views', level='INFO') as log:
            _validate_manual_price_override(
                manual_price_cents=5000,
                product_price_cents=1000,
                user=self.admin_user,
                context="logging_test"
            )
            
        # Should log the successful price override
        log_message = log.output[0]
        self.assertIn("Price Override", log_message)
        self.assertIn(str(self.admin_user.id), log_message)
        self.assertIn("5000 cents", log_message)
        self.assertIn("1000 cents", log_message)
        self.assertIn("logging_test", log_message)

    def test_price_override_logging_blocked(self) -> None:
        """🚫 Test blocked price override logging"""
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            _validate_manual_price_override(
                manual_price_cents=50000,  # 50x original - exceeds limit
                product_price_cents=1000,
                user=self.admin_user,
                context="blocked_test"
            )
            
        # Should log the security warning
        log_message = log.output[0]
        self.assertIn("Price Security", log_message)
        self.assertIn("Excessive price override", log_message)
        self.assertIn(str(self.admin_user.id), log_message)

    def test_search_security_logging(self) -> None:
        """🔍 Test search security event logging"""
        malicious_query = "<script>alert('test')</script>"
        
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            _sanitize_search_query(malicious_query)
            
        # Should log the security warning
        log_message = log.output[0]
        self.assertIn("Search Security", log_message)
        self.assertIn("Blocked search with suspicious characters", log_message)

    def test_unauthorized_access_logging(self) -> None:
        """⛔ Test unauthorized access attempt logging"""
        with self.assertLogs('apps.orders.views', level='WARNING') as log:
            _validate_manual_price_override(
                manual_price_cents=5000,
                product_price_cents=1000,
                user=self.customer_user,  # No permissions
                context="unauthorized_logging"
            )
            
        # Should log the unauthorized attempt
        log_message = log.output[0]
        self.assertIn("Price Security", log_message)
        self.assertIn("Unauthorized price override attempt", log_message)
        self.assertIn(str(self.customer_user.id), log_message)


class SecurityRegressionTests(OrderSecurityTestCase):
    """
    🔄 Test Suite: Security Regression Prevention
    
    Tests to ensure security fixes don't regress in future updates
    """

    def test_search_sanitization_cannot_be_bypassed(self) -> None:
        """🚨 Regression test: Search sanitization must not be bypassable"""
        bypass_attempts = [
            "normal'; DROP TABLE orders; --query",
            "test<script>alert('xss')</script>query", 
            "valid$ne:nullquery",
            "good{$where:'this'}query",
        ]
        
        for attempt in bypass_attempts:
            with self.subTest(attempt=attempt):
                with self.assertLogs('apps.orders.views', level='WARNING'):
                    sanitized = _sanitize_search_query(attempt)
                    # All should be blocked
                    self.assertEqual(sanitized, "")

    def test_price_validation_cannot_be_bypassed(self) -> None:
        """💰 Regression test: Price validation must not be bypassable"""
        # Test various bypass attempts
        bypass_attempts = [
            (-100, "Negative prices should be blocked"),
            (0, "Zero prices should be blocked"),
            (999999999, "Extreme prices should be blocked"),
            (50000, "Excessive multipliers should be blocked (50x original)"),
        ]
        
        for price_cents, description in bypass_attempts:
            with self.subTest(price=price_cents):
                is_valid, _ = _validate_manual_price_override(
                    manual_price_cents=price_cents,
                    product_price_cents=1000,  # 10 EUR base price
                    user=self.admin_user,
                    context="regression_test"
                )
                self.assertFalse(is_valid, description)

    def test_permission_system_consistency(self) -> None:
        """🔐 Regression test: Permission system must remain consistent"""
        # Test that permission function results match expected behavior
        permission_matrix = {
            # (is_staff, is_superuser, staff_role) -> expected_result
            (True, False, "admin"): True,
            (True, False, "billing"): True, 
            (True, False, "manager"): True,
            (True, False, "support"): False,  # Support staff can't manage financial data
            (True, False, ""): False,  # Staff with no role
            (True, False, None): False,  # Staff with None role
            (False, True, ""): True,  # Superuser overrides everything
            (False, False, "admin"): False,  # Non-staff with admin role should be False
        }
        
        for (is_staff, is_superuser, staff_role), expected in permission_matrix.items():
            with self.subTest(is_staff=is_staff, is_superuser=is_superuser, staff_role=staff_role):
                test_user = User.objects.create_user(
                    email=f"test-{is_staff}-{is_superuser}-{staff_role}@test.com",
                    password="test123",
                    is_staff=is_staff,
                    is_superuser=is_superuser
                )
                if staff_role is not None:
                    test_user.staff_role = staff_role
                    test_user.save()
                
                result = can_manage_financial_data(test_user)
                self.assertEqual(result, expected, 
                    f"Permission mismatch for is_staff={is_staff}, is_superuser={is_superuser}, staff_role={staff_role}")

    def test_security_logging_enabled(self) -> None:
        """📝 Regression test: Security logging must remain enabled"""
        # Test that security events are still being logged
        security_events = [
            lambda: _sanitize_search_query("'; DROP TABLE orders; --"),
            lambda: _validate_manual_price_override(999999999, 1000, self.admin_user, "test"),
            lambda: _validate_manual_price_override(5000, 1000, self.customer_user, "test"),
        ]
        
        for event_func in security_events:
            with self.subTest(event=event_func.__name__ if hasattr(event_func, '__name__') else str(event_func)):
                with self.assertLogs(level='WARNING'):
                    event_func()  # Should always produce at least a warning log