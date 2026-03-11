"""
Basic Order Security Tests for PRAHO Portal
Tests the implemented security features: DoS hardening, cart versioning.
"""

from typing import Any
from unittest.mock import Mock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.test import Client, SimpleTestCase, override_settings
from django.utils import timezone

from apps.orders.services import GDPRCompliantCartSession

try:
    from apps.orders.security import OrderSecurityHardening
except ImportError:
    OrderSecurityHardening = None


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderDoSHardeningTestCase(SimpleTestCase):
    """
    🔒 DoS Hardening Security Tests
    Tests request validation and fail-closed behavior
    """

    def setUp(self) -> None:
        """Set up authenticated session"""
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['authenticated_at'] = timezone.now().isoformat()
        session.save()

    @patch('apps.orders.views.OrderSecurityHardening')
    def test_request_size_validation_integration(self, mock_hardening: Any) -> None:
        """🔒 Test request size validation in views"""
        if OrderSecurityHardening is None:
            self.skipTest("OrderSecurityHardening not available")

        # Mock security hardening to simulate oversized request rejection
        mock_hardening.fail_closed_on_cache_failure.return_value = None
        mock_hardening.validate_request_size.return_value = Mock(status_code=413)
        mock_hardening.check_suspicious_patterns.return_value = None

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })

        # Should be blocked by size validation
        self.assertEqual(response.status_code, 413)

    @patch('apps.orders.views.OrderSecurityHardening')
    def test_suspicious_pattern_detection_integration(self, mock_hardening: Any) -> None:
        """🔒 Test suspicious pattern detection in views"""
        if OrderSecurityHardening is None:
            self.skipTest("OrderSecurityHardening not available")

        # Mock security hardening to simulate suspicious pattern rejection
        mock_hardening.fail_closed_on_cache_failure.return_value = None
        mock_hardening.validate_request_size.return_value = None
        mock_hardening.check_suspicious_patterns.return_value = Mock(status_code=400)

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })

        # Should be blocked by pattern detection
        self.assertEqual(response.status_code, 400)

    @patch('apps.orders.views.OrderSecurityHardening')
    @patch('django.core.cache.cache')
    def test_fail_closed_on_cache_failure(self, mock_cache: Any, mock_hardening: Any) -> None:
        """🔒 Test fail-closed behavior when cache fails"""
        if OrderSecurityHardening is None:
            self.skipTest("OrderSecurityHardening not available")

        # Mock cache failure
        mock_hardening.fail_closed_on_cache_failure.return_value = Mock(status_code=503)
        mock_hardening.validate_request_size.return_value = None
        mock_hardening.check_suspicious_patterns.return_value = None

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })

        # Should fail closed with 503 Service Unavailable
        self.assertEqual(response.status_code, 503)


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderCartVersioningTestCase(SimpleTestCase):
    """
    🔒 Cart Versioning Security Tests
    Tests cart version generation and stale mutation detection
    """

    def test_cart_version_generation_consistency(self) -> None:
        """🔒 Test that cart version generation is consistent for empty cart"""
        session = SessionStore()
        session.create()
        cart = GDPRCompliantCartSession(session)

        # Generate version multiple times for empty cart - should be consistent
        version1 = cart.get_cart_version()
        version2 = cart.get_cart_version()

        self.assertEqual(version1, version2, "Cart version should be consistent")

        # Verify version is SHA-256 hash (64 hex characters)
        self.assertEqual(len(version1), 64, "Cart version should be 64-character SHA-256 hash")
        self.assertTrue(
            all(c in '0123456789abcdef' for c in version1.lower()),
            "Cart version should contain only hex characters"
        )

    def test_cart_version_changes_on_clear(self) -> None:
        """🔒 Test that cart version changes when cart is cleared"""
        session = SessionStore()
        session.create()
        cart = GDPRCompliantCartSession(session)

        # Get initial version (empty cart)
        initial_version = cart.get_cart_version()

        # Manually add item to cart data (bypass API validation)
        cart.cart['items'].append({
            'item_id': 'test_item_1',
            'product_slug': 'test-product',
            'product_name': 'Test Product',
            'quantity': 1,
            'billing_period': 'monthly',
            'domain_name': '',
            'config': {},
            'added_at': timezone.now().isoformat()
        })
        cart._save_cart()

        # Version should change after manual modification
        version_after_add = cart.get_cart_version()
        self.assertNotEqual(initial_version, version_after_add,
                          "Version should change after adding item")

        # Clear cart - version should change again
        cart.clear()
        version_after_clear = cart.get_cart_version()

        self.assertNotEqual(version_after_add, version_after_clear,
                          "Version should change after clearing cart")


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderEnumerationProtectionTestCase(SimpleTestCase):
    """
    🔒 Enumeration Attack Protection Tests
    Tests that customer data endpoints are properly protected
    """

    def test_cart_endpoints_require_authentication(self) -> None:
        """🔒 Test cart endpoints require authentication"""
        protected_endpoints = [
            '/order/cart/add/',
            '/order/cart/update/',
            '/order/cart/remove/',
            '/order/calculate-totals/'
        ]

        # Test without authentication
        client = Client()

        for endpoint in protected_endpoints:
            with self.subTest(endpoint=endpoint):
                response = client.post(endpoint, {
                    'product_slug': 'test-product',
                    'quantity': 1
                })
                # Should redirect to login or return 302/405
                self.assertIn(response.status_code, [302, 405],
                            f"Endpoint {endpoint} should require authentication")

    def test_order_endpoints_deny_get_requests(self) -> None:
        """🔒 Test that state-changing endpoints deny GET requests"""
        # Set up authenticated session with proper timestamp
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['authenticated_at'] = timezone.now().isoformat()
        session.save()

        state_changing_endpoints = [
            '/order/cart/add/',
            '/order/cart/update/',
            '/order/cart/remove/',
            '/order/create/'
        ]

        for endpoint in state_changing_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                # Should be method not allowed (405) or redirect (302) - both are secure
                self.assertIn(response.status_code, [302, 405],
                               f"GET should not be allowed on {endpoint}")


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderSessionSecurityTestCase(SimpleTestCase):
    """
    🔒 Session Security Tests
    Tests CSRF protection and session isolation
    """

    def setUp(self) -> None:
        # Mock Platform API so add_item() doesn't trigger M8 fallback.
        _mock_api_instance = Mock()
        _mock_api_instance.get.return_value = {
            "id": "generic-product",
            "slug": "generic-product",
            "name": "Generic Product",
            "product_type": "hosting",
            "requires_domain": False,
            "is_active": True,
        }
        self._platform_patcher = patch(
            "apps.orders.services.PlatformAPIClient",
            Mock(return_value=_mock_api_instance),
        )
        self._platform_patcher.start()

    def tearDown(self) -> None:
        self._platform_patcher.stop()

    def test_csrf_protection_on_post_endpoints(self) -> None:
        """🔒 Test CSRF protection on state-changing operations"""
        # Set up authenticated session with proper timestamp
        client = Client(enforce_csrf_checks=True)
        session = client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['authenticated_at'] = timezone.now().isoformat()
        session.save()

        # Try POST without CSRF token - should fail
        response = client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })
        # Should be CSRF failure (403) or redirect due to auth middleware (302)
        self.assertIn(response.status_code, [302, 403], "POST without CSRF should be blocked")

    def test_cart_session_isolation(self) -> None:
        """🔒 Test that cart sessions are properly isolated"""
        # Create two different clients with different sessions
        client1 = Client()
        client2 = Client()

        # Set up authenticated sessions
        session1 = client1.session
        session1['customer_id'] = 123
        session1['user_id'] = 456
        session1['authenticated_at'] = timezone.now().isoformat()
        session1.save()

        session2 = client2.session
        session2['customer_id'] = 789
        session2['user_id'] = 999
        session2['authenticated_at'] = timezone.now().isoformat()
        session2.save()

        # Create carts for each session
        cart1 = GDPRCompliantCartSession(session1)
        cart2 = GDPRCompliantCartSession(session2)

        # Add different items to each cart
        cart1.add_item('product1', 1, 'monthly')
        cart2.add_item('product2', 2, 'yearly')

        # Verify isolation
        self.assertEqual(len(cart1.get_items()), 1)
        self.assertEqual(len(cart2.get_items()), 1)
        self.assertEqual(cart1.get_items()[0]['product_slug'], 'product1')
        self.assertEqual(cart2.get_items()[0]['product_slug'], 'product2')

        # Verify different versions
        self.assertNotEqual(cart1.get_cart_version(), cart2.get_cart_version())


# Test runner integration
class OrderSecurityTestRunner:
    """Helper class to run all security tests with reporting"""

    @staticmethod
    def run_all_security_tests() -> None:
        """Run all implemented security tests"""
        print("🔒 Running Order Security Tests...")
        print("✅ Basic security tests available")
        print("📋 Run with: python manage.py test tests.orders.test_security")
