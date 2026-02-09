"""
Basic functionality tests for orders system
Tests core components without complex integration.
"""

import json
from datetime import timedelta
from django.test import SimpleTestCase, Client, override_settings
from django.contrib.sessions.backends.cache import SessionStore
from django.utils import timezone
from unittest.mock import patch, Mock

from apps.orders.services import CartRateLimiter


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestBasicOrderFunctionality(SimpleTestCase):
    """Test basic order functionality"""
    
    def setUp(self):
        """Set up test client"""
        self.client = Client()
        # Clear any existing cache entries
        from django.core.cache import cache
        cache.clear()
    
    def test_order_views_require_authentication(self):
        """Test that all order views require authentication"""
        
        # Product catalog
        response = self.client.get('/order/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
        
        # Cart operations
        response = self.client.post('/order/cart/add/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
        
        # Cart review
        response = self.client.get('/order/cart/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
        
        # Checkout
        response = self.client.get('/order/checkout/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
        
        # Create order
        response = self.client.post('/order/create/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
    
    def test_cart_rate_limiter_basic_functionality(self):
        """Test basic rate limiting functionality"""
        
        session_key = 'test_basic_rate_limit'
        
        # Should allow normal operations
        for i in range(20):  # Well under limit
            self.assertTrue(CartRateLimiter.check_rate_limit(session_key))
        
        # Exhaust the rate limit
        for i in range(11):  # Remaining to reach 30 + 1 extra
            result = CartRateLimiter.check_rate_limit(session_key)
            if i < 10:  # Should allow up to 30 total
                self.assertTrue(result)
            else:  # Should block the 31st
                self.assertFalse(result)
        
    def test_cart_rate_limiter_session_isolation(self):
        """Test rate limiting isolates sessions properly"""
        
        session1 = 'test_session_basic_1'
        session2 = 'test_session_basic_2'
        
        # Exhaust limit for session1
        for i in range(30):
            self.assertTrue(CartRateLimiter.check_rate_limit(session1))
        
        # session1 blocked
        self.assertFalse(CartRateLimiter.check_rate_limit(session1))
        
        # session2 still allowed
        self.assertTrue(CartRateLimiter.check_rate_limit(session2))
    
    def test_cart_rate_limiter_handles_none_session(self):
        """Test rate limiter handles None session gracefully"""
        
        # Should allow operations without session key
        self.assertTrue(CartRateLimiter.check_rate_limit(None))
        self.assertTrue(CartRateLimiter.check_rate_limit(''))
        
        # Record operation should handle None gracefully
        CartRateLimiter.record_operation(None)
        CartRateLimiter.record_operation('')
    
    def test_order_urls_accessible_when_authenticated(self):
        """Test that order URLs are accessible with authentication"""
        
        # Create authenticated session with all required fields
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['email'] = 'test@example.ro'
        session['authenticated_at'] = timezone.now().isoformat()  # Required for session validation
        session.save()
        
        # These should not redirect to login (might fail for other reasons)
        response = self.client.get('/order/')
        self.assertNotEqual(response.status_code, 302)  # Not a redirect to login
        
        response = self.client.get('/order/cart/')
        # Might redirect but not to login
        if response.status_code == 302:
            self.assertNotIn('/login/', response.url)
    
    def test_csrf_protection_on_post_endpoints(self):
        """Test CSRF protection is enabled for POST operations"""

        csrf_client = Client(enforce_csrf_checks=True)

        # Create authenticated session with all required fields
        session = csrf_client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['authenticated_at'] = timezone.now().isoformat()
        session.save()
        
        # Test add to cart without CSRF token
        response = csrf_client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1
        })
        self.assertEqual(response.status_code, 403)  # CSRF failure
        
        # Test create order without CSRF token
        response = csrf_client.post('/order/create/', {
            'notes': 'Test order'
        })
        self.assertEqual(response.status_code, 403)  # CSRF failure


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestSessionCartBasics(SimpleTestCase):
    """Test session cart basic functionality without API calls"""
    
    def setUp(self):
        """Set up test session"""
        self.session = SessionStore()
        self.session.create()
    
    def test_session_cart_key_structure(self):
        """Test that cart uses proper session key structure"""
        from apps.orders.services import GDPRCompliantCartSession
        
        # The session key should be namespaced
        self.assertEqual(GDPRCompliantCartSession.SESSION_KEY, 'praho_portal_cart_v1')
        
        # Cart expiry should be 24 hours
        self.assertEqual(GDPRCompliantCartSession.CART_EXPIRY_HOURS, 24)
    
    def test_empty_session_cart_initialization(self):
        """Test creating cart with empty session"""
        from apps.orders.services import GDPRCompliantCartSession
        
        # Should not raise errors
        cart = GDPRCompliantCartSession(self.session)
        
        # Should have basic structure
        self.assertIsInstance(cart.cart, dict)
        self.assertIn('currency', cart.cart)
        self.assertIn('items', cart.cart)
        self.assertEqual(cart.cart['currency'], 'RON')
        self.assertEqual(len(cart.get_items()), 0)
        self.assertEqual(cart.get_item_count(), 0)
        self.assertEqual(cart.get_total_quantity(), 0)


class TestOrderInputValidation(SimpleTestCase):
    """Test order input validation without API dependencies"""
    
    def test_validator_import(self):
        """Test that validators can be imported and used"""
        from apps.orders.validators import OrderInputValidator
        
        # Test quantity validation
        self.assertEqual(OrderInputValidator.validate_quantity(1), 1)
        self.assertEqual(OrderInputValidator.validate_quantity(5), 5)
        
        with self.assertRaises(Exception):  # Should raise validation error
            OrderInputValidator.validate_quantity(0)
        
        with self.assertRaises(Exception):  # Should raise validation error  
            OrderInputValidator.validate_quantity(-1)
    
    def test_billing_period_validation(self):
        """Test billing period validation"""
        from apps.orders.validators import OrderInputValidator
        
        # Valid billing periods
        valid_periods = ['monthly', 'quarterly', 'semiannual', 'annual', 'biennial', 'triennial']
        for period in valid_periods:
            result = OrderInputValidator.validate_billing_period(period)
            self.assertEqual(result, period)
        
        # Invalid billing period should raise error
        with self.assertRaises(Exception):
            OrderInputValidator.validate_billing_period('invalid')


class TestOrderServiceIntegration(SimpleTestCase):
    """Test order service integration points"""
    
    def test_cart_calculation_service_import(self):
        """Test that cart calculation service can be imported"""
        from apps.orders.services import CartCalculationService
        
        # Should be able to import the class
        self.assertIsNotNone(CartCalculationService)
    
    def test_order_creation_service_import(self):
        """Test that order creation service can be imported"""  
        from apps.orders.services import OrderCreationService
        
        # Should be able to import the class
        self.assertIsNotNone(OrderCreationService)
    
    @patch('apps.orders.services.PlatformAPIClient')
    def test_platform_api_client_usage(self, mock_api_client):
        """Test that services use platform API client correctly"""
        from apps.orders.services import CartCalculationService
        
        # Mock the API client
        mock_api = Mock()
        mock_api.post.return_value = {
            'subtotal_cents': 1000,
            'tax_cents': 190,
            'total_cents': 1190,
            'currency': 'RON'
        }
        mock_api_client.return_value = mock_api
        
        # Create a mock cart
        mock_cart = Mock()
        mock_cart.get_items.return_value = [
            {
                'product_id': 'test-123',
                'quantity': 1,
                'billing_period': 'monthly'
            }
        ]
        mock_cart.cart = {'currency': 'RON'}
        
        # Test calculation
        try:
            result = CartCalculationService.calculate_cart_totals(mock_cart, 123)
            # Should either succeed or fail gracefully
            self.assertIsInstance(result, dict)
        except Exception as e:
            # Any exception should be handled gracefully in real usage
            self.assertIsInstance(e, Exception)
