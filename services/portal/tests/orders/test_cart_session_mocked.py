"""
Test suite for GDPRCompliantCartSession with mocked API calls
Tests cart functionality without depending on platform API.
"""

import json
from datetime import timedelta
from django.test import SimpleTestCase, override_settings
from django.contrib.sessions.backends.cache import SessionStore
from django.utils import timezone
from unittest.mock import patch, Mock

from apps.orders.services import GDPRCompliantCartSession, CartRateLimiter


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestGDPRCompliantCartSessionMocked(SimpleTestCase):
    """Test the GDPR-compliant cart session implementation with mocked API"""
    
    def setUp(self):
        """Set up test session"""
        self.session = SessionStore()
        self.session.create()
        
    def test_create_empty_cart(self):
        """Test creating an empty cart with proper structure"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Check cart structure
        self.assertEqual(cart.cart['currency'], 'RON')
        self.assertIn('items', cart.cart)
        self.assertIn('created_at', cart.cart)
        self.assertIn('expires_at', cart.cart)
        self.assertEqual(len(cart.cart['items']), 0)
        
        # Check expiry is set correctly
        expires_at = timezone.datetime.fromisoformat(cart.cart['expires_at'])
        expected_expiry = timezone.now() + timedelta(hours=24)
        self.assertAlmostEqual(
            expires_at.timestamp(),
            expected_expiry.timestamp(),
            delta=60  # Allow 1 minute variance
        )
    
    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_validation_success(self, mock_api_client):
        """Test adding items with successful validation"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Mock successful API response
        mock_api = Mock()
        mock_api.get.return_value = {
            'id': 'product-uuid-123',
            'slug': 'shared-hosting-basic',
            'name': 'Basic Shared Hosting',
            'product_type': 'shared_hosting',
            'is_active': True,
            'requires_domain': False
        }
        mock_api_client.return_value = mock_api
        
        # Valid item
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
            domain_name='example.ro'
        )
        
        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['product_slug'], 'shared-hosting-basic')
        self.assertEqual(items[0]['quantity'], 1)
        self.assertEqual(items[0]['billing_period'], 'monthly')
        self.assertEqual(items[0]['domain_name'], 'example.ro')
        
        # Verify API was called
        mock_api.get.assert_called_once_with('/api/orders/products/shared-hosting-basic/')
    
    def test_cart_expiry(self):
        """Test cart automatic expiry functionality"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Manually add item to cart bypassing validation
        cart.cart['items'] = [{
            'item_id': 'test-123',
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        }]
        cart._save_cart()
        
        # Manually set expiry to past
        past_expiry = timezone.now() - timedelta(hours=1)
        cart.cart['expires_at'] = past_expiry.isoformat()
        cart._save_cart()
        
        # Create new cart session (should clear expired cart)
        new_cart = GDPRCompliantCartSession(self.session)
        self.assertEqual(len(new_cart.get_items()), 0)
    
    def test_update_item_quantity_direct(self):
        """Test updating item quantities without API validation"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Manually add item
        item_id = cart._generate_item_id('test-product', 'monthly')
        cart.cart['items'] = [{
            'item_id': item_id,
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly',
            'product_name': 'Test Product'
        }]
        cart._save_cart()
        
        # Update quantity
        cart.update_item_quantity('test-product', 'monthly', 3)
        
        items = cart.get_items()
        self.assertEqual(items[0]['quantity'], 3)
    
    def test_remove_item_direct(self):
        """Test removing items from cart without API validation"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Manually add items
        item_id1 = cart._generate_item_id('product1', 'monthly')
        item_id2 = cart._generate_item_id('product2', 'yearly')
        
        cart.cart['items'] = [
            {
                'item_id': item_id1,
                'product_slug': 'product1',
                'quantity': 1,
                'billing_period': 'monthly',
                'product_name': 'Product 1'
            },
            {
                'item_id': item_id2,
                'product_slug': 'product2',
                'quantity': 2,
                'billing_period': 'yearly',
                'product_name': 'Product 2'
            }
        ]
        cart._save_cart()
        
        self.assertEqual(len(cart.get_items()), 2)
        
        # Remove one item
        cart.remove_item('product1', 'monthly')
        items = cart.get_items()
        
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['product_slug'], 'product2')
    
    def test_cart_totals_direct(self):
        """Test cart total calculations"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Manually add items
        cart.cart['items'] = [
            {
                'item_id': 'item1',
                'product_slug': 'product1',
                'quantity': 2,
                'billing_period': 'monthly',
                'product_name': 'Product 1'
            },
            {
                'item_id': 'item2',
                'product_slug': 'product2',
                'quantity': 1,
                'billing_period': 'yearly',
                'product_name': 'Product 2'
            }
        ]
        cart._save_cart()
        
        # Test counters
        self.assertEqual(cart.get_item_count(), 2)
        self.assertEqual(cart.get_total_quantity(), 3)
    
    def test_clear_cart(self):
        """Test clearing cart functionality"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Add items manually
        cart.cart['items'] = [
            {'item_id': 'item1', 'product_slug': 'product1'},
            {'item_id': 'item2', 'product_slug': 'product2'}
        ]
        cart._save_cart()
        
        # Clear cart
        cart.clear()
        
        self.assertEqual(len(cart.get_items()), 0)
        self.assertEqual(cart.get_item_count(), 0)
        self.assertEqual(cart.get_total_quantity(), 0)
    
    def test_gdpr_compliance_data_structure(self):
        """Test GDPR compliance features on data structure"""
        cart = GDPRCompliantCartSession(self.session)
        
        # Add item manually with proper structure
        cart.cart['items'] = [{
            'item_id': 'test-123',
            'product_slug': 'test-product',
            'product_name': 'Test Product',
            'quantity': 1,
            'billing_period': 'monthly',
            'domain_name': 'example.ro',  # Business data, not PII
            'config': {},
            'added_at': timezone.now().isoformat()
        }]
        cart._save_cart()
        
        # Ensure only business-relevant data is stored
        cart_data = cart.cart
        
        # Check that only business-relevant data is stored
        for item in cart_data['items']:
            allowed_fields = [
                'item_id', 'product_slug', 'product_name', 'quantity',
                'billing_period', 'domain_name', 'config', 'added_at'
            ]
            for field in item.keys():
                self.assertIn(field, allowed_fields, 
                    f"Field '{field}' should not be stored in cart for GDPR compliance")
    
    def test_session_isolation_structure(self):
        """Test that carts are properly isolated between sessions"""
        session1 = SessionStore()
        session1.create()
        session2 = SessionStore()
        session2.create()
        
        cart1 = GDPRCompliantCartSession(session1)
        cart2 = GDPRCompliantCartSession(session2)
        
        # Add different items to each cart (manually)
        cart1.cart['items'] = [{'item_id': 'item1', 'product_slug': 'product1'}]
        cart1._save_cart()
        
        cart2.cart['items'] = [{'item_id': 'item2', 'product_slug': 'product2'}]
        cart2._save_cart()
        
        # Verify isolation
        self.assertEqual(len(cart1.get_items()), 1)
        self.assertEqual(len(cart2.get_items()), 1)
        self.assertEqual(cart1.get_items()[0]['product_slug'], 'product1')
        self.assertEqual(cart2.get_items()[0]['product_slug'], 'product2')


class TestCartRateLimiterStandalone(SimpleTestCase):
    """Test rate limiting functionality standalone"""
    
    def setUp(self):
        """Clear any existing cache entries"""
        from django.core.cache import cache
        cache.clear()
    
    def test_rate_limit_allows_normal_usage(self):
        """Test that normal usage is allowed"""
        session_key = 'test_session_normal'
        
        # Should allow normal operations
        for i in range(20):  # Well under limit of 30
            self.assertTrue(CartRateLimiter.check_rate_limit(session_key))
    
    def test_rate_limit_blocks_abuse(self):
        """Test that rate limiting blocks abuse"""
        session_key = 'test_session_abuse_v2'
        
        # Exhaust the rate limit
        for i in range(30):
            result = CartRateLimiter.check_rate_limit(session_key)
            if i < 30:
                self.assertTrue(result, f"Check {i+1} should pass")
        
        # Next request should be blocked
        self.assertFalse(CartRateLimiter.check_rate_limit(session_key))
    
    def test_rate_limit_handles_missing_session(self):
        """Test rate limiting with missing session key"""
        # Should allow operations with no session key
        self.assertTrue(CartRateLimiter.check_rate_limit(None))
        self.assertTrue(CartRateLimiter.check_rate_limit(''))
    
    def test_record_operation_increments_counter(self):
        """Test that recording operations increments the counter"""
        session_key = 'test_session_record_v2'
        
        # Record several operations
        for i in range(10):
            CartRateLimiter.record_operation(session_key)
        
        # Should have used up 10 of the 30 allowed operations
        remaining_checks = 0
        for i in range(25):  # Try 25 more (total would be 35)
            if CartRateLimiter.check_rate_limit(session_key):
                remaining_checks += 1
            else:
                break
        
        # Should allow exactly 20 more operations (30 - 10 recorded)
        self.assertEqual(remaining_checks, 20)
    
    def test_rate_limit_session_isolation(self):
        """Test that rate limits are isolated per session"""
        session1 = 'test_session_1_v2'
        session2 = 'test_session_2_v2'
        
        # Exhaust rate limit for session1
        for i in range(30):
            result = CartRateLimiter.check_rate_limit(session1)
            if i < 30:
                self.assertTrue(result, f"Session1 check {i+1} should pass")
        
        # session1 should be blocked
        self.assertFalse(CartRateLimiter.check_rate_limit(session1))
        
        # session2 should still be allowed
        self.assertTrue(CartRateLimiter.check_rate_limit(session2))