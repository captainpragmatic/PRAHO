"""
Test suite for GDPRCompliantCartSession
Tests cart functionality, GDPR compliance, and security measures.
"""

import json
from datetime import timedelta
from django.test import SimpleTestCase, override_settings
from django.contrib.sessions.backends.cache import SessionStore
from django.utils import timezone
from unittest.mock import patch, Mock

from apps.orders.services import GDPRCompliantCartSession


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestGDPRCompliantCartSession(SimpleTestCase):
    """Test the GDPR-compliant cart session implementation"""

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

    def test_add_item_validation(self):
        """Test adding items with validation"""
        cart = GDPRCompliantCartSession(self.session)

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

    def test_cart_expiry(self):
        """Test cart automatic expiry functionality"""
        cart = GDPRCompliantCartSession(self.session)

        # Add item to cart
        cart.add_item(
            product_slug='test-product',
            quantity=1,
            billing_period='monthly'
        )

        # Manually set expiry to past
        past_expiry = timezone.now() - timedelta(hours=1)
        cart.cart['expires_at'] = past_expiry.isoformat()
        cart._save_cart()

        # Create new cart session (should clear expired cart)
        new_cart = GDPRCompliantCartSession(self.session)
        self.assertEqual(len(new_cart.get_items()), 0)

    def test_update_item_quantity(self):
        """Test updating item quantities"""
        cart = GDPRCompliantCartSession(self.session)

        # Add item
        cart.add_item(
            product_slug='test-product',
            quantity=1,
            billing_period='monthly'
        )

        # Update quantity
        cart.update_item_quantity('test-product', 'monthly', 3)

        items = cart.get_items()
        self.assertEqual(items[0]['quantity'], 3)

    def test_remove_item(self):
        """Test removing items from cart"""
        cart = GDPRCompliantCartSession(self.session)

        # Add two items
        cart.add_item('product1', 1, 'monthly')
        cart.add_item('product2', 2, 'yearly')

        self.assertEqual(len(cart.get_items()), 2)

        # Remove one item
        cart.remove_item('product1', 'monthly')
        items = cart.get_items()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['product_slug'], 'product2')

    def test_cart_totals(self):
        """Test cart total calculations"""
        cart = GDPRCompliantCartSession(self.session)

        # Add items
        cart.add_item('product1', 2, 'monthly')
        cart.add_item('product2', 1, 'yearly')

        # Test counters
        self.assertEqual(cart.get_item_count(), 2)
        self.assertEqual(cart.get_total_quantity(), 3)

    def test_clear_cart(self):
        """Test clearing cart functionality"""
        cart = GDPRCompliantCartSession(self.session)

        # Add items
        cart.add_item('product1', 1, 'monthly')
        cart.add_item('product2', 2, 'yearly')

        # Clear cart
        cart.clear()

        self.assertEqual(len(cart.get_items()), 0)
        self.assertEqual(cart.get_item_count(), 0)
        self.assertEqual(cart.get_total_quantity(), 0)

    def test_gdpr_compliance(self):
        """Test GDPR compliance features"""
        cart = GDPRCompliantCartSession(self.session)

        # Add item with minimal PII
        cart.add_item(
            product_slug='test-product',
            quantity=1,
            billing_period='monthly',
            domain_name='example.ro'  # This is business data, not PII
        )

        # Ensure no personal data is stored in cart
        cart_data = cart.cart

        # Check that only business-relevant data is stored
        for item in cart_data['items']:
            # These fields should NOT contain PII
            allowed_fields = [
                'item_id', 'product_slug', 'product_name', 'product_type',
                'quantity', 'billing_period', 'domain_name', 'config', 'added_at'
            ]
            for field in item.keys():
                self.assertIn(field, allowed_fields,
                    f"Field '{field}' should not be stored in cart for GDPR compliance")

    def test_session_isolation(self):
        """Test that carts are properly isolated between sessions"""
        session1 = SessionStore()
        session1.create()
        session2 = SessionStore()
        session2.create()

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
