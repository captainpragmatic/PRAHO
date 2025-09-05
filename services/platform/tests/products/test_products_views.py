"""
🔒 View Security Tests for Products App
Tests access control, CSRF protection, rate limiting, and security logging in views.
"""

from decimal import Decimal
from unittest.mock import patch
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core.exceptions import PermissionDenied

from apps.products.models import Product, ProductPrice
from apps.billing.models import Currency

User = get_user_model()


class ProductViewAccessControlTests(TestCase):
    """🔒 Tests for access control in product views"""
    
    def setUp(self):
        self.client = Client()
        
        # Create test users
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True
        )
        
        self.staff_user = User.objects.create_user(
            email="staff@test.com", 
            password="testpass123",
            is_staff=True,
            staff_role="support",
            is_superuser=False
        )
        
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
            is_staff=False
        )
        
        # Create test product
        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting"
        )
        
        # Create test currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON"
        )
    
    def test_product_list_requires_staff(self):
        """🔒 Test that product list requires staff access"""
        url = reverse('products:product_list')
        
        # Test unauthenticated access
        response = self.client.get(url)
        self.assertRedirects(response, f"/users/login/?next={url}")
        
        # Test regular user access - staff_required_strict returns 403 for non-staff
        self.client.login(email="user@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Test staff user access
        self.client.login(email="staff@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_product_create_requires_admin(self):
        """🔒 Test that product creation requires admin access"""
        url = reverse('products:product_create')
        
        # Test staff user (non-admin) access
        self.client.login(email="staff@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Test admin user access
        self.client.login(email="admin@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_product_edit_requires_admin(self):
        """🔒 Test that product editing requires admin access"""
        url = reverse('products:product_edit', kwargs={'slug': self.product.slug})
        
        # Test staff user (non-admin) access
        self.client.login(email="staff@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Test admin user access
        self.client.login(email="admin@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_product_toggle_requires_admin(self):
        """🔒 Test that product status toggles require admin access"""
        urls = [
            reverse('products:product_toggle_active', kwargs={'slug': self.product.slug}),
            reverse('products:product_toggle_public', kwargs={'slug': self.product.slug}),
            reverse('products:product_toggle_featured', kwargs={'slug': self.product.slug})
        ]
        
        for url in urls:
            # Test staff user (non-admin) access
            self.client.login(email="staff@test.com", password="testpass123")
            response = self.client.post(url)
            self.assertEqual(response.status_code, 403, f"Failed for URL: {url}")
    
    def test_price_create_requires_admin(self):
        """🔒 Test that price creation requires admin access"""
        url = reverse('products:product_price_create', kwargs={'slug': self.product.slug})
        
        # Test staff user (non-admin) access
        self.client.login(email="staff@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Test admin user access
        self.client.login(email="admin@test.com", password="testpass123")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class ProductViewCSRFProtectionTests(TestCase):
    """🔒 Tests for CSRF protection in product views"""
    
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True
        )
        
        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting"
        )
        
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu", 
            symbol="RON"
        )
    
    def test_product_create_csrf_protected(self):
        """🔒 Test that product creation is CSRF protected"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_create')
        
        # Test POST without CSRF token
        response = self.client.post(url, {
            'name': 'New Product',
            'slug': 'new-product',
            'product_type': 'vps'
        })
        self.assertEqual(response.status_code, 403)
    
    def test_product_edit_csrf_protected(self):
        """🔒 Test that product editing is CSRF protected"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_edit', kwargs={'slug': self.product.slug})
        
        # Test POST without CSRF token
        response = self.client.post(url, {
            'name': 'Updated Product',
            'slug': self.product.slug,
            'product_type': 'vps'
        })
        self.assertEqual(response.status_code, 403)
    
    def test_product_toggles_csrf_protected(self):
        """🔒 Test that product status toggles are CSRF protected"""
        self.client.login(email="admin@test.com", password="testpass123")
        
        urls = [
            reverse('products:product_toggle_active', kwargs={'slug': self.product.slug}),
            reverse('products:product_toggle_public', kwargs={'slug': self.product.slug}),
            reverse('products:product_toggle_featured', kwargs={'slug': self.product.slug})
        ]
        
        for url in urls:
            response = self.client.post(url)
            self.assertEqual(response.status_code, 403, f"CSRF not enforced for: {url}")
    
    def test_price_create_csrf_protected(self):
        """🔒 Test that price creation is CSRF protected"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_price_create', kwargs={'slug': self.product.slug})
        
        # Test POST without CSRF token
        response = self.client.post(url, {
            'currency': self.currency.id,
            'billing_period': 'monthly',
            'amount_cents': 10000
        })
        self.assertEqual(response.status_code, 403)


class ProductViewSecurityLoggingTests(TestCase):
    """🔒 Tests for security logging in product views"""
    
    def setUp(self):
        self.client = Client()
        
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123", 
            is_staff=True,
            is_superuser=True
        )
        
        self.staff_user = User.objects.create_user(
            email="staff@test.com",
            password="testpass123",
            is_staff=True,
            staff_role="support"
        )
        
        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product", 
            product_type="shared_hosting"
        )
        
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON"
        )
    
    @patch('apps.products.views.log_security_event')
    def test_product_list_access_logged(self, mock_log):
        """🔒 Test that product list access is logged"""
        self.client.login(email="staff@test.com", password="testpass123")
        url = reverse('products:product_list')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Should log access event
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'product_list_access')
        self.assertIn('user_email', call_args['details'])
    
    @patch('apps.products.views.log_security_event')
    def test_product_detail_access_logged(self, mock_log):
        """🔒 Test that product detail access is logged"""
        self.client.login(email="staff@test.com", password="testpass123")
        url = reverse('products:product_detail', kwargs={'slug': self.product.slug})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Should log access event
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'product_detail_access')
        self.assertEqual(call_args['details']['product_slug'], self.product.slug)
    
    @patch('apps.products.views.log_security_event')
    def test_product_creation_logged(self, mock_log):
        """🔒 Test that product creation attempts and success are logged"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_create')
        
        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']
        
        response = self.client.post(url, {
            'name': 'New Product',
            'slug': 'new-product',
            'product_type': 'vps',
            'csrfmiddlewaretoken': csrf_token
        })
        
        # Should log both attempt and success
        self.assertEqual(mock_log.call_count, 2)
        call_types = [call[1]['event_type'] for call in mock_log.call_args_list]
        self.assertIn('product_create_attempt', call_types)
        self.assertIn('product_created', call_types)
    
    @patch('apps.products.views.log_security_event')
    def test_product_status_change_logged(self, mock_log):
        """🔒 Test that product status changes are logged"""
        self.client.login(email="admin@test.com", password="testpass123")
        
        # First get CSRF token
        list_url = reverse('products:product_list')
        response = self.client.get(list_url)
        csrf_token = response.context['csrf_token']
        
        url = reverse('products:product_toggle_active', kwargs={'slug': self.product.slug})
        response = self.client.post(url, {'csrfmiddlewaretoken': csrf_token})
        
        # Should log status change
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'product_status_changed')
        self.assertEqual(call_args['details']['field'], 'is_active')
    
    @patch('apps.products.views.log_security_event')
    def test_pricing_access_logged(self, mock_log):
        """🔒 Test that pricing access is logged"""
        self.client.login(email="staff@test.com", password="testpass123")
        url = reverse('products:product_prices', kwargs={'slug': self.product.slug})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Should log pricing access
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'product_pricing_access')
        self.assertEqual(call_args['details']['product_slug'], self.product.slug)
    
    @patch('apps.products.views.log_security_event')
    def test_price_creation_logged(self, mock_log):
        """🔒 Test that price creation is logged"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_price_create', kwargs={'slug': self.product.slug})
        
        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']
        
        response = self.client.post(url, {
            'currency': self.currency.id,
            'billing_period': 'monthly',
            'amount_cents': 10000,
            'setup_cents': 0,
            'discount_percent': 0,
            'minimum_quantity': 1,
            'is_active': True,
            'csrfmiddlewaretoken': csrf_token
        })
        
        # Should log both attempt and success
        self.assertEqual(mock_log.call_count, 2)
        call_types = [call[1]['event_type'] for call in mock_log.call_args_list]
        self.assertIn('product_price_create_attempt', call_types)
        self.assertIn('product_price_created', call_types)


class ProductViewValidationTests(TestCase):
    """🔒 Tests for input validation in product views"""

    def setUp(self):
        self.client = Client()

        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )

        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting",
        )

        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON",
        )

    @patch('apps.products.views.log_security_event')
    def test_product_validation_failure_logged(self, mock_log):
        """🔒 Test that product validation failures are logged"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_create')

        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']

        # Try to create product with dangerous config
        response = self.client.post(url, {
            'name': 'Dangerous Product',
            'slug': 'dangerous-product',
            'product_type': 'vps',
            'module_config': '{"command": "eval(\'malicious\')"}',
            'csrfmiddlewaretoken': csrf_token,
        })

        # Should log validation failure
        call_types = [call[1]['event_type'] for call in mock_log.call_args_list]
        self.assertIn('product_validation_failed', call_types)

    @patch('apps.products.views.log_security_event')
    def test_price_validation_failure_logged(self, mock_log):
        """🔒 Test that price validation failures are logged"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_price_create', kwargs={'slug': self.product.slug})

        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']

        # Try to create price with negative amount
        response = self.client.post(url, {
            'currency': self.currency.id,
            'billing_period': 'monthly',
            'amount_cents': -1000,  # Negative price
            'csrfmiddlewaretoken': csrf_token,
        })

        # Should log validation failure
        call_types = [call[1]['event_type'] for call in mock_log.call_args_list]
        self.assertIn('product_price_validation_failed', call_types)

    def test_safe_product_creation_succeeds(self):
        """✅ Test that safe product creation succeeds"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_create')

        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']

        response = self.client.post(url, {
            'name': 'Safe Product',
            'slug': 'safe-product',
            'description': 'This is a safe product description',
            'product_type': 'shared_hosting',
            'is_active': True,
            'is_public': True,
            'csrfmiddlewaretoken': csrf_token,
        })

        # Should redirect on success
        self.assertEqual(response.status_code, 302)

        # Product should be created
        self.assertTrue(Product.objects.filter(slug='safe-product').exists())

    def test_safe_price_creation_succeeds(self):
        """✅ Test that safe price creation succeeds"""
        self.client.login(email="admin@test.com", password="testpass123")
        url = reverse('products:product_price_create', kwargs={'slug': self.product.slug})

        # First get the form to get CSRF token
        response = self.client.get(url)
        csrf_token = response.context['csrf_token']

        response = self.client.post(url, {
            'currency': self.currency.id,
            'billing_period': 'monthly',
            'amount_cents': 2999,  # 29.99
            'setup_cents': 500,    # 5.00
            'discount_percent': 10,
            'minimum_quantity': 1,
            'maximum_quantity': 10,
            'is_active': True,
            'csrfmiddlewaretoken': csrf_token,
        })

        # Should redirect on success
        self.assertEqual(response.status_code, 302)

        # Price should be created
        self.assertTrue(ProductPrice.objects.filter(product=self.product).exists())
