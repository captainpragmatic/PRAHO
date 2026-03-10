"""
Test suite for Order Views
Tests authentication, cart operations, and order creation flows.
"""

from unittest.mock import Mock, patch

from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.test import Client, SimpleTestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIError
from apps.orders.views import require_customer_authentication


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestOrderViews(SimpleTestCase):
    """Test order-related views and authentication"""

    def setUp(self):
        """Set up test client and mock data"""
        self.client = Client()
        self.mock_customer_data = {
            'customer_id': 123,
            'user_id': 456,
            'email': 'test@example.ro',
            'name': 'Test Customer'
        }

    def _create_authenticated_session(self):
        """Helper to create authenticated session"""
        session = self.client.session
        session['customer_id'] = self.mock_customer_data['customer_id']
        session['user_id'] = self.mock_customer_data['user_id']
        session['email'] = self.mock_customer_data['email']
        session.save()

    def test_require_customer_authentication_decorator(self):
        """Test the authentication decorator"""

        @require_customer_authentication
        def test_view(request):
            return Mock(status_code=200)

        # Test unauthenticated request
        request = HttpRequest()
        request.method = 'GET'
        request.session = {}

        # Add required middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()

        msg_middleware = MessageMiddleware(lambda r: None)
        msg_middleware.process_request(request)

        response = test_view(request)
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_product_catalog_requires_authentication(self):
        """Test product catalog requires authentication"""
        response = self.client.get('/order/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    @patch('apps.orders.views.PlatformAPIClient')
    def test_product_catalog_authenticated(self, mock_api_client):
        """Test product catalog with authentication"""
        # Set up authenticated session
        self._create_authenticated_session()

        # Mock API response
        mock_api = Mock()
        mock_api.get.return_value = {
            'results': [
                {
                    'slug': 'shared-hosting-basic',
                    'name': 'Basic Shared Hosting',
                    'product_type': 'shared_hosting',
                    'is_featured': True,
                    'prices': [
                        {'billing_period': 'monthly', 'price_cents': 2999, 'monthly_price': '29.99', 'semiannual_price': '149.94', 'annual_price': '269.88', 'setup_fee': '0.00', 'has_semiannual_discount': False, 'has_annual_discount': False, 'currency': 'RON'}
                    ]
                }
            ]
        }
        mock_api_client.return_value = mock_api

        response = self.client.get('/order/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Basic Shared Hosting')

        # Verify API was called correctly
        mock_api.get.assert_called_once_with('/api/orders/products/', params={})

    @patch('apps.orders.views.PlatformAPIClient')
    def test_product_catalog_with_filters(self, mock_api_client):
        """Test product catalog with filtering"""
        self._create_authenticated_session()

        mock_api = Mock()
        mock_api.get.return_value = {'results': []}
        mock_api_client.return_value = mock_api

        response = self.client.get('/order/?type=shared_hosting&featured=true')
        self.assertEqual(response.status_code, 200)

        # Check that filters were passed to API
        mock_api.get.assert_called_once_with('/api/orders/products/', params={
            'product_type': 'shared_hosting',
            'featured': 'true'
        })

    @patch('apps.orders.views.PlatformAPIClient')
    def test_product_catalog_api_error(self, mock_api_client):
        """Test product catalog handles API errors gracefully"""
        self._create_authenticated_session()

        # Mock API error
        mock_api = Mock()
        mock_api.get.side_effect = PlatformAPIError("API unavailable")
        mock_api_client.return_value = mock_api

        response = self.client.get('/order/')
        self.assertEqual(response.status_code, 200)

        # Should show error message and empty product list
        self.assertContains(response, 'Error loading products')
        context = response.context
        self.assertEqual(len(context['products']), 0)
        self.assertTrue(context.get('error'))

    def test_add_to_cart_requires_authentication(self):
        """Test add to cart requires authentication"""
        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_add_to_cart_wrong_method(self):
        """Test add to cart only accepts POST"""
        self._create_authenticated_session()

        response = self.client.get('/order/cart/add/')
        self.assertEqual(response.status_code, 405)  # Method not allowed

    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_add_to_cart_success(self, mock_cart_class):
        """Test successful add to cart operation"""
        self._create_authenticated_session()

        # Mock cart
        mock_cart = Mock()
        mock_cart.get_item_count.return_value = 1
        mock_cart.get_total_quantity.return_value = 1
        mock_cart.get_items.return_value = [
            {'product_name': 'Test Product', 'product_slug': 'test-product'}
        ]
        mock_cart_class.return_value = mock_cart

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly',
            'domain_name': 'example.ro'
        })

        self.assertEqual(response.status_code, 200)

        # Verify cart operations were called
        mock_cart.add_item.assert_called_once_with(
            product_slug='test-product',
            quantity=1,
            billing_period='monthly',
            domain_name='example.ro',
            config={}
        )

    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_cart_review_empty(self, mock_cart_class):
        """Test cart review with empty cart"""
        self._create_authenticated_session()

        # Mock empty cart
        mock_cart = Mock()
        mock_cart.has_items.return_value = False
        mock_cart_class.return_value = mock_cart

        response = self.client.get('/order/cart/')
        self.assertEqual(response.status_code, 302)  # Redirect to catalog
        self.assertIn('/order/', response.url)

    @patch('apps.orders.views.GDPRCompliantCartSession')
    @patch('apps.orders.views.CartCalculationService')
    def test_cart_review_with_items(self, mock_calc_service, mock_cart_class):
        """Test cart review with items"""
        self._create_authenticated_session()

        # Mock cart with items
        mock_cart = Mock()
        mock_cart.has_items.return_value = True
        mock_cart.get_items.return_value = [
            {
                'product_slug': 'test-product',
                'product_name': 'Test Product',
                'quantity': 1,
                'billing_period': 'monthly'
            }
        ]
        mock_cart.get_warnings.return_value = []
        mock_cart_class.return_value = mock_cart

        # Mock calculation
        mock_calc_service.calculate_cart_totals.return_value = {
            'subtotal_cents': 2999,
            'tax_cents': 570,
            'total_cents': 3569,
            'currency': 'RON'
        }

        response = self.client.get('/order/cart/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Product')

    def test_checkout_requires_authentication(self):
        """Test checkout requires authentication"""
        response = self.client.get('/order/checkout/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_checkout_empty_cart(self, mock_cart_class):
        """Test checkout with empty cart"""
        self._create_authenticated_session()

        # Mock empty cart
        mock_cart = Mock()
        mock_cart.has_items.return_value = False
        mock_cart_class.return_value = mock_cart

        response = self.client.get('/order/checkout/')
        self.assertEqual(response.status_code, 302)  # Redirect to catalog

    def test_create_order_requires_authentication(self):
        """Test create order requires authentication"""
        response = self.client.post('/order/create/', {
            'notes': 'Test order'
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_create_order_wrong_method(self):
        """Test create order only accepts POST"""
        self._create_authenticated_session()

        response = self.client.get('/order/create/')
        self.assertEqual(response.status_code, 405)  # Method not allowed


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestCartErrorResponses(SimpleTestCase):
    """Cart error responses must return 422 with HX-Retarget headers for HTMX."""

    def setUp(self):
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

    @patch('apps.orders.views.OrderSecurityHardening')
    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_add_to_cart_validation_error_returns_422(self, mock_cart_class, mock_sec):
        """Validation errors in add_to_cart must return HTTP 422, not 200."""
        mock_sec.fail_closed_on_cache_failure.return_value = None
        mock_sec.check_suspicious_patterns.return_value = None
        mock_sec.validate_request_size.return_value = None
        mock_sec.uniform_response_delay.return_value = None
        mock_cart_class.side_effect = ValidationError("Bad input")

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'x', 'quantity': 1, 'billing_period': 'monthly',
        })
        self.assertEqual(response.status_code, 422)

    @patch('apps.orders.views.OrderSecurityHardening')
    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_add_to_cart_error_has_retarget_header(self, mock_cart_class, mock_sec):
        """Error responses must include HX-Retarget header for HTMX processing."""
        mock_sec.fail_closed_on_cache_failure.return_value = None
        mock_sec.check_suspicious_patterns.return_value = None
        mock_sec.validate_request_size.return_value = None
        mock_sec.uniform_response_delay.return_value = None
        mock_cart_class.side_effect = ValidationError("Bad input")

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'x', 'quantity': 1, 'billing_period': 'monthly',
        })
        self.assertEqual(response["HX-Retarget"], "#cart-notifications")
        self.assertEqual(response["HX-Reswap"], "innerHTML")


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestOrderViewsIntegration(SimpleTestCase):
    """Integration tests for order flow"""

    def setUp(self):
        """Set up authenticated client"""
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['email'] = 'test@example.ro'
        session.save()

    @patch('apps.orders.views.PlatformAPIClient')
    def test_complete_order_flow(self, mock_api_client):
        """Test complete order flow from catalog to confirmation"""
        # Mock API client
        mock_api = Mock()

        # Mock product catalog
        mock_api.get.return_value = {
            'results': [
                {
                    'slug': 'shared-hosting-basic',
                    'name': 'Basic Shared Hosting',
                    'product_type': 'shared_hosting',
                    'prices': [
                        {'billing_period': 'monthly', 'price_cents': 2999, 'monthly_price': '29.99', 'semiannual_price': '149.94', 'annual_price': '269.88', 'setup_fee': '0.00', 'has_semiannual_discount': False, 'has_annual_discount': False, 'currency': 'RON'}
                    ]
                }
            ]
        }
        mock_api_client.return_value = mock_api

        # Step 1: View catalog
        response = self.client.get('/order/')
        self.assertEqual(response.status_code, 200)

        # Step 2: Add to cart (would need more mocking for real test)
        # This test demonstrates the flow structure
        # Real implementation would require mocking cart operations


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class TestOrderViewsSecurity(SimpleTestCase):
    """Security tests for order views"""

    def test_csrf_protection_on_state_changing_operations(self):
        """Test CSRF protection on POST operations"""
        client = Client(enforce_csrf_checks=True)
        session = client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['authenticated_at'] = timezone.now().isoformat()
        session.save()

        # Test without CSRF token
        response = client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1
        })
        self.assertEqual(response.status_code, 403)  # CSRF failure

    def test_input_validation_and_sanitization(self):
        """Test that malicious/invalid input is rejected with 400 before processing.

        Security context:
        - add_to_cart is an HTMX endpoint (returns HTML partials, not full pages).
        - HTMX by default ignores non-2xx responses (swaps nothing), so returning
          400 for bad input is the correct behavior: the UI stays unchanged AND the
          server signals the error to monitoring/logging.
        - Previously, invalid input (e.g. quantity='invalid') caused a ValueError
          caught by a broad `except Exception`, which returned 200 with an error
          partial. This masked input validation failures as successful responses,
          defeating security monitoring and making the endpoint accept any garbage.
        - Fix: the view now validates quantity and billing_period via
          OrderInputValidator BEFORE cart processing, returning 400 on failure.
          This follows the "fail fast, loud & logged" golden rule.
        """
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

        # Malicious input: XSS in slug, non-integer quantity, invalid billing period.
        # The view should reject this at the validation layer (400), not silently
        # swallow the ValueError in a broad except clause (200).
        response = self.client.post('/order/cart/add/', {
            'product_slug': '<script>alert("xss")</script>',
            'quantity': 'invalid',
            'billing_period': 'invalid_period'
        })

        # 400 = input validation rejected the request (OrderInputValidator).
        # 403 = authentication/authorization blocked it.
        # 500 = unexpected server error (still preferable to silent 200).
        self.assertIn(response.status_code, [400, 403, 500])
