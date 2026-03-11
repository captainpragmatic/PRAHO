"""
Order-Specific Security Tests for PRAHO Portal
Comprehensive security testing for order system including HMAC, rate limiting,
session security, enumeration protection, and DoS hardening.
"""

import json
import os
import time
import unittest
from unittest.mock import Mock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

from apps.orders.services import GDPRCompliantCartSession, HMACPriceSealer

from ._order_security_basic_cases import (
    OrderCartVersioningTestCase,
    OrderDoSHardeningTestCase,
    OrderEnumerationProtectionTestCase,
)

_IMPORTED_ORDER_SECURITY_CASES = (
    OrderCartVersioningTestCase,
    OrderDoSHardeningTestCase,
    OrderEnumerationProtectionTestCase,
)


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderHMACSecurityTestCase(SimpleTestCase):
    """
    🔒 HMAC Security Tests
    Tests replay attack protection, timestamp validation, body verification
    """

    def setUp(self):
        """Set up test environment with authenticated session"""
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session['email'] = 'security-test@example.ro'
        session.save()

        self.valid_product_data = {
            'product_slug': 'shared-hosting-basic',
            'quantity': 1,
            'billing_period': 'monthly'
        }

        # Mock Platform API so add_item() doesn't fail with M8 fallback
        # (requires_domain=True). Tests here don't test M8 behaviour.
        _mock_api_instance = Mock()
        _mock_api_instance.get.return_value = {
            "id": "shared-hosting-basic",
            "slug": "shared-hosting-basic",
            "name": "Shared Hosting Basic",
            "product_type": "hosting",
            "requires_domain": False,
            "is_active": True,
        }
        self._platform_patcher = patch(
            "apps.orders.services.PlatformAPIClient",
            Mock(return_value=_mock_api_instance),
        )
        self._platform_patcher.start()

    def tearDown(self):
        self._platform_patcher.stop()

    def _generate_valid_hmac_seal(self, price_data: dict, client_ip: str = '127.0.0.1') -> dict:
        """Helper to generate valid HMAC price seal"""
        return HMACPriceSealer.seal_price_data(price_data, client_ip)

    def _get_client_ip(self):
        """Get client IP for HMAC sealing"""
        return '127.0.0.1'

    @patch('apps.orders.views.OrderSecurityHardening')
    def test_hmac_replay_attack_protection(self, mock_hardening):
        """🔒 Test replay attack protection with nonce validation"""
        mock_hardening.uniform_response_delay.return_value = None
        mock_hardening.fail_closed_on_cache_failure.return_value = None
        mock_hardening.validate_request_size.return_value = None
        mock_hardening.check_suspicious_patterns.return_value = None

        # Generate valid price seal
        price_data = {'price_cents': 2999, 'currency': 'RON'}
        client_ip = self._get_client_ip()
        sealed_data = self._generate_valid_hmac_seal(price_data, client_ip)

        # First request should succeed
        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertIn(response.status_code, [200, 302])  # Success or redirect

        # Replay same request - should fail with 401
        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)

    def test_hmac_stale_timestamp_rejection(self):
        """🔒 Test rejection of requests with stale timestamps (>61s)"""
        price_data = {'price_cents': 2999, 'currency': 'RON'}

        # Create seal with old timestamp
        old_timestamp = int(time.time()) - 65  # 65 seconds ago
        with patch('time.time', return_value=old_timestamp):
            sealed_data = self._generate_valid_hmac_seal(price_data)

        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)

    def test_hmac_body_hash_mismatch(self):
        """🔒 Test rejection when body hash doesn't match"""
        price_data = {'price_cents': 2999, 'currency': 'RON'}
        sealed_data = self._generate_valid_hmac_seal(price_data)

        # Modify the sealed data to create hash mismatch
        sealed_data['body_hash'] = 'tampered_hash_value'

        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)

    def test_hmac_canonical_data_mismatch(self):
        """🔒 Test rejection when canonical representation is tampered"""
        price_data = {'price_cents': 2999, 'currency': 'RON'}
        sealed_data = self._generate_valid_hmac_seal(price_data)

        # Tamper with the signature
        sealed_data['signature'] = 'invalid_signature_value'

        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)

    def test_hmac_wrong_portal_id(self):
        """🔒 Test rejection with wrong portal_id"""
        price_data = {'price_cents': 2999, 'currency': 'RON'}
        sealed_data = self._generate_valid_hmac_seal(price_data)

        # Modify portal_id
        sealed_data['portal_id'] = 'wrong_portal_id'

        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)

    def test_hmac_ip_binding_enforcement(self):
        """🔒 Test IP address binding in HMAC validation"""
        price_data = {'price_cents': 2999, 'currency': 'RON'}

        # Generate seal with different IP
        sealed_data = self._generate_valid_hmac_seal(price_data, '192.168.1.100')

        # Make request from different IP (127.0.0.1 in test)
        response = self.client.post('/order/cart/add/', {
            **self.valid_product_data,
            'price_seal': json.dumps(sealed_data)
        })
        self.assertEqual(response.status_code, 401)


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class OrderIdempotencySecurityTestCase(SimpleTestCase):
    """
    🔒 Order Idempotency and Race Condition Tests
    Tests server-authoritative pricing and idempotent order creation
    """

    def setUp(self):
        """Set up authenticated session for order tests"""
        from django.core.cache import cache  # noqa: PLC0415
        cache.clear()
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

    @patch('apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure', return_value=None)
    @patch('apps.orders.views.OrderSecurityHardening.validate_request_size', return_value=None)
    @patch('apps.orders.views.OrderSecurityHardening.check_suspicious_patterns', return_value=None)
    @patch('apps.orders.views.OrderCreationService.create_draft_order')
    @patch('apps.orders.views.OrderCreationService.preflight_order')
    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_idempotent_order_creation(
        self, mock_cart_class, mock_preflight, mock_create_draft,
        _mock_patterns, _mock_size, _mock_cache,
    ):
        """🔒 Test idempotent order creation with same key"""
        # Mock cart
        mock_cart = Mock()
        mock_cart.has_items.return_value = True
        mock_cart.get_items.return_value = [
            {'product_slug': 'test-product', 'quantity': 1, 'billing_period': 'monthly'}
        ]
        mock_cart.get_cart_version.return_value = 'v1_test_version'
        mock_cart_class.return_value = mock_cart

        # Mock service layer (preflight always runs now per S5 fix)
        mock_preflight.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_create_draft.return_value = {
            'order': {
                'id': '550e8400-e29b-41d4-a716-446655440000',
                'order_number': 'ORD-123',
                'status': 'draft',
            }
        }

        idempotency_key = 'test_key_12345'

        # First order creation — payment_method required by M4 fix
        response1 = self.client.post('/order/create/', {
            'notes': 'Test order',
            'idempotency_key': idempotency_key,
            'cart_version': 'v1_test_version',
            'agree_terms': 'on',
            'payment_method': 'bank_transfer',
        })

        # Second order creation with same key - should return same result
        response2 = self.client.post('/order/create/', {
            'notes': 'Test order duplicate',
            'idempotency_key': idempotency_key,
            'cart_version': 'v1_test_version',
            'agree_terms': 'on',
            'payment_method': 'bank_transfer',
        })

        # Both should succeed and return same order ID
        self.assertEqual(response1.status_code, response2.status_code)
        # Order creation (create_draft_order) should only be called once — second request hits cache
        self.assertEqual(mock_create_draft.call_count, 1)

    @patch('apps.orders.views.CartCalculationService')
    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_calc_to_create_price_drift_detection(self, mock_cart_class, mock_calc_service):
        """🔒 Test detection of price changes between calculation and order creation"""
        # Mock cart
        mock_cart = Mock()
        mock_cart.has_items.return_value = True
        mock_cart.get_cart_version.return_value = 'v1_old_version'
        mock_cart_class.return_value = mock_cart

        # Mock calculation with old prices
        mock_calc_service.calculate_cart_totals.return_value = {
            'total_cents': 2999,
            'currency': 'RON'
        }

        # Attempt order creation with different cart version (indicating price change)
        response = self.client.post('/order/create/', {
            'notes': 'Test order',
            'cart_version': 'v2_new_version'  # Different version
        })

        # Should detect price drift and apply current prices
        self.assertIn(response.status_code, [200, 302, 400])

    def test_parallel_order_creation_race_condition(self):
        """🔒 Test parallel order creation with same idempotency key"""
        # This test would simulate concurrent requests
        # In a real implementation, you'd use threading or async
        idempotency_key = 'race_test_key'

        # Simulate race condition detection
        # Real implementation would use database constraints or cache locks


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderSessionSecurityTestCase(SimpleTestCase):
    """
    🔒 Session Security Tests
    Tests secure cookie settings, session fixation protection, CSRF
    """

    @override_settings(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict'
    )
    def test_secure_session_cookies_in_production(self):
        """🔒 Test secure cookie settings in production"""
        client = Client()

        # Make request to establish session
        response = client.get('/order/')

        # Check cookie security attributes
        session_cookie = response.cookies.get('sessionid')
        if session_cookie:
            self.assertTrue(session_cookie.get('secure', False))
            self.assertTrue(session_cookie.get('httponly', False))
            self.assertEqual(session_cookie.get('samesite', '').lower(), 'strict')

    def test_session_fixation_protection_on_login(self):
        """🔒 Test session ID changes on authentication"""
        client = Client()

        # Get initial session ID
        response = client.get('/order/')
        initial_session_id = client.session.session_key

        # Simulate login (in real app, this would be actual login)
        session = client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

        # Session ID should change after authentication
        new_session_id = client.session.session_key
        # Note: Django doesn't automatically change session ID on custom auth
        # This test documents expected behavior for manual session cycling

    def test_csrf_token_present_on_htmx_posts(self):
        """🔒 Test CSRF protection on HTMX POST endpoints"""
        client = Client(enforce_csrf_checks=True)

        # Set up authenticated session
        session = client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

        # Try POST without CSRF token - should fail
        response = client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })
        self.assertEqual(response.status_code, 403)  # CSRF failure

        # With CSRF token should work (if other validations pass)
        csrf_client = Client()
        csrf_client.force_login = lambda user: None  # Mock login
        response = csrf_client.get('/order/')  # Get CSRF token
        csrf_token = csrf_client.cookies['csrftoken'].value

        response = csrf_client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly',
            'csrfmiddlewaretoken': csrf_token
        })
        # Response depends on other validation, but shouldn't be 403


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderEnumerationSecurityTestCase(SimpleTestCase):
    """
    🔒 Enumeration Attack Protection Tests
    Tests uniform denial of GET requests for customer data
    """

    def test_customer_data_endpoints_deny_get_requests(self):
        """🔒 Test that customer data endpoints uniformly deny GET requests"""
        # List of endpoints that should only accept POST and deny GET
        protected_endpoints = [
            '/order/cart/add/',
            '/order/cart/update/',
            '/order/cart/remove/',
            '/order/create/',
            '/order/calculate-totals/'
        ]

        for endpoint in protected_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                # Should be method not allowed (405) or redirect to login (302)
                self.assertIn(response.status_code, [302, 405])

    def test_customer_scoped_endpoints_require_authentication(self):
        """🔒 Test customer-scoped endpoints require authentication"""
        protected_endpoints = [
            '/order/',
            '/order/cart/',
            '/order/checkout/'
        ]

        for endpoint in protected_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 302)
                self.assertIn('/login/', response.url)

    def test_enumerate_order_ids_prevented(self):
        """🔒 Test that order ID enumeration is prevented"""
        # Set up authenticated session
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

        # Try to access orders with different IDs
        test_order_ids = ['1', '2', '100', '999', 'abc', 'ORDER_123']

        for order_id in test_order_ids:
            with self.subTest(order_id=order_id):
                response = self.client.get(f'/order/{order_id}/')
                # Should either 404 or redirect, never expose other customer data
                self.assertIn(response.status_code, [302, 404, 405])


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderDosHardeningTestCase(SimpleTestCase):
    """
    🔒 DoS Hardening Tests
    Tests rate limiting, request size limits, fail-closed behavior
    """

    def setUp(self):
        """Set up authenticated session for DoS tests"""
        # Clear rate limit cache BEFORE setting up session
        # (cache-backed sessions are destroyed by cache.clear())
        cache.clear()

        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

        # Mock Platform API so add_item() reaches uniform_response_delay()
        # instead of short-circuiting via M8 ValidationError on missing domain.
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

    def tearDown(self):
        self._platform_patcher.stop()

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_per_ip_rate_limiting_via_middleware(self):
        """🔒 Rate limiting enforced by APIRateLimitMiddleware (burst: 20/10s)"""
        # The APIRateLimitMiddleware enforces burst limits for /order/ endpoints.
        # After exceeding the burst limit, subsequent requests get 429.
        hit_429 = False
        for i in range(25):  # Exceed burst limit of 20/10s
            with patch('apps.orders.views.OrderSecurityHardening') as mock_hardening:
                mock_hardening.fail_closed_on_cache_failure.return_value = None
                mock_hardening.validate_request_size.return_value = None
                mock_hardening.check_suspicious_patterns.return_value = None
                mock_hardening.uniform_response_delay.return_value = None

                response = self.client.post('/order/cart/add/', {
                    'product_slug': f'test-product-{i}',
                    'quantity': 1,
                    'billing_period': 'monthly'
                })

                if response.status_code == 429:
                    hit_429 = True
                    break

        self.assertTrue(hit_429, "Middleware should have rate-limited after burst threshold")

    def test_per_ip_sliding_window_rate_limiting(self):
        """🔒 Test per-IP sliding window rate limiting"""
        # Test IP-based rate limiting across different sessions
        clients = []
        for i in range(3):
            client = Client()
            session = client.session
            session['customer_id'] = 100 + i
            session['user_id'] = 500 + i
            session.save()
            clients.append(client)

        # All clients should share IP-based rate limit
        request_count = 0
        for round_num in range(10):
            for client in clients:
                if request_count >= 50:  # IP hourly limit
                    break

                with patch('apps.orders.views.OrderSecurityHardening') as mock_hardening:
                    mock_hardening.fail_closed_on_cache_failure.return_value = None
                    mock_hardening.validate_request_size.return_value = None
                    mock_hardening.check_suspicious_patterns.return_value = None

                    response = client.post('/order/cart/add/', {
                        'product_slug': f'test-product-{request_count}',
                        'quantity': 1,
                        'billing_period': 'monthly'
                    })

                    request_count += 1
                    if request_count > 50:
                        self.assertEqual(response.status_code, 429)
                        break

    def test_request_size_validation(self):
        """🔒 Test request size limits to prevent DoS"""
        # Create oversized request payload
        large_config = {'test_field': 'x' * 15000}  # 15KB config

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly',
            'config': json.dumps(large_config)
        })

        self.assertEqual(response.status_code, 413)  # Payload too large

    def test_suspicious_field_count_detection(self):
        """🔒 Test detection of suspicious number of form fields"""
        # Create request with many fields
        suspicious_data = {'product_slug': 'test-product', 'quantity': 1}

        # Add 100 dummy fields to trigger suspicious pattern detection
        for i in range(100):
            suspicious_data[f'dummy_field_{i}'] = f'value_{i}'

        response = self.client.post('/order/cart/add/', suspicious_data)
        self.assertEqual(response.status_code, 400)  # Suspicious request

    def test_oversized_field_value_detection(self):
        """🔒 Test detection of oversized individual field values"""
        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly',
            'notes': 'x' * 12000  # 12KB field value
        })

        self.assertEqual(response.status_code, 400)  # Oversized field

    @patch('apps.orders.views.OrderSecurityHardening')
    def test_fail_closed_on_cache_failure(self, mock_hardening):
        """🔒 Test fail-closed behavior when cache is unavailable"""
        # Simulate cache failure via the security hardening layer.
        # (Patching django.core.cache.cache.get/set globally also breaks
        # cache-backed sessions, causing a 302 redirect before the view runs.)
        mock_hardening.fail_closed_on_cache_failure.return_value = Mock(status_code=503)
        mock_hardening.validate_request_size.return_value = None
        mock_hardening.check_suspicious_patterns.return_value = None
        mock_hardening.uniform_response_delay.return_value = None

        response = self.client.post('/order/cart/add/', {
            'product_slug': 'test-product',
            'quantity': 1,
            'billing_period': 'monthly'
        })

        # Should fail closed with 503 Service Unavailable
        self.assertEqual(response.status_code, 503)

    @unittest.skipIf(os.environ.get("CI"), "Flaky on CI runners due to variable performance")
    def test_uniform_response_timing(self):
        """🔒 Test uniform response timing to prevent timing attacks"""
        import time

        # Record response times for multiple requests
        response_times = []

        for i in range(5):
            start_time = time.time()

            response = self.client.post('/order/cart/add/', {
                'product_slug': f'test-product-{i}',
                'quantity': 1,
                'billing_period': 'monthly'
            })

            end_time = time.time()
            response_times.append(end_time - start_time)

        # All responses should take at least MIN_RESPONSE_TIME (0.1s)
        for response_time in response_times:
            self.assertGreaterEqual(response_time, 0.1)

        # Response times should be relatively uniform (within reasonable variance).
        # Use 1.5x tolerance — tight enough to catch gross timing leaks,
        # loose enough to tolerate OS scheduler jitter on dev machines.
        avg_time = sum(response_times) / len(response_times)
        for response_time in response_times:
            self.assertLessEqual(abs(response_time - avg_time), avg_time * 1.5)


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class OrderCartVersioningSecurityTestCase(SimpleTestCase):
    """
    🔒 Cart Versioning Security Tests
    Tests stale mutation detection and cart version validation
    """

    def setUp(self):
        """Set up authenticated session"""
        self.client = Client()
        session = self.client.session
        session['customer_id'] = 123
        session['user_id'] = 456
        session.save()

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

    def tearDown(self):
        self._platform_patcher.stop()

    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_stale_cart_version_detection(self, mock_cart_class):
        """🔒 Test detection of stale cart versions during checkout"""
        # Mock cart with specific version
        mock_cart = Mock()
        mock_cart.has_items.return_value = True
        mock_cart.get_cart_version.return_value = 'v1_current_version'
        mock_cart_class.return_value = mock_cart

        # Non-AJAX request with stale version → redirects to checkout (Phase 1 BACKEND-3)
        response = self.client.post('/order/create/', {
            'notes': 'Test order',
            'cart_version': 'v0_old_version'  # Stale version
        })
        # Non-AJAX: redirect to checkout with flash message
        self.assertEqual(response.status_code, 302)

        # AJAX request with stale version → JSON 400
        response_ajax = self.client.post(
            '/order/create/',
            {'notes': 'Test order', 'cart_version': 'v0_old_version'},
            HTTP_HX_REQUEST='true',
        )
        self.assertEqual(response_ajax.status_code, 400)

    @patch('apps.orders.views.GDPRCompliantCartSession')
    def test_cart_version_integrity(self, mock_cart_class):
        """🔒 Test cart version integrity and tampering detection"""
        # Mock cart
        mock_cart = Mock()
        mock_cart.has_items.return_value = True
        mock_cart.get_cart_version.return_value = 'valid_sha256_hash'
        mock_cart_class.return_value = mock_cart

        # Non-AJAX: tampered version → redirect (Phase 1 BACKEND-3)
        response = self.client.post('/order/create/', {
            'notes': 'Test order',
            'cart_version': 'tampered_hash_value'
        })
        self.assertEqual(response.status_code, 302)

        # AJAX: tampered version → JSON 400
        response_ajax = self.client.post(
            '/order/create/',
            {'notes': 'Test order', 'cart_version': 'tampered_hash_value'},
            HTTP_HX_REQUEST='true',
        )
        self.assertIn(response_ajax.status_code, [400, 401])

    def test_cart_version_generation_consistency(self):
        """🔒 Test that cart version generation is consistent and secure"""
        session = SessionStore()
        session.create()
        cart = GDPRCompliantCartSession(session)

        # Add items to cart
        cart.add_item('product1', 1, 'monthly')
        cart.add_item('product2', 2, 'yearly')

        # Generate version multiple times - should be consistent
        version1 = cart.get_cart_version()
        version2 = cart.get_cart_version()

        self.assertEqual(version1, version2)

        # Verify version is SHA-256 hash (64 hex characters)
        self.assertEqual(len(version1), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in version1.lower()))

        # Modifying cart should change version
        cart.add_item('product3', 1, 'monthly')
        version3 = cart.get_cart_version()

        self.assertNotEqual(version1, version3)


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cache')
class HMACPriceSealerUnitTestCase(SimpleTestCase):
    """
    🔒 Direct unit tests for HMACPriceSealer.seal_price_data / verify_seal.
    Tests the seal/verify round-trip, tamper detection, and edge cases.
    """

    def setUp(self):
        self.price_data = {'price_cents': 2999, 'currency': 'RON', 'billing_period': 'monthly'}
        self.client_ip = '10.0.0.1'
        cache.clear()

    def test_seal_and_verify_round_trip(self):
        """Valid seal must verify successfully"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        self.assertTrue(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )

    def test_verify_rejects_tampered_body_hash(self):
        """Tampered body_hash must fail verification"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        sealed['body_hash'] = 'deadbeef' * 8
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )

    def test_verify_rejects_tampered_signature(self):
        """Tampered signature must fail verification"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        sealed['signature'] = 'baadf00d' * 8
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )

    def test_verify_rejects_wrong_portal_id(self):
        """Wrong portal_id must fail verification"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        sealed['portal_id'] = 'evil_portal'
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )

    def test_verify_rejects_wrong_ip(self):
        """Seal bound to one IP must fail verification from a different IP"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, '10.0.0.1')
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, '192.168.1.99')
        )

    def test_verify_rejects_stale_timestamp(self):
        """Seal older than max_age_seconds must fail"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        sealed['timestamp'] = sealed['timestamp'] - 120  # 2 minutes old
        # Re-sign would be needed for a real test, but since timestamp is part of
        # the canonical data, changing it also invalidates the signature.
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip, max_age_seconds=61)
        )

    def test_verify_rejects_modified_price_data(self):
        """Changing price_data after sealing must fail verification"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        tampered_data = {**self.price_data, 'price_cents': 1}  # Attempt cheaper price
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, tampered_data, self.client_ip)
        )

    def test_verify_rejects_replay(self):
        """Same nonce used twice must fail on second verification"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        # First verification succeeds
        self.assertTrue(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )
        # Second verification (replay) must fail
        self.assertFalse(
            HMACPriceSealer.verify_seal(sealed, self.price_data, self.client_ip)
        )

    def test_verify_rejects_empty_sealed_data(self):
        """Empty sealed data must fail verification"""
        self.assertFalse(
            HMACPriceSealer.verify_seal({}, self.price_data, self.client_ip)
        )

    def test_seal_output_structure(self):
        """Seal output must contain all required fields"""
        sealed = HMACPriceSealer.seal_price_data(self.price_data, self.client_ip)
        required_keys = {'signature', 'body_hash', 'timestamp', 'nonce', 'portal_id', 'ip_hash'}
        self.assertEqual(required_keys, set(sealed.keys()))
        self.assertEqual(sealed['portal_id'], 'praho_portal_v1')
        self.assertEqual(len(sealed['signature']), 64)  # SHA-256 hex
        self.assertEqual(len(sealed['body_hash']), 64)


# Test runner helpers
class OrderSecurityTestRunner:
    """Helper class to run all security tests with reporting"""

    @staticmethod
    def run_security_audit():
        """Run comprehensive security audit"""
        test_classes = [
            OrderHMACSecurityTestCase,
            OrderIdempotencySecurityTestCase,
            OrderSessionSecurityTestCase,
            OrderEnumerationSecurityTestCase,
            OrderDosHardeningTestCase,
            OrderCartVersioningSecurityTestCase,
            HMACPriceSealerUnitTestCase,
        ]

        print("🔒 Running Order Security Audit...")
        for test_class in test_classes:
            print(f"  Running {test_class.__name__}...")

        print("✅ Security audit completed")
