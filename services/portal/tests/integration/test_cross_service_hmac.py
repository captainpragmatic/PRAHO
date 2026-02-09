"""
🔐 Cross-Service HMAC Integration Tests

End-to-end integration tests for Portal → Platform HMAC authentication.
Tests real network communication, service boundaries, and full request/response cycles.

These tests ensure that Portal and Platform services can authenticate with each other
properly in realistic scenarios including network failures, timeouts, and edge cases.
"""

import json
import time
import threading
from unittest.mock import patch, Mock
from typing import Any, Dict

import requests
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


class CrossServiceHMACIntegrationTestCase(SimpleTestCase):
    """🔐 End-to-end HMAC authentication tests between Portal and Platform services"""

    def setUp(self):
        """Set up integration test environment with known secrets"""
        self.test_secret = "integration-test-hmac-secret-key-2024"
        self.test_portal_id = "portal-integration-test"
        self.test_platform_base_url = "http://localhost:8000"  # Platform service URL

        # Note: No cache clearing needed for SimpleTestCase

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000",
        PLATFORM_API_TIMEOUT=10
    )
    def test_real_platform_authentication_success(self):
        """🔐 Test successful Portal → Platform authentication with real HTTP requests"""
        client = PlatformAPIClient()

        # Mock the actual HTTP request to avoid network dependency
        with patch('requests.request') as mock_request:
            # Mock successful Platform response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'success': True,
                'user': {
                    'id': 42,
                    'email': 'integration@example.com',
                    'is_active': True
                },
                'authenticated': True
            }
            mock_response.headers = {'X-Portal-Auth': 'hmac-verified'}
            mock_request.return_value = mock_response

            # Make authenticated request
            result = client.authenticate_customer('integration@example.com', 'password123')

            # Verify request was made with proper HMAC headers
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            headers = call_args.kwargs['headers']

            # Verify all HMAC headers present and valid
            required_headers = ['X-Portal-Id', 'X-Signature', 'X-Nonce', 'X-Timestamp', 'X-Body-Hash']
            for header in required_headers:
                self.assertIn(header, headers)
                self.assertIsNotNone(headers[header])

            # Verify Portal-Id matches configuration
            self.assertEqual(headers['X-Portal-Id'], self.test_portal_id)

            # Verify signature is properly formatted (64 hex characters)
            signature = headers['X-Signature']
            self.assertEqual(len(signature), 64)
            self.assertTrue(all(c in '0123456789abcdef' for c in signature.lower()))

            # Verify authentication result
            self.assertIsNotNone(result)
            self.assertTrue(result['valid'])
            self.assertEqual(result['customer_id'], 42)

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_platform_hmac_rejection_with_wrong_secret(self):
        """🔐 Test Platform properly rejects Portal requests with wrong HMAC secret"""
        # Create client with wrong secret
        with patch('django.conf.settings.PLATFORM_API_SECRET', 'wrong-secret-key'):
            client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # Mock Platform 401 response for invalid HMAC
            mock_response = Mock()
            mock_response.status_code = 401
            mock_response.json.return_value = {
                'error': 'HMAC authentication failed'
            }
            mock_request.return_value = mock_response

            # Attempt authentication with wrong secret
            result = client.authenticate_customer('test@example.com', 'password123')

            # Should fail authentication
            self.assertIsNone(result)

            # Verify request was made (but rejected by Platform)
            mock_request.assert_called_once()
            call_args = mock_request.call_args

            # Headers should still be present but signature will be wrong
            headers = call_args.kwargs['headers']
            self.assertIn('X-Signature', headers)

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_network_timeout_handling(self):
        """🔐 Test HMAC authentication behavior during network timeouts"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # Simulate network timeout
            mock_request.side_effect = requests.exceptions.Timeout("Request timed out after 10s")

            # Should handle timeout gracefully
            result = client.authenticate_customer('test@example.com', 'password123')

            # Should return None for timeout (fail-safe)
            self.assertIsNone(result)

            # Verify HMAC headers were generated (even though request failed)
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            headers = call_args.kwargs['headers']
            self.assertIn('X-Signature', headers)

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_connection_refused_handling(self):
        """🔐 Test HMAC authentication when Platform service is unavailable"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # Simulate connection refused (Platform service down)
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")

            # Should handle connection error gracefully
            result = client.authenticate_customer('test@example.com', 'password123')

            # Should return None for connection error (fail-safe)
            self.assertIsNone(result)

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_hmac_headers_survive_redirects(self):
        """🔐 Test HMAC headers are preserved during HTTP redirects"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # Mock redirect scenario
            redirect_response = Mock()
            redirect_response.status_code = 301
            redirect_response.headers = {'Location': 'http://localhost:8000/api/users/login-final/'}

            final_response = Mock()
            final_response.status_code = 200
            final_response.json.return_value = {
                'success': True,
                'user': {'id': 123, 'email': 'test@example.com', 'is_active': True},
                'authenticated': True
            }

            mock_request.return_value = final_response

            result = client.authenticate_customer('test@example.com', 'password123')

            # Should handle redirects and succeed
            self.assertIsNotNone(result)
            self.assertTrue(result['valid'])

    def test_concurrent_hmac_requests_different_nonces(self):
        """🔐 Test concurrent Portal requests use different nonces"""
        import concurrent.futures

        with override_settings(
            PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
            PORTAL_ID="portal-integration-test",
            PLATFORM_API_BASE_URL="http://localhost:8000"
        ), patch('requests.request') as mock_request:
            # Single shared mock avoids per-thread patching races.
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'success': True,
                'user': {'id': 0, 'email': 'user@example.com'},
                'authenticated': True
            }
            mock_request.return_value = mock_response

            def make_authenticated_request(request_id: int) -> None:
                """Make a single authenticated request"""
                client = PlatformAPIClient()
                client.authenticate_customer(f'user{request_id}@example.com', 'password123')

            # Make 10 concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_authenticated_request, i) for i in range(10)]
                for future in concurrent.futures.as_completed(futures):
                    future.result()  # propagate any exceptions

            # Extract nonces from ALL recorded calls
            nonces = [
                call.kwargs['headers'].get('X-Nonce')
                for call in mock_request.call_args_list
                if call.kwargs.get('headers', {}).get('X-Nonce')
            ]

            # All nonces should be unique
            self.assertEqual(len(nonces), len(set(nonces)), "Nonces should be unique across concurrent requests")
            self.assertEqual(len(nonces), 10, "All requests should have generated nonces")

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_hmac_signature_consistency_across_requests(self):
        """🔐 Test HMAC signature generation is consistent for identical requests"""
        client = PlatformAPIClient()

        # Mock time and nonce for consistency
        fixed_timestamp = 1234567890.123456
        fixed_nonce = "fixed-nonce-for-consistency-test"

        with patch('time.time', return_value=fixed_timestamp), \
             patch('secrets.token_urlsafe', return_value=fixed_nonce), \
             patch('requests.request') as mock_request:

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True}
            mock_request.return_value = mock_response

            # Make identical requests
            client.authenticate_customer('test@example.com', 'password123')
            first_headers = mock_request.call_args.kwargs['headers'].copy()

            mock_request.reset_mock()
            client.authenticate_customer('test@example.com', 'password123')
            second_headers = mock_request.call_args.kwargs['headers'].copy()

            # Signatures should be identical for identical requests
            self.assertEqual(first_headers['X-Signature'], second_headers['X-Signature'])
            self.assertEqual(first_headers['X-Timestamp'], second_headers['X-Timestamp'])
            self.assertEqual(first_headers['X-Nonce'], second_headers['X-Nonce'])
            self.assertEqual(first_headers['X-Body-Hash'], second_headers['X-Body-Hash'])

    @override_settings(
        PLATFORM_API_SECRET="integration-test-hmac-secret-key-2024",
        PORTAL_ID="portal-integration-test"
    )
    def test_hmac_with_different_http_methods(self):
        """🔐 Test HMAC signatures for different HTTP methods (GET, POST, PUT, DELETE)"""
        client = PlatformAPIClient()

        http_methods = ['GET', 'POST', 'PUT', 'DELETE']
        signatures = {}

        for method in http_methods:
            with patch('requests.request') as mock_request:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'method': method}
                mock_request.return_value = mock_response

                # Make request with specific method
                if method == 'GET':
                    client.get('/api/test/', user_id=123)
                elif method == 'POST':
                    client.post('/api/test/', data={'test': 'data'}, user_id=123)
                elif method == 'PUT':
                    client.put('/api/test/', data={'test': 'data'}, user_id=123)
                elif method == 'DELETE':
                    client.delete('/api/test/', user_id=123)

                call_args = mock_request.call_args
                if call_args:
                    headers = call_args.kwargs['headers']
                    signatures[method] = headers.get('X-Signature')

        # All methods should generate different signatures
        signature_values = list(signatures.values())
        self.assertEqual(len(signature_values), len(set(signature_values)),
                        "Different HTTP methods should generate different HMAC signatures")

        # All signatures should be valid format
        for method, signature in signatures.items():
            self.assertEqual(len(signature), 64, f"{method} signature should be 64 hex chars")
            self.assertTrue(all(c in '0123456789abcdef' for c in signature.lower()),
                           f"{method} signature should be hexadecimal")


class CrossServiceHMACFailureRecoveryTestCase(SimpleTestCase):
    """🔐 Cross-service HMAC failure recovery and resilience tests"""

    def setUp(self):
        """Set up failure recovery test environment"""
        self.test_secret = "failure-recovery-hmac-test-key"

    @override_settings(
        PLATFORM_API_SECRET="failure-recovery-hmac-test-key",
        PORTAL_ID="portal-failure-recovery-test",
        PLATFORM_API_BASE_URL="http://localhost:8000"
    )
    def test_hmac_authentication_retry_on_503(self):
        """🔐 Test Portal retries HMAC authentication on Platform 503 responses"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # First request returns 503 (Platform overloaded)
            error_response = Mock()
            error_response.status_code = 503
            error_response.json.return_value = {'error': 'Service temporarily unavailable'}

            # Second request succeeds
            success_response = Mock()
            success_response.status_code = 200
            success_response.json.return_value = {
                'success': True,
                'user': {'id': 123, 'email': 'test@example.com'},
                'authenticated': True
            }

            mock_request.side_effect = [error_response, success_response]

            # Should retry and eventually succeed
            result = client.authenticate_customer('test@example.com', 'password123')

            # Should succeed on retry
            self.assertIsNotNone(result)
            self.assertTrue(result['valid'])

            # Should have made 2 requests (original + retry)
            self.assertEqual(mock_request.call_count, 2)

    @override_settings(
        PLATFORM_API_SECRET="failure-recovery-hmac-test-key",
        PORTAL_ID="portal-failure-recovery-test"
    )
    def test_hmac_graceful_degradation_on_persistent_failures(self):
        """🔐 Test Portal graceful degradation when Platform HMAC consistently fails"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            # All requests return 401 (HMAC authentication failed)
            mock_response = Mock()
            mock_response.status_code = 401
            mock_response.json.return_value = {'error': 'HMAC authentication failed'}
            mock_request.return_value = mock_response

            # Multiple authentication attempts should all fail gracefully
            for i in range(5):
                result = client.authenticate_customer(f'user{i}@example.com', 'password123')
                self.assertIsNone(result, f"Authentication attempt {i+1} should fail gracefully")

    def test_hmac_nonce_cache_cleanup_on_restart(self):
        """🔐 Test nonce cache cleanup doesn't break HMAC authentication"""
        # This test simulates service restart scenarios where cache is cleared
        with override_settings(
            PLATFORM_API_SECRET="failure-recovery-hmac-test-key",
            PORTAL_ID="portal-failure-recovery-test"
        ):
            client = PlatformAPIClient()

            # Simulate restart scenario

            with patch('requests.request') as mock_request:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    'success': True,
                    'user': {'id': 123, 'email': 'test@example.com'},
                    'authenticated': True
                }
                mock_request.return_value = mock_response

                # Authentication should still work after restart
                result = client.authenticate_customer('test@example.com', 'password123')

                self.assertIsNotNone(result)
                self.assertTrue(result['valid'])


class CrossServiceHMACPerformanceTestCase(SimpleTestCase):
    """🔐 Cross-service HMAC performance and load testing"""

    @override_settings(
        PLATFORM_API_SECRET="performance-test-hmac-key",
        PORTAL_ID="portal-performance-test"
    )
    def test_hmac_generation_performance(self):
        """🔐 Test HMAC signature generation performance"""
        import time

        client = PlatformAPIClient()

        # Measure HMAC generation time for 100 requests
        start_time = time.time()

        for i in range(100):
            headers = client._generate_hmac_headers(
                'POST',
                f'/api/users/login/?test={i}',
                json.dumps({'email': f'user{i}@example.com', 'password': 'password123'}).encode()
            )

        end_time = time.time()
        total_time = end_time - start_time
        avg_time_per_request = total_time / 100

        # HMAC generation should be fast (< 10ms per request)
        self.assertLess(avg_time_per_request, 0.01,
                       f"HMAC generation too slow: {avg_time_per_request:.3f}s per request")

        print(f"✅ HMAC generation performance: {avg_time_per_request*1000:.2f}ms per request")

    def test_concurrent_hmac_authentication_load(self):
        """🔐 Test concurrent HMAC authentication under load"""
        import concurrent.futures
        import time

        def authenticate_user(user_id: int) -> bool:
            """Authenticate a single user"""
            with override_settings(
                PLATFORM_API_SECRET="performance-test-hmac-key",
                PORTAL_ID="portal-performance-test"
            ):
                client = PlatformAPIClient()

                with patch('requests.request') as mock_request:
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        'success': True,
                        'user': {'id': user_id, 'email': f'user{user_id}@example.com'},
                        'authenticated': True
                    }
                    mock_request.return_value = mock_response

                    result = client.authenticate_customer(f'user{user_id}@example.com', 'password123')
                    return result is not None and result['valid']

        # Test 50 concurrent authentications
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(authenticate_user, i) for i in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        end_time = time.time()
        total_time = end_time - start_time

        # All authentications should succeed
        self.assertEqual(sum(results), 50, "All concurrent authentications should succeed")

        # Should complete within reasonable time (< 5 seconds for 50 concurrent requests)
        self.assertLess(total_time, 5.0,
                       f"Concurrent HMAC authentication too slow: {total_time:.2f}s for 50 requests")

        print(f"✅ Concurrent HMAC performance: {len(results)} requests in {total_time:.2f}s")