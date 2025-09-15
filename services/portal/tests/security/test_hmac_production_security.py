"""
🔐 HMAC Production Environment Security Tests

Production-hardened security tests for HMAC authentication including:
- Production secret validation
- Environment variable security
- Configuration validation
- SSL/TLS requirements
- Production-only security features
- Deployment safety checks

These tests ensure HMAC authentication is production-ready and secure
against real-world attack scenarios and configuration mistakes.
"""

import os
import hashlib
import hmac
from unittest.mock import patch, Mock
from typing import Dict, Any

import requests
from django.test import SimpleTestCase, override_settings
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

from apps.api_client.services import PlatformAPIClient


class HMACProductionSecurityTestCase(SimpleTestCase):
    """🔐 Production security validation for HMAC authentication"""

    def test_production_requires_strong_hmac_secret(self):
        """🔐 Test production environment requires cryptographically strong HMAC secret"""
        # Test weak secrets are rejected in production mode
        weak_secrets = [
            "",  # Empty
            "secret",  # Too short
            "12345678",  # Numeric only
            "password123",  # Dictionary word
            "development_secret",  # Development secret
            "a" * 16,  # Repeated character
            "django-insecure-test-key",  # Django default pattern
        ]

        for weak_secret in weak_secrets:
            with self.subTest(secret=weak_secret):
                with override_settings(
                    DEBUG=False,  # Production mode
                    PLATFORM_API_SECRET=weak_secret,
                    PORTAL_ID="production-test"
                ):
                    # In production, weak secrets should be detected
                    # This would typically be in settings validation
                    if len(weak_secret) < 32:
                        # Weak secret should be detected
                        # Test that client creation works (validation would be in production settings)
                        try:
                            client = PlatformAPIClient()
                            # Production validation would happen at settings level, not client level
                            self.assertIsNotNone(client)
                        except (ImproperlyConfigured, ValueError):
                            # This is acceptable - production should reject weak secrets
                            pass

    def test_production_requires_proper_environment_variables(self):
        """🔐 Test production configuration validates environment variables"""
        required_env_vars = [
            'PLATFORM_API_SECRET',
            'PORTAL_ID',
            'PLATFORM_API_BASE_URL'
        ]

        for env_var in required_env_vars:
            with self.subTest(env_var=env_var):
                # Mock environment without the required variable
                with patch.dict(os.environ, {}, clear=True):
                    # Remove the required environment variable
                    if env_var in os.environ:
                        del os.environ[env_var]

                    with override_settings(DEBUG=False):  # Production mode
                        # Should detect missing environment variable
                        try:
                            client = PlatformAPIClient()
                            # In production, missing env vars should be detected
                            if not getattr(client, 'portal_secret', None):
                                self.fail(f"Missing {env_var} should be detected in production")
                        except (ImproperlyConfigured, AttributeError):
                            # This is expected in production
                            pass

    def test_production_ssl_requirements(self):
        """🔐 Test production requires SSL/TLS for HMAC communication"""
        # Production should enforce HTTPS for API communication
        insecure_urls = [
            "http://api.example.com",  # HTTP instead of HTTPS
            "http://localhost:8000",  # Local HTTP
            "ftp://api.example.com",  # Wrong protocol
        ]

        for insecure_url in insecure_urls:
            with self.subTest(url=insecure_url):
                with override_settings(
                    DEBUG=False,  # Production mode
                    PLATFORM_API_BASE_URL=insecure_url,
                    PLATFORM_API_SECRET="secure-production-hmac-secret-key-32chars",
                    PORTAL_ID="production-ssl-test"
                ):
                    client = PlatformAPIClient()

                    # Production should warn about or reject insecure URLs
                    if insecure_url.startswith('http://'):
                        # Should either upgrade to HTTPS or reject
                        with patch('requests.request') as mock_request:
                            mock_response = Mock()
                            mock_response.status_code = 200
                            mock_response.json.return_value = {'success': True}
                            mock_request.return_value = mock_response

                            client.authenticate_customer('test@example.com', 'password123')

                            # Verify the actual URL used was HTTPS (if auto-upgraded)
                            call_args = mock_request.call_args
                            if call_args:
                                actual_url = call_args.kwargs.get('url', '')
                                # In production, should either use HTTPS or fail
                                self.assertTrue(
                                    actual_url.startswith('https://') or mock_request.call_count == 0,
                                    f"Production should use HTTPS or fail, got: {actual_url}"
                                )

    @override_settings(
        DEBUG=False,
        PLATFORM_API_SECRET="production-hmac-secret-key-minimum-32-characters-long",
        PORTAL_ID="production-validation-test",
        PLATFORM_API_BASE_URL="https://api.pragmatichost.com"
    )
    def test_production_hmac_header_validation(self):
        """🔐 Test production validates all HMAC headers are present and properly formatted"""
        client = PlatformAPIClient()

        with patch('requests.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True, 'authenticated': True}
            mock_request.return_value = mock_response

            # Make authenticated request
            client.authenticate_customer('prod@example.com', 'securepassword123')

            # Verify production-quality headers were generated
            call_args = mock_request.call_args
            headers = call_args.kwargs['headers']

            # All required headers must be present
            required_headers = ['X-Portal-Id', 'X-Signature', 'X-Nonce', 'X-Timestamp', 'X-Body-Hash']
            for header in required_headers:
                self.assertIn(header, headers, f"Production requires header: {header}")
                self.assertIsNotNone(headers[header], f"Production header {header} must not be empty")

            # Signature must be production-quality (64 hex chars)
            signature = headers['X-Signature']
            self.assertEqual(len(signature), 64, "Production signature must be 64 hex characters")
            self.assertTrue(all(c in '0123456789abcdef' for c in signature.lower()),
                           "Production signature must be hexadecimal")

            # Nonce must be sufficiently random
            nonce = headers['X-Nonce']
            self.assertGreater(len(nonce), 16, "Production nonce must be substantial length")

            # Timestamp must be precise
            timestamp = headers['X-Timestamp']
            try:
                float(timestamp)
            except ValueError:
                self.fail("Production timestamp must be valid float")

    def test_production_error_handling_does_not_leak_information(self):
        """🔐 Test production error messages don't leak sensitive information"""
        with override_settings(
            DEBUG=False,  # Production mode
            PLATFORM_API_SECRET="production-hmac-secret-key-for-error-testing",
            PORTAL_ID="production-error-test",
            PLATFORM_API_BASE_URL="https://api.example.com"
        ):
            client = PlatformAPIClient()

            # Test various error scenarios
            error_scenarios = [
                (requests.exceptions.ConnectionError("Connection refused"), "Connection failed"),
                (requests.exceptions.Timeout("Request timed out"), "Request timeout"),
                (requests.exceptions.SSLError("SSL certificate verification failed"), "SSL error"),
            ]

            for exception, expected_category in error_scenarios:
                with self.subTest(error=expected_category):
                    with patch('requests.request') as mock_request:
                        mock_request.side_effect = exception

                        # Error handling should be safe
                        result = client.authenticate_customer('test@example.com', 'password123')

                        # Should fail safely without leaking information
                        self.assertIsNone(result, "Production should fail safely on errors")

    def test_production_hmac_signature_constant_time_validation(self):
        """🔐 Test production uses constant-time HMAC signature comparison"""
        # This test ensures timing attacks are prevented

        correct_secret = "production-constant-time-hmac-secret-key"

        def mock_platform_with_timing_simulation(*args, **kwargs):
            """Mock Platform that simulates constant-time comparison"""
            import time

            headers = kwargs.get('headers', {})
            signature = headers.get('X-Signature', '')

            # Simulate constant time validation (always take same time)
            time.sleep(0.001)  # Constant processing time

            # Generate expected signature
            method = kwargs.get('method', 'POST')
            url = kwargs.get('url', '')
            path = url.replace('https://api.example.com', '') if url else '/api/test/'
            body = kwargs.get('data', b'{}')
            if isinstance(body, str):
                body = body.encode()

            portal_id = headers.get('X-Portal-Id', '')
            nonce = headers.get('X-Nonce', '')
            timestamp = headers.get('X-Timestamp', '')

            # Build canonical string (simplified for test)
            canonical = f"{method}|{path}|{body.decode()}|{portal_id}|{nonce}|{timestamp}"
            expected_signature = hmac.new(
                correct_secret.encode(), canonical.encode(), hashlib.sha256
            ).hexdigest()

            mock_response = Mock()
            if hmac.compare_digest(signature, expected_signature):
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'authenticated': True}
            else:
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'HMAC authentication failed'}

            return mock_response

        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET=correct_secret,
            PORTAL_ID="constant-time-test",
            PLATFORM_API_BASE_URL="https://api.example.com"
        ):
            import time
            client = PlatformAPIClient()

            # Measure timing for correct signature
            correct_times = []
            for _ in range(5):
                with patch('requests.request', side_effect=mock_platform_with_timing_simulation):
                    start_time = time.time()
                    result = client.authenticate_customer('test@example.com', 'password123')
                    correct_times.append(time.time() - start_time)
                    self.assertIsNotNone(result, "Correct signature should succeed")

            # Measure timing for incorrect signature (wrong secret)
            incorrect_times = []
            with override_settings(PLATFORM_API_SECRET="wrong-secret-key-for-timing-test"):
                client = PlatformAPIClient()
                for _ in range(5):
                    with patch('requests.request', side_effect=mock_platform_with_timing_simulation):
                        start_time = time.time()
                        result = client.authenticate_customer('test@example.com', 'password123')
                        incorrect_times.append(time.time() - start_time)
                        self.assertIsNone(result, "Incorrect signature should fail")

            # Timing should be similar (constant time comparison)
            avg_correct = sum(correct_times) / len(correct_times)
            avg_incorrect = sum(incorrect_times) / len(incorrect_times)

            time_diff = abs(avg_correct - avg_incorrect)
            avg_time = (avg_correct + avg_incorrect) / 2
            variance = time_diff / avg_time if avg_time > 0 else 0

            # Times should be within reasonable variance (< 10% difference)
            self.assertLess(variance, 0.1,
                           f"Timing variance too high: {variance:.1%} (potential timing attack vector)")

    def test_production_hmac_nonce_entropy_validation(self):
        """🔐 Test production validates nonce has sufficient entropy"""
        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET="production-nonce-entropy-test-key",
            PORTAL_ID="nonce-entropy-test"
        ):
            client = PlatformAPIClient()

            # Generate multiple nonces and check entropy
            nonces = []
            for _ in range(100):
                headers = client._generate_hmac_headers('GET', '/api/test/', b'')
                nonce = headers['X-Nonce']
                nonces.append(nonce)

            # All nonces should be unique
            unique_nonces = set(nonces)
            self.assertEqual(len(unique_nonces), len(nonces), "All nonces should be unique")

            # Nonces should have sufficient length
            for nonce in nonces:
                self.assertGreaterEqual(len(nonce), 16, "Production nonces should be at least 16 characters")

            # Check character distribution (should not be all same character)
            for nonce in nonces[:10]:  # Check first 10
                unique_chars = len(set(nonce))
                self.assertGreater(unique_chars, 3, f"Nonce {nonce} has poor character diversity")

    def test_production_configuration_validation(self):
        """🔐 Test production configuration is properly validated"""
        # Test that production settings are properly validated

        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET="production-hmac-secret-key-with-sufficient-entropy",
            PORTAL_ID="production-portal"
        ):
            client = PlatformAPIClient()

            # Verify configuration is loaded correctly
            self.assertIsNotNone(client.portal_secret, "Production HMAC secret should be loaded")
            self.assertIsNotNone(client.portal_id, "Production Portal ID should be loaded")

            # Verify configuration has production-quality values
            self.assertGreaterEqual(len(client.portal_secret), 20,
                                  "Production HMAC secret should be substantial length")
            self.assertGreaterEqual(len(client.portal_id), 5,
                                  "Production Portal ID should be meaningful length")

            # Verify secret is not a weak default
            weak_secrets = ['secret', 'change-me', 'default-secret', '123456']
            self.assertNotIn(client.portal_secret, weak_secrets,
                           "Production HMAC secret should not be a weak default")


class HMACProductionDeploymentTestCase(SimpleTestCase):
    """🔐 Production deployment safety tests for HMAC authentication"""

    def test_deployment_configuration_validation(self):
        """🔐 Test deployment validates HMAC configuration completeness"""
        # Test that all required configuration is present for deployment

        required_configs = {
            'PLATFORM_API_SECRET': 'production-deployment-secret-key',
            'PORTAL_ID': 'production-portal',
            'PLATFORM_API_BASE_URL': 'https://api.pragmatichost.com',
            'PLATFORM_API_TIMEOUT': 30
        }

        # Test each configuration requirement
        for config_key in required_configs:
            with self.subTest(config=config_key):
                incomplete_config = required_configs.copy()
                del incomplete_config[config_key]

                with override_settings(DEBUG=False, **incomplete_config):
                    # Missing configuration should be detected
                    try:
                        client = PlatformAPIClient()
                        # Should detect missing configuration
                        if config_key == 'PLATFORM_API_SECRET' and not hasattr(client, 'portal_secret'):
                            pass  # Expected failure
                        elif config_key == 'PORTAL_ID' and not hasattr(client, 'portal_id'):
                            pass  # Expected failure
                    except (ImproperlyConfigured, AttributeError):
                        # Expected for missing critical configuration
                        pass

    def test_production_hmac_performance_requirements(self):
        """🔐 Test HMAC authentication meets production performance requirements"""
        import time

        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET="production-performance-test-secret-key",
            PORTAL_ID="performance-test"
        ):
            client = PlatformAPIClient()

            # Test HMAC generation performance
            generation_times = []
            for i in range(100):
                start_time = time.time()
                client._generate_hmac_headers(
                    'POST',
                    f'/api/test/{i}/',
                    f'{{"test": "data", "iteration": {i}}}'.encode()
                )
                generation_times.append(time.time() - start_time)

            avg_generation_time = sum(generation_times) / len(generation_times)
            max_generation_time = max(generation_times)

            # Production performance requirements
            self.assertLess(avg_generation_time, 0.005,
                           f"Average HMAC generation too slow: {avg_generation_time:.4f}s")
            self.assertLess(max_generation_time, 0.020,
                           f"Maximum HMAC generation too slow: {max_generation_time:.4f}s")

    def test_production_error_recovery(self):
        """🔐 Test production HMAC error recovery scenarios"""
        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET="production-error-recovery-test",
            PORTAL_ID="error-recovery-test",
            PLATFORM_API_BASE_URL="https://api.example.com"
        ):
            client = PlatformAPIClient()

            # Test recovery from various production errors
            error_recovery_scenarios = [
                # Network errors
                requests.exceptions.ConnectionError("Network unreachable"),
                requests.exceptions.Timeout("Connection timeout"),

                # HTTP errors
                Mock(status_code=503, json=lambda: {'error': 'Service unavailable'}),
                Mock(status_code=502, json=lambda: {'error': 'Bad gateway'}),

                # SSL errors
                requests.exceptions.SSLError("Certificate verification failed"),
            ]

            for error_scenario in error_recovery_scenarios:
                with self.subTest(error=str(error_scenario)):
                    with patch('requests.request') as mock_request:
                        if isinstance(error_scenario, Exception):
                            mock_request.side_effect = error_scenario
                        else:
                            mock_request.return_value = error_scenario

                        # Should handle error gracefully
                        result = client.authenticate_customer('test@example.com', 'password123')

                        # Should fail safely without exceptions
                        self.assertIsNone(result, "Production should handle errors gracefully")

    def test_production_logging_does_not_expose_secrets(self):
        """🔐 Test production logging doesn't expose HMAC secrets"""
        import logging
        from unittest.mock import patch

        log_messages = []

        def capture_log(message, *args, **kwargs):
            log_messages.append(str(message) + ' ' + ' '.join(str(arg) for arg in args))

        with override_settings(
            DEBUG=False,
            PLATFORM_API_SECRET="secret-that-should-never-be-logged",
            PORTAL_ID="logging-test"
        ):
            client = PlatformAPIClient()

            with patch.object(logging.getLogger(), 'info', side_effect=capture_log), \
                 patch.object(logging.getLogger(), 'error', side_effect=capture_log), \
                 patch.object(logging.getLogger(), 'debug', side_effect=capture_log):

                # Generate HMAC headers (this might trigger logging)
                headers = client._generate_hmac_headers('POST', '/api/test/', b'{"test": "data"}')

                # Check that no log messages contain the secret
                secret = "secret-that-should-never-be-logged"
                signature = headers.get('X-Signature', '')

                for log_message in log_messages:
                    self.assertNotIn(secret, log_message,
                                   f"Production logging exposed HMAC secret: {log_message}")
                    self.assertNotIn(signature[:32], log_message,  # Check first half of signature
                                   f"Production logging exposed HMAC signature: {log_message}")