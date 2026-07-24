"""
Tests for security system checks.

Tests the Django system checks that validate security configuration
to ensure proper IP trust and middleware setup.
"""

import types

from django.core.checks import Error
from django.core.checks import Warning as DjangoWarning
from django.test import TestCase, override_settings

from apps.common import checks
from apps.common.checks import (
    check_api_token_configuration,
    check_ip_trust_configuration,
    check_proxy_ssl_configuration,
    check_security_middleware_configuration,
)


class TestIPTrustSystemChecks(TestCase):
    """Test IP trust configuration system checks."""

    def test_missing_trusted_proxy_list_warning(self):
        """Test warning when IPWARE_TRUSTED_PROXY_LIST is not defined."""
        # Create a mock settings object without the attribute
        fake_settings = types.SimpleNamespace()
        fake_settings.DEBUG = True  # Set some required attribute

        # Temporarily replace settings with our mock
        original_settings = checks.settings
        checks.settings = fake_settings

        try:
            errors = check_ip_trust_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W030')
        finally:
            # Restore original settings
            checks.settings = original_settings

    def test_production_empty_proxy_list_warning(self):
        """Test warning for production with empty proxy list."""
        with override_settings(DEBUG=False, IPWARE_TRUSTED_PROXY_LIST=[]):
            errors = check_ip_trust_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W031')

    def test_development_with_proxies_warning(self):
        """Test warning for development with trusted proxies."""
        with override_settings(DEBUG=True, IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8']):
            errors = check_ip_trust_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W032')

    def test_invalid_proxy_type_error(self):
        """Test error for non-string proxy entries."""
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=[123, 'valid']):
            errors = check_ip_trust_configuration(None)

            # Should have one error for the invalid type
            error_ids = [e.id for e in errors if isinstance(e, Error)]
            self.assertIn('security.E030', error_ids)

    def test_invalid_ip_format_error(self):
        """Test error for invalid IP format."""
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=['invalid-ip', '300.300.300.300']):
            errors = check_ip_trust_configuration(None)

            # Should have errors for both invalid IPs
            error_ids = [e.id for e in errors if isinstance(e, Error)]
            self.assertEqual(error_ids.count('security.E031'), 2)

    def test_valid_ip_addresses_pass(self):
        """Test that valid IP addresses pass validation."""
        with override_settings(
            DEBUG=False,
            IPWARE_TRUSTED_PROXY_LIST=['10.0.0.1', '192.168.1.0/24', '2001:db8::/32']
        ):
            errors = check_ip_trust_configuration(None)

            # Should have no errors for valid IPs
            error_messages = [e.msg for e in errors if isinstance(e, Error)]
            self.assertEqual(error_messages, [])

    def test_dangerous_cidr_range_error(self):
        """Test error for dangerous CIDR ranges."""
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=['0.0.0.0/0', '::/0']):
            errors = check_ip_trust_configuration(None)

            # Should have errors for dangerous ranges
            error_ids = [e.id for e in errors if isinstance(e, Error)]
            self.assertEqual(error_ids.count('security.E032'), 2)

    def test_public_ip_range_warning(self):
        """Test warning for public IP ranges."""
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=['8.8.8.0/24']):
            errors = check_ip_trust_configuration(None)

            # Should have warning for public range
            warning_ids = [e.id for e in errors if isinstance(e, DjangoWarning)]
            self.assertIn('security.W033', warning_ids)


class TestProxySSLSystemChecks(TestCase):
    """Test proxy SSL configuration system checks."""

    def test_missing_ssl_header_with_proxies_warning(self):
        """Test warning when SSL header missing with trusted proxies."""
        with override_settings(
            DEBUG=False,
            IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'],
            SECURE_PROXY_SSL_HEADER=None
        ):
            errors = check_proxy_ssl_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W034')

    def test_invalid_ssl_header_format_error(self):
        """Test error for invalid SSL header format."""
        with override_settings(SECURE_PROXY_SSL_HEADER='invalid'):
            errors = check_proxy_ssl_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], Error)
            self.assertEqual(errors[0].id, 'security.E033')

    def test_ssl_header_without_http_prefix_warning(self):
        """Test warning when SSL header doesn't start with HTTP_."""
        with override_settings(SECURE_PROXY_SSL_HEADER=('X_FORWARDED_PROTO', 'https')):
            errors = check_proxy_ssl_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W035')

    def test_valid_ssl_header_passes(self):
        """Test that valid SSL header configuration passes."""
        with override_settings(
            DEBUG=False,
            IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'],
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https')
        ):
            errors = check_proxy_ssl_configuration(None)

            # Should have no errors or warnings
            self.assertEqual(len(errors), 0)


class TestMiddlewareSystemChecks(TestCase):
    """Test middleware configuration system checks."""

    def test_missing_security_middleware_warning(self):
        """Test warning when SecurityHeadersMiddleware is missing."""
        with override_settings(MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.middleware.common.CommonMiddleware',
        ]):
            errors = check_security_middleware_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W036')

    def test_security_middleware_wrong_position_warning(self):
        """Test warning when SecurityHeadersMiddleware is in wrong position."""
        with override_settings(MIDDLEWARE=[
            'apps.common.middleware.SecurityHeadersMiddleware',  # Wrong: before Django security
            'django.middleware.security.SecurityMiddleware',
            'django.middleware.common.CommonMiddleware',
        ]):
            errors = check_security_middleware_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W037')

    def test_security_middleware_last_position_warning(self):
        """Test warning when SecurityHeadersMiddleware is the last middleware."""
        with override_settings(MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'apps.common.middleware.SecurityHeadersMiddleware',  # Wrong: last position
        ]):
            errors = check_security_middleware_configuration(None)

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DjangoWarning)
            self.assertEqual(errors[0].id, 'security.W038')

    def test_valid_middleware_configuration_passes(self):
        """Test that valid middleware configuration passes."""
        with override_settings(MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'apps.common.middleware.SecurityHeadersMiddleware',  # Correct position
            'django.middleware.common.CommonMiddleware',
        ]):
            errors = check_security_middleware_configuration(None)

            # Should have no errors or warnings
            self.assertEqual(len(errors), 0)


class TestAPITokenConfigurationChecks(TestCase):
    """API token settings must form a coherent issuance policy at startup."""

    def test_valid_configuration_produces_no_findings(self):
        """The shipped defaults (90/365 days, 20 active tokens) are coherent."""
        with override_settings(
            API_TOKEN_DEFAULT_TTL_DAYS=90,
            API_TOKEN_MAX_TTL_DAYS=365,
            API_TOKEN_MAX_ACTIVE_PER_USER=20,
        ):
            self.assertEqual(check_api_token_configuration(None), [])

    def test_non_positive_max_is_an_error(self):
        """MAX < 1 clamps every issued TTL to <= 0 days — tokens would expire immediately."""
        for bad_max in (0, -30):
            with self.subTest(max_ttl=bad_max), override_settings(
                API_TOKEN_DEFAULT_TTL_DAYS=90, API_TOKEN_MAX_TTL_DAYS=bad_max
            ):
                errors = check_api_token_configuration(None)
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], Error)
                self.assertEqual(errors[0].id, 'security.E062')

    def test_default_exceeding_max_is_an_error(self):
        """An omitted TTL must never produce a longer-lived token than the max allows."""
        with override_settings(API_TOKEN_DEFAULT_TTL_DAYS=730, API_TOKEN_MAX_TTL_DAYS=365):
            errors = check_api_token_configuration(None)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], Error)
            self.assertEqual(errors[0].id, 'security.E063')

    def test_zero_default_is_explicit_opt_out_warning(self):
        """DEFAULT <= 0 is the documented no-expiry opt-out — allowed, but flagged."""
        with override_settings(API_TOKEN_DEFAULT_TTL_DAYS=0, API_TOKEN_MAX_TTL_DAYS=365):
            findings = check_api_token_configuration(None)
            self.assertEqual(len(findings), 1)
            self.assertIsInstance(findings[0], DjangoWarning)
            self.assertEqual(findings[0].id, 'security.W063')

    def test_non_positive_active_token_limit_is_an_error(self):
        """A zero/negative cap would prevent every user from issuing a token."""
        for bad_limit in (0, -1):
            with self.subTest(active_token_limit=bad_limit), override_settings(
                API_TOKEN_DEFAULT_TTL_DAYS=90,
                API_TOKEN_MAX_TTL_DAYS=365,
                API_TOKEN_MAX_ACTIVE_PER_USER=bad_limit,
            ):
                errors = check_api_token_configuration(None)

                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], Error)
                self.assertEqual(errors[0].id, 'security.E064')
