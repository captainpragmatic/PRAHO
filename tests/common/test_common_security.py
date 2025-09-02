"""
Comprehensive HTTPS security tests for PRAHO Platform.

Tests HTTPS enforcement, secure cookies, HSTS configuration,
and production security settings to ensure robust transport security.
"""

from django.conf import settings
from django.core.checks import Error, Warning as DjangoWarning
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from django.http import HttpResponse

from apps.common.checks import (
    check_https_security_configuration,
    check_session_security_configuration,
    check_security_middleware_configuration,
)
from apps.common.middleware import SecurityHeadersMiddleware


class HTTPSSecurityConfigurationTest(TestCase):
    """Test HTTPS security configuration validation."""

    def setUp(self):
        self.request_factory = RequestFactory()

    def test_production_ssl_redirect_without_proxy_header_error(self):
        """Test error when SSL redirect enabled without proxy header."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=None,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                isinstance(error, Error) and 
                'SECURE_SSL_REDIRECT enabled but SECURE_PROXY_SSL_HEADER not configured' in str(error)
                for error in errors
            ))

    def test_production_ssl_redirect_with_proxy_header_valid(self):
        """Test valid SSL redirect configuration with proxy header."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            SESSION_COOKIE_SECURE=True,
            CSRF_COOKIE_SECURE=True,
            SECURE_HSTS_SECONDS=31536000,
            ALLOWED_HOSTS=['app.pragmatichost.com'],
            CSRF_TRUSTED_ORIGINS=['https://app.pragmatichost.com'],
        ):
            errors = check_https_security_configuration(None)
            # Should have no critical errors for this configuration
            critical_errors = [e for e in errors if isinstance(e, Error)]
            self.assertEqual(len(critical_errors), 0)

    def test_production_insecure_session_cookies_warning(self):
        """Test warning when session cookies not secure in HTTPS environment."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            SESSION_COOKIE_SECURE=False,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'SESSION_COOKIE_SECURE is False' in str(error)
                for error in errors
            ))

    def test_production_insecure_csrf_cookies_warning(self):
        """Test warning when CSRF cookies not secure in HTTPS environment."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            CSRF_COOKIE_SECURE=False,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'CSRF_COOKIE_SECURE is False' in str(error)
                for error in errors
            ))

    def test_production_missing_hsts_warning(self):
        """Test warning when HSTS not configured in HTTPS environment."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            SECURE_HSTS_SECONDS=0,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'HSTS not configured' in str(error)
                for error in errors
            ))

    def test_production_short_hsts_warning(self):
        """Test warning when HSTS timeout is too short."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            SECURE_HSTS_SECONDS=60,  # Too short
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'HSTS timeout too short' in str(error)
                for error in errors
            ))

    def test_production_wildcard_allowed_hosts_warning(self):
        """Test warning when ALLOWED_HOSTS uses wildcard in production."""
        with override_settings(
            DEBUG=False,
            ALLOWED_HOSTS=['*'],
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'ALLOWED_HOSTS not properly configured' in str(error)
                for error in errors
            ))

    def test_production_missing_csrf_origins_warning(self):
        """Test warning when CSRF_TRUSTED_ORIGINS not configured with HTTPS."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            CSRF_TRUSTED_ORIGINS=[],
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'CSRF_TRUSTED_ORIGINS not configured' in str(error)
                for error in errors
            ))

    def test_production_http_csrf_origins_warning(self):
        """Test warning when CSRF origins use HTTP in HTTPS environment."""
        with override_settings(
            DEBUG=False,
            SECURE_SSL_REDIRECT=True,
            SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
            CSRF_TRUSTED_ORIGINS=['http://app.pragmatichost.com'],
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'CSRF trusted origin uses HTTP in HTTPS-enforced environment' in str(error)
                for error in errors
            ))

    def test_production_security_middleware_missing_error(self):
        """Test error when SecurityMiddleware missing in production."""
        with override_settings(
            DEBUG=False,
            MIDDLEWARE=[
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.common.CommonMiddleware',
            ],
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'SecurityMiddleware not found in MIDDLEWARE' in str(error)
                for error in errors
            ))

    def test_production_security_middleware_wrong_position_warning(self):
        """Test warning when SecurityMiddleware not first in production."""
        with override_settings(
            DEBUG=False,
            MIDDLEWARE=[
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.security.SecurityMiddleware',
            ],
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'SecurityMiddleware must be first in MIDDLEWARE' in str(error)
                for error in errors
            ))

    def test_development_ssl_redirect_warning(self):
        """Test warning when SSL redirect enabled in development."""
        with override_settings(
            DEBUG=True,
            SECURE_SSL_REDIRECT=True,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'SECURE_SSL_REDIRECT enabled in development environment' in str(error)
                for error in errors
            ))

    def test_development_hsts_enabled_warning(self):
        """Test warning when HSTS enabled in development."""
        with override_settings(
            DEBUG=True,
            SECURE_HSTS_SECONDS=3600,
        ):
            errors = check_https_security_configuration(None)
            self.assertTrue(any(
                'HSTS enabled in development environment' in str(error)
                for error in errors
            ))

    def test_development_secure_cookies_warning(self):
        """Test warning when secure cookies enabled in development."""
        with override_settings(
            DEBUG=True,
            SESSION_COOKIE_SECURE=True,
            CSRF_COOKIE_SECURE=True,
        ):
            errors = check_https_security_configuration(None)
            
            session_warning = any(
                'SESSION_COOKIE_SECURE enabled in development' in str(error)
                for error in errors
            )
            csrf_warning = any(
                'CSRF_COOKIE_SECURE enabled in development' in str(error)
                for error in errors
            )
            
            self.assertTrue(session_warning)
            self.assertTrue(csrf_warning)

    def test_development_valid_configuration(self):
        """Test valid development configuration with no warnings."""
        with override_settings(
            DEBUG=True,
            SECURE_SSL_REDIRECT=False,
            SECURE_HSTS_SECONDS=0,
            SESSION_COOKIE_SECURE=False,
            CSRF_COOKIE_SECURE=False,
            ALLOWED_HOSTS=['localhost', '127.0.0.1'],
        ):
            errors = check_https_security_configuration(None)
            # Should have minimal warnings for valid development config
            critical_warnings = [
                e for e in errors 
                if 'development environment' in str(e) 
                and any(keyword in str(e) for keyword in ['SSL_REDIRECT', 'HSTS', 'SECURE'])
            ]
            self.assertEqual(len(critical_warnings), 0)


class SessionSecurityConfigurationTest(TestCase):
    """Test session security configuration validation."""

    def test_production_httponly_disabled_warning(self):
        """Test warning when SESSION_COOKIE_HTTPONLY disabled in production."""
        with override_settings(
            DEBUG=False,
            SESSION_COOKIE_HTTPONLY=False,
        ):
            errors = check_session_security_configuration(None)
            self.assertTrue(any(
                'SESSION_COOKIE_HTTPONLY disabled in production' in str(error)
                for error in errors
            ))

    def test_production_long_session_timeout_warning(self):
        """Test warning when session timeout is too long in production."""
        with override_settings(
            DEBUG=False,
            SESSION_COOKIE_AGE=172800,  # 2 days
        ):
            errors = check_session_security_configuration(None)
            self.assertTrue(any(
                'Session timeout very long for production' in str(error)
                for error in errors
            ))

    def test_production_insecure_samesite_warning(self):
        """Test warning when SESSION_COOKIE_SAMESITE not secure."""
        with override_settings(
            DEBUG=False,
            SESSION_COOKIE_SAMESITE=None,
        ):
            errors = check_session_security_configuration(None)
            self.assertTrue(any(
                'SESSION_COOKIE_SAMESITE not set to secure value' in str(error)
                for error in errors
            ))

    def test_production_cache_session_without_cache_warning(self):
        """Test warning when cache sessions configured without cache."""
        with override_settings(
            DEBUG=False,
            SESSION_ENGINE='django.contrib.sessions.backends.cache',
            CACHES={},  # No default cache
        ):
            errors = check_session_security_configuration(None)
            self.assertTrue(any(
                'Cache-based sessions configured but no default cache configured' in str(error)
                for error in errors
            ))

    def test_production_secure_session_configuration_valid(self):
        """Test valid secure session configuration in production."""
        with override_settings(
            DEBUG=False,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_AGE=3600,  # 1 hour
            SESSION_COOKIE_SAMESITE='Lax',
            SESSION_ENGINE='django.contrib.sessions.backends.db',
        ):
            errors = check_session_security_configuration(None)
            # Should have no warnings for secure configuration
            session_warnings = [
                e for e in errors 
                if 'session' in str(e).lower()
            ]
            self.assertEqual(len(session_warnings), 0)

    def test_development_no_session_checks(self):
        """Test that session checks are skipped in development."""
        with override_settings(
            DEBUG=True,
            SESSION_COOKIE_HTTPONLY=False,
            SESSION_COOKIE_AGE=172800,
        ):
            errors = check_session_security_configuration(None)
            # Should have no warnings for development
            self.assertEqual(len(errors), 0)


class SecurityMiddlewareTest(TestCase):
    """Test SecurityHeadersMiddleware functionality."""

    def setUp(self):
        self.request_factory = RequestFactory()
        self.middleware = SecurityHeadersMiddleware(self.get_response)

    def get_response(self, request):
        """Mock response function for middleware testing."""
        return HttpResponse("Test response")

    def test_security_headers_added(self):
        """Test that security headers are properly added."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        # Check for essential security headers
        self.assertIn('Content-Security-Policy', response)
        self.assertIn('X-Content-Type-Options', response)
        self.assertIn('X-Frame-Options', response)
        self.assertIn('X-XSS-Protection', response)
        self.assertIn('Referrer-Policy', response)

    def test_csp_allows_trusted_cdns(self):
        """Test that CSP allows trusted CDN domains."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        csp_header = response.get('Content-Security-Policy', '')
        self.assertIn('unpkg.com', csp_header)
        self.assertIn('cdn.tailwindcss.com', csp_header)

    def test_security_headers_values(self):
        """Test specific security header values."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')
        self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')

    @override_settings(DEBUG=False)
    def test_production_security_headers(self):
        """Test security headers in production mode."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        # Production should have all security headers
        expected_headers = [
            'Content-Security-Policy',
            'X-Content-Type-Options', 
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
        ]
        
        for header in expected_headers:
            self.assertIn(header, response, f"Missing security header: {header}")

    def test_csp_default_src_self(self):
        """Test that CSP default-src is set to 'self'."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        csp_header = response.get('Content-Security-Policy', '')
        self.assertIn("default-src 'self'", csp_header)

    def test_csp_object_src_none(self):
        """Test that CSP object-src is set to 'none' for security."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        csp_header = response.get('Content-Security-Policy', '')
        self.assertIn("object-src 'none'", csp_header)

    def test_csp_base_uri_self(self):
        """Test that CSP base-uri is set to 'self' to prevent base tag injection."""
        request = self.request_factory.get('/')
        response = self.middleware(request)
        
        csp_header = response.get('Content-Security-Policy', '')
        self.assertIn("base-uri 'self'", csp_header)


class HTTPSIntegrationTest(TestCase):
    """Integration tests for HTTPS security features."""

    def test_production_settings_integration(self):
        """Test that production settings work together correctly."""
        production_settings = {
            'DEBUG': False,
            'ALLOWED_HOSTS': ['app.pragmatichost.com'],
            'CSRF_TRUSTED_ORIGINS': ['https://app.pragmatichost.com'],
            'SECURE_SSL_REDIRECT': True,
            'SECURE_PROXY_SSL_HEADER': ('HTTP_X_FORWARDED_PROTO', 'https'),
            'SESSION_COOKIE_SECURE': True,
            'CSRF_COOKIE_SECURE': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'SECURE_HSTS_SECONDS': 31536000,
            'SECURE_HSTS_INCLUDE_SUBDOMAINS': True,
            'SECURE_HSTS_PRELOAD': False,
            'SECURE_CONTENT_TYPE_NOSNIFF': True,
            'SECURE_REFERRER_POLICY': 'strict-origin-when-cross-origin',
            'X_FRAME_OPTIONS': 'DENY',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_AGE': 3600,
            'MIDDLEWARE': [
                'django.middleware.security.SecurityMiddleware',
                'apps.common.middleware.RequestIDMiddleware',
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.common.CommonMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
                'django.contrib.messages.middleware.MessageMiddleware',
                'django.middleware.clickjacking.XFrameOptionsMiddleware',
                'apps.common.middleware.SecurityHeadersMiddleware',
            ],
        }
        
        with override_settings(**production_settings):
            # Check HTTPS configuration
            https_errors = check_https_security_configuration(None)
            critical_https_errors = [e for e in https_errors if isinstance(e, Error)]
            
            # Check session configuration
            session_errors = check_session_security_configuration(None)
            critical_session_errors = [e for e in session_errors if isinstance(e, Error)]
            
            # Check middleware configuration
            middleware_errors = check_security_middleware_configuration(None)
            critical_middleware_errors = [e for e in middleware_errors if isinstance(e, Error)]
            
            # Should have no critical errors for proper production config
            self.assertEqual(len(critical_https_errors), 0, 
                f"HTTPS configuration errors: {critical_https_errors}")
            self.assertEqual(len(critical_session_errors), 0,
                f"Session configuration errors: {critical_session_errors}")
            self.assertEqual(len(critical_middleware_errors), 0,
                f"Middleware configuration errors: {critical_middleware_errors}")

    def test_development_settings_integration(self):
        """Test that development settings work correctly."""
        development_settings = {
            'DEBUG': True,
            'ALLOWED_HOSTS': ['localhost', '127.0.0.1'],
            'CSRF_TRUSTED_ORIGINS': ['http://localhost:8001', 'http://127.0.0.1:8001'],
            'SECURE_SSL_REDIRECT': False,
            'SECURE_HSTS_SECONDS': 0,
            'SESSION_COOKIE_SECURE': False,
            'CSRF_COOKIE_SECURE': False,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'X_FRAME_OPTIONS': 'SAMEORIGIN',
            'SESSION_COOKIE_AGE': 86400,  # 24 hours for development
        }
        
        with override_settings(**development_settings):
            # Check HTTPS configuration
            https_errors = check_https_security_configuration(None)
            
            # Check session configuration  
            session_errors = check_session_security_configuration(None)
            
            # Should have minimal warnings for development
            development_warnings = [
                e for e in https_errors + session_errors
                if 'development environment' in str(e)
            ]
            
            # Valid development config should not trigger development warnings
            ssl_warnings = [w for w in development_warnings if 'SSL_REDIRECT' in str(w)]
            hsts_warnings = [w for w in development_warnings if 'HSTS' in str(w)]
            
            self.assertEqual(len(ssl_warnings), 0, "Should not warn about disabled SSL in development")
            self.assertEqual(len(hsts_warnings), 0, "Should not warn about disabled HSTS in development")

    def test_staging_settings_integration(self):
        """Test that staging settings work correctly."""
        staging_settings = {
            'DEBUG': False,
            'ALLOWED_HOSTS': ['staging.pragmatichost.com'],
            'CSRF_TRUSTED_ORIGINS': ['https://staging.pragmatichost.com'],
            'SECURE_SSL_REDIRECT': True,
            'SECURE_PROXY_SSL_HEADER': ('HTTP_X_FORWARDED_PROTO', 'https'),
            'SESSION_COOKIE_SECURE': True,
            'CSRF_COOKIE_SECURE': True,
            'SECURE_HSTS_SECONDS': 3600,  # Shorter than production
            'SECURE_HSTS_INCLUDE_SUBDOMAINS': False,  # More flexible for staging
            'SESSION_COOKIE_AGE': 7200,  # 2 hours for staging
        }
        
        with override_settings(**staging_settings):
            https_errors = check_https_security_configuration(None)
            session_errors = check_session_security_configuration(None)
            
            # Should have no critical errors for staging
            all_errors = https_errors + session_errors
            critical_errors = [e for e in all_errors if isinstance(e, Error)]
            
            self.assertEqual(len(critical_errors), 0,
                f"Staging should have no critical errors: {critical_errors}")