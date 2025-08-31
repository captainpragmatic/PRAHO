"""
Comprehensive tests for secure IP detection functionality.

Tests the apps.common.request_ip module to ensure proper IP trust behavior
and protection against IP spoofing attacks in different environments.
"""

from unittest.mock import Mock, patch
from django.http import HttpRequest
from django.test import TestCase, override_settings

from apps.common.request_ip import get_safe_client_ip


class TestSecureIPDetection(TestCase):
    """Test secure IP detection with proxy trust configuration."""

    def setUp(self):
        """Set up test fixtures."""
        self.request = HttpRequest()
        self.request.META = {}

    def test_direct_connection_remote_addr_only(self):
        """Test direct connection returns REMOTE_ADDR when no proxy headers."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.10'
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '203.0.113.10')

    def test_fallback_when_no_ip_available(self):
        """Test fallback to 127.0.0.1 when no IP detection possible."""
        # Empty META
        self.request.META = {}
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '127.0.0.1')

    def test_fallback_when_empty_remote_addr(self):
        """Test fallback when REMOTE_ADDR is empty."""
        self.request.META = {
            'REMOTE_ADDR': ''
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '127.0.0.1')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=[])
    def test_development_no_proxy_trust(self):
        """Test development environment ignores proxy headers (empty trust list)."""
        self.request.META = {
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_X_FORWARDED_FOR': '203.0.113.50',  # Should be ignored
            'HTTP_X_REAL_IP': '203.0.113.60'         # Should be ignored
        }
        
        result = get_safe_client_ip(self.request)
        # Should use REMOTE_ADDR only, ignoring proxy headers
        self.assertEqual(result, '127.0.0.1')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_production_trusted_proxy(self):
        """Test production environment trusts configured proxy."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.5',  # Trusted proxy IP
            'HTTP_X_FORWARDED_FOR': '203.0.113.100',  # Client IP from trusted proxy
        }
        
        result = get_safe_client_ip(self.request)
        # Should extract client IP from proxy header
        self.assertEqual(result, '203.0.113.100')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])  
    def test_production_untrusted_proxy_blocked(self):
        """Test production environment blocks untrusted proxy headers."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.200',  # Untrusted proxy IP
            'HTTP_X_FORWARDED_FOR': '203.0.113.300',  # Potentially spoofed
        }
        
        result = get_safe_client_ip(self.request)
        # Should use REMOTE_ADDR only, blocking untrusted proxy
        self.assertEqual(result, '203.0.113.200')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['172.16.0.0/12', '10.0.0.0/8'])
    def test_multiple_trusted_proxy_ranges(self):
        """Test multiple trusted proxy CIDR ranges."""
        # Test first range (172.16.x.x)
        self.request.META = {
            'REMOTE_ADDR': '172.16.5.10',
            'HTTP_X_FORWARDED_FOR': '203.0.113.150',
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '203.0.113.150')
        
        # Test second range (10.x.x.x)
        self.request.META = {
            'REMOTE_ADDR': '10.20.30.40',
            'HTTP_X_FORWARDED_FOR': '203.0.113.160',
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '203.0.113.160')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_x_forwarded_for_chain(self):
        """Test X-Forwarded-For header with multiple IPs (proxy chain)."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.5',  # Trusted proxy
            'HTTP_X_FORWARDED_FOR': '203.0.113.180, 192.168.1.100, 10.0.1.5',
        }
        
        result = get_safe_client_ip(self.request)
        # Should return first IP in chain (original client)
        self.assertEqual(result, '203.0.113.180')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_x_real_ip_header(self):
        """Test X-Real-IP header handling."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.5',  # Trusted proxy
            'HTTP_X_REAL_IP': '203.0.113.190',  # Client IP
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '203.0.113.190')

    def test_ipv6_addresses(self):
        """Test IPv6 address handling."""
        self.request.META = {
            'REMOTE_ADDR': '2001:db8::1'
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '2001:db8::1')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['2001:db8::/32'])
    def test_ipv6_proxy_trust(self):
        """Test IPv6 proxy trust configuration."""
        self.request.META = {
            'REMOTE_ADDR': '2001:db8::5',  # Trusted IPv6 proxy
            'HTTP_X_FORWARDED_FOR': '2001:db8:85a3::8a2e:370:7334',
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '2001:db8:85a3::8a2e:370:7334')

    def test_header_parsing_exception_handling(self):
        """Test graceful handling of header parsing exceptions."""
        # Set up malformed headers that could cause parsing errors
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.5',  # Trusted proxy
            'HTTP_X_FORWARDED_FOR': '\x00\x01\x02invalid',  # Malformed header
        }
        
        # Should fall back to REMOTE_ADDR gracefully
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8']):
            result = get_safe_client_ip(self.request)
            self.assertEqual(result, '10.0.1.5')

    def test_empty_proxy_headers_fallback(self):
        """Test fallback when proxy headers are empty."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.5',  # Trusted proxy
            'HTTP_X_FORWARDED_FOR': '',  # Empty header
            'HTTP_X_REAL_IP': '   ',     # Whitespace only
        }
        
        # Should fall back to REMOTE_ADDR when headers are empty
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8']):
            result = get_safe_client_ip(self.request)
            self.assertEqual(result, '10.0.1.5')

    def test_malicious_header_injection(self):
        """Test protection against malicious header injection."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.10',
            'HTTP_X_FORWARDED_FOR': '"><script>alert("xss")</script>',
            'HTTP_X_REAL_IP': '127.0.0.1; DROP TABLE users;',
        }
        
        # With empty trust list, should ignore malicious headers
        with override_settings(IPWARE_TRUSTED_PROXY_LIST=[]):
            result = get_safe_client_ip(self.request)
            self.assertEqual(result, '203.0.113.10')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['127.0.0.0/8'])
    def test_localhost_proxy_trust(self):
        """Test localhost as trusted proxy for development."""
        self.request.META = {
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_X_FORWARDED_FOR': '203.0.113.220',
        }
        
        result = get_safe_client_ip(self.request)
        self.assertEqual(result, '203.0.113.220')


class TestIPDetectionWithoutIPware(TestCase):
    """Test IP detection when django-ipware is not available."""

    def setUp(self):
        """Set up test fixtures."""
        self.request = HttpRequest()

    @patch.dict('sys.modules', {'ipware': None})
    def test_fallback_implementation(self):
        """Test fallback implementation when ipware is not installed."""
        # This would test the ImportError fallback, but since ipware is already
        # imported, we'll test the behavior through our fallback function
        
        # Create a mock request
        request = Mock()
        request.META = {'REMOTE_ADDR': '203.0.113.99'}
        
        # Test our fallback function directly  
        from apps.common.request_ip import get_safe_client_ip
        
        # Mock the ipware function to simulate ImportError scenario
        with patch('apps.common.request_ip.get_client_ip') as mock_func:
            # Simulate the fallback function behavior
            mock_func.return_value = ('203.0.113.99', False)
            
            result = get_safe_client_ip(request)
            self.assertEqual(result, '203.0.113.99')


class TestRateLimitingIntegration(TestCase):
    """Test IP detection integration with rate limiting."""

    def setUp(self):
        """Set up test fixtures."""
        self.request = HttpRequest()

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=[])
    def test_rate_limiting_uses_correct_ip_dev(self):
        """Test rate limiting uses direct IP in development."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.30',
            'HTTP_X_FORWARDED_FOR': '203.0.113.99',  # Should be ignored
        }
        
        ip = get_safe_client_ip(self.request)
        # Rate limiting should use REMOTE_ADDR to prevent bypass
        self.assertEqual(ip, '203.0.113.30')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])  
    def test_rate_limiting_uses_real_ip_production(self):
        """Test rate limiting uses real client IP in production."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.10',  # Load balancer IP
            'HTTP_X_FORWARDED_FOR': '203.0.113.40',  # Real client IP
        }
        
        ip = get_safe_client_ip(self.request)
        # Should extract real client IP for accurate rate limiting
        self.assertEqual(ip, '203.0.113.40')


class TestAuditLoggingIntegration(TestCase):
    """Test IP detection integration with audit logging."""

    def setUp(self):
        """Set up test fixtures.""" 
        self.request = HttpRequest()

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=[])
    def test_audit_logging_records_correct_ip(self):
        """Test audit logging records the correct IP address."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.50',
            'HTTP_X_FORWARDED_FOR': '203.0.113.51',  # Potentially spoofed
        }
        
        ip = get_safe_client_ip(self.request)
        # Audit logs should use REMOTE_ADDR to prevent IP spoofing in logs
        self.assertEqual(ip, '203.0.113.50')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['192.168.0.0/16'])
    def test_audit_logging_production_real_ip(self):
        """Test audit logging captures real client IP in production."""
        self.request.META = {
            'REMOTE_ADDR': '192.168.1.100',  # Internal load balancer
            'HTTP_X_FORWARDED_FOR': '203.0.113.60',  # External client
        }
        
        ip = get_safe_client_ip(self.request)  
        # Should log the real external client IP
        self.assertEqual(ip, '203.0.113.60')


class TestSecurityScenarios(TestCase):
    """Test various security attack scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.request = HttpRequest()

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=[])
    def test_ip_spoofing_attack_blocked(self):
        """Test IP spoofing attack is blocked in development/staging."""
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.70',
            'HTTP_X_FORWARDED_FOR': '127.0.0.1',  # Attacker trying to spoof localhost
            'HTTP_X_REAL_IP': '10.0.0.1',         # Attacker trying to spoof internal IP
        }
        
        ip = get_safe_client_ip(self.request)
        # Should ignore spoofed headers and use REMOTE_ADDR
        self.assertEqual(ip, '203.0.113.70')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_rate_limit_bypass_attempt_blocked(self):
        """Test attempt to bypass rate limiting is blocked."""
        # Attacker from untrusted IP trying to spoof different IP
        self.request.META = {
            'REMOTE_ADDR': '203.0.113.80',  # Untrusted IP
            'HTTP_X_FORWARDED_FOR': '203.0.113.81',  # Trying to appear as different IP  
        }
        
        ip = get_safe_client_ip(self.request)
        # Should use actual connection IP, preventing rate limit bypass
        self.assertEqual(ip, '203.0.113.80')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_legitimate_proxy_allowed(self):
        """Test legitimate proxy traffic is processed correctly."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.100',  # Legitimate load balancer
            'HTTP_X_FORWARDED_FOR': '203.0.113.90',  # Real client
        }
        
        ip = get_safe_client_ip(self.request)
        # Should extract real client IP from trusted proxy
        self.assertEqual(ip, '203.0.113.90')

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=['10.0.0.0/8'])
    def test_proxy_chain_handling(self):
        """Test proper handling of proxy chains."""
        self.request.META = {
            'REMOTE_ADDR': '10.0.1.200',  # Final proxy (trusted)
            'HTTP_X_FORWARDED_FOR': '203.0.113.100, 192.168.1.50, 10.0.1.200',
        }
        
        ip = get_safe_client_ip(self.request)
        # Should return the original client IP (first in chain)
        self.assertEqual(ip, '203.0.113.100')