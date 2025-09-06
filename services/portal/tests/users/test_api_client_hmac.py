"""
🔐 Portal API Client HMAC Authentication Tests

Tests for the HMAC authentication system between Portal and Platform services.
These tests verify that the Portal can securely authenticate with the Platform API.
"""

import base64
import hashlib
import hmac
import json
import time
from unittest.mock import Mock, patch
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


class HMACAuthenticationTestCase(TestCase):
    """Test HMAC authentication implementation in Portal API Client"""
    
    def setUp(self):
        """Set up test client with known configuration"""
        self.client = PlatformAPIClient()
        self.test_secret = "test-hmac-secret-for-unit-tests"
        self.test_portal_id = "test-portal-001"
        
        # Override settings for testing
        with patch.object(settings, 'PORTAL_ID', self.test_portal_id), \
             patch.object(settings, 'PLATFORM_API_SECRET', self.test_secret), \
             patch.object(settings, 'PLATFORM_API_BASE_URL', 'http://testserver'), \
             patch.object(settings, 'PLATFORM_API_TIMEOUT', 10):
            self.client = PlatformAPIClient()

    def test_generate_hmac_headers_format(self):
        """Test that HMAC headers are generated in correct format"""
        method = "POST"
        path = "/api/users/login/"
        body = b'{"email": "test@example.com", "password": "test123"}'
        
        headers = self.client._generate_hmac_headers(method, path, body)
        
        # Verify all required headers are present
        required_headers = [
            'X-Portal-Id', 'X-Nonce', 'X-Timestamp', 
            'X-Body-Hash', 'X-Signature', 'Content-Type', 'Accept'
        ]
        for header in required_headers:
            self.assertIn(header, headers, f"Missing required header: {header}")
            
        # Verify header formats
        self.assertEqual(headers['X-Portal-Id'], self.test_portal_id)
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(headers['Accept'], 'application/json')
        
        # Verify nonce is base64-encoded and reasonable length
        nonce = headers['X-Nonce']
        self.assertTrue(len(nonce) > 10, "Nonce should be substantial length")
        
        # Verify timestamp is numeric
        timestamp = float(headers['X-Timestamp'])
        self.assertAlmostEqual(timestamp, time.time(), delta=5.0)
        
        # Verify body hash is base64-encoded SHA-256
        expected_body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        self.assertEqual(headers['X-Body-Hash'], expected_body_hash)
        
        # Verify signature is hex-encoded and correct length for SHA-256
        signature = headers['X-Signature']
        self.assertEqual(len(signature), 64, "HMAC-SHA256 signature should be 64 hex chars")
        self.assertTrue(all(c in '0123456789abcdef' for c in signature.lower()))

    def test_hmac_signature_canonical_string(self):
        """Test that canonical string is built correctly for HMAC signing"""
        method = "POST"
        path = "/api/users/login/"
        body = b'{"test": "data"}'
        
        # Generate headers to get the components
        headers = self.client._generate_hmac_headers(method, path, body)
        
        # Manually build expected canonical string
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        expected_canonical = "\n".join([
            method,
            path,
            'application/json',  # content-type
            body_hash,
            headers['X-Nonce'],
            headers['X-Timestamp']
        ])
        
        # Generate expected signature
        expected_signature = hmac.new(
            self.test_secret.encode(),
            expected_canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        self.assertEqual(headers['X-Signature'], expected_signature)

    def test_hmac_signature_different_bodies_different_signatures(self):
        """Test that different request bodies produce different signatures"""
        method = "POST"
        path = "/api/test/"
        
        body1 = b'{"email": "user1@example.com"}'
        body2 = b'{"email": "user2@example.com"}'
        
        # Mock time to ensure timestamps are the same
        with patch('time.time', return_value=1234567890.0), \
             patch('secrets.token_urlsafe', return_value='fixed-nonce-for-test'):
            
            headers1 = self.client._generate_hmac_headers(method, path, body1)
            headers2 = self.client._generate_hmac_headers(method, path, body2)
        
        # Same timestamp and nonce, but different bodies should produce different signatures
        self.assertEqual(headers1['X-Timestamp'], headers2['X-Timestamp'])
        self.assertEqual(headers1['X-Nonce'], headers2['X-Nonce'])
        self.assertNotEqual(headers1['X-Body-Hash'], headers2['X-Body-Hash'])
        self.assertNotEqual(headers1['X-Signature'], headers2['X-Signature'])

    @patch('apps.api_client.services.requests.request')
    def test_successful_authentication_request(self, mock_request):
        """Test successful HMAC authenticated request to platform"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'user': {
                'id': 123,
                'email': 'test@example.com',
                'is_active': True
            },
            'message': 'Authentication successful'
        }
        mock_request.return_value = mock_response
        
        # Make authenticated request
        result = self.client.authenticate_customer('test@example.com', 'password123')
        
        # Verify request was made with HMAC headers
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        
        # Check HMAC headers were included
        headers = call_args.kwargs['headers']
        hmac_headers = ['X-Portal-Id', 'X-Nonce', 'X-Timestamp', 'X-Body-Hash', 'X-Signature']
        for header in hmac_headers:
            self.assertIn(header, headers)
        
        # Verify result format
        self.assertIsNotNone(result)
        self.assertTrue(result['valid'])
        self.assertEqual(result['customer_id'], 123)

    @patch('apps.api_client.services.requests.request')
    def test_authentication_failure_401_response(self, mock_request):
        """Test handling of 401 authentication failure from platform"""
        # Mock 401 response (invalid HMAC)
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            'error': 'HMAC authentication failed: HMAC signature verification failed'
        }
        mock_request.return_value = mock_response
        
        # This should return None for authentication failure
        result = self.client.authenticate_customer('test@example.com', 'wrongpassword')
        
        self.assertIsNone(result)

    @patch('apps.api_client.services.requests.request')
    def test_connection_error_handling(self, mock_request):
        """Test handling of connection errors to platform service"""
        # Mock connection error
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        result = self.client.authenticate_customer('test@example.com', 'password')
        
        # Should return None for connection errors
        self.assertIsNone(result)

    @patch('apps.api_client.services.requests.request')
    def test_request_timeout_handling(self, mock_request):
        """Test handling of request timeouts"""
        # Mock timeout error  
        mock_request.side_effect = requests.exceptions.Timeout("Request timed out")
        
        result = self.client.authenticate_customer('test@example.com', 'password')
        
        self.assertIsNone(result)

    def test_empty_body_hmac_generation(self):
        """Test HMAC generation with empty request body"""
        method = "GET"
        path = "/api/users/validate/"
        body = b''
        
        headers = self.client._generate_hmac_headers(method, path, body)
        
        # Empty body should still have a valid hash
        expected_empty_hash = base64.b64encode(hashlib.sha256(b'').digest()).decode('ascii')
        self.assertEqual(headers['X-Body-Hash'], expected_empty_hash)
        
        # Should still have valid signature
        self.assertEqual(len(headers['X-Signature']), 64)

    def test_special_characters_in_path(self):
        """Test HMAC generation with special characters in path"""
        method = "GET"
        path = "/api/users/search/?email=test%40example.com&status=active"
        body = b''
        
        # Should not raise any exceptions
        headers = self.client._generate_hmac_headers(method, path, body)
        
        # Should produce valid signature
        self.assertIn('X-Signature', headers)
        self.assertEqual(len(headers['X-Signature']), 64)

    @patch('time.time')
    def test_timestamp_precision(self, mock_time):
        """Test that timestamps have sufficient precision"""
        mock_time.return_value = 1234567890.123456
        
        headers = self.client._generate_hmac_headers("GET", "/test/", b'')
        timestamp = headers['X-Timestamp']
        
        # Should preserve microsecond precision
        self.assertEqual(timestamp, "1234567890.123456")

    def test_nonce_uniqueness(self):
        """Test that nonces are unique across multiple requests"""
        nonces = set()
        
        # Generate multiple requests
        for _ in range(100):
            headers = self.client._generate_hmac_headers("GET", "/test/", b'test')
            nonce = headers['X-Nonce']
            
            # Each nonce should be unique
            self.assertNotIn(nonce, nonces, "Nonce collision detected")
            nonces.add(nonce)

    @override_settings(
        PLATFORM_API_BASE_URL='http://testserver',
        PLATFORM_API_SECRET='test-secret-override',
        PORTAL_ID='test-portal-override'
    )
    def test_settings_override_in_client(self):
        """Test that client respects Django settings overrides"""
        client = PlatformAPIClient()
        
        # Verify settings are loaded correctly
        self.assertEqual(client.base_url, 'http://testserver')
        self.assertEqual(client.portal_secret, 'test-secret-override')
        self.assertEqual(client.portal_id, 'test-portal-override')


class PlatformAPIClientIntegrationTestCase(TestCase):
    """Integration tests for complete Portal → Platform API workflows"""
    
    def setUp(self):
        self.client = PlatformAPIClient()

    @patch('apps.api_client.services.requests.request')  
    def test_full_authentication_workflow(self, mock_request):
        """Test complete authentication workflow with proper HMAC"""
        # Mock platform response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'user': {
                'id': 42,
                'email': 'integration@example.com',
                'first_name': 'Integration',
                'last_name': 'Test',
                'is_active': True,
                'is_staff': False
            },
            'message': 'Authentication successful'
        }
        mock_request.return_value = mock_response
        
        # Perform authentication
        result = self.client.authenticate_customer(
            email='integration@example.com',
            password='secure-password-123'
        )
        
        # Verify the request was made correctly
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        
        # Verify HTTP method and URL (requests.request() uses keyword args)
        self.assertEqual(call_args.kwargs['method'], 'POST')
        expected_url = f"{self.client.base_url}/users/login/"
        self.assertEqual(call_args.kwargs['url'], expected_url)
        
        # Verify HMAC authentication headers
        headers = call_args.kwargs['headers']
        required_headers = ['X-Portal-Id', 'X-Signature', 'X-Nonce', 'X-Timestamp', 'X-Body-Hash']
        for header in required_headers:
            self.assertIn(header, headers)
            self.assertIsNotNone(headers[header])
        
        # Verify request body
        request_data = call_args.kwargs['data']
        expected_data = json.dumps({
            'email': 'integration@example.com',
            'password': 'secure-password-123'
        }).encode('utf-8')
        self.assertEqual(request_data, expected_data)
        
        # Verify response transformation
        self.assertIsNotNone(result)
        self.assertTrue(result['valid'])
        self.assertEqual(result['customer_id'], 42)
        self.assertEqual(result['token'], 42)  # Uses user ID as token
        
        # Verify customer data is included
        customer_data = result['customer_data']
        self.assertEqual(customer_data['email'], 'integration@example.com')
        self.assertEqual(customer_data['first_name'], 'Integration')
        self.assertTrue(customer_data['is_active'])
