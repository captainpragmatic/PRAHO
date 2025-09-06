#!/usr/bin/env python3
"""
🔐 Portal HMAC Authentication Test

Test script to verify the new HMAC authentication system works correctly
between Portal and Platform services.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict

import requests


class PortalHMACTester:
    """Test the Portal→Platform HMAC authentication"""
    
    def __init__(self, platform_url: str = "http://localhost:8700", portal_secret: str = "dev-shared-secret-change-in-production"):
        self.platform_url = platform_url.rstrip('/')
        self.portal_id = "portal-001"
        self.portal_secret = portal_secret
        
    def _generate_hmac_headers(self, method: str, path: str, body: bytes) -> Dict[str, str]:
        """Generate HMAC headers for authentication"""
        # Generate unique nonce and timestamp
        nonce = secrets.token_urlsafe(16)
        timestamp = str(time.time())
        
        # Compute body hash
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        
        # Build canonical string for signing - match platform exactly
        content_type = 'application/json'
        canonical_string = "\n".join([
            method.upper(),  # Ensure uppercase
            path,
            content_type,
            body_hash,
            nonce,
            timestamp
        ])
        
        # Generate HMAC signature
        signature = hmac.new(
            self.portal_secret.encode(),
            canonical_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Debug output
        print(f"🔍 Debug HMAC generation:")
        print(f"   Method: '{method.upper()}'")
        print(f"   Path: '{path}'")
        print(f"   Content-Type: '{content_type}'")
        print(f"   Body Hash: '{body_hash}'")
        print(f"   Nonce: '{nonce}'")
        print(f"   Timestamp: '{timestamp}'")
        print(f"   Canonical String:")
        for i, line in enumerate(canonical_string.split('\n')):
            print(f"     {i}: '{line}'")
        print(f"   Signature: '{signature}'")
        
        return {
            'X-Portal-Id': self.portal_id,
            'X-Nonce': nonce,
            'X-Timestamp': timestamp,
            'X-Body-Hash': body_hash,
            'X-Signature': signature,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    
    def test_authentication(self, email: str, password: str) -> Dict[str, Any]:
        """Test customer authentication via HMAC"""
        print(f"🧪 Testing HMAC authentication for: {email}")
        
        # Prepare request data
        data = {'email': email, 'password': password}
        request_body = json.dumps(data).encode('utf-8')
        path = '/api/users/login/'
        
        # Generate HMAC headers
        headers = self._generate_hmac_headers('POST', path, request_body)
        
        # Make request
        url = f"{self.platform_url}{path}"
        try:
            response = requests.post(
                url,
                headers=headers,
                data=request_body,
                timeout=10
            )
            
            print(f"🌐 Request: POST {url}")
            print(f"📊 Response: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Authentication successful!")
                print(f"📄 Response: {json.dumps(result, indent=2)}")
                return result
            else:
                print(f"❌ Authentication failed: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"📄 Error: {json.dumps(error_data, indent=2)}")
                except:
                    print(f"📄 Raw response: {response.text}")
                return {'error': f"HTTP {response.status_code}", 'details': response.text}
                
        except requests.exceptions.ConnectionError:
            print(f"🔥 Connection failed to {url}")
            print("💡 Make sure the platform service is running:")
            print("   - Platform: http://localhost:8700")
            print("   - Portal: http://localhost:8701")
            return {'error': 'Connection failed'}
        except Exception as e:
            print(f"🔥 Unexpected error: {e}")
            return {'error': str(e)}
    
    def test_invalid_signature(self) -> None:
        """Test that invalid signatures are rejected"""
        print(f"\n🧪 Testing invalid signature rejection...")
        
        # Prepare request with invalid signature
        data = {'email': 'test@example.com', 'password': 'test'}
        request_body = json.dumps(data).encode('utf-8')
        path = '/api/users/login/'
        
        headers = self._generate_hmac_headers('POST', path, request_body)
        # Corrupt the signature
        headers['X-Signature'] = 'invalid-signature'
        
        url = f"{self.platform_url}{path}"
        try:
            response = requests.post(
                url,
                headers=headers,
                data=request_body,
                timeout=10
            )
            
            if response.status_code == 401:
                print("✅ Invalid signature correctly rejected")
            else:
                print(f"❌ Expected 401, got {response.status_code}")
                
        except Exception as e:
            print(f"🔥 Error testing invalid signature: {e}")


if __name__ == "__main__":
    print("🔐 Portal HMAC Authentication Tester")
    print("=" * 50)
    
    tester = PortalHMACTester()
    
    # Test valid authentication (you'll need to create a test user first)
    result = tester.test_authentication(
        email="admin@example.com",
        password="test123"
    )
    
    # Test invalid signature
    tester.test_invalid_signature()
    
    print("\n🎯 Test completed!")
