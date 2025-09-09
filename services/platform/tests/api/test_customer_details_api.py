import base64
import hashlib
import hmac
import json
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings

from apps.customers.models import Customer
from apps.users.models import CustomerMembership


class CustomerDetailsAPITests(TestCase):
    """Integration tests for POST /api/customers/details/ with HMAC + membership"""

    def setUp(self) -> None:
        self.client = Client()
        self.secret = 'unit-test-secret'
        self.portal_id = 'portal-it'

        User = get_user_model()
        self.user = User.objects.create_user(email='owner@example.com', password='testpass123', is_active=True)
        self.other_user = User.objects.create_user(email='viewer@example.com', password='testpass123', is_active=True)

        # Active customer is required by secure_auth.get_authenticated_customer
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company SRL',
            customer_type='company',
            primary_email='contact@example.com',
            status='active',
        )

        # Grant membership to self.user
        CustomerMembership.objects.create(customer=self.customer, user=self.user, role='owner', is_primary=True)

    def _sign(self, method: str, path: str, body: bytes, portal_id: str, nonce: str, timestamp: str) -> str:
        """Compute signature using the same canonicalization as the middleware (Phase 2)."""
        import urllib.parse
        parsed = urllib.parse.urlsplit(path)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        pairs.sort(key=lambda kv: (kv[0], kv[1]))
        normalized_query = urllib.parse.urlencode(pairs, doseq=True)
        normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

        content_type = 'application/json'
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')

        canonical = "\n".join([
            method,
            normalized_path,
            content_type,
            body_hash,
            portal_id,
            nonce,
            timestamp,
        ])
        return hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    def _headers(self, method: str, path: str, body: bytes, nonce: str, timestamp: str) -> dict[str, str]:
        sig = self._sign(method, path, body, self.portal_id, nonce, timestamp)
        return {
            'HTTP_X_PORTAL_ID': self.portal_id,
            'HTTP_X_NONCE': nonce,
            'HTTP_X_TIMESTAMP': timestamp,
            'HTTP_X_BODY_HASH': base64.b64encode(hashlib.sha256(body).digest()).decode('ascii'),
            'HTTP_X_SIGNATURE': sig,
        }

    @override_settings(
        PLATFORM_API_SECRET='unit-test-secret',
        MIDDLEWARE=[
            # Minimal stack + HMAC middleware (after AuthenticationMiddleware)
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.locale.LocaleMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'apps.common.middleware.PortalServiceHMACMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
    )
    def test_customer_details_success_hmac_and_membership(self):
        path = '/api/customers/details/'
        ts = str(time.time())
        body_dict = {
            'customer_id': self.customer.id,
            'user_id': self.user.id,
            'action': 'get_customer_details',
            'timestamp': float(ts),
        }
        body = json.dumps(body_dict).encode()
        headers = self._headers('POST', path, body, nonce='nonce-success-1', timestamp=ts)

        resp = self.client.post(path, data=body, content_type='application/json', **headers)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get('success'))
        self.assertIn('customer', data)
        cust = data['customer']
        self.assertEqual(cust['id'], self.customer.id)
        # Ensure safe nested structure and no sensitive fields like CNP
        self.assertIn('tax_profile', cust)
        if cust['tax_profile'] is not None:
            self.assertNotIn('cnp', cust['tax_profile'])

    @override_settings(
        PLATFORM_API_SECRET='unit-test-secret',
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.locale.LocaleMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'apps.common.middleware.PortalServiceHMACMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
    )
    def test_customer_details_denied_without_membership(self):
        path = '/api/customers/details/'
        ts = str(time.time())
        body_dict = {
            'customer_id': self.customer.id,
            'user_id': self.other_user.id,  # No membership for this user
            'action': 'get_customer_details',
            'timestamp': float(ts),
        }
        body = json.dumps(body_dict).encode()
        headers = self._headers('POST', path, body, nonce='nonce-nomember-1', timestamp=ts)

        resp = self.client.post(path, data=body, content_type='application/json', **headers)

        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertFalse(data.get('success'))
        # Generic error prevents information leakage
        self.assertEqual(data.get('error'), 'Access denied')

    @override_settings(
        PLATFORM_API_SECRET='unit-test-secret',
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.locale.LocaleMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'apps.common.middleware.PortalServiceHMACMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
    )
    def test_customer_details_invalid_signature_rejected(self):
        path = '/api/customers/details/'
        ts = str(time.time())
        body_dict = {
            'customer_id': self.customer.id,
            'user_id': self.user.id,
            'action': 'get_customer_details',
            'timestamp': float(ts),
        }
        body = json.dumps(body_dict).encode()

        # Build headers with wrong signature
        headers = {
            'HTTP_X_PORTAL_ID': self.portal_id,
            'HTTP_X_NONCE': 'nonce-bad-1',
            'HTTP_X_TIMESTAMP': ts,
            'HTTP_X_BODY_HASH': base64.b64encode(hashlib.sha256(body).digest()).decode('ascii'),
            'HTTP_X_SIGNATURE': '0' * 64,
        }

        resp = self.client.post(path, data=body, content_type='application/json', **headers)
        self.assertEqual(resp.status_code, 401)
        self.assertIn('HMAC authentication failed', resp.content.decode())
