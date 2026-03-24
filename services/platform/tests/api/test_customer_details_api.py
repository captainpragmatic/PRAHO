import base64
import hashlib
import json
import time

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.users.models import CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class CustomerDetailsAPITests(HMACTestMixin, TestCase):
    """Integration tests for POST /api/customers/details/ with HMAC + membership"""

    def setUp(self) -> None:
        User = get_user_model()
        self.user = User.objects.create_user(email='owner@example.com', password='testpass123', is_active=True)
        self.other_user = User.objects.create_user(email='viewer@example.com', password='testpass123', is_active=True)

        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company SRL',
            customer_type='company',
            primary_email='contact@example.com',
            status='active',
        )

        CustomerMembership.objects.create(customer=self.customer, user=self.user, role='owner', is_primary=True)

    def test_customer_details_success_hmac_and_membership(self):
        resp = self.portal_post('/api/customers/details/', {
            'customer_id': self.customer.id,
            'user_id': self.user.id,
            'action': 'get_customer_details',
        })

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get('success'))
        self.assertIn('customer', data)
        cust = data['customer']
        self.assertEqual(cust['id'], self.customer.id)
        self.assertIn('tax_profile', cust)
        if cust['tax_profile'] is not None:
            self.assertNotIn('cnp', cust['tax_profile'])

    def test_customer_details_denied_without_membership(self):
        resp = self.portal_post('/api/customers/details/', {
            'customer_id': self.customer.id,
            'user_id': self.other_user.id,
            'action': 'get_customer_details',
        })

        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertFalse(data.get('success'))
        self.assertEqual(data.get('error'), 'Access denied')

    def test_customer_details_invalid_signature_rejected(self):
        path = '/api/customers/details/'
        body_dict = {
            'customer_id': self.customer.id,
            'user_id': self.user.id,
            'action': 'get_customer_details',
            'timestamp': time.time(),
        }
        body = json.dumps(body_dict).encode()

        headers = {
            'HTTP_X_PORTAL_ID': 'test-portal',
            'HTTP_X_NONCE': 'nonce-bad-1',
            'HTTP_X_TIMESTAMP': str(int(time.time())),
            'HTTP_X_BODY_HASH': base64.b64encode(hashlib.sha256(body).digest()).decode('ascii'),
            'HTTP_X_SIGNATURE': '0' * 64,
        }

        resp = self.client.post(path, data=body, content_type='application/json', **headers)
        self.assertEqual(resp.status_code, 401)
        self.assertIn('HMAC authentication failed', resp.content.decode())
