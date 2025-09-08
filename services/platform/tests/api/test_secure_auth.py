import json
import time

from django.http import HttpRequest
from django.test import TestCase

from apps.api.secure_auth import validate_hmac_authenticated_request


class SecureAuthValidationTests(TestCase):
    def _make_request(self, body_dict: dict) -> HttpRequest:
        req = HttpRequest()
        req.method = 'POST'
        body = json.dumps(body_dict).encode()
        req._body = body
        req.META['CONTENT_TYPE'] = 'application/json'
        # Simulate that middleware already authenticated HMAC
        setattr(req, '_portal_authenticated', True)
        return req

    def test_missing_user_id_is_rejected(self):
        request = self._make_request({
            'customer_id': 123,
            'timestamp': time.time(),
        })
        data, error = validate_hmac_authenticated_request(request)
        self.assertIsNone(data)
        self.assertIsNotNone(error)
        self.assertEqual(error.status_code, 400)

    def test_valid_body_is_accepted(self):
        request = self._make_request({
            'customer_id': 123,
            'user_id': 42,
            'timestamp': time.time(),
        })
        data, error = validate_hmac_authenticated_request(request)
        self.assertIsNone(error)
        self.assertIsInstance(data, dict)
        self.assertEqual(data['user_id'], 42)
        self.assertEqual(data['customer_id'], 123)

