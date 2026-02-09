import base64
import hashlib
import hmac
import json
import time

from django.conf import settings
from django.http import HttpResponse
from django.test import TestCase, RequestFactory, override_settings

from apps.common.middleware import PortalServiceHMACMiddleware


class PortalHMACTests(TestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.secret = 'unit-test-secret'

    def _sign(self, method: str, path: str, body: bytes, portal_id: str, nonce: str, timestamp: str) -> str:
        # Server canonicalization: normalize path/query and content-type
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

    @override_settings(PLATFORM_API_SECRET='unit-test-secret')
    def test_valid_signature_allows_request(self):
        ts = time.time()
        body = json.dumps({'user_id': 1, 'customer_id': 2, 'timestamp': ts}).encode()
        method = 'POST'
        raw_path = '/api/test/?b=2&a=1'
        portal_id = 'portal-xyz'
        nonce = 'nonce-123'
        timestamp = str(ts)

        # Compute signature
        signature = self._sign(method, raw_path, body, portal_id, nonce, timestamp)

        # Build request
        request = self.factory.post(raw_path, data=body, content_type='application/json')
        request.META['HTTP_X_PORTAL_ID'] = portal_id
        request.META['HTTP_X_NONCE'] = nonce
        request.META['HTTP_X_TIMESTAMP'] = timestamp
        request.META['HTTP_X_BODY_HASH'] = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        request.META['HTTP_X_SIGNATURE'] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))
        response = middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Portal-Auth'], 'hmac-verified')

    @override_settings(PLATFORM_API_SECRET='unit-test-secret')
    def test_invalid_signature_rejected(self):
        ts = time.time()
        body = json.dumps({'user_id': 1, 'customer_id': 2, 'timestamp': ts}).encode()
        method = 'POST'
        raw_path = '/api/test/?x=1'
        portal_id = 'portal-xyz'
        nonce = 'nonce-abc'
        timestamp = str(ts)

        # Intentionally wrong signature
        signature = '0' * 64

        request = self.factory.post(raw_path, data=body, content_type='application/json')
        request.META['HTTP_X_PORTAL_ID'] = portal_id
        request.META['HTTP_X_NONCE'] = nonce
        request.META['HTTP_X_TIMESTAMP'] = timestamp
        request.META['HTTP_X_BODY_HASH'] = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        request.META['HTTP_X_SIGNATURE'] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))
        response = middleware(request)

        body_text = response.content.decode()
        self.assertEqual(response.status_code, 401)
        self.assertIn('HMAC authentication failed', body_text)
        # Should not leak specific verification reason
        self.assertNotIn('HMAC signature verification failed', body_text)

    @override_settings(PLATFORM_API_SECRET='unit-test-secret')
    def test_timestamp_mismatch_rejected(self):
        # Header/body timestamp mismatch should be rejected
        body = json.dumps({'user_id': 1, 'customer_id': 2, 'timestamp': 111.0}).encode()
        method = 'POST'
        raw_path = '/api/test/'
        portal_id = 'portal-xyz'
        nonce = 'nonce-xyz'
        header_ts = '222.0'
        signature = self._sign(method, raw_path, body, portal_id, nonce, header_ts)

        request = self.factory.post(raw_path, data=body, content_type='application/json')
        request.META['HTTP_X_PORTAL_ID'] = portal_id
        request.META['HTTP_X_NONCE'] = nonce
        request.META['HTTP_X_TIMESTAMP'] = header_ts
        request.META['HTTP_X_BODY_HASH'] = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        request.META['HTTP_X_SIGNATURE'] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))
        response = middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertIn('HMAC authentication failed', response.content.decode())

    @override_settings(PLATFORM_API_SECRET='unit-test-secret', HMAC_RATE_LIMIT_WINDOW=60, HMAC_RATE_LIMIT_MAX_CALLS=2)
    def test_rate_limit_triggers(self):
        # Hit more than 2 times within window -> 429
        method = 'POST'
        raw_path = '/api/test/'
        portal_id = 'portal-rl'
        nonce_base = 'nonce-rl-'
        ts = str(time.time())

        def make_req(i: int):
            body = json.dumps({'user_id': 1, 'customer_id': 2, 'timestamp': float(ts)}).encode()
            signature = self._sign(method, raw_path, body, portal_id, f'{nonce_base}{i}', ts)
            req = self.factory.post(raw_path, data=body, content_type='application/json')
            req.META['HTTP_X_PORTAL_ID'] = portal_id
            req.META['HTTP_X_NONCE'] = f'{nonce_base}{i}'
            req.META['HTTP_X_TIMESTAMP'] = ts
            req.META['HTTP_X_BODY_HASH'] = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
            req.META['HTTP_X_SIGNATURE'] = signature
            return req

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))
        r1 = middleware(make_req(1))
        r2 = middleware(make_req(2))
        r3 = middleware(make_req(3))
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r3.status_code, 429)

    @override_settings(PLATFORM_API_SECRET='unit-test-secret')
    def test_nonce_replay_rejected(self):
        # Same nonce should be rejected on second use
        method = 'POST'
        raw_path = '/api/test/'
        portal_id = 'portal-replay'
        nonce = 'replay-n'
        ts = str(time.time())
        body = json.dumps({'user_id': 1, 'customer_id': 2, 'timestamp': float(ts)}).encode()
        signature = self._sign(method, raw_path, body, portal_id, nonce, ts)

        request1 = self.factory.post(raw_path, data=body, content_type='application/json')
        for meta in (
            ('HTTP_X_PORTAL_ID', portal_id),
            ('HTTP_X_NONCE', nonce),
            ('HTTP_X_TIMESTAMP', ts),
            ('HTTP_X_BODY_HASH', base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')),
            ('HTTP_X_SIGNATURE', signature),
        ):
            request1.META[meta[0]] = meta[1]

        request2 = self.factory.post(raw_path, data=body, content_type='application/json')
        for meta in (
            ('HTTP_X_PORTAL_ID', portal_id),
            ('HTTP_X_NONCE', nonce),
            ('HTTP_X_TIMESTAMP', ts),
            ('HTTP_X_BODY_HASH', base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')),
            ('HTTP_X_SIGNATURE', signature),
        ):
            request2.META[meta[0]] = meta[1]

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))
        r1 = middleware(request1)
        r2 = middleware(request2)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 401)
