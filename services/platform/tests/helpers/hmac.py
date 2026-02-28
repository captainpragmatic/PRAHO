"""
Shared HMAC signing utilities for Portal-to-Platform API tests.

Usage in TestCase classes:

    from tests.helpers.hmac import HMACTestMixin

    class MyTest(HMACTestMixin, TestCase):
        def test_something(self):
            response = self.portal_post("/api/some/endpoint/", {
                "user_id": 1,
                "customer_id": 2,
            })
            self.assertEqual(response.status_code, 200)

The mixin computes REAL HMAC signatures identical to what the Portal sends.
Requests flow through the actual PortalServiceHMACMiddleware — no mocking.

For tests using RequestFactory instead of TestClient, use the standalone
functions: sign_request() and hmac_headers().
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from django.http import HttpResponse

if TYPE_CHECKING:
    from django.test import Client

# Shared test secret — must match @override_settings(PLATFORM_API_SECRET=...)
HMAC_TEST_SECRET = "test-hmac-secret"  # noqa: S105

# Minimal middleware stack that includes HMAC validation.
# Use with @override_settings(MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
HMAC_TEST_MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.common.middleware.PortalServiceHMACMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


def sign_request(  # noqa: PLR0913
    method: str,
    path: str,
    body: bytes,
    portal_id: str,
    nonce: str,
    timestamp: str,
    secret: str = HMAC_TEST_SECRET,
) -> str:
    """Compute HMAC signature using the same canonicalization as PortalServiceHMACMiddleware."""
    parsed = urllib.parse.urlsplit(path)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    normalized_query = urllib.parse.urlencode(pairs, doseq=True)
    normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

    content_type = "application/json"
    body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")

    canonical = "\n".join([
        method,
        normalized_path,
        content_type,
        body_hash,
        portal_id,
        nonce,
        timestamp,
    ])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def hmac_headers(  # noqa: PLR0913
    method: str,
    path: str,
    body: bytes,
    portal_id: str = "test-portal",
    nonce: str | None = None,
    timestamp: str | None = None,
    secret: str = HMAC_TEST_SECRET,
) -> dict[str, str]:
    """Build the full set of HMAC headers for a Django TestClient request.

    Returns dict with HTTP_X_* keys ready for **kwargs to client.post().
    """
    if nonce is None:
        nonce = f"test-nonce-{time.time()}"
    if timestamp is None:
        timestamp = str(time.time())

    sig = sign_request(method, path, body, portal_id, nonce, timestamp, secret)
    return {
        "HTTP_X_PORTAL_ID": portal_id,
        "HTTP_X_NONCE": nonce,
        "HTTP_X_TIMESTAMP": timestamp,
        "HTTP_X_BODY_HASH": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        "HTTP_X_SIGNATURE": sig,
    }


class HMACTestMixin:
    """Mixin for TestCase classes that need to send HMAC-signed requests.

    Provides portal_post() and portal_get() that compute real HMAC signatures
    and send requests through Django's TestClient with the full middleware stack.

    Usage:
        @override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
        class MyAPITest(HMACTestMixin, TestCase):
            def test_endpoint(self):
                response = self.portal_post("/api/endpoint/", {"user_id": 1})
                self.assertEqual(response.status_code, 200)
    """

    client: Client
    portal_id: str = "test-portal"

    def portal_post(self, path: str, data: dict | None = None, **extra: Any) -> HttpResponse:
        """Send an HMAC-signed POST request through TestClient."""
        if data is None:
            data = {}
        if "timestamp" not in data:
            data["timestamp"] = time.time()

        body = json.dumps(data).encode()
        headers = hmac_headers("POST", path, body, portal_id=self.portal_id)
        headers.update(extra)
        return self.client.post(path, body, content_type="application/json", **headers)

    def portal_get(self, path: str, data: dict | None = None, **extra: Any) -> HttpResponse:
        """Send an HMAC-signed GET request through TestClient."""
        body = json.dumps(data or {}).encode()
        headers = hmac_headers("GET", path, body, portal_id=self.portal_id)
        headers.update(extra)
        return self.client.get(path, content_type="application/json", **headers)
