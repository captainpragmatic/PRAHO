"""Every request the real Portal client signs must verify on the real Platform middleware.

The Portal's own tests compare its signature against a Portal-side rebuild of the canonical
string, so a Portal signer that Platform never accepted passed them for months: the pipe-joined
"legacy" canonical used for HTTPS with DEBUG off, and paths signed in a different spelling than
Platform's `request.get_full_path()`. This test signs with the real client in its own process
(Portal and Platform both own a top-level `apps` package), records the request exactly as
`requests` would put it on the wire, and replays it through `PortalServiceHMACMiddleware`.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, ClassVar

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.common.middleware import PortalServiceHMACMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = "cross-service-signature-secret-0123456789"
PORTAL_ID = "portal-signature-check"

CONFIGURATIONS = {
    "https-debug-off": {"DEBUG": False, "BASE_URL": "https://platform.example.test/api", "INSECURE": False},
    "http-debug-off": {"DEBUG": False, "BASE_URL": "http://platform.example.test/api", "INSECURE": True},
    "https-debug-on": {"DEBUG": True, "BASE_URL": "https://platform.example.test/api", "INSECURE": False},
}
# Raw paths: whatever the HTTP stack does to them on the way out, the signature must match.
INVOICE_NUMBERS = {
    "plain": "INV-0001",
    "space": "INV 0001",
    "diacritic": "FACTă-1",
    "semicolon": "A;B=1",
    "invalid-utf8-escape": "%C8",
    "malformed-escape": "%C8%99%ZZ",
    "dot-dot": "..",
    "encoded-slash": "x%2Fpdf",
    "bare-percent": "100%",
}
# Customer-typed document numbers through the real call site: each must arrive as exactly one
# path segment, unchanged, or Platform would answer for a different route than the one named.
DOCUMENT_NUMBERS = {
    "plain": "INV-0001",
    "diacritic": "FACTă-1",
    "invalid-utf8-escape": "%C8",
    "encoded-slash": "x%2Fpdf",
    "newline": "a\nb",
}
CALLS = (
    "localisation",
    "login",
    "query-params",
    "none-param",
    "binary",
    "binary-with-headers",
    "payment-intent",
    "stripe-config",
    *(f"invoice-{name}" for name in INVOICE_NUMBERS),
    *(f"document-{name}" for name in DOCUMENT_NUMBERS),
)

# Runs with services/portal as the working directory, so `apps` is the Portal's package.
PORTAL_RECORDER = """
import base64
import json
import sys
from unittest.mock import patch

import django
import requests
from django.conf import settings

settings.configure(
    INSTALLED_APPS=["apps.common"],  # login imports the rate-limit counter model
    SECRET_KEY="signature-check-test-only",
    DEBUG=True,
    PLATFORM_API_BASE_URL="http://platform.example.test/api",  # read by the module-level client
    PLATFORM_API_SECRET=SECRET,
    PORTAL_HMAC_SECRET=SECRET,
    PORTAL_ID=PORTAL_ID,
    PLATFORM_API_TIMEOUT=5,
    PLATFORM_API_READ_MAX_RETRIES=0,
)
django.setup()

from django.test import override_settings

from apps.api_client.services import PlatformAPIClient

records = []
current = {}


def transport(*, method, url, headers, data=None, params=None, **kwargs):
    prepared = requests.Request(method, url, headers=headers, data=data, params=params).prepare()
    body = prepared.body or b""
    if isinstance(body, str):
        body = body.encode()
    records.append(
        {
            **current,
            "method": prepared.method,
            "path_url": prepared.path_url,
            "headers": {key: value for key, value in prepared.headers.items()},
            "body": base64.b64encode(body).decode(),
        }
    )
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"success": True, "data": {}}).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def calls(client):
    yield "localisation", lambda: client.get_localisation_defaults()
    yield "login", lambda: client.authenticate_customer("customer@example.test", "correct-password")
    yield "query-params", lambda: client._make_request(
        "GET", "/customers/search/", user_id=1, params={"z": "1", "a": "2"}
    )
    yield "none-param", lambda: client._make_request(
        "GET", "/customers/search/", user_id=1, params={"q": None, "a": "1"}
    )
    yield "binary", lambda: client._make_binary_request(
        "POST", "/billing/invoices/INV-0001/pdf/", data={"customer_id": 1, "user_id": 1}
    )
    yield "binary-with-headers", lambda: client.download_ticket_attachment(1, 1, 2, 3)
    yield "payment-intent", lambda: client.post_billing("create-payment-intent/", data={"order_id": "o-1"}, user_id=1)
    yield "stripe-config", lambda: client.get_billing("stripe-config/")
    for name, number in INVOICE_NUMBERS.items():
        yield f"invoice-{name}", lambda number=number: client._make_request(
            "GET", f"/billing/invoices/{number}/", user_id=1
        )
    for name, number in DOCUMENT_NUMBERS.items():
        yield f"document-{name}", lambda number=number: client.get_invoice_detail_secure(1, number)


with patch("apps.api_client.services.portal_request", side_effect=transport):
    for configuration, values in CONFIGURATIONS.items():
        with override_settings(
            DEBUG=values["DEBUG"],
            PLATFORM_API_BASE_URL=values["BASE_URL"],
            PLATFORM_API_ALLOW_INSECURE_HTTP=values["INSECURE"],
        ):
            client = PlatformAPIClient()
            for call, invoke in calls(client):
                current.clear()
                current.update(configuration=configuration, call=call)
                try:
                    invoke()
                except Exception as error:  # The reply is canned; only the request matters here.
                    print(f"{configuration}/{call}: {error!r}", file=sys.stderr)

print(json.dumps(records), flush=True)
"""


def _record_portal_requests() -> list[dict[str, Any]]:
    environment = dict(os.environ)
    environment.pop("DJANGO_SETTINGS_MODULE", None)
    environment["PYTHONPATH"] = ""
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    constants = (
        f"SECRET = {SECRET!r}\nPORTAL_ID = {PORTAL_ID!r}\n"
        f"CONFIGURATIONS = {CONFIGURATIONS!r}\nINVOICE_NUMBERS = {INVOICE_NUMBERS!r}\n"
        f"DOCUMENT_NUMBERS = {DOCUMENT_NUMBERS!r}\n"
    )
    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and a test-owned script
        [sys.executable, "-c", constants + PORTAL_RECORDER],
        cwd=REPO_ROOT / "services/portal",
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise AssertionError(f"Portal recorder failed ({completed.returncode}):\n{completed.stderr}")
    records: list[dict[str, Any]] = json.loads(completed.stdout.strip().splitlines()[-1])
    return records


@override_settings(
    PLATFORM_API_SECRET=SECRET,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "signatures"}},
)
class PortalSignatureVerifiesOnPlatformTests(SimpleTestCase):
    records: ClassVar[list[dict[str, Any]]]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.records = _record_portal_requests()

    def _replay(self, record: dict[str, Any], signature: str | None = None) -> tuple[HttpResponse, list[str]]:
        reached: list[str] = []

        def view(request: HttpRequest) -> HttpResponse:
            reached.append(request.path)
            return HttpResponse("view reached")

        cache.clear()  # each test replays every record; a nonce is accepted once
        headers = record["headers"]
        request = RequestFactory().generic(
            record["method"],
            record["path_url"],
            data=base64.b64decode(record["body"]),
            content_type=headers.get("Content-Type", "application/json"),
        )
        for name, value in headers.items():
            if name.lower().startswith("x-"):
                request.META["HTTP_" + name.upper().replace("-", "_")] = value
        if signature is not None:
            request.META["HTTP_X_SIGNATURE"] = signature
        return PortalServiceHMACMiddleware(view)(request), reached

    def test_the_recorder_made_exactly_one_request_per_call(self) -> None:
        seen = [(record["configuration"], record["call"]) for record in self.records]
        expected = [(configuration, call) for configuration in CONFIGURATIONS for call in CALLS]
        self.assertEqual(sorted(seen), sorted(expected))

    def test_every_probed_path_is_signature_checked(self) -> None:
        # A public endpoint answers 200 whatever the signature says, which would make the
        # verification test below pass without checking anything.
        for record in self.records:
            with self.subTest(configuration=record["configuration"], call=record["call"], path=record["path_url"]):
                response, reached = self._replay(record, signature="0" * 64)
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(reached, [])

    def test_every_signed_request_verifies_on_platform(self) -> None:
        for record in self.records:
            with self.subTest(configuration=record["configuration"], call=record["call"], path=record["path_url"]):
                response, reached = self._replay(record)
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(len(reached), 1)

    def test_payment_calls_are_signed_for_api_billing(self) -> None:
        # Platform's Caddy configuration publishes only /api/* on its hostname.
        payments = [record for record in self.records if record["call"] in {"payment-intent", "stripe-config"}]
        self.assertEqual(len(payments), 2 * len(CONFIGURATIONS))
        for record in payments:
            with self.subTest(configuration=record["configuration"], call=record["call"]):
                self.assertTrue(record["path_url"].startswith("/api/billing/"), record["path_url"])

    def test_document_numbers_reach_platform_as_one_unchanged_segment(self) -> None:
        documents = [record for record in self.records if record["call"].startswith("document-")]
        self.assertEqual(len(documents), len(CONFIGURATIONS) * len(DOCUMENT_NUMBERS))
        for record in documents:
            number = DOCUMENT_NUMBERS[record["call"].removeprefix("document-")]
            with self.subTest(configuration=record["configuration"], number=number):
                response, reached = self._replay(record)
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(reached, [f"/api/billing/invoices/{number}/"])
