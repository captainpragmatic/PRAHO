"""The real Portal client signs, Platform authenticates, and Portal parses service domains."""

import json
import os
import subprocess
import sys
from pathlib import Path

from services.platform.tests.helpers.service_domains import ServiceDomainsFixture

REPO_ROOT = Path(__file__).resolve().parents[2]

# Run Portal imports in their own process so apps.* remains isolated from Platform.
PORTAL_ROUND_TRIP = """
import json
import sys
from unittest.mock import patch

import django
import requests
from django.conf import settings

settings.configure(
    INSTALLED_APPS=[],
    SECRET_KEY="wp8-test-only",
    DEBUG=True,
    PLATFORM_API_BASE_URL="http://testserver/api",
    PLATFORM_API_SECRET="test-hmac-secret",
    PLATFORM_API_TIMEOUT=5,
    PLATFORM_API_READ_MAX_RETRIES=0,
    PORTAL_ID="test-portal",
)
django.setup()

from apps.services.services import ServicesAPIClient

def transport(*, method: str, url: str, headers: dict[str, str], data: bytes, **kwargs: object) -> requests.Response:
    print(json.dumps({"method": method, "url": url, "headers": headers, "body": data.decode()}), flush=True)
    reply = json.loads(sys.stdin.readline())
    response = requests.Response()
    response.status_code = reply["status"]
    response._content = reply["body"].encode()
    response.headers["Content-Type"] = reply["content_type"]
    return response

with patch("apps.api_client.services.portal_request", side_effect=transport):
    domains = ServicesAPIClient().get_service_domains(
        int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    )
print(json.dumps(domains), flush=True)
"""


class TestServiceDomainsHMACRoundTrip(ServiceDomainsFixture):
    def test_portal_signs_and_parses_its_own_service_domains(self) -> None:
        path = f"/api/services/{self.service.pk}/domains/"
        probe = self.portal_post(path, self._body())
        self.assertEqual(probe.status_code, 200, probe.content)
        environment = dict(os.environ)
        environment.pop("DJANGO_SETTINGS_MODULE", None)
        environment["PYTHONPATH"] = ""
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with subprocess.Popen(  # noqa: S603 -- fixed interpreter, test-owned script and fixture IDs
            [sys.executable, "-c", PORTAL_ROUND_TRIP, str(self.customer.pk), str(self.user.pk), str(self.service.pk)],
            cwd=REPO_ROOT / "services/portal",
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as portal:
            assert portal.stdout is not None
            try:
                envelope = json.loads(portal.stdout.readline())
                headers = {
                    "HTTP_" + key.upper().replace("-", "_"): value
                    for key, value in envelope["headers"].items()
                    if key.startswith("X-")
                }
                path = f"/api/services/{self.service.pk}/domains/"
                response = self.client.generic(
                    envelope["method"],
                    path,
                    envelope["body"],
                    content_type=envelope["headers"]["Content-Type"],
                    **headers,
                )
                reply = {
                    "status": response.status_code,
                    "body": response.content.decode(),
                    "content_type": response.headers["Content-Type"],
                }
                output, errors = portal.communicate(json.dumps(reply) + "\n", timeout=15)
            finally:
                if portal.poll() is None:
                    portal.kill()
                    portal.communicate()

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(portal.returncode, 0, errors)
        self.assertEqual(envelope["url"], f"http://testserver{path}")
        payload = json.loads(envelope["body"])
        self.assertEqual(payload["customer_id"], self.customer.pk)
        self.assertEqual(payload["user_id"], self.user.pk)
        self.assertCountEqual(
            json.loads(output),
            response.json()["data"]["domains"],
        )
        self.assertCountEqual(
            [domain["name"] for domain in json.loads(output)],
            ["wp8-example.com", "blog.wp8-example.com"],
        )
