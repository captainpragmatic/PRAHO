"""#295: the server webhook health check could never report healthy.

The view read Server.has_valid_api_config — an attribute that does not exist — so every
request died in the broad except and returned a generic 500. These tests fail on master
with that behavior and pin the resurrected endpoint's semantics: HTTP 200 means the
endpoint is alive; the top-level status reflects configuration completeness, so a monitor
keyed on it cannot read an unconfigured server as healthy.
"""

import json

from django.test import RequestFactory, TestCase

from apps.provisioning.models import Server
from apps.provisioning.webhooks import server_webhook_health_check


class ServerWebhookHealthCheckTests(TestCase):
    """Top-level status derives from configuration completeness."""

    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _server(self, n: int, **overrides) -> Server:
        defaults = {
            "name": f"Health Server {n}",
            "hostname": f"health{n}.test.ro",
            "primary_ip": f"10.0.1.{n}",
            "server_type": "shared",
            "status": "active",
            "is_active": True,
            "location": "Bucharest",
            "datacenter": "M247",
            "cpu_model": "Xeon E5",
            "cpu_cores": 8,
            "ram_gb": 32,
            "disk_type": "ssd",
            "disk_capacity_gb": 500,
            "os_type": "linux",
            "management_api_url": "https://health.test.ro:10000/api",
            "management_webhook_secret": "s3cret-value",
        }
        defaults.update(overrides)
        return Server.objects.create(**defaults)

    def _get(self, server: Server) -> dict:
        request = self.factory.get(f"/webhooks/server/{server.id}/health/")
        response = server_webhook_health_check(request, str(server.id))
        self.assertEqual(response.status_code, 200)
        return json.loads(response.content)

    def test_fully_configured_server_reports_healthy(self) -> None:
        payload = self._get(self._server(1))

        self.assertEqual(payload["status"], "healthy")
        self.assertTrue(payload["has_valid_api_config"])
        self.assertTrue(payload["api_endpoint_configured"])
        self.assertTrue(payload["webhook_secret_configured"])

    def test_missing_webhook_secret_reports_degraded(self) -> None:
        payload = self._get(self._server(2, management_webhook_secret=""))

        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["has_valid_api_config"])
        self.assertFalse(payload["webhook_secret_configured"])

    def test_missing_api_url_reports_degraded(self) -> None:
        payload = self._get(self._server(3, management_api_url=""))

        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["has_valid_api_config"])
        self.assertFalse(payload["api_endpoint_configured"])
