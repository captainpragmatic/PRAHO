"""The Portal service page shows no node IP, hostname or server status (ADR-0061 P0.9)."""

import time
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

NODE_IP = "203.0.113.77"
NODE_HOSTNAME = "node-secret-7.hosting.example.net"


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"],
)
class ServiceDetailNodeDetailsTests(SimpleTestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update({
            "customer_id": 42, "user_id": 7,
            "user_memberships": [{"customer_id": 42, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def _page(self, service: dict) -> str:
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {}
            api.get_service_domains.return_value = []
            response = self.client.get(reverse("services:detail", kwargs={"service_id": 5}))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_page_renders_no_node_details_even_if_a_payload_carried_them(self) -> None:
        page = self._page({
            "id": 5, "status": "active", "service_name": "Hosting", "domain": "site.example.com",
            "server": {"name": "node-secret-7", "hostname": NODE_HOSTNAME, "primary_ip": NODE_IP, "status": "online"},
            "server_ip": NODE_IP, "server_name": "node-secret-7",
        })
        self.assertIn("site.example.com", page)
        for leaked in (NODE_IP, NODE_HOSTNAME, "node-secret-7"):
            self.assertNotIn(leaked, page)
        self.assertNotIn("Server IP", page)
        self.assertNotIn("Assigned Server", page)

    def test_a_service_with_no_hosting_data_at_all_renders(self) -> None:
        page = self._page({"id": 5, "status": "pending", "service_name": "Hosting"})
        self.assertIn("Hosting", page)
        self.assertNotIn("Pending assignment", page)
