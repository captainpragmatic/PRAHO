"""Coverage additions for Virtualmin server pages through the real URL configuration."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Protocol, cast
from unittest.mock import patch
from uuid import uuid4

from django.contrib.messages import get_messages
from django.http import HttpRequest, HttpResponse
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from requests import Response

from apps.provisioning.virtualmin_models import VirtualminServer
from tests.factories.core_factories import create_admin_user, create_staff_user, create_user
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class ClientResponse(Protocol):
    wsgi_request: HttpRequest


@override_settings(LANGUAGE_CODE="en")
class VirtualminViewsFixture(VirtualminTaskTestBase):
    """Reuse the neighbouring customer, service, server and account fixture."""

    def setUp(self) -> None:
        super().setUp()
        self.admin = create_admin_user("coverage-admin")
        self.client.force_login(self.admin)
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        self.http_status = 200
        self.payload: dict[str, object] = {"status": "success"}
        self.requests: list[dict[str, object]] = []
        transport = patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=self.respond,
        )
        transport.start()
        self.addCleanup(transport.stop)

    def respond(self, method: str, url: str, **kwargs: object) -> Response:
        params = dict(cast("dict[str, object]", kwargs["params"]))
        self.requests.append({"url": url, "auth": kwargs.get("auth"), **params})
        response = Response()
        response.status_code = self.http_status
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(self.payload).encode()
        response._content_consumed = True
        return response

    def messages(self, response: HttpResponse) -> str:
        return " ".join(str(message) for message in get_messages(cast("ClientResponse", response).wsgi_request))

    def server_data(self) -> dict[str, str]:
        return {
            "name": "Coverage node",
            "hostname": "coverage-node.example.com",
            "api_port": "10000",
            "api_username": "praho_api",
            "api_password": "Coverage-Password-934!",
            "use_ssl": "on",
            "ssl_verify": "on",
            "status": "active",
            "max_domains": "150",
            "max_disk_gb": "200",
            "max_bandwidth_gb": "500",
        }


class VirtualminServerPageCoverageTests(VirtualminViewsFixture):
    def test_server_list_reports_capacity_and_actions(self) -> None:
        VirtualminServer.objects.create(
            name="Offline node", hostname="offline.example.com", status="disabled", current_domains=7
        )
        response = self.client.get(reverse("provisioning:virtualmin_servers"))
        self.assertContains(response, self.server.name)
        self.assertContains(response, "Offline node")
        self.assertEqual(response.context["total_domains"], 17)
        self.assertEqual(response.context["active_servers"], 1)
        row = next(row for row in response.context["table_data"] if row["id"] == self.server.pk)
        self.assertEqual(row["capacity"], "10/1000")
        self.assertEqual(row["status"]["variant"], "success")
        self.assertEqual(
            row["actions"][1]["url"],
            reverse("provisioning:virtualmin_server_edit", args=[self.server.pk]),
        )

    def test_server_detail_distinguishes_tracked_and_remote_domains(self) -> None:
        self.payload["domains"] = [
            {"domain": self.account.domain, "username": self.account.virtualmin_username},
            {"domain": "remote.example.com", "username": "remoteuser", "description": "Remote tenant"},
        ]
        response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]))
        self.assertContains(response, "remote.example.com")
        self.assertEqual([row["is_tracked_in_praho"] for row in response.context["actual_domains"]], [True, False])
        self.assertIsNone(response.context["domains_error"])

    def test_server_detail_displays_gateway_failure(self) -> None:
        self.http_status = 403
        response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]))
        self.assertContains(response, "Access forbidden")
        self.assertEqual(response.context["actual_domains"], [])
        self.assertIn("Access forbidden", response.context["domains_error"])

    def test_inactive_server_detail_does_not_list_remote_domains(self) -> None:
        self.server.status = "maintenance"
        self.server.save(update_fields=["status"])
        response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]))
        self.assertContains(response, self.server.hostname)
        self.assertEqual(response.context["actual_domains"], [])
        self.assertIsNone(response.context["domains_error"])
        self.assertEqual(self.requests, [])

    def test_detail_explains_each_health_state(self) -> None:
        for status, age, error, expected in (
            ("disabled", None, "", "Health check has never been performed"),
            ("active", 60, "", "Server is healthy and responding"),
            ("disabled", 7200, "", "Health check is stale"),
            ("disabled", 60, "probe failed", "Server is not responding to health checks"),
        ):
            with self.subTest(expected=expected):
                self.server.status = status
                self.server.last_health_check = None if age is None else timezone.now() - timedelta(seconds=age)
                self.server.health_check_error = error
                self.server.save()
                response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]))
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected, response.context["health_status"]["status_message"])

    def test_server_forms_render_initial_values(self) -> None:
        for name, args in (
            ("virtualmin_server_create", []),
            ("virtualmin_server_edit", [self.server.pk]),
        ):
            with self.subTest(name=name):
                response = self.client.get(reverse(f"provisioning:{name}", args=args))
                self.assertContains(response, 'name="hostname"')
                self.assertEqual(response.context["form_action"], reverse(f"provisioning:{name}", args=args))
        self.assertEqual(response.context["form"].initial["hostname"], self.server.hostname)

    def test_create_persists_encrypted_credentials_and_capacity(self) -> None:
        data = self.server_data()
        response = self.client.post(reverse("provisioning:virtualmin_server_create"), data)
        self.assertEqual(response.status_code, 302, str(response.context["form"].errors) if response.context else "")
        server = VirtualminServer.objects.get(hostname=data["hostname"])
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_server_detail", args=[server.pk]),
            fetch_redirect_response=False,
        )
        self.assertEqual(server.get_api_password(), data["api_password"])
        self.assertEqual(server.max_domains, 150)
        self.assertEqual(server.max_disk_gb, 200)
        self.assertIn("created successfully", self.messages(response))

    def test_invalid_create_renders_errors_without_a_row(self) -> None:
        data = self.server_data()
        data["hostname"] = "bad host!"
        response = self.client.post(reverse("provisioning:virtualmin_server_create"), data)
        self.assertContains(response, "Invalid hostname")
        self.assertIn("hostname", response.context["form"].errors)
        self.assertFalse(VirtualminServer.objects.filter(name=data["name"]).exists())

    def test_edit_preserves_password_when_blank(self) -> None:
        data = self.server_data()
        data.update(hostname=self.server.hostname, api_password="", name="Renamed node")
        response = self.client.post(reverse("provisioning:virtualmin_server_edit", args=[self.server.pk]), data)
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]),
            fetch_redirect_response=False,
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.name, "Renamed node")
        self.assertEqual(self.server.get_api_password(), "test_password")
        self.assertEqual(self.server.max_domains, 150)

    def test_invalid_edit_keeps_the_stored_configuration(self) -> None:
        data = self.server_data()
        data["api_port"] = "invalid-port"
        response = self.client.post(reverse("provisioning:virtualmin_server_edit", args=[self.server.pk]), data)
        self.assertContains(response, "Enter a whole number")
        self.server.refresh_from_db()
        self.assertEqual(self.server.name, "vm-test-1")
        self.assertEqual(self.server.api_port, 10000)

    def test_connection_requires_credentials_and_post(self) -> None:
        url = reverse("provisioning:virtualmin_server_test_connection")
        response = self.client.post(url, {"hostname": self.server.hostname})
        self.assertContains(response, "Please fill in all required fields")
        self.assertEqual(self.requests, [])
        self.assertEqual(self.client.get(url).status_code, 405)

    def test_connection_uses_operator_credentials_without_persisting_a_server(self) -> None:
        data = self.server_data()
        response = self.client.post(reverse("provisioning:virtualmin_server_test_connection"), data)
        self.assertContains(response, "Connection Successful")
        self.assertContains(response, data["hostname"])
        self.assertEqual(self.requests[0]["auth"], ("praho_api", data["api_password"]))
        self.assertEqual(self.requests[0]["program"], "info")
        self.assertFalse(VirtualminServer.objects.filter(hostname=data["hostname"]).exists())

    def test_connection_renders_transport_denial(self) -> None:
        self.http_status = 403
        response = self.client.post(reverse("provisioning:virtualmin_server_test_connection"), self.server_data())
        self.assertContains(response, "Connection Failed")
        self.assertContains(response, "Access forbidden")
        self.assertNotContains(response, self.server_data()["api_password"])

    def test_health_check_persists_success_and_returns_htmx_card(self) -> None:
        response = self.client.post(
            reverse("provisioning:virtualmin_server_health", args=[self.server.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertContains(response, "Server is healthy")
        self.server.refresh_from_db()
        self.assertIsNotNone(self.server.last_health_check)
        self.assertEqual(self.server.consecutive_health_failures, 0)
        self.assertEqual(self.server.health_check_error, "")

    def test_failed_health_check_records_error_without_success_timestamp(self) -> None:
        self.http_status = 403
        response = self.client.post(reverse("provisioning:virtualmin_server_health", args=[self.server.pk]))
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]),
            fetch_redirect_response=False,
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.consecutive_health_failures, 1)
        self.assertIsNone(self.server.last_health_check)
        self.assertIn("Access forbidden", self.server.health_check_error)
        self.assertIn("Health check failed", self.messages(response))

    def test_missing_servers_return_404(self) -> None:
        for name, method in (
            ("virtualmin_server_detail", "get"),
            ("virtualmin_server_edit", "get"),
            ("virtualmin_server_health", "post"),
        ):
            with self.subTest(name=name):
                response = getattr(self.client, method)(reverse(f"provisioning:{name}", args=[uuid4()]))
                self.assertEqual(response.status_code, 404)
        self.assertEqual(VirtualminServer.objects.count(), 1)

    def test_customer_cannot_read_or_create_servers(self) -> None:
        self.client.force_login(create_user())
        response = self.client.post(reverse("provisioning:virtualmin_server_create"), self.server_data())
        self.assertEqual(response.status_code, 302)
        self.assertIn("next=", response["Location"])
        self.assertFalse(VirtualminServer.objects.filter(name="Coverage node").exists())
        response = self.client.get(reverse("provisioning:virtualmin_servers"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("next=", response["Location"])

    def test_support_staff_can_read_server_list(self) -> None:
        self.client.force_login(create_staff_user("coverage-support"))
        self.assertContains(self.client.get(reverse("provisioning:virtualmin_servers")), self.server.name)
