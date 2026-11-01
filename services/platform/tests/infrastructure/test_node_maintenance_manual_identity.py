"""Real server edits preserve the transport target owned by current maintenance."""

import secrets
from datetime import timedelta

from django.test import Client
from django.urls import reverse
from django.utils import timezone

from apps.infrastructure.node_maintenance_execution import claim_direct_operation
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.users.models import User
from tests.api.test_node_maintenance_api import _MaintenanceAPIFixture
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class ManualMaintenanceIdentityTests(_MaintenanceAPIFixture):
    def setUp(self) -> None:
        super().setUp()
        staff = User.objects.create_superuser(email="manual-target-operator@example.test", password=None)
        self.staff_client = Client()
        self.staff_client.force_login(staff)
        self.node.api_username = "root"
        self.node.save(update_fields=["api_username"])
        self.window_id = self._schedule(
            self.node,
            "Manual target maintenance",
            starts_at=timezone.now() - timedelta(seconds=30),
        )
        self.edit_url = reverse("provisioning:virtualmin_server_edit", args=[self.node.pk])

    def payload(self, **changes: object) -> dict[str, object]:
        return {
            "name": self.node.name,
            "hostname": self.node.hostname,
            "ipv4_address": self.node.ipv4_address or "",
            "ipv6_address": self.node.ipv6_address or "",
            "api_port": str(self.node.api_port),
            "api_username": self.node.api_username,
            "use_ssl": "on" if self.node.use_ssl else "",
            "ssl_verify": "on" if self.node.ssl_verify else "",
            "ssl_cert_fingerprint": self.node.ssl_cert_fingerprint,
            "status": self.node.status,
            "max_domains": str(self.node.max_domains),
            "max_disk_gb": str(self.node.max_disk_gb) if self.node.max_disk_gb is not None else "",
            "max_bandwidth_gb": str(self.node.max_bandwidth_gb) if self.node.max_bandwidth_gb is not None else "",
            **changes,
        }

    def test_public_edit_cannot_retarget_live_manual_work(self) -> None:
        self._action(self.window_id, "start")
        original = self.node.hostname

        response = self.staff_client.post(self.edit_url, self.payload(hostname="replacement.example.com"))

        self.node.refresh_from_db()
        self.assertEqual(self.node.hostname, original)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maintenance")
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=self.window_id).status, "running")

    def test_every_public_transport_field_is_preserved_during_manual_work(self) -> None:
        self._action(self.window_id, "start")
        changes = (
            {"ipv4_address": "8.8.8.8"},
            {"ipv6_address": "2606:4700:4700::1111"},
            {"api_port": "10001"},
            {"api_username": "praho_other"},
            {"ssl_verify": "", "ssl_cert_fingerprint": "ab" * 32},
            {"ssl_cert_fingerprint": "cd" * 32},
            {"api_password": secrets.token_urlsafe(24) + "aA1!"},
        )
        original = self.payload()
        original_password = self.node.get_api_password()
        for edited in changes:
            with self.subTest(fields=tuple(edited)):
                response = self.staff_client.post(self.edit_url, self.payload(**edited))
                self.node.refresh_from_db()
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "Maintenance")
                self.assertEqual(self.payload(), original)
                self.assertTrue(self.node.get_api_password() == original_password, "The stored credential changed")

    def test_cosmetic_and_capacity_edits_remain_available(self) -> None:
        self._action(self.window_id, "start")
        capacity = self.node.max_domains + 10

        response = self.staff_client.post(
            self.edit_url,
            self.payload(name="Clearer display name", max_domains=str(capacity)),
        )

        self.assertEqual(
            response.status_code,
            302,
            response.context["form"].errors if response.status_code == 200 else response.content,
        )
        self.node.refresh_from_db()
        self.assertEqual((self.node.name, self.node.max_domains), ("Clearer display name", capacity))
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=self.window_id).status, "running")

    def test_an_unwindowed_native_claim_also_protects_its_server_target(self) -> None:
        deployment = _create_deployment("completed", external_node_id="manual-target-native-fixture")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        claimed = claim_direct_operation(deployment, "reboot")
        self.assertTrue(claimed.is_ok(), claimed)
        original = self.node.hostname

        response = self.staff_client.post(self.edit_url, self.payload(hostname="replacement.example.com"))

        self.node.refresh_from_db()
        self.assertEqual(self.node.hostname, original)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maintenance")

    def test_unclaimed_schedule_does_not_freeze_the_server(self) -> None:
        response = self.staff_client.post(self.edit_url, self.payload(hostname="replacement.example.com"))

        self.assertEqual(
            response.status_code,
            302,
            response.context["form"].errors if response.status_code == 200 else response.content,
        )
        self.node.refresh_from_db()
        self.assertEqual(self.node.hostname, "replacement.example.com")
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=self.window_id).status, "scheduled")

    def test_existing_staff_edit_permission_does_not_bypass_current_ownership(self) -> None:
        self._action(self.window_id, "start")
        staff = User.objects.create_user(
            email="manual-target-support@example.test",
            password=None,
            is_staff=True,
            staff_role="support",
        )
        self.staff_client.force_login(staff)
        original = self.node.hostname

        response = self.staff_client.post(self.edit_url, self.payload(hostname="replacement.example.com"))

        self.assertEqual(response.status_code, 200)
        self.node.refresh_from_db()
        self.assertEqual(self.node.hostname, original)

    def test_customer_cannot_edit_a_server(self) -> None:
        self.staff_client.force_login(self.user)
        original = self.node.hostname

        response = self.staff_client.post(self.edit_url, self.payload(hostname="replacement.example.com"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login/", response.url)
        self.node.refresh_from_db()
        self.assertEqual(self.node.hostname, original)
