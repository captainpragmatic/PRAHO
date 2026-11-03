"""Source administration is explicit, audited and never performs host I/O."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from django.test import Client, TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.security.models import SecuritySource
from apps.users.models import User


@override_settings(ENVIRONMENT="staging", PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED=True)
class SecuritySourceManagementViewTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(email="source-admin@example.test", staff_role="admin", is_staff=True)
        self.client.force_login(self.admin)

    def data(self) -> dict[str, str]:
        return {
            "kind": "portal", "transport": "local", "hostname": "localhost", "port": "0", "host_keys": "",
            "installation_id": str(uuid4()), "configuration_digest": "b" * 64,
            "sync_enabled": "on", "reason": "Enroll the independently qualified staging Portal installation",
        }

    def test_enroll_and_edit_source_locally_without_a_host_call(self) -> None:
        payload = self.data()
        with (
            patch("apps.common.crowdsec_transport.local_rpc", side_effect=AssertionError("RPC inside staff request")),
            patch("apps.common.crowdsec_transport.remote_rpc", side_effect=AssertionError("RPC inside staff request")),
        ):
            response = self.client.post("/security/sources/new/", payload)
            self.assertEqual(response.status_code, 302)
            source = SecuritySource.objects.get()
            self.assertEqual(source.hostname, "localhost")
            payload.update(generation="1", sync_enabled="", reason="Suspend synchronization during host maintenance")
            response = self.client.post(f"/security/sources/{source.pk}/", payload)
            self.assertEqual(response.status_code, 302)
        source.refresh_from_db()
        self.assertFalse(source.sync_enabled)
        self.assertEqual(source.generation, 2)
        self.assertTrue(AuditEvent.objects.filter(metadata__security_operation="enroll").exists())
        self.assertTrue(AuditEvent.objects.filter(metadata__reason=payload["reason"]).exists())

    def test_support_manager_billing_cannot_manage_sources(self) -> None:
        for role in ("support", "manager", "billing"):
            with self.subTest(role=role):
                user = User.objects.create_user(email=f"source-{role}@example.test", staff_role=role, is_staff=True)
                self.client.force_login(user)
                self.assertEqual(self.client.get("/security/sources/new/").status_code, 403)
                self.assertEqual(self.client.post("/security/sources/new/", self.data()).status_code, 403)
        self.assertFalse(SecuritySource.objects.exists())

    def test_stale_edit_cannot_overwrite_current_configuration(self) -> None:
        payload = self.data()
        self.assertEqual(self.client.post("/security/sources/new/", payload).status_code, 302)
        source = SecuritySource.objects.get()
        payload.update(generation="1", configuration_digest="c" * 64)
        self.assertEqual(self.client.post(f"/security/sources/{source.pk}/", payload).status_code, 302)
        payload["configuration_digest"] = "d" * 64
        self.assertEqual(self.client.post(f"/security/sources/{source.pk}/", payload).status_code, 400)
        source.refresh_from_db()
        self.assertEqual(source.configuration_digest, "c" * 64)

    def test_retirement_is_post_only_csrf_protected_and_keeps_history(self) -> None:
        self.assertEqual(self.client.post("/security/sources/new/", self.data()).status_code, 302)
        source = SecuritySource.objects.get()
        url = f"/security/sources/{source.pk}/retire/"
        self.assertEqual(self.client.get(url).status_code, 405)
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post(url, {"generation": "1", "reason": "Replace physical installation"}).status_code, 403)
        response = self.client.post(url, {"generation": "1", "reason": "Replace physical installation"})
        self.assertEqual(response.status_code, 302)
        source.refresh_from_db()
        self.assertIsNotNone(source.retired_at)
        self.assertFalse(source.sync_enabled)

    def test_invalid_enrollment_and_missing_reason_create_nothing(self) -> None:
        payload = self.data()
        payload["reason"] = ""
        self.assertEqual(self.client.post("/security/sources/new/", payload).status_code, 400)
        payload.update(reason="Review local enrollment", hostname="untrusted.example.test")
        self.assertEqual(self.client.post("/security/sources/new/", payload).status_code, 400)
        self.assertFalse(SecuritySource.objects.exists())
