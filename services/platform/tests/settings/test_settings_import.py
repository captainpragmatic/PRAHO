"""
Tests for Settings Import endpoint.

Validates JSON body import, multipart file upload, sensitive setting filtering,
unknown key rejection, admin-only access, size limits, and security event logging.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from apps.settings.models import SettingCategory, SystemSetting

User = get_user_model()


class SettingsImportTests(TestCase):
    """Tests for the import_settings view."""

    def setUp(self) -> None:
        self.client = Client()
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
            is_staff=False,
        )
        self.url = reverse("settings:import_settings")

        # Create a known setting in the DB so we can test importing against it
        self.category = SettingCategory.objects.create(key="billing", name="Billing")
        SystemSetting.objects.create(
            key="billing.proforma_validity_days",
            name="Proforma Validity Days",
            description="Days until proforma expires",
            data_type="integer",
            value=30,
            default_value=30,
            category="billing",
        )

    def _make_payload(self, settings_list: list[dict]) -> str:
        return json.dumps({"settings": settings_list})

    def test_import_settings_json_body(self) -> None:
        """POST valid JSON body should update settings."""
        self.client.force_login(self.admin_user)
        payload = self._make_payload(
            [
                {"key": "billing.proforma_validity_days", "value": 45},
            ]
        )

        response = self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["imported"], 1)

    def test_import_settings_file_upload(self) -> None:
        """POST multipart file upload should update settings."""
        self.client.force_login(self.admin_user)
        payload = self._make_payload(
            [
                {"key": "billing.proforma_validity_days", "value": 60},
            ]
        )
        uploaded = SimpleUploadedFile(
            "settings.json",
            payload.encode("utf-8"),
            content_type="application/json",
        )

        response = self.client.post(self.url, data={"file": uploaded})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["imported"], 1)

    def test_import_rejects_sensitive_without_flag(self) -> None:
        """Sensitive settings should be skipped by default."""
        self.client.force_login(self.admin_user)
        # Mark the setting as sensitive
        SystemSetting.objects.filter(key="billing.proforma_validity_days").update(is_sensitive=True)

        payload = self._make_payload(
            [
                {"key": "billing.proforma_validity_days", "value": 99},
            ]
        )

        response = self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["skipped"]), 1)
        self.assertIn("sensitive", data["skipped"][0]["reason"])

    def test_import_allows_sensitive_with_flag(self) -> None:
        """Sensitive settings should be imported when ?include_sensitive=true."""
        self.client.force_login(self.admin_user)
        SystemSetting.objects.filter(key="billing.proforma_validity_days").update(is_sensitive=True)

        payload = self._make_payload(
            [
                {"key": "billing.proforma_validity_days", "value": 99},
            ]
        )

        response = self.client.post(
            f"{self.url}?include_sensitive=true",
            data=payload,
            content_type="application/json",
        )

        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["imported"], 1)
        self.assertEqual(len(data["skipped"]), 0)

    def test_import_rejects_unknown_keys(self) -> None:
        """Unknown setting keys should be skipped."""
        self.client.force_login(self.admin_user)
        payload = self._make_payload(
            [
                {"key": "nonexistent.category_key", "value": "anything"},
            ]
        )

        response = self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["skipped"]), 1)
        self.assertIn("unknown", data["skipped"][0]["reason"])

    def test_import_requires_admin(self) -> None:
        """Non-admin user should get 403."""
        self.client.force_login(self.regular_user)
        payload = self._make_payload([{"key": "billing.proforma_validity_days", "value": 45}])

        response = self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_import_rejects_oversized_payload(self) -> None:
        """Payload larger than 1MB should be rejected with 400."""
        self.client.force_login(self.admin_user)
        # Create a payload just over 1MB
        large_value = "x" * (1024 * 1024)
        payload = self._make_payload([{"key": "billing.proforma_validity_days", "value": large_value}])

        response = self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("too large", data["error"])

    @patch("apps.settings.views.log_security_event")
    def test_import_logs_security_event(self, mock_log: object) -> None:
        """Import should log a security event."""
        self.client.force_login(self.admin_user)
        payload = self._make_payload(
            [
                {"key": "billing.proforma_validity_days", "value": 45},
            ]
        )

        self.client.post(
            self.url,
            data=payload,
            content_type="application/json",
        )

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args
        self.assertEqual(call_kwargs.kwargs["event_type"], "settings_imported")

    def test_import_rejects_invalid_json(self) -> None:
        """Invalid JSON should return 400."""
        self.client.force_login(self.admin_user)

        response = self.client.post(
            self.url,
            data="not valid json{{{",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("Invalid JSON", data["error"])

    def test_import_rejects_missing_settings_key(self) -> None:
        """Payload without 'settings' key should return 400."""
        self.client.force_login(self.admin_user)

        response = self.client.post(
            self.url,
            data=json.dumps({"data": []}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("settings", data["error"].lower())
