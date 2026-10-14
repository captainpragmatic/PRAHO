"""backup.s3_endpoint_url: S3-compatible storage (MinIO, Ceph RGW) for backup archives."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.settings.services import SettingsService


class S3EndpointSettingTests(TestCase):
    def setUp(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("backup.aws_access_key_id", "AKIALAB"), Ok)
        self.assertIsInstance(SettingsService.update_setting("backup.aws_secret_access_key", "lab-secret"), Ok)
        self.assertIsInstance(SettingsService.update_setting("backup.aws_region", "eu-central-1"), Ok)

    def _client_kwargs(self) -> dict[str, Any]:
        service = VirtualminBackupService(MagicMock())
        boto3_module = MagicMock()
        with patch("apps.provisioning.virtualmin_backup_service.boto3", boto3_module):
            service._get_s3_client()
        boto3_module.client.assert_called_once()
        args, kwargs = boto3_module.client.call_args
        self.assertEqual(args, ("s3",))
        return dict(kwargs)

    def test_endpoint_url_passed_to_the_client_when_set(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("backup.s3_endpoint_url", "http://minio.lab:9000"), Ok)

        kwargs = self._client_kwargs()

        self.assertEqual(kwargs["endpoint_url"], "http://minio.lab:9000")
        self.assertEqual(kwargs["aws_access_key_id"], "AKIALAB")
        self.assertEqual(kwargs["aws_secret_access_key"], "lab-secret")
        self.assertEqual(kwargs["region_name"], "eu-central-1")
        # Custom endpoints are addressed path-style: a virtual-hosted bucket
        # name ("bucket.minio.lab") does not resolve for self-hosted storage.
        self.assertEqual(kwargs["config"].s3["addressing_style"], "path")

    def test_default_is_aws_without_endpoint_override(self) -> None:
        kwargs = self._client_kwargs()

        self.assertNotIn("endpoint_url", kwargs)
        self.assertNotIn("config", kwargs)
        self.assertEqual(kwargs["region_name"], "eu-central-1")

    def test_blank_endpoint_is_treated_as_aws(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("backup.s3_endpoint_url", "   "), Ok)

        kwargs = self._client_kwargs()

        self.assertNotIn("endpoint_url", kwargs)
