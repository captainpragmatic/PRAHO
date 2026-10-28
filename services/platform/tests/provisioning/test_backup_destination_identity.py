"""Backup proof must describe the exact storage client and bucket used for its upload."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService, backup_storage_configuration
from apps.provisioning.virtualmin_models import VirtualminServer


class BackupDestinationTests(SimpleTestCase):
    def test_a_b_a_during_client_construction_uses_the_captured_snapshot(self) -> None:
        expected = backup_storage_configuration().identity
        captured = {}

        def factory(_service, **kwargs):
            original = self.values["backup.s3_endpoint_url"]
            self.values["backup.s3_endpoint_url"] = "https://intermediate.storage.test"
            captured.update(kwargs)
            self.values["backup.s3_endpoint_url"] = original
            return self.client

        with patch("apps.provisioning.virtualmin_backup_service.boto3.client", side_effect=factory):
            result = self.service._upload_backup_to_s3("aba-proof", {"backup_location": "spool", "backup_path": str(self.archive)})
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(captured["endpoint_url"], "https://new.storage.test")
        self.assertEqual(result.unwrap()["storage_identity"], expected)

    def setUp(self) -> None:
        self.values = {"backup.aws_access_key_id": "fixture-access", "backup.aws_secret_access_key": "fixture-secret",
                       "backup.s3_bucket_name": "new-backups", "backup.s3_endpoint_url": "https://new.storage.test", "backup.aws_region": "eu-west-1"}
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.archive = Path(self.directory.name) / "archive.tar.gz"
        self.archive.write_bytes(b"archive")
        self.service = VirtualminBackupService(VirtualminServer())
        self.client = Mock()
        self.setting = patch("apps.provisioning.virtualmin_backup_service.SettingsService.get_setting", side_effect=lambda key, default=None: self.values.get(key, default))
        self.setting.start()
        self.addCleanup(self.setting.stop)

    def test_prewarmed_client_cannot_certify_a_new_destination(self) -> None:
        old = Mock()
        self.service._s3_client = old
        self.service._backup_bucket = "old-backups"
        with patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.client) as factory:
            result = self.service._upload_backup_to_s3("destination-proof", {"backup_location": "spool", "backup_path": str(self.archive)})
        self.assertTrue(result.is_ok(), result)
        factory.assert_called_once()
        self.assertEqual(factory.call_args.kwargs["endpoint_url"], "https://new.storage.test")
        self.assertEqual(self.client.put_object.call_args.kwargs["Bucket"], "new-backups")
        old.put_object.assert_not_called()
        self.assertRegex(result.unwrap()["storage_identity"], r"^[a-f0-9]{64}$")

    def test_destination_change_during_upload_retains_spool_without_metadata_commit(self) -> None:
        def upload(**kwargs):
            if str(kwargs["Key"]).endswith("backup.tar.gz"):
                self.values["backup.s3_endpoint_url"] = "https://changed.storage.test"

        self.client.put_object.side_effect = upload
        with patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.client):
            result = self.service._upload_backup_to_s3("changed-proof", {"backup_location": "spool", "backup_path": str(self.archive)})
        self.assertTrue(result.is_err())
        self.assertTrue(self.archive.exists())
        self.assertEqual(self.client.put_object.call_count, 1)
