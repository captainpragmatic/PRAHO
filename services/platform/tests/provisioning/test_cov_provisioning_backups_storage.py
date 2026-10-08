"""Coverage additions for published backup storage and checksum-evidenced downloads."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import BinaryIO, cast
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Retriability, retriability_of
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import SpoolReservation
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class MemoryS3:
    """S3 transport fixture: consume actual upload bytes and write actual downloads."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.writes: list[dict[str, object]] = []
        self.download_bytes: bytes | None = None
        self.head_size: int | None = None
        self.failure: str | None = None
        self.exceptions = SimpleNamespace(NoSuchKey=FileNotFoundError)

    def get_paginator(self, operation: str) -> MemoryS3:
        if self.failure == "list":
            raise OSError("S3 listing unavailable")
        if operation != "list_objects_v2":
            raise AssertionError(operation)
        return self

    def paginate(self, **kwargs: object) -> Iterator[dict[str, object]]:
        keys = sorted(key for key in self.objects if key.startswith(str(kwargs["Prefix"])))
        yield {}
        for key in keys:
            yield {"Contents": [{"Key": key}]}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        if self.failure == "get":
            raise OSError("S3 metadata unavailable")
        if key not in self.objects:
            raise FileNotFoundError(key)
        return {"Body": io.BytesIO(self.objects[key])}

    def head_object(self, **kwargs: object) -> dict[str, int]:
        key = str(kwargs["Key"])
        if self.failure == "head":
            raise OSError("S3 archive unavailable")
        return {"ContentLength": self.head_size if self.head_size is not None else len(self.objects[key])}

    def download_file(self, bucket: str, key: str, filename: str) -> None:
        if self.failure == "download":
            raise OSError("S3 transfer interrupted")
        Path(filename).write_bytes(self.download_bytes if self.download_bytes is not None else self.objects[key])

    def put_object(self, **kwargs: object) -> dict[str, object]:
        if self.failure == "put":
            raise OSError("S3 upload refused")
        body = cast("str | BinaryIO", kwargs["Body"])
        data = body.encode() if isinstance(body, str) else body.read()
        self.objects[str(kwargs["Key"])] = data
        self.writes.append({key: value for key, value in kwargs.items() if key != "Body"})
        return {}

    def delete_objects(self, **kwargs: object) -> dict[str, object]:
        if self.failure == "delete":
            raise OSError("S3 deletion unavailable")
        removed = cast("dict[str, list[dict[str, str]]]", kwargs["Delete"])["Objects"]
        for item in removed:
            self.objects.pop(item["Key"], None)
        return {"Deleted": removed}

    def manifest(self, backup_id: str, metadata: dict[str, object], archive: bytes = b"archive") -> None:
        prefix = f"virtualmin-backups/{backup_id}/"
        self.objects[prefix + "metadata.json"] = json.dumps(metadata).encode()
        self.objects[prefix + "backup.tar.gz"] = archive


class BackupStorageCoverageTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.spool = Path(directory.name)
        self.spool.chmod(0o700)
        for key, value in (
            ("backup.s3_bucket_name", "coverage-backups"),
            ("provisioning.migration_spool_dir", str(self.spool)),
        ):
            result = SettingsService.update_setting(key, value)
            self.assertTrue(result.is_ok(), result)
        self.s3 = MemoryS3()
        self.backups = VirtualminBackupService(self.server)
        transport = patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.s3)
        transport.start()
        self.addCleanup(transport.stop)
        self.archive_name = "virtualmin_backup_" + "a" * 32 + ".tar.gz"

    def metadata(self, backup_id: str = "published") -> dict[str, object]:
        return {
            "backup_id": backup_id,
            "domain": self.account.domain,
            "praho_service_id": str(self.account.service_id),
            "backup_type": "full",
            "status": "completed",
            "created_at": timezone.now().isoformat(),
            "archive_name": self.archive_name,
            "checksum_sha256": hashlib.sha256(b"archive").hexdigest(),
        }

    def test_listing_filters_service_type_and_age_and_sorts_newest_first(self) -> None:
        old = self.metadata("old")
        old["created_at"] = (timezone.now() - timedelta(days=2)).isoformat()
        newer = self.metadata("new")
        foreign = {**self.metadata("foreign"), "praho_service_id": "another-service"}
        expired = {**self.metadata("expired"), "created_at": (timezone.now() - timedelta(days=91)).isoformat()}
        config = {**self.metadata("config"), "backup_type": "config_only"}
        unattributed = self.metadata("unattributed")
        del unattributed["praho_service_id"]
        for metadata in (old, newer, foreign, expired, config, unattributed):
            self.s3.manifest(str(metadata["backup_id"]), metadata)
        self.s3.objects["virtualmin-backups/broken/metadata.json"] = b"{bad json"
        result = self.backups.list_backups(self.account, backup_type="full")
        self.assertEqual([item["backup_id"] for item in result.unwrap()], ["new", "old"])
        unfiltered = self.backups.list_backups(max_age_days=1).unwrap()
        self.assertEqual({item["backup_id"] for item in unfiltered}, {"new", "foreign", "config", "unattributed"})

    def test_listing_storage_failure_returns_a_diagnostic(self) -> None:
        self.s3.failure = "list"
        result = self.backups.list_backups()
        self.assertEqual(result.unwrap_err(), "Failed to list backups: S3 listing unavailable")

    def test_deletion_removes_archive_and_manifest_and_reports_effect(self) -> None:
        self.s3.manifest("selected", self.metadata("selected"))
        self.s3.manifest("other", self.metadata("other"))
        result = self.backups.delete_backup("selected")
        self.assertEqual(result.unwrap()["deleted_objects"], 2)
        self.assertEqual(result.unwrap()["backup_id"], "selected")
        self.assertEqual(
            set(self.s3.objects),
            {"virtualmin-backups/other/metadata.json", "virtualmin-backups/other/backup.tar.gz"},
        )

    def test_missing_backup_and_storage_deletion_failure_return_errors(self) -> None:
        self.assertEqual(self.backups.delete_backup("missing").unwrap_err(), "Backup missing not found")
        self.s3.manifest("published", self.metadata())
        self.s3.failure = "delete"
        result = self.backups.delete_backup("published")
        self.assertIn("S3 deletion unavailable", result.unwrap_err())
        self.assertEqual(len(self.s3.objects), 2)

    def test_restore_refuses_missing_or_unverifiable_manifests(self) -> None:
        cases = (
            (None, "Backup metadata not found"),
            ({}, "lacks a checksum"),
            ({"checksum_sha256": "a" * 64}, "lacks an archive name"),
            ({"checksum_sha256": "a" * 64, "archive_name": "../../outside"}, "archive name is malformed"),
        )
        for metadata, diagnostic in cases:
            self.s3.objects.clear()
            if metadata is not None:
                self.s3.manifest("published", metadata)
            with self.subTest(diagnostic=diagnostic):
                result = self.backups._download_backup_to_spool("published")
            self.assertIn(diagnostic, result.unwrap_err())
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertFalse(SpoolReservation.objects.exists())
            self.assertEqual(list(self.spool.iterdir()), [])

    def test_downloaded_archive_keeps_reservation_and_matches_manifest(self) -> None:
        metadata = self.metadata()
        self.s3.manifest("published", metadata)
        result = self.backups._download_backup_to_spool("published")
        path, downloaded_metadata = result.unwrap()
        self.assertEqual(Path(path).read_bytes(), b"archive")
        self.assertEqual(downloaded_metadata, metadata)
        reservation = SpoolReservation.objects.get(archive_name=self.archive_name)
        self.assertEqual(reservation.expected_bytes, len(b"archive"))
        self.assertEqual(reservation.owner, f"restore:{self.archive_name}")

    def test_download_corruption_removes_bytes_and_releases_capacity(self) -> None:
        self.s3.manifest("published", self.metadata())
        for content, diagnostic in (
            (b"short", "Downloaded file size mismatch"),
            (b"corrupt", "Backup checksum verification failed"),
        ):
            self.s3.download_bytes = content
            with self.subTest(diagnostic=diagnostic):
                result = self.backups._download_backup_to_spool("published")
            self.assertIn(diagnostic, result.unwrap_err())
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertFalse((self.spool / self.archive_name).exists())
            self.assertFalse(SpoolReservation.objects.exists())

    def test_download_transport_errors_are_terminal_and_release_capacity(self) -> None:
        self.s3.manifest("published", self.metadata())
        for stage, diagnostic in (
            ("get", "S3 metadata unavailable"),
            ("head", "Backup file not found in S3"),
            ("download", "S3 transfer interrupted"),
        ):
            self.s3.failure = stage
            with self.subTest(stage=stage):
                result = self.backups._download_backup_to_spool("published")
            self.assertIn(diagnostic, result.unwrap_err())
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertFalse(SpoolReservation.objects.exists())

    def test_capacity_refusal_is_retriable_without_reserving_or_downloading(self) -> None:
        self.s3.manifest("published", self.metadata())
        self.s3.head_size = 2**100
        result = self.backups._download_backup_to_spool("published")
        self.assertIn("Transfer spool capacity is reserved", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        self.assertFalse(SpoolReservation.objects.exists())
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_insecure_spool_refuses_download_before_creating_files(self) -> None:
        self.s3.manifest("published", self.metadata())
        self.spool.chmod(0o755)
        result = self.backups._download_backup_to_spool("published")
        self.assertEqual(result.unwrap_err(), "Transfer spool must be a private directory")
        self.assertEqual(list(self.spool.iterdir()), [])
        self.assertFalse(SpoolReservation.objects.exists())

    def test_verification_requires_local_nonempty_bytes_and_transfer_evidence(self) -> None:
        path = self.spool / self.archive_name
        metadata: dict[str, object] = {"backup_location": "remote", "backup_path": str(path)}
        self.assertIn("has not been fetched", self.backups._verify_backup_integrity("verify", metadata).unwrap_err())
        metadata["backup_location"] = "spool"
        self.assertIn("Backup file not found", self.backups._verify_backup_integrity("verify", metadata).unwrap_err())
        path.write_bytes(b"")
        self.assertEqual(self.backups._verify_backup_integrity("verify", metadata).unwrap_err(), "Backup file is empty")
        path.write_bytes(b"invalid tar")
        self.assertIn("evidence missing", self.backups._verify_backup_integrity("verify", metadata).unwrap_err())
        metadata["checksum_sha256_remote"] = "0" * 64
        self.assertIn("checksum mismatch", self.backups._verify_backup_integrity("verify", metadata).unwrap_err())
        metadata["checksum_sha256_remote"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertIn("Invalid backup archive", self.backups._verify_backup_integrity("verify", metadata).unwrap_err())

    def test_directory_archive_path_returns_verification_error(self) -> None:
        (self.spool / "entry").write_bytes(b"entry")
        metadata: dict[str, object] = {"backup_location": "spool", "backup_path": str(self.spool)}
        result = self.backups._verify_backup_integrity("directory", metadata)
        self.assertIn("Backup verification failed:", result.unwrap_err())
        self.assertTrue(self.spool.is_dir())

    def test_empty_tar_archive_is_refused(self) -> None:
        path = self.spool / self.archive_name
        with tarfile.open(path, "w:gz"):
            pass
        metadata = {
            "backup_location": "spool",
            "backup_path": str(path),
            "checksum_sha256_remote": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        self.assertEqual(
            self.backups._verify_backup_integrity("empty-tar", metadata).unwrap_err(), "Backup archive is empty"
        )

    def test_verified_archive_is_published_encrypted_before_manifest_and_local_bytes_removed(self) -> None:
        path = self.spool / self.archive_name
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("virtualmin/config")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"data"))
        data = path.read_bytes()
        metadata = {
            **self.metadata(),
            "backup_location": "spool",
            "backup_path": str(path),
            "checksum_sha256_remote": hashlib.sha256(data).hexdigest(),
        }
        verified = self.backups._verify_backup_integrity("published", metadata)
        self.assertTrue(verified.is_ok(), verified)
        self.assertEqual(metadata["verification_status"], "passed")
        self.assertEqual(metadata["file_count"], 1)
        self.assertEqual(metadata["file_size_bytes"], len(data))
        uploaded = self.backups._upload_backup_to_s3("published", metadata)
        self.assertTrue(uploaded.is_ok(), uploaded)
        archive_key = "virtualmin-backups/published/backup.tar.gz"
        manifest_key = "virtualmin-backups/published/metadata.json"
        self.assertEqual(self.s3.objects[archive_key], data)
        self.assertEqual(json.loads(self.s3.objects[manifest_key]), metadata)
        self.assertEqual([item["Key"] for item in self.s3.writes], [archive_key, manifest_key])
        self.assertTrue(all(item["ServerSideEncryption"] == "AES256" for item in self.s3.writes))
        self.assertEqual(uploaded.unwrap()["s3_bucket"], "coverage-backups")
        self.assertFalse(path.exists())

    def test_upload_guards_and_failure_preserve_local_bytes(self) -> None:
        path = self.spool / self.archive_name
        metadata: dict[str, object] = {"backup_location": "remote", "backup_path": str(path)}
        self.assertIn("not in the controller spool", self.backups._upload_backup_to_s3("p", metadata).unwrap_err())
        metadata["backup_location"] = "spool"
        self.assertIn("not found for upload", self.backups._upload_backup_to_s3("p", metadata).unwrap_err())
        path.write_bytes(b"archive")
        self.s3.failure = "put"
        self.assertEqual(
            self.backups._upload_backup_to_s3("p", metadata).unwrap_err(), "S3 upload failed: S3 upload refused"
        )
        self.assertEqual(path.read_bytes(), b"archive")
        self.assertEqual(self.s3.objects, {})

    def test_spool_cleanup_removes_only_controller_staged_artifacts(self) -> None:
        path = self.spool / self.archive_name
        path.write_bytes(b"archive")
        metadata: dict[str, object] = {"backup_location": "remote", "backup_path": str(path)}
        self.backups._release_spool_artifacts(metadata)
        self.assertEqual(path.read_bytes(), b"archive")
        metadata["backup_location"] = "spool"
        self.backups._release_spool_artifacts(metadata)
        self.assertFalse(path.exists())
        metadata["backup_path"] = str(self.spool)
        with self.assertLogs("apps.provisioning.virtualmin_backup_service", level="WARNING") as logs:
            self.backups._release_spool_artifacts(metadata)
        self.assertTrue(self.spool.is_dir())
        self.assertIn("Spool cleanup failed", logs.output[0])

    def test_restore_authorization_refuses_foreign_service_and_domain_and_cleans_spool(self) -> None:
        for field, value, diagnostic in (
            ("praho_service_id", "foreign", "does not belong to this account"),
            ("domain", "foreign.example.test", "domain does not match"),
        ):
            self.s3.manifest("published", {**self.metadata(), field: value})
            with self.subTest(field=field):
                result = self.backups.restore_domain(self.account, RestoreConfig(backup_id="published"))
            self.assertIn(diagnostic, result.unwrap_err())
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertFalse((self.spool / self.archive_name).exists())
            self.assertFalse(SpoolReservation.objects.exists())
