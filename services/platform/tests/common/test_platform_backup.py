"""Offsite evidence must establish a complete pair, not merely a successful upload call."""

import hashlib
import io
import json
from typing import cast
from unittest.mock import Mock
from uuid import uuid4

from botocore.client import BaseClient
from botocore.exceptions import ClientError
from django.test import SimpleTestCase

from apps.common.platform_backup import MAX_PARTS, TRANSFER_CHUNK, BackupArtifact, PlatformBackupPublisher


class PlatformBackupPublisherTests(SimpleTestCase):
    def test_conditional_retry_preserves_existing_artifact_and_manifest(self) -> None:
        bodies = (b"database", b"media")
        artifacts = [self.artifact(role, body) for role, body in zip(("database", "media"), bodies, strict=True)]
        for artifact, body in zip(artifacts, bodies, strict=True):
            self.publisher.upload(self.run, artifact, io.BytesIO(body))
        self.publisher.publish(self.run, artifacts)
        before = dict(self.objects)
        with self.assertRaises(ClientError):
            self.publisher.upload(self.run, artifacts[0], io.BytesIO(bodies[0]))
        with self.assertRaises(ClientError):
            self.publisher.publish(self.run, artifacts)
        self.assertEqual(self.objects, before)
        self.assertFalse(self.uploads)

    def test_short_reads_form_full_sized_parts_and_invalid_digest_never_completes(self) -> None:
        class ShortStream(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 33333))

        body = b"x" * (TRANSFER_CHUNK + 17)
        self.publisher.upload(self.run, self.artifact("database", body), ShortStream(body))
        self.assertEqual([len(call.kwargs["Body"]) for call in self.client.upload_part.call_args_list], [TRANSFER_CHUNK, 17])
        self.assertEqual(next(iter(self.objects.values())), body)
        self.client.complete_multipart_upload.reset_mock()
        with self.assertRaises(ValueError):
            self.publisher.upload(uuid4(), self.artifact("media", b"expected"), io.BytesIO(b"corrupt!"))
        self.client.complete_multipart_upload.assert_not_called()
        self.assertFalse(self.uploads)

    def test_capacity_is_rejected_before_starting_a_remote_upload(self) -> None:
        artifact = BackupArtifact("database", TRANSFER_CHUNK * MAX_PARTS + 1, "a" * 64)
        with self.assertRaises(ValueError):
            self.publisher.upload(self.run, artifact, io.BytesIO())
        self.client.create_multipart_upload.assert_not_called()

    def test_final_configuration_refusal_cannot_publish_a_manifest(self) -> None:
        artifacts = [self.artifact("database", b"database"), self.artifact("media", b"media")]
        for artifact, body in zip(artifacts, (b"database", b"media"), strict=True):
            self.publisher.upload(self.run, artifact, io.BytesIO(body))
        with self.assertRaises(ValueError):
            self.publisher.publish(self.run, artifacts, before_publish=Mock(side_effect=ValueError("Configuration changed")))
        self.client.put_object.assert_not_called()

    def test_reused_run_cannot_corrupt_an_already_published_pair(self) -> None:
        bodies = (b"database", b"media")
        artifacts = [self.artifact(role, body) for role, body in zip(("database", "media"), bodies, strict=True)]
        for artifact, body in zip(artifacts, bodies, strict=True):
            self.publisher.upload(self.run, artifact, io.BytesIO(body))
        self.publisher.publish(self.run, artifacts)
        before = dict(self.objects)
        with self.assertRaises(ValueError):
            self.publisher.upload(self.run, artifacts[0], io.BytesIO(b"corrupt!"))
        self.assertEqual(self.objects, before)

    def setUp(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, list[bytes]] = {}
        self.client = Mock()
        self.client.create_multipart_upload.side_effect = self.begin
        self.client.upload_part.side_effect = self.part
        self.client.complete_multipart_upload.side_effect = self.complete
        self.client.abort_multipart_upload.side_effect = lambda **kw: self.uploads.pop(kw["UploadId"], None)
        self.client.get_object.side_effect = lambda **kw: {"Body": io.BytesIO(self.objects[kw["Key"]])}
        self.client.put_object.side_effect = self.put
        self.source, self.run = uuid4(), uuid4()
        self.publisher = PlatformBackupPublisher(cast(BaseClient, self.client), "private-backups", self.source)

    def begin(self, **kwargs):
        upload_id = str(uuid4())
        self.uploads[upload_id] = []
        return {"UploadId": upload_id}

    def part(self, **kwargs):
        self.uploads[kwargs["UploadId"]].append(kwargs["Body"])
        return {"ETag": str(kwargs["PartNumber"])}

    def complete(self, **kwargs):
        self.assertEqual(kwargs["IfNoneMatch"], "*")
        if kwargs["Key"] in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "CompleteMultipartUpload")
        self.objects[kwargs["Key"]] = b"".join(self.uploads.pop(kwargs["UploadId"]))

    def put(self, **kwargs) -> None:
        self.assertEqual(kwargs["IfNoneMatch"], "*")
        if kwargs["Key"] in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[kwargs["Key"]] = kwargs["Body"].encode()

    def artifact(self, role: str, body: bytes) -> BackupArtifact:
        return BackupArtifact(role, len(body), hashlib.sha256(body).hexdigest())

    def test_manifest_is_published_only_after_both_objects_are_verified(self) -> None:
        database, media = b"database-content", b"uploaded-documents"
        artifacts = [self.artifact("database", database), self.artifact("media", media)]
        self.publisher.upload(self.run, artifacts[0], io.BytesIO(database))
        self.assertEqual(len(self.objects), 1)
        self.assertFalse(any(key.endswith("manifest.json") for key in self.objects))
        self.publisher.upload(self.run, artifacts[1], io.BytesIO(media))
        key = self.publisher.publish(self.run, artifacts)
        self.assertIn(key, self.objects)
        manifest = json.loads(self.objects[key])
        self.assertEqual(manifest["run_id"], str(self.run))
        self.assertEqual({artifact["role"] for artifact in manifest["artifacts"]}, {"database", "media"})
        self.assertEqual(self.client.get_object.call_count, 2)

    def test_corrupted_remote_object_cannot_be_a_completed_backup(self) -> None:
        artifacts = [self.artifact("database", b"database"), self.artifact("media", b"media")]
        for artifact, body in zip(artifacts, (b"database", b"media"), strict=True):
            self.publisher.upload(self.run, artifact, io.BytesIO(body))
        self.assertEqual(len(self.objects), 2)
        self.objects[next(iter(self.objects))] = b"corrupted"
        with self.assertRaises(ValueError):
            self.publisher.publish(self.run, artifacts)
        self.assertFalse(any(key.endswith("manifest.json") for key in self.objects))

    def test_source_checksum_mismatch_and_incomplete_pair_fail(self) -> None:
        with self.assertRaises(ValueError):
            self.publisher.upload(self.run, self.artifact("database", b"expected"), io.BytesIO(b"different"))
        with self.assertRaises(ValueError):
            self.publisher.publish(self.run, [self.artifact("database", b"database")])

    def test_docker_recovery_metadata_survives_offsite_publication(self) -> None:
        artifacts = [self.artifact("database", b"database"), self.artifact("media", b"media")]
        for artifact, body in zip(artifacts, (b"database", b"media"), strict=True):
            self.publisher.upload(self.run, artifact, io.BytesIO(body))
        recovery = {"format_version": 1, "database_major": 16, "images": {"platform": {"id": "sha256:" + "a" * 64, "reference": "praho-platform:v1.0.0"}},
                    "database": {"file": "pair.sql.gz", "sha256": artifacts[0].sha256},
                    "media": {"file": "pair.media.tar.gz", "sha256": artifacts[1].sha256}}
        key = self.publisher.publish(self.run, artifacts, recovery=recovery)
        self.assertEqual(json.loads(self.objects[key])["recovery"], recovery)
