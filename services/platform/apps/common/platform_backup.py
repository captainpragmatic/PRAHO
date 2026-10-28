"""Publish a complete Platform database/media pair to private S3-compatible storage."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import BinaryIO
from uuid import UUID

from botocore.client import BaseClient
from django.utils import timezone

TRANSFER_CHUNK = 8 * 1024 * 1024
MAX_PARTS = 10000
logger = logging.getLogger(__name__)
ARTIFACT_ROLES = frozenset({"database", "media"})
MAX_RECOVERY_BYTES = 16384


def _validate_recovery(recovery: Mapping[str, object], artifacts: Sequence[BackupArtifact]) -> None:
    if (
        set(recovery) - {"format_version", "database_major", "images", "database", "media", "created_at"}
        or recovery.get("format_version") != 1
        or type(recovery.get("database_major")) is not int
        or len(json.dumps(dict(recovery), allow_nan=False)) > MAX_RECOVERY_BYTES
    ):
        raise ValueError("Invalid recovery metadata")
    images = recovery.get("images")
    if not isinstance(images, dict) or "platform" not in images or set(images) - {"platform", "portal", "qcluster"}:
        raise ValueError("Missing recovery images")
    for image in images.values():
        if (
            not isinstance(image, dict)
            or set(image) != {"id", "reference"}
            or re.fullmatch(r"sha256:[a-f0-9]{64}", str(image.get("id", ""))) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", str(image.get("reference", ""))) is None
        ):
            raise ValueError("Invalid recovery image")
    for artifact in artifacts:
        metadata = recovery.get(artifact.role)
        if (
            not isinstance(metadata, dict)
            or set(metadata) != {"file", "sha256"}
            or metadata["sha256"] != artifact.sha256
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(metadata["file"])) is None
        ):
            raise ValueError("Recovery metadata does not describe the uploaded pair")


class DigestingStream(io.RawIOBase):
    """Non-seekable streaming input; managed transfers never buffer the entire archive."""

    def __init__(self, source: BinaryIO, expected_size: int) -> None:
        super().__init__()
        self.source = source
        self.expected_size = expected_size
        self.length = 0
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(min(size, TRANSFER_CHUNK) if size >= 0 else TRANSFER_CHUNK)
        self.length += len(data)
        if self.length > self.expected_size:
            raise ValueError("Backup input exceeds its declared size")
        self.digest.update(data)
        return data


@dataclass(frozen=True)
class BackupArtifact:
    role: str
    size: int
    sha256: str
    format: str = "binary"

    def validate(self) -> None:
        if self.role not in {"database", "media"} or self.size <= 0 or not re.fullmatch(r"[a-f0-9]{64}", self.sha256):
            raise ValueError("Invalid backup artifact")
        if self.format not in {"binary", "postgres-custom", "sql-gzip", "tar-gzip"}:
            raise ValueError("Unsupported backup format")


class PlatformBackupPublisher:
    def __init__(self, client: BaseClient, bucket: str, source_id: UUID) -> None:
        self.client = client
        self.bucket = bucket
        self.source_id = source_id

    def upload(self, run_id: UUID, artifact: BackupArtifact, stream: BinaryIO) -> None:
        """Stream a single artifact; publishing the pair is a separate, verified step."""
        artifact.validate()
        if artifact.size > TRANSFER_CHUNK * MAX_PARTS:
            raise ValueError("Backup artifact exceeds the multipart capacity")
        reader = DigestingStream(stream, artifact.size)
        target = {"Bucket": self.bucket, "Key": self._key(run_id, artifact.role)}
        upload_id = self.client.create_multipart_upload(
            **target,
            ServerSideEncryption="AES256",
            Metadata={"sha256": artifact.sha256},
        )["UploadId"]
        try:
            parts: list[dict[str, str | int]] = []
            while True:
                chunks = []
                remaining = TRANSFER_CHUNK
                while remaining and (block := reader.read(remaining)):
                    chunks.append(block)
                    remaining -= len(block)
                if not chunks:
                    break
                number = len(parts) + 1
                if number > MAX_PARTS:
                    raise ValueError("Backup artifact exceeds the multipart capacity")
                response = self.client.upload_part(
                    **target, UploadId=upload_id, PartNumber=number, Body=b"".join(chunks)
                )
                parts.append({"PartNumber": number, "ETag": response["ETag"]})
            if reader.length != artifact.size or not hmac.compare_digest(reader.digest.hexdigest(), artifact.sha256):
                raise ValueError("Backup input checksum or length mismatch")
            self.client.complete_multipart_upload(
                **target, UploadId=upload_id, MultipartUpload={"Parts": parts}, IfNoneMatch="*"
            )
        except Exception:
            try:
                self.client.abort_multipart_upload(**target, UploadId=upload_id)
            except Exception:
                logger.warning("⚠️ [Backup] Incomplete multipart cleanup failed; remote objects were retained")
            raise

    def publish(
        self,
        run_id: UUID,
        artifacts: Sequence[BackupArtifact],
        *,
        recovery: Mapping[str, object] | None = None,
        before_publish: Callable[[], None] | None = None,
    ) -> str:
        """Verify both remote objects before writing the manifest commit marker."""
        if len(artifacts) != len(ARTIFACT_ROLES) or {artifact.role for artifact in artifacts} != ARTIFACT_ROLES:
            raise ValueError("A complete database and media pair is required")
        if recovery is not None:
            _validate_recovery(recovery, artifacts)
        for artifact in artifacts:
            artifact.validate()
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(run_id, artifact.role))
            body = response["Body"]
            digest = hashlib.sha256()
            length = 0
            try:
                while block := body.read(TRANSFER_CHUNK):
                    length += len(block)
                    if length > artifact.size:
                        raise ValueError("Remote backup exceeds its expected size")
                    digest.update(block)
            finally:
                body.close()
            if length != artifact.size or not hmac.compare_digest(digest.hexdigest(), artifact.sha256):
                raise ValueError("Remote backup checksum or length mismatch")
        key = self._key(run_id, "manifest.json")
        manifest = {
            "format_version": 1,
            "source_id": str(self.source_id),
            "run_id": str(run_id),
            "completed_at": timezone.now().isoformat(),
            "artifacts": [asdict(artifact) for artifact in artifacts],
        }
        if recovery is not None:
            manifest["recovery"] = dict(recovery)
        if before_publish is not None:
            before_publish()
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(manifest),
            ContentType="application/json",
            ServerSideEncryption="AES256",
            IfNoneMatch="*",
        )
        return key

    def _key(self, run_id: UUID, role: str) -> str:
        if not isinstance(run_id, UUID) or not isinstance(self.source_id, UUID):
            raise ValueError("Backup identities must be UUIDs")
        return f"platform-backups/{self.source_id}/{run_id}/{role}"
