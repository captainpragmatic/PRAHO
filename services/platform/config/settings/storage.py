"""Where uploaded and generated files (media) live: the filesystem, or a private S3-compatible bucket.

ADR-0057. The filesystem is the default and what every stack with a media volume or directory uses.
MEDIA_STORAGE=s3 is for container platforms without a shared volume. Nothing serves media from the
bucket: Django reads each file and returns it, so the bucket stays private (Block Public Access and
a bucket policy, never object ACLs), and any URL the storage could mint is signed and expires in
five minutes. The bucket's versioning and lifecycle rules are its backup.

A half-configured bucket refuses to start rather than falling back to the container's disk, which
is lost when the container is replaced.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from django.core.exceptions import ImproperlyConfigured

FILESYSTEM_BACKEND = "django.core.files.storage.FileSystemStorage"
S3_BACKEND = "storages.backends.s3.S3Storage"
S3_REQUIRED = ("MEDIA_S3_BUCKET", "MEDIA_S3_ACCESS_KEY_ID", "MEDIA_S3_SECRET_ACCESS_KEY")
SERVER_SIDE_ENCRYPTION = ("AES256", "aws:kms")
SIGNED_URL_SECONDS = 300


def _value(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip()


def media_storage(env: Mapping[str, str]) -> dict[str, Any]:
    """The STORAGES["default"] entry for MEDIA_STORAGE (filesystem when unset)."""
    choice = _value(env, "MEDIA_STORAGE").lower() or "filesystem"
    if choice == "filesystem":
        return {"BACKEND": FILESYSTEM_BACKEND}
    if choice != "s3":
        raise ImproperlyConfigured(f"MEDIA_STORAGE must be 'filesystem' or 's3', not {choice!r}")

    missing = [name for name in S3_REQUIRED if not _value(env, name)]
    if missing:
        raise ImproperlyConfigured(f"MEDIA_STORAGE=s3 needs {', '.join(missing)}")
    endpoint = _value(env, "MEDIA_S3_ENDPOINT_URL")
    if endpoint and not endpoint.startswith("https://"):
        raise ImproperlyConfigured("MEDIA_S3_ENDPOINT_URL must use https: media holds invoices and personal data")
    encryption = _value(env, "MEDIA_S3_SERVER_SIDE_ENCRYPTION")
    if encryption and encryption not in SERVER_SIDE_ENCRYPTION:
        raise ImproperlyConfigured(
            f"MEDIA_S3_SERVER_SIDE_ENCRYPTION must be one of {', '.join(SERVER_SIDE_ENCRYPTION)}"
        )

    return {
        "BACKEND": S3_BACKEND,
        "OPTIONS": {
            "bucket_name": _value(env, "MEDIA_S3_BUCKET"),
            # Its own key, not the SES one: least privilege both ways.
            "access_key": _value(env, "MEDIA_S3_ACCESS_KEY_ID"),
            "secret_key": _value(env, "MEDIA_S3_SECRET_ACCESS_KEY"),
            "endpoint_url": endpoint or None,  # None: AWS itself
            "region_name": _value(env, "MEDIA_S3_REGION") or None,
            "location": "media",
            # Bucket-owner-enforced buckets reject ACLs; the bucket policy keeps objects private.
            "default_acl": None,
            "querystring_auth": True,
            "querystring_expire": SIGNED_URL_SECONDS,
            "custom_domain": None,
            # Issued documents are never replaced in place: a clashing name gets a suffix.
            "file_overwrite": False,
            "object_parameters": {"ServerSideEncryption": encryption} if encryption else {},
        },
    }
