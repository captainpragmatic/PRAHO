"""Media can live in a private S3-compatible bucket, opt-in, with the filesystem as the default.

ADR-0057. A container platform has no shared media volume, so MEDIA_STORAGE=s3 puts uploads and
generated documents in a bucket. Nothing serves media from the bucket: Django reads every file and
any URL the storage could mint is signed and short-lived. A half-configured bucket must stop the
start, not fall back to the container's disk.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase
from storages.backends.s3 import S3Storage

from config.settings.storage import media_storage
from tests.settings.test_logging_configuration import _PROD_ENV

FILESYSTEM = "django.core.files.storage.FileSystemStorage"
S3 = "storages.backends.s3.S3Storage"
BUCKET_ENV = {
    "MEDIA_STORAGE": "s3",
    "MEDIA_S3_BUCKET": "praho-media",
    "MEDIA_S3_ACCESS_KEY_ID": "media-key-id",
    "MEDIA_S3_SECRET_ACCESS_KEY": "media-key-secret",
    "MEDIA_S3_REGION": "eu-central-1",
}


def _settings_module(name: str, env: dict[str, str]) -> ModuleType:
    previous = sys.modules.pop(name, None)
    try:
        with patch.dict(os.environ, {**_PROD_ENV, **env}), patch("config.settings.base.validate_production_secret_key"):
            for key in ("MEDIA_STORAGE", *BUCKET_ENV):
                if key not in env:
                    os.environ.pop(key, None)
            return importlib.import_module(name)
    finally:
        sys.modules.pop(name, None)
        if previous is not None:
            sys.modules[name] = previous


class MediaStorageChoiceTests(SimpleTestCase):
    def test_the_filesystem_is_the_default(self) -> None:
        for env in ({}, {"MEDIA_STORAGE": ""}, {"MEDIA_STORAGE": "filesystem"}):
            with self.subTest(env=env):
                self.assertEqual(media_storage(env), {"BACKEND": FILESYSTEM})

    def test_an_unknown_choice_stops_the_start(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "MEDIA_STORAGE"):
            media_storage({"MEDIA_STORAGE": "s3-public"})

    def test_a_half_configured_bucket_stops_the_start(self) -> None:
        for missing in ("MEDIA_S3_BUCKET", "MEDIA_S3_ACCESS_KEY_ID", "MEDIA_S3_SECRET_ACCESS_KEY"):
            with self.subTest(missing=missing), self.assertRaisesMessage(ImproperlyConfigured, missing):
                media_storage({**BUCKET_ENV, missing: " "})

    def test_an_unencrypted_endpoint_is_refused(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "https"):
            media_storage({**BUCKET_ENV, "MEDIA_S3_ENDPOINT_URL": "http://minio.internal:9000"})

    def test_the_bucket_is_private_and_never_overwritten(self) -> None:
        config = media_storage({**BUCKET_ENV, "MEDIA_S3_ENDPOINT_URL": "https://fsn1.your-objectstorage.com"})

        self.assertEqual(config["BACKEND"], S3)
        options = config["OPTIONS"]
        self.assertEqual(options["bucket_name"], "praho-media")
        self.assertEqual(options["endpoint_url"], "https://fsn1.your-objectstorage.com")
        self.assertEqual(options["location"], "media")
        # Bucket-owner-enforced buckets reject ACLs; privacy is the bucket policy's job.
        self.assertIsNone(options["default_acl"])
        self.assertTrue(options["querystring_auth"])
        self.assertEqual(options["querystring_expire"], 300)
        self.assertIsNone(options["custom_domain"])
        self.assertFalse(options["file_overwrite"])
        self.assertEqual(options["object_parameters"], {})

    def test_server_side_encryption_is_optional_and_checked(self) -> None:
        config = media_storage({**BUCKET_ENV, "MEDIA_S3_SERVER_SIDE_ENCRYPTION": "AES256"})
        self.assertEqual(config["OPTIONS"]["object_parameters"], {"ServerSideEncryption": "AES256"})
        with self.assertRaisesMessage(ImproperlyConfigured, "MEDIA_S3_SERVER_SIDE_ENCRYPTION"):
            media_storage({**BUCKET_ENV, "MEDIA_S3_SERVER_SIDE_ENCRYPTION": "rot13"})

    def test_the_options_build_a_storage_that_only_signs_urls(self) -> None:
        storage = S3Storage(**media_storage(BUCKET_ENV)["OPTIONS"])  # No network: URLs are signed locally.

        url = storage.url("invoices/pdf/INV-1.pdf")

        self.assertIn("X-Amz-Signature=", url)
        self.assertIn("X-Amz-Expires=300", url)
        self.assertIn("/media/invoices/pdf/INV-1.pdf", url)
        self.assertIsNone(storage.default_acl)


class DeployedMediaStorageTests(SimpleTestCase):
    def test_deployed_settings_read_the_choice_and_keep_static_hashed(self) -> None:
        for name in ("config.settings.prod", "config.settings.staging"):
            with self.subTest(settings=name):
                filesystem = _settings_module(name, {}).STORAGES
                bucket = _settings_module(name, BUCKET_ENV).STORAGES
                self.assertEqual(filesystem["default"]["BACKEND"], FILESYSTEM)
                self.assertEqual(bucket["default"]["BACKEND"], S3)
                self.assertEqual(
                    bucket["staticfiles"]["BACKEND"], "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
                )

    def test_local_settings_ignore_the_choice(self) -> None:
        for name in ("config.settings.base", "config.settings.dev"):
            with self.subTest(settings=name):
                self.assertEqual(_settings_module(name, BUCKET_ENV).STORAGES["default"]["BACKEND"], FILESYSTEM)
