"""Backup verification expects members only for components the domain has.

Virtualmin writes a `<domain>_<feature>` member only for features enabled on
that domain. A stock `--minimal` install (PRAHO's own node playbook) has no mail
feature, so a default backup (email included) of such a domain had no
`_mail` member. PRAHO refused it, and with it the pre-restore safety backup, so
every forced restore of a mail-less domain was refused. Observed on the
Virtualmin 8.3.0 lab: "Pre-restore safety backup failed: Backup is missing
requested feature members: mail".

The fix records the domain's enabled features at dispatch and expects the
requested components that are also enabled. An unknown feature list keeps
the strict check.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import requests

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

LAB_FEATURES = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"]


class BackupDomainFeatureTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.backups = VirtualminBackupService(self.server)
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "backup.tar.gz"

    def _archive(self, *features: str) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for feature in features:
                member = tarfile.TarInfo(f"./{self.account.domain}_{feature}")
                member.size = 4
                archive.addfile(member, io.BytesIO(b"data"))
        self.path.write_bytes(buffer.getvalue())

    def _metadata(self, domain_features: list[str] | None) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "backup_type": "full",
            "domain": self.account.domain,
            "backup_location": "spool",
            "backup_path": str(self.path),
            "include_email": True,
            "include_databases": True,
            "include_files": True,
            "include_ssl": True,
            "checksum_sha256_remote": hashlib.sha256(self.path.read_bytes()).hexdigest(),
        }
        if domain_features is not None:
            metadata["domain_features"] = domain_features
        return metadata

    def test_components_the_domain_lacks_are_not_expected(self) -> None:
        self._archive("virtualmin", "mysql", "dir.tar", "ssl")
        metadata = self._metadata(LAB_FEATURES)

        result = self.backups._verify_backup_integrity("bk", metadata)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(metadata["components_not_on_domain"], ["mail"])

    def test_enabled_components_are_still_required(self) -> None:
        self._archive("virtualmin", "mysql", "dir.tar", "ssl")

        result = self.backups._verify_backup_integrity("bk", self._metadata([*LAB_FEATURES, "mail"]))

        self.assertTrue(result.is_err())
        self.assertIn("mail", result.unwrap_err())

    def test_unknown_domain_features_keep_the_strict_check(self) -> None:
        self._archive("virtualmin", "mysql", "dir.tar", "ssl")

        result = self.backups._verify_backup_integrity("bk", self._metadata(None))

        self.assertTrue(result.is_err())
        self.assertIn("mail", result.unwrap_err())

    def test_domain_features_are_read_from_the_8x_listing(self) -> None:
        listing = {
            "command": "list-domains",
            "status": "success",
            "data": [{"name": self.account.domain, "values": {"id": ["1"], "features": [" ".join(LAB_FEATURES)]}}],
        }

        def transport(method: str, url: str, **kwargs: Any) -> requests.Response:
            params = kwargs["params"]
            self.assertEqual((params["program"], params["domain"]), ("list-domains", self.account.domain))
            return http_response(json.loads(json.dumps(listing)))

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            features = self.backups._domain_features(self.account)

        self.assertEqual(features, sorted(LAB_FEATURES))

    def test_domain_features_are_unknown_when_the_listing_has_none(self) -> None:
        listing = {"command": "list-domains", "status": "success", "data": [{"name": self.account.domain, "values": {}}]}
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(listing)):
            self.assertIsNone(self.backups._domain_features(self.account))
