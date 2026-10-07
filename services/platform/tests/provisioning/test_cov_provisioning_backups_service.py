"""Coverage additions for backup admission, remote payloads and restore ownership."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import override_settings

from apps.common.types import Retriability, retriability_of
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class BackupServiceCoverageTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.backups = VirtualminBackupService(self.server)
        blocked = patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=AssertionError("Unexpected HTTP dispatch"),
        )
        blocked.start()
        self.addCleanup(blocked.stop)

    def managed_node(self) -> None:
        provider = CloudProvider.objects.create(
            name="Backup provider", provider_type="hetzner", code="bkp", credential_identifier="backup-test"
        )
        region = NodeRegion.objects.create(
            provider=provider,
            name="Backup region",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider,
            name="Backup small",
            display_name="Small",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.01",
            monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Backup Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )
        NodeDeployment.objects.create(
            provider=provider,
            node_size=size,
            region=region,
            panel_type=panel,
            hostname="prd-sha-bkp-de-fsn1-001",
            node_number=1,
            ipv4_address="203.0.113.1",
            virtualmin_server=self.server,
        )

    def test_manual_server_refuses_backup_and_preserves_correlation(self) -> None:
        result = self.backups.backup_domain(self.account, progress_key="manual-job")
        self.assertTrue(result.is_err())
        self.assertIn("archive transport is unavailable", result.unwrap_err())
        progress = self.backups.get_backup_status("manual-job")
        self.assertTrue(str(progress["backup_id"]).startswith(self.account.domain))
        self.assertIsNone(self.backups._progress_key)
        self.assertIsNone(self.backups._ownership)

    def test_manual_server_refuses_archive_fetch_and_push(self) -> None:
        fetch = self.backups._fetch_archive_to_spool({})
        push = self.backups._push_archive_to_target(self.server, "virtualmin_backup_" + "a" * 32 + ".tar.gz", "0" * 64)
        self.assertIn("archive transport is unavailable", fetch.unwrap_err())
        self.assertIn("archive transport is unavailable", push.unwrap_err())
        self.assertEqual(retriability_of(push), Retriability.NOT_RETRIABLE)

    def test_selective_restore_is_refused_before_download(self) -> None:
        result = self.backups.restore_domain(self.account, RestoreConfig(backup_id="selective", restore_email=False))
        self.assertIn("all components must be enabled", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertIsNone(self.backups._ownership)

    def test_remote_backup_payload_and_progress_follow_selected_components(self) -> None:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(cast("dict[str, object]", kwargs["params"]))
            return http_response({"status": "success"})

        for config, skipped in (
            (BackupConfig(), None),
            (BackupConfig(include_email=False), "mail"),
            (BackupConfig(include_databases=False), "mysql"),
            (BackupConfig(include_files=False), "dir"),
            (BackupConfig(include_ssl=False), "ssl"),
            (
                BackupConfig(include_email=False, include_databases=False, include_files=False, include_ssl=False),
                "mail,mysql,dir,ssl",
            ),
        ):
            with (
                self.subTest(config=config),
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport),
            ):
                metadata = self.backups._initialize_backup_metadata(self.account, "full", "full-id", config)
                result = self.backups._execute_backup_by_type(config, self.account, "full-id", metadata)
            self.assertEqual(result.unwrap(), f"/tmp/{metadata['archive_name']}")  # noqa: S108  # Remote node path.
            self.assertEqual(sent[-1]["domain"], self.account.domain)
            self.assertEqual(sent[-1]["dest"], result.unwrap())
            self.assertEqual(sent[-1].get("skip-features"), skipped)
            self.assertTrue(sent[-1]["all-features"])
            self.assertEqual(self.backups.get_backup_status("full-id")["progress"], 30)

    def test_config_only_backup_uses_config_features_and_returns_remote_path(self) -> None:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(cast("dict[str, object]", kwargs["params"]))
            return http_response({"status": "success"})

        config = BackupConfig(backup_type="config_only")
        metadata = self.backups._initialize_backup_metadata(self.account, "config_only", "config-id", config)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups._execute_backup_by_type(config, self.account, "config-id", metadata)
        self.assertEqual(result.unwrap(), f"/tmp/{metadata['archive_name']}")  # noqa: S108  # Remote node path.
        self.assertEqual(sent[0]["only-features"], "virtualmin,dir")
        self.assertNotIn("all-features", sent[0])
        self.assertEqual(self.backups.get_backup_status("config-id")["status"], "backing_up_config")

    def test_remote_failure_never_returns_an_archive_path(self) -> None:
        for backup_type in ("full", "config_only"):
            for payload, status, diagnostic in (
                ({"status": "failure", "message": "quota exhausted"}, 200, "rejected: quota exhausted"),
                ("Error: unrecognized response", 200, "ambiguous"),
                ({"message": "queued"}, 200, "explicit synchronous success"),
                ({}, 403, "failed:"),
            ):
                with (
                    self.subTest(backup_type=backup_type, diagnostic=diagnostic),
                    patch(
                        "apps.provisioning.virtualmin_gateway.safe_request",
                        return_value=http_response(payload, status),
                    ),
                ):
                    config = BackupConfig(backup_type=backup_type)
                    metadata = self.backups._initialize_backup_metadata(self.account, backup_type, "failure-id", config)
                    result = self.backups._execute_backup_by_type(config, self.account, "failure-id", metadata)
                self.assertTrue(result.is_err())
                self.assertIn(diagnostic, result.unwrap_err())

    def test_transport_exception_returns_a_failure_for_each_backup_type(self) -> None:
        for backup_type, diagnostic in (("full", "Full backup failed"), ("config_only", "Config backup failed")):
            with (
                self.subTest(backup_type=backup_type),
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=RuntimeError("transport broke")),
            ):
                config = BackupConfig(backup_type=backup_type)
                metadata = self.backups._initialize_backup_metadata(self.account, backup_type, "exception-id", config)
                result = self.backups._execute_backup_by_type(config, self.account, "exception-id", metadata)
            self.assertEqual(result.unwrap_err(), f"{diagnostic}: transport broke")

    def test_unsupported_backup_type_is_explicitly_refused(self) -> None:
        result = self.backups._execute_backup_by_type(
            BackupConfig(backup_type="incremental"), self.account, "unsupported", {}
        )
        self.assertEqual(result.unwrap_err(), "Unsupported backup type: incremental")

    def test_unreachable_managed_server_refuses_before_backup(self) -> None:
        self.managed_node()
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, 403)):
            result = self.backups.backup_domain(self.account)
        self.assertIn(f"Server {self.server.hostname} is unreachable", result.unwrap_err())

    def test_failed_domain_lookup_refuses_before_backup(self) -> None:
        self.managed_node()
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[http_response({"status": "success"}), http_response({}, 403)],
        ):
            result = self.backups.backup_domain(self.account)
        self.assertIn("Failed to get domain info:", result.unwrap_err())

    def test_oversized_account_refuses_before_backup(self) -> None:
        self.managed_node()
        updated = SettingsService.update_setting("provisioning.max_backup_size_gb", 1)
        self.assertTrue(updated.is_ok(), updated)
        payload = {
            "status": "success",
            "data": [{"name": self.account.domain, "values": {"disk_usage": "2G"}}],
        }

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("Mapping[str, object]", kwargs["params"])
            return http_response(payload if params["program"] == "list-domains" else {"status": "success"})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups.backup_domain(self.account)
        self.assertEqual(result.unwrap_err(), "Estimated backup size (3072MB) exceeds limit (1GB)")

    def test_superseded_backup_dispatches_no_remote_mutation(self) -> None:
        self.managed_node()
        payload = {
            "status": "success",
            "data": [{"name": self.account.domain, "values": {"disk_usage": "1M"}}],
        }

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("Mapping[str, object]", kwargs["params"])
            self.assertIn(params["program"], ("info", "list-domains", "list-bandwidth"))
            return http_response(payload if params["program"] == "list-domains" else {"status": "success"})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups.backup_domain(self.account, ownership=lambda: False)
        self.assertEqual(result.unwrap_err(), "Backup execution superseded; no remote work performed")

    def test_ownership_exception_marks_progress_failed_and_clears_execution_context(self) -> None:
        self.managed_node()
        payload = {
            "status": "success",
            "data": [{"name": self.account.domain, "values": {"disk_usage": "1M"}}],
        }

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("Mapping[str, object]", kwargs["params"])
            return http_response(payload if params["program"] == "list-domains" else {"status": "success"})

        def ownership() -> bool:
            raise RuntimeError("lease storage unavailable")

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups.backup_domain(self.account, progress_key="lease-job", ownership=ownership)
        self.assertEqual(result.unwrap_err(), "Backup operation failed: lease storage unavailable")
        progress = self.backups.get_backup_status("lease-job")
        self.assertEqual((progress["status"], progress["progress"]), ("failed", 100))
        self.assertIsNone(self.backups._ownership)
        self.assertIsNone(self.backups._progress_key)

    def test_restore_target_gate_checks_owner_state_and_force(self) -> None:
        cases = (
            ([], False, False, ""),
            (
                [{"name": self.account.domain, "values": {"Username": "foreign", "Status": "Enabled"}}],
                True,
                None,
                "foreign ownership",
            ),
            (
                [{"name": self.account.domain, "values": {"Username": self.account.virtualmin_username}}],
                True,
                None,
                "state is unverifiable",
            ),
            (
                [
                    {
                        "name": self.account.domain,
                        "values": {
                            "Username": self.account.virtualmin_username,
                            "Status": "Enabled",
                        },
                    }
                ],
                False,
                None,
                "enable force restore",
            ),
            (
                [
                    {
                        "name": self.account.domain,
                        "values": {
                            "Username": self.account.virtualmin_username,
                            "Status": "Disabled",
                        },
                    }
                ],
                True,
                True,
                "",
            ),
        )
        for rows, force, expected, diagnostic in cases:
            with (
                self.subTest(expected=expected, diagnostic=diagnostic),
                patch(
                    "apps.provisioning.virtualmin_gateway.safe_request",
                    return_value=http_response({"status": "success", "data": rows}),
                ),
            ):
                result = self.backups._target_domain_gate(self.server, self.account, force=force)
            if expected is None:
                self.assertIn(diagnostic, result.unwrap_err())
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            else:
                self.assertEqual(result.unwrap(), expected)

    def test_restore_target_listing_failure_is_terminal(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, 403)):
            result = self.backups._target_domain_gate(self.server, self.account, force=True)
        self.assertIn("Target listing failed:", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_restored_domain_verification_requires_the_expected_owner(self) -> None:
        for username, succeeds in ((self.account.virtualmin_username, True), ("foreign", False)):
            with (
                self.subTest(username=username),
                patch(
                    "apps.provisioning.virtualmin_gateway.safe_request",
                    return_value=http_response(
                        {
                            "status": "success",
                            "data": [{"name": self.account.domain, "values": {"Username": username}}],
                        }
                    ),
                ),
            ):
                result = self.backups._verify_restored_domain(self.server, self.account)
            self.assertEqual(result.is_ok(), succeeds)
            if not succeeds:
                self.assertIn("owner mismatch", result.unwrap_err())
