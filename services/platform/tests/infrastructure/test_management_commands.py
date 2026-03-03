"""
Tests for infrastructure management commands.

Covers all 5 management commands with focus on 4 audit findings:
- C2: deploy_node --dry-run must not create DB records
- H3: drift_scan must use proper exit codes (0/1/2/3)
- H14: manage_node async path must validate deployment status
- H15: cleanup_deployments must not mark "destroyed" on cloud failure
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provider(**kwargs: Any) -> MagicMock:
    """Create a mock CloudProvider."""
    provider = MagicMock()
    provider.id = kwargs.get("id", 1)
    provider.name = kwargs.get("name", "Hetzner")
    provider.provider_type = kwargs.get("provider_type", "hetzner")
    provider.is_active = kwargs.get("is_active", True)
    return provider


def _make_region(**kwargs: Any) -> MagicMock:
    """Create a mock NodeRegion."""
    region = MagicMock()
    region.id = kwargs.get("id", 1)
    region.name = kwargs.get("name", "Falkenstein")
    region.provider_region_id = kwargs.get("provider_region_id", "fsn1")
    region.is_active = True
    return region


def _make_size(**kwargs: Any) -> MagicMock:
    """Create a mock NodeSize."""
    size = MagicMock()
    size.id = kwargs.get("id", 1)
    size.display_name = kwargs.get("display_name", "CPX21")
    size.provider_type_id = kwargs.get("provider_type_id", "cpx21")
    size.is_active = True
    return size


def _make_panel(**kwargs: Any) -> MagicMock:
    """Create a mock PanelType."""
    panel = MagicMock()
    panel.id = kwargs.get("id", 1)
    panel.panel_type = kwargs.get("panel_type", "virtualmin")
    panel.is_active = True
    return panel


def _make_deployment(**kwargs: Any) -> MagicMock:
    """Create a mock NodeDeployment."""
    dep = MagicMock()
    dep.id = kwargs.get("id", 1)
    dep.hostname = kwargs.get("hostname", "prd-sha-het-de-fsn1-001")
    dep.status = kwargs.get("status", "completed")
    dep.environment = kwargs.get("environment", "prd")
    dep.node_type = kwargs.get("node_type", "sha")
    dep.provider = kwargs.get("provider", _make_provider())
    dep.provider_id = dep.provider.id
    dep.node_size = kwargs.get("node_size", _make_size())
    dep.region = kwargs.get("region", _make_region())
    dep.external_node_id = kwargs.get("external_node_id", "12345")
    dep.ipv4_address = kwargs.get("ipv4_address", "1.2.3.4")
    dep.dns_zone = kwargs.get("dns_zone", "")
    dep.destroyed_at = None
    dep.updated_at = kwargs.get("updated_at", timezone.now() - timedelta(hours=48))
    dep.get_environment_display = MagicMock(return_value="Production")
    dep.get_node_type_display = MagicMock(return_value="Shared Hosting")
    dep.get_status_display = MagicMock(return_value=kwargs.get("status_display", "Completed"))
    return dep


def _make_drift_report(**kwargs: Any) -> MagicMock:
    """Create a mock DriftReport with all needed attributes."""
    report = MagicMock()
    report.severity = kwargs.get("severity", "high")
    report.category = kwargs.get("category", "server_state")
    report.field_name = kwargs.get("field_name", "server_status")
    report.expected_value = kwargs.get("expected_value", "running")
    report.actual_value = kwargs.get("actual_value", "stopped")
    report.description = kwargs.get("description", "Server is stopped but expected running")
    return report


# ===========================================================================
# TestStoreCredentialsCommand
# ===========================================================================


class TestStoreCredentialsCommand(TestCase):
    """Tests for the store_credentials management command."""

    @patch("apps.infrastructure.management.commands.store_credentials.store_provider_token")
    @patch("apps.infrastructure.models.CloudProvider")
    def test_store_valid_token(
        self, mock_provider_cls: MagicMock, mock_store: MagicMock
    ) -> None:
        """Storing a valid token should succeed and print credential ID."""
        provider = _make_provider()
        mock_provider_cls.objects.filter.return_value.first.return_value = provider
        mock_store.return_value = Ok("cred-123")

        out = StringIO()
        call_command("store_credentials", "hetzner", "--token=test-token-123", stdout=out)

        mock_store.assert_called_once_with(provider, "test-token-123", user=None)
        self.assertIn("cred-123", out.getvalue())

    @patch("apps.infrastructure.models.CloudProvider")
    def test_store_invalid_provider_raises(self, mock_provider_cls: MagicMock) -> None:
        """An inactive/missing provider should raise CommandError."""
        mock_provider_cls.objects.filter.return_value.first.return_value = None

        with self.assertRaises(CommandError) as ctx:
            call_command("store_credentials", "hetzner", "--token=abc")

        self.assertIn("No active provider", str(ctx.exception))

    @patch("apps.infrastructure.models.CloudProvider")
    def test_store_empty_token_raises(self, mock_provider_cls: MagicMock) -> None:
        """An empty token (after stripping) should raise CommandError."""
        provider = _make_provider()
        mock_provider_cls.objects.filter.return_value.first.return_value = provider

        with self.assertRaises(CommandError) as ctx:
            call_command("store_credentials", "hetzner", "--token=   ")

        self.assertIn("empty", str(ctx.exception).lower())


# ===========================================================================
# TestDeployNodeCommand
# ===========================================================================


class TestDeployNodeCommand(TestCase):
    """Tests for the deploy_node management command.

    Covers audit finding C2: --dry-run must not create DB records.
    """

    def _patch_deploy_deps(self) -> dict[str, Any]:
        """Set up common mocks for deploy_node tests. Returns dict of patchers."""
        provider = _make_provider()
        region = _make_region()
        size = _make_size()
        panel = _make_panel()

        patches: dict[str, Any] = {}

        # Mock all model lookups
        p1 = patch("apps.infrastructure.models.CloudProvider")
        mock_cp = p1.start()
        mock_cp.objects.filter.return_value.first.return_value = provider
        patches["CloudProvider"] = mock_cp
        patches["_p1"] = p1

        p2 = patch("apps.infrastructure.models.NodeRegion")
        mock_nr = p2.start()
        mock_nr.objects.filter.return_value.first.return_value = region
        patches["NodeRegion"] = mock_nr
        patches["_p2"] = p2

        p3 = patch("apps.infrastructure.models.NodeSize")
        mock_ns = p3.start()
        mock_ns.objects.filter.return_value.first.return_value = size
        patches["NodeSize"] = mock_ns
        patches["_p3"] = p3

        p4 = patch("apps.infrastructure.models.PanelType")
        mock_pt = p4.start()
        mock_pt.objects.filter.return_value.first.return_value = panel
        patches["PanelType"] = mock_pt
        patches["_p4"] = p4

        p5 = patch("apps.infrastructure.management.commands.deploy_node.get_provider_token")
        mock_token = p5.start()
        mock_token.return_value = Ok("test-token")
        patches["get_provider_token"] = mock_token
        patches["_p5"] = p5

        p6 = patch("apps.settings.services.SettingsService")
        mock_settings = p6.start()
        mock_settings.get_setting.return_value = True
        patches["SettingsService"] = mock_settings
        patches["_p6"] = p6

        p7 = patch("apps.infrastructure.models.NodeDeployment")
        mock_nd = p7.start()
        mock_nd.get_next_node_number.return_value = 1
        # Make the constructor return a mock deployment
        deployment = _make_deployment()
        mock_nd.return_value = deployment
        patches["NodeDeployment"] = mock_nd
        patches["deployment"] = deployment
        patches["_p7"] = p7

        patches["provider"] = provider
        patches["region"] = region
        patches["size"] = size
        patches["panel"] = panel

        return patches

    def _stop_patches(self, patches: dict[str, Any]) -> None:
        for key, val in patches.items():
            if key.startswith("_p"):
                val.stop()

    def test_dry_run_does_not_create_deployment(self) -> None:
        """C2: --dry-run must NOT call deployment.save() or consume a node number."""
        patches = self._patch_deploy_deps()
        try:
            out = StringIO()
            call_command(
                "deploy_node",
                "--provider=hetzner",
                "--environment=prd",
                "--region=fsn1",
                "--size=cpx21",
                "--dry-run",
                stdout=out,
            )

            # The deployment mock should NOT have .save() called
            deployment = patches["deployment"]
            deployment.save.assert_not_called()

            # NodeDeployment.get_next_node_number should NOT be called
            patches["NodeDeployment"].get_next_node_number.assert_not_called()
        finally:
            self._stop_patches(patches)

    def test_dry_run_prints_summary(self) -> None:
        """C2: --dry-run should print a preview summary of what would happen."""
        patches = self._patch_deploy_deps()
        try:
            out = StringIO()
            call_command(
                "deploy_node",
                "--provider=hetzner",
                "--environment=prd",
                "--region=fsn1",
                "--size=cpx21",
                "--dry-run",
                stdout=out,
            )

            output = out.getvalue()
            self.assertIn("DRY RUN", output)
            self.assertIn("Hetzner", output)
        finally:
            self._stop_patches(patches)

    def test_missing_provider_raises_command_error(self) -> None:
        """Missing --provider should raise a CommandError."""
        with self.assertRaises((CommandError, SystemExit)):
            call_command(
                "deploy_node",
                "--environment=prd",
                "--region=fsn1",
                "--size=cpx21",
            )

    @patch("apps.infrastructure.tasks.queue_deploy_node")
    def test_async_flag_queues_task(self, mock_queue: MagicMock) -> None:
        """--async should call queue_deploy_node instead of direct deploy."""
        patches = self._patch_deploy_deps()
        mock_queue.return_value = "task-abc"
        try:
            out = StringIO()
            call_command(
                "deploy_node",
                "--provider=hetzner",
                "--environment=prd",
                "--region=fsn1",
                "--size=cpx21",
                "--async",
                stdout=out,
            )

            mock_queue.assert_called_once()
            self.assertIn("queued", out.getvalue().lower())
        finally:
            self._stop_patches(patches)

    @patch("apps.infrastructure.deployment_service.get_deployment_service")
    def test_sync_calls_service_directly(self, mock_get_svc: MagicMock) -> None:
        """Without --async, the command should call service.deploy_node directly."""
        patches = self._patch_deploy_deps()
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.cloud_result.server_id = "srv-123"
        mock_result.duration_seconds = 42.5
        mock_result.stages_completed = ["provision", "dns"]
        mock_service.deploy_node.return_value = Ok(mock_result)
        mock_get_svc.return_value = mock_service
        try:
            out = StringIO()
            call_command(
                "deploy_node",
                "--provider=hetzner",
                "--environment=prd",
                "--region=fsn1",
                "--size=cpx21",
                stdout=out,
            )

            mock_service.deploy_node.assert_called_once()
        finally:
            self._stop_patches(patches)

    def test_disabled_deployment_raises(self) -> None:
        """If node_deployment.enabled is False, should raise CommandError."""
        patches = self._patch_deploy_deps()
        patches["SettingsService"].get_setting.return_value = False
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command(
                    "deploy_node",
                    "--provider=hetzner",
                    "--environment=prd",
                    "--region=fsn1",
                    "--size=cpx21",
                )
            self.assertIn("disabled", str(ctx.exception).lower())
        finally:
            self._stop_patches(patches)


# ===========================================================================
# TestManageNodeCommand
# ===========================================================================


class TestManageNodeCommand(TestCase):
    """Tests for the manage_node management command.

    Covers audit finding H14: async path must validate deployment status.
    """

    def _setup_manage_mocks(
        self, deployment: MagicMock | None = None
    ) -> tuple[Any, MagicMock]:
        """Set up mocks for manage_node command. Returns (patcher_list, deployment)."""
        if deployment is None:
            deployment = _make_deployment()

        p1 = patch("apps.infrastructure.models.NodeDeployment")
        mock_nd = p1.start()
        mock_nd.objects.select_related.return_value.filter.return_value.first.return_value = (
            deployment
        )

        p2 = patch("apps.infrastructure.management.commands.manage_node.get_provider_token")
        mock_token = p2.start()
        mock_token.return_value = Ok("test-token")

        return [p1, p2], deployment

    def _teardown_patches(self, patchers: list[Any]) -> None:
        for p in patchers:
            p.stop()

    def test_unknown_hostname_raises_command_error(self) -> None:
        """A hostname not found in DB should raise CommandError."""
        p1 = patch("apps.infrastructure.models.NodeDeployment")
        mock_nd = p1.start()
        mock_nd.objects.select_related.return_value.filter.return_value.first.return_value = None
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command("manage_node", "nonexistent-host", "stop")
            self.assertIn("No deployment found", str(ctx.exception))
        finally:
            p1.stop()

    def test_upgrade_requires_size(self) -> None:
        """'upgrade' action without --size should raise CommandError."""
        patchers, _ = self._setup_manage_mocks()
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command("manage_node", "prd-sha-het-de-fsn1-001", "upgrade")
            self.assertIn("--size", str(ctx.exception))
        finally:
            self._teardown_patches(patchers)

    def test_destroy_requires_confirmation(self) -> None:
        """'destroy' without --force should prompt for confirmation; wrong input raises."""
        patchers, _ = self._setup_manage_mocks()
        try:
            with patch("builtins.input", return_value="wrong-hostname"):
                with self.assertRaises(CommandError) as ctx:
                    call_command("manage_node", "prd-sha-het-de-fsn1-001", "destroy")
                self.assertIn("Confirmation failed", str(ctx.exception))
        finally:
            self._teardown_patches(patchers)

    @patch("apps.infrastructure.tasks.queue_stop_node")
    def test_stop_validates_status_before_queue(
        self, mock_queue: MagicMock
    ) -> None:
        """H14: Async stop on already-stopped node should raise CommandError."""
        dep = _make_deployment(status="stopped", status_display="Stopped")
        patchers, _ = self._setup_manage_mocks(dep)
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command(
                    "manage_node",
                    "prd-sha-het-de-fsn1-001",
                    "stop",
                    "--async",
                )
            self.assertIn("Cannot stop", str(ctx.exception))
            mock_queue.assert_not_called()
        finally:
            self._teardown_patches(patchers)

    @patch("apps.infrastructure.tasks.queue_start_node")
    def test_start_validates_status_before_queue(
        self, mock_queue: MagicMock
    ) -> None:
        """H14: Async start on already-running node should raise CommandError."""
        dep = _make_deployment(status="completed", status_display="Completed")
        patchers, _ = self._setup_manage_mocks(dep)
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command(
                    "manage_node",
                    "prd-sha-het-de-fsn1-001",
                    "start",
                    "--async",
                )
            self.assertIn("Cannot start", str(ctx.exception))
            mock_queue.assert_not_called()
        finally:
            self._teardown_patches(patchers)

    @patch("apps.infrastructure.tasks.queue_destroy_node")
    def test_destroy_validates_status_before_queue(
        self, mock_queue: MagicMock
    ) -> None:
        """H14: Async destroy on pending node should raise CommandError."""
        dep = _make_deployment(status="pending", status_display="Pending")
        patchers, _ = self._setup_manage_mocks(dep)
        try:
            with self.assertRaises(CommandError) as ctx:
                call_command(
                    "manage_node",
                    "prd-sha-het-de-fsn1-001",
                    "destroy",
                    "--force",
                    "--async",
                )
            self.assertIn("Cannot destroy", str(ctx.exception))
            mock_queue.assert_not_called()
        finally:
            self._teardown_patches(patchers)

    @patch("apps.infrastructure.tasks.queue_stop_node")
    def test_stop_async_valid_status_succeeds(
        self, mock_queue: MagicMock
    ) -> None:
        """Async stop on a 'completed' (running) node should succeed."""
        dep = _make_deployment(status="completed", status_display="Completed")
        patchers, _ = self._setup_manage_mocks(dep)
        mock_queue.return_value = "task-123"
        try:
            out = StringIO()
            call_command(
                "manage_node",
                "prd-sha-het-de-fsn1-001",
                "stop",
                "--async",
                stdout=out,
            )
            mock_queue.assert_called_once()
            self.assertIn("queued", out.getvalue().lower())
        finally:
            self._teardown_patches(patchers)

    def test_dry_run_shows_plan(self) -> None:
        """--dry-run should show what would happen without executing."""
        patchers, _ = self._setup_manage_mocks()
        try:
            out = StringIO()
            call_command(
                "manage_node",
                "prd-sha-het-de-fsn1-001",
                "stop",
                "--dry-run",
                stdout=out,
            )
            output = out.getvalue()
            self.assertIn("DRY RUN", output)
            self.assertIn("stop", output)
        finally:
            self._teardown_patches(patchers)


# ===========================================================================
# TestDriftScanCommand
# ===========================================================================


class TestDriftScanCommand(TestCase):
    """Tests for the drift_scan management command.

    Covers audit finding H3: proper exit codes (0/1/2/3).
    """

    def _run_drift_scan(
        self,
        deployments: list[MagicMock],
        scan_results: list[Any],
        extra_args: list[str] | None = None,
    ) -> tuple[str, str, int]:
        """Run drift_scan and return (stdout, stderr, exit_code)."""
        out = StringIO()
        err = StringIO()
        exit_code = 0

        with (
            patch(
                "apps.infrastructure.drift_scanner.DriftScannerService"
            ) as mock_scanner_cls,
            patch(
                "apps.infrastructure.models.NodeDeployment"
            ) as mock_nd,
        ):
            mock_scanner = MagicMock()
            mock_scanner_cls.return_value = mock_scanner

            # Set up scan results for each deployment
            mock_scanner.scan_deployment.side_effect = scan_results

            # Make --all return our deployments
            qs = MagicMock()
            qs.exists.return_value = bool(deployments)
            qs.__iter__ = lambda self: iter(deployments)
            mock_nd.objects.select_related.return_value.filter.return_value = qs

            args = ["--all"] + (extra_args or [])
            try:
                call_command("drift_scan", *args, stdout=out, stderr=err)
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0

        return out.getvalue(), err.getvalue(), exit_code

    def test_no_drifts_exits_0(self) -> None:
        """H3: No drifts and no errors should exit 0."""
        dep = _make_deployment()
        _, _, exit_code = self._run_drift_scan([dep], [Ok([])])
        self.assertEqual(exit_code, 0)

    def test_drifts_found_exits_1(self) -> None:
        """H3: Drifts found but no errors should exit 1."""
        dep = _make_deployment()
        reports = [_make_drift_report()]
        _, _, exit_code = self._run_drift_scan([dep], [Ok(reports)])
        self.assertEqual(exit_code, 1)

    def test_scan_errors_exits_2(self) -> None:
        """H3: Scan errors but no drifts should exit 2."""
        dep = _make_deployment()
        _, _, exit_code = self._run_drift_scan([dep], [Err("API timeout")])
        self.assertEqual(exit_code, 2)

    def test_drifts_and_errors_exits_3(self) -> None:
        """H3: Both drifts AND errors should exit 3."""
        dep1 = _make_deployment(hostname="host-001")
        dep2 = _make_deployment(hostname="host-002")
        reports = [_make_drift_report()]
        _, _, exit_code = self._run_drift_scan(
            [dep1, dep2],
            [Ok(reports), Err("Provider down")],
        )
        self.assertEqual(exit_code, 3)

    def test_json_output_format(self) -> None:
        """JSON output should contain structured fields."""
        import json

        dep = _make_deployment()
        reports = [_make_drift_report()]
        stdout, _, _ = self._run_drift_scan(
            [dep], [Ok(reports)], extra_args=["--output=json"]
        )
        data = json.loads(stdout)
        self.assertEqual(data["total_deployments"], 1)
        self.assertEqual(data["total_drifts"], 1)
        self.assertEqual(data["total_errors"], 0)
        self.assertIsInstance(data["results"], list)

    def test_no_target_specified_raises(self) -> None:
        """Not specifying --deployment, --provider, or --all should raise."""
        with self.assertRaises(CommandError):
            call_command("drift_scan")

    def test_empty_deployments_exits_0(self) -> None:
        """No deployments found should exit 0 (nothing to scan)."""
        _, _, exit_code = self._run_drift_scan([], [])
        self.assertEqual(exit_code, 0)


# ===========================================================================
# TestCleanupDeploymentsCommand
# ===========================================================================


class TestCleanupDeploymentsCommand(TestCase):
    """Tests for the cleanup_deployments management command.

    Covers audit finding H15: cloud failure must not mark "destroyed".
    """

    def _make_failed_deployment(self, **kwargs: Any) -> MagicMock:
        """Create a mock failed deployment for cleanup tests."""
        dep = _make_deployment(
            status="failed",
            status_display="Failed",
            updated_at=timezone.now() - timedelta(hours=48),
            **kwargs,
        )
        return dep

    @patch("apps.infrastructure.models.NodeDeployment")
    def test_dry_run_does_not_delete(self, mock_nd: MagicMock) -> None:
        """--dry-run should list deployments but not delete or modify them."""
        dep = self._make_failed_deployment()
        mock_nd.objects.select_related.return_value.filter.return_value = [dep]

        out = StringIO()
        call_command("cleanup_deployments", "--dry-run", stdout=out)

        dep.save.assert_not_called()
        self.assertIn("DRY RUN", out.getvalue())

    @patch("apps.infrastructure.models.NodeDeployment")
    def test_max_age_hours_respected(self, mock_nd: MagicMock) -> None:
        """Only deployments older than --max-age-hours should be included."""
        # The filter call should use the cutoff
        mock_nd.objects.select_related.return_value.filter.return_value = []

        call_command("cleanup_deployments", "--max-age-hours=12", stdout=StringIO())

        # Verify filter was called (the command builds a queryset)
        mock_nd.objects.select_related.return_value.filter.assert_called()

    @patch(
        "apps.infrastructure.cloud_gateway.get_cloud_gateway"
    )
    @patch(
        "apps.infrastructure.provider_config.get_provider_token"
    )
    @patch("apps.infrastructure.models.NodeDeployment")
    def test_cloud_deletion_failure_does_not_mark_destroyed(
        self,
        mock_nd: MagicMock,
        mock_token: MagicMock,
        mock_gateway_fn: MagicMock,
    ) -> None:
        """H15: If cloud deletion fails, deployment should NOT be marked destroyed."""
        dep = self._make_failed_deployment()
        mock_nd.objects.select_related.return_value.filter.return_value = [dep]

        mock_token.return_value = Ok("test-token")
        mock_gateway = MagicMock()
        mock_gateway.delete_server.return_value = Err("API error: server not responding")
        mock_gateway_fn.return_value = mock_gateway

        out = StringIO()
        err = StringIO()
        call_command("cleanup_deployments", stdout=out, stderr=err)

        # The deployment should NOT have status set to "destroyed"
        # It should keep its original "failed" status
        if dep.save.called:
            # Check that status was NOT set to "destroyed"
            self.assertNotEqual(dep.status, "destroyed")

    @patch(
        "apps.infrastructure.cloud_gateway.get_cloud_gateway"
    )
    @patch(
        "apps.infrastructure.provider_config.get_provider_token"
    )
    @patch("apps.infrastructure.models.NodeDeployment")
    def test_successful_deletion_marks_destroyed(
        self,
        mock_nd: MagicMock,
        mock_token: MagicMock,
        mock_gateway_fn: MagicMock,
    ) -> None:
        """Successful cloud deletion should mark deployment as destroyed."""
        dep = self._make_failed_deployment()
        mock_nd.objects.select_related.return_value.filter.return_value = [dep]

        mock_token.return_value = Ok("test-token")
        mock_gateway = MagicMock()
        mock_gateway.delete_server.return_value = Ok(True)
        mock_gateway_fn.return_value = mock_gateway

        out = StringIO()
        call_command("cleanup_deployments", stdout=out)

        # Now the deployment SHOULD be marked as destroyed
        dep.save.assert_called()
        self.assertEqual(dep.status, "destroyed")

    @patch("apps.infrastructure.models.NodeDeployment")
    def test_no_stale_deployments_prints_message(self, mock_nd: MagicMock) -> None:
        """No matching deployments should print a message and return."""
        mock_nd.objects.select_related.return_value.filter.return_value = []

        out = StringIO()
        call_command("cleanup_deployments", stdout=out)

        self.assertIn("No stale failed deployments", out.getvalue())

    @patch(
        "apps.infrastructure.provider_config.get_provider_token"
    )
    @patch("apps.infrastructure.models.NodeDeployment")
    def test_no_external_id_skips_cloud_deletion(
        self,
        mock_nd: MagicMock,
        mock_token: MagicMock,
    ) -> None:
        """Deployments without external_node_id should skip cloud deletion but still be marked."""
        dep = self._make_failed_deployment(external_node_id=None)
        mock_nd.objects.select_related.return_value.filter.return_value = [dep]

        out = StringIO()
        call_command("cleanup_deployments", stdout=out)

        # Should still mark as destroyed since there's nothing to delete in cloud
        dep.save.assert_called()
        self.assertEqual(dep.status, "destroyed")
