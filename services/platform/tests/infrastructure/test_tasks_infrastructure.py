"""
Tests for infrastructure async tasks (tasks.py).

Verifies:
- Cloudflare API tokens are NOT serialized to task queue (C3)
- Tokens are fetched at execution time from SettingsService
- Timezone handling in calculate_daily_costs_task (C4)
- Task functions handle missing deployments/providers gracefully
- Queue functions pass correct arguments to async_task
"""

from __future__ import annotations

import inspect
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)
from apps.infrastructure.tasks import (
    calculate_daily_costs_task,
    deploy_node_task,
    destroy_node_task,
    queue_deploy_node,
    queue_destroy_node,
    queue_retry_deployment,
    retry_deployment_task,
)

User = get_user_model()


def _create_test_deployment(status: str = "pending") -> NodeDeployment:
    """Create a minimal NodeDeployment for task tests."""
    provider, _ = CloudProvider.objects.get_or_create(
        code="TST",
        defaults={
            "name": "Test Provider",
            "provider_type": "hetzner",
            "is_active": True,
            "credential_identifier": "test-cred",
        },
    )
    region, _ = NodeRegion.objects.get_or_create(
        provider=provider,
        normalized_code="tst1",
        defaults={
            "name": "Test Region",
            "provider_region_id": "tst1",
            "country_code": "de",
            "city": "Test",
            "is_active": True,
        },
    )
    size, _ = NodeSize.objects.get_or_create(
        provider=provider,
        provider_type_id="cx11",
        defaults={
            "name": "TEST",
            "display_name": "Test Size",
            "vcpus": 1,
            "memory_gb": 2,
            "disk_gb": 20,
            "hourly_cost_eur": "0.0050",
            "monthly_cost_eur": "3.29",
            "is_active": True,
        },
    )
    panel, _ = PanelType.objects.get_or_create(
        panel_type="virtualmin",
        defaults={
            "name": "Virtualmin GPL",
            "ansible_playbook": "virtualmin.yml",
            "version": "7.10.0",
            "is_active": True,
        },
    )
    user, _ = User.objects.get_or_create(
        email="task-test@test.com",
        defaults={"password": "!unusable"},
    )
    next_number = NodeDeployment.objects.filter(
        environment="dev", node_type="sha", provider=provider, region=region
    ).count() + 1
    deployment = NodeDeployment(
        environment="dev",
        node_type="sha",
        provider=provider,
        region=region,
        node_size=size,
        panel_type=panel,
        hostname=f"tsk-tst-tst-de-tst1-{next_number:03d}",
        dns_zone="test.example.com",
        node_number=next_number,
        initiated_by=user,
        status=status,
    )
    deployment.save()
    return deployment


# ===========================================================================
# C3: Cloudflare token must NOT appear in task function signatures
# ===========================================================================


class TestCloudflareTokenNotInTaskSignatures(TestCase):
    """C3: cloudflare_api_token must not be a parameter of task functions."""

    def test_deploy_node_task_no_cloudflare_param(self) -> None:
        sig = inspect.signature(deploy_node_task)
        self.assertNotIn("cloudflare_api_token", sig.parameters)

    def test_destroy_node_task_no_cloudflare_param(self) -> None:
        sig = inspect.signature(destroy_node_task)
        self.assertNotIn("cloudflare_api_token", sig.parameters)

    def test_retry_deployment_task_no_cloudflare_param(self) -> None:
        sig = inspect.signature(retry_deployment_task)
        self.assertNotIn("cloudflare_api_token", sig.parameters)


class TestCloudflareTokenNotInQueueSignatures(TestCase):
    """C3: cloudflare_api_token must not be a parameter of queue functions."""

    def test_queue_deploy_node_no_cloudflare_param(self) -> None:
        sig = inspect.signature(queue_deploy_node)
        self.assertNotIn("cloudflare_api_token", sig.parameters)

    def test_queue_destroy_node_no_cloudflare_param(self) -> None:
        sig = inspect.signature(queue_destroy_node)
        self.assertNotIn("cloudflare_api_token", sig.parameters)

    def test_queue_retry_deployment_no_cloudflare_param(self) -> None:
        sig = inspect.signature(queue_retry_deployment)
        self.assertNotIn("cloudflare_api_token", sig.parameters)


class TestCloudflareTokenFetchedAtRuntime(TestCase):
    """C3: Task functions must fetch cloudflare token from SettingsService at runtime."""

    @patch("apps.infrastructure.tasks.get_deployment_service")
    @patch("apps.infrastructure.provider_config.get_provider_token")
    @patch("apps.settings.services.SettingsService.get_setting")
    def test_deploy_task_fetches_cloudflare_from_settings(
        self, mock_get_setting: MagicMock, mock_get_token: MagicMock, mock_get_service: MagicMock
    ) -> None:
        deployment = _create_test_deployment("pending")
        mock_get_token.return_value = MagicMock(is_err=lambda: False, unwrap=lambda: "test-token")
        mock_get_setting.return_value = "cf-token-from-settings"
        mock_service = MagicMock()
        mock_service.deploy_node.return_value = MagicMock(
            is_err=lambda: False,
            unwrap=lambda: MagicMock(
                hostname="test", stages_completed=[], virtualmin_server_id=None, duration_seconds=0
            ),
        )
        mock_get_service.return_value = mock_service

        deploy_node_task(deployment.id, deployment.provider_id, user_id=None)

        mock_get_setting.assert_called_with("node_deployment.dns_cloudflare_api_token")
        # Verify the service was called with the fetched token
        call_kwargs = mock_service.deploy_node.call_args
        self.assertEqual(call_kwargs.kwargs.get("cloudflare_api_token"), "cf-token-from-settings")

    @patch("apps.infrastructure.tasks.get_deployment_service")
    @patch("apps.infrastructure.provider_config.get_provider_token")
    @patch("apps.settings.services.SettingsService.get_setting")
    def test_destroy_task_fetches_cloudflare_from_settings(
        self, mock_get_setting: MagicMock, mock_get_token: MagicMock, mock_get_service: MagicMock
    ) -> None:
        deployment = _create_test_deployment("completed")
        mock_get_token.return_value = MagicMock(is_err=lambda: False, unwrap=lambda: "test-token")
        mock_get_setting.return_value = "cf-token-from-settings"
        mock_service = MagicMock()
        mock_service.destroy_node.return_value = MagicMock(is_err=lambda: False, unwrap=lambda: True)
        mock_get_service.return_value = mock_service

        destroy_node_task(deployment.id, deployment.provider_id, user_id=None)

        mock_get_setting.assert_called_with("node_deployment.dns_cloudflare_api_token")

    @patch("apps.infrastructure.tasks.get_deployment_service")
    @patch("apps.infrastructure.provider_config.get_provider_token")
    @patch("apps.settings.services.SettingsService.get_setting")
    def test_retry_task_fetches_cloudflare_from_settings(
        self, mock_get_setting: MagicMock, mock_get_token: MagicMock, mock_get_service: MagicMock
    ) -> None:
        deployment = _create_test_deployment("failed")
        mock_get_token.return_value = MagicMock(is_err=lambda: False, unwrap=lambda: "test-token")
        mock_get_setting.return_value = "cf-token-from-settings"
        mock_service = MagicMock()
        mock_service.retry_deployment.return_value = MagicMock(
            is_err=lambda: False,
            unwrap=lambda: MagicMock(hostname="test", stages_completed=[], duration_seconds=0),
        )
        mock_get_service.return_value = mock_service

        retry_deployment_task(deployment.id, deployment.provider_id, user_id=None)

        mock_get_setting.assert_called_with("node_deployment.dns_cloudflare_api_token")


# ===========================================================================
# C3: Queue functions must NOT pass cloudflare token to async_task
# ===========================================================================


class TestQueueFunctionsNoCloudflareInPayload(TestCase):
    """C3: Queue functions must not pass cloudflare tokens to async_task."""

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_queue_deploy_no_cloudflare_in_args(self, mock_async: MagicMock) -> None:
        queue_deploy_node(deployment_id=1, provider_id=2, user_id=3)
        args = mock_async.call_args
        # Positional args after the function path should be: deployment_id, provider_id, user_id
        positional_args = args[0]
        self.assertEqual(positional_args, ("apps.infrastructure.tasks.deploy_node_task", 1, 2, 3))

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_queue_destroy_no_cloudflare_in_args(self, mock_async: MagicMock) -> None:
        queue_destroy_node(deployment_id=1, provider_id=2, user_id=3)
        args = mock_async.call_args
        positional_args = args[0]
        self.assertEqual(positional_args, ("apps.infrastructure.tasks.destroy_node_task", 1, 2, 3))

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_queue_retry_no_cloudflare_in_args(self, mock_async: MagicMock) -> None:
        queue_retry_deployment(deployment_id=1, provider_id=2, user_id=3)
        args = mock_async.call_args
        positional_args = args[0]
        self.assertEqual(positional_args, ("apps.infrastructure.tasks.retry_deployment_task", 1, 2, 3))


# ===========================================================================
# C4: Timezone handling in calculate_daily_costs_task
# ===========================================================================


class TestCalculateDailyCostsTimezone(TestCase):
    """C4: calculate_daily_costs_task must not call make_aware on already-aware datetimes."""

    @patch("apps.infrastructure.cost_service.get_cost_tracking_service")
    def test_no_make_aware_crash(self, mock_get_service: MagicMock) -> None:
        """Task should not crash with ValueError from double make_aware."""
        mock_service = MagicMock()
        mock_service.calculate_all_deployment_costs.return_value = []
        mock_service.get_cost_summary.return_value = MagicMock(total_eur=0)
        mock_get_service.return_value = mock_service

        # This would crash before the fix with:
        # ValueError: Not naive datetime (tzinfo is already set)
        result = calculate_daily_costs_task()
        self.assertTrue(result["success"])

    @patch("apps.infrastructure.cost_service.get_cost_tracking_service")
    def test_yesterday_bounds_are_timezone_aware(self, mock_get_service: MagicMock) -> None:
        """Period bounds passed to cost service must be timezone-aware."""
        mock_service = MagicMock()
        mock_service.calculate_all_deployment_costs.return_value = []
        mock_service.get_cost_summary.return_value = MagicMock(total_eur=0)
        mock_get_service.return_value = mock_service

        calculate_daily_costs_task()

        # Check that calculate_all_deployment_costs was called with aware datetimes
        call_args = mock_service.calculate_all_deployment_costs.call_args[0]
        yesterday_start, yesterday_end = call_args
        self.assertIsNotNone(yesterday_start.tzinfo)
        self.assertIsNotNone(yesterday_end.tzinfo)

    @patch("apps.infrastructure.cost_service.get_cost_tracking_service")
    def test_yesterday_bounds_span_one_day(self, mock_get_service: MagicMock) -> None:
        """yesterday_end - yesterday_start should be approximately 1 day."""
        mock_service = MagicMock()
        mock_service.calculate_all_deployment_costs.return_value = []
        mock_service.get_cost_summary.return_value = MagicMock(total_eur=0)
        mock_get_service.return_value = mock_service

        calculate_daily_costs_task()

        call_args = mock_service.calculate_all_deployment_costs.call_args[0]
        yesterday_start, yesterday_end = call_args
        delta = yesterday_end - yesterday_start
        # Should be close to 24 hours (minus 1 microsecond)
        self.assertAlmostEqual(delta.total_seconds(), 86400, delta=1)


# ===========================================================================
# Task error handling
# ===========================================================================


class TestTaskDeploymentNotFound(TestCase):
    """Task functions handle missing deployments gracefully."""

    def test_deploy_task_deployment_not_found(self) -> None:
        result = deploy_node_task(deployment_id=99999, provider_id=1)
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])

    def test_destroy_task_deployment_not_found(self) -> None:
        result = destroy_node_task(deployment_id=99999, provider_id=1)
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])

    def test_retry_task_deployment_not_found(self) -> None:
        result = retry_deployment_task(deployment_id=99999, provider_id=1)
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])


class TestTaskProviderNotFound(TestCase):
    """Task functions handle missing providers gracefully."""

    def test_deploy_task_provider_not_found(self) -> None:
        deployment = _create_test_deployment("pending")
        result = deploy_node_task(deployment_id=deployment.id, provider_id=99999)
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])

    def test_destroy_task_provider_not_found(self) -> None:
        deployment = _create_test_deployment("completed")
        result = destroy_node_task(deployment_id=deployment.id, provider_id=99999)
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])


class TestTaskTokenFetchFailure(TestCase):
    """Task functions handle token fetch failures gracefully."""

    @patch("apps.infrastructure.provider_config.get_provider_token")
    def test_deploy_task_token_fetch_failure(self, mock_get_token: MagicMock) -> None:
        deployment = _create_test_deployment("pending")
        mock_get_token.return_value = MagicMock(is_err=lambda: True, unwrap_err=lambda: "vault error")

        result = deploy_node_task(deployment.id, deployment.provider_id)
        self.assertFalse(result["success"])
        self.assertIn("provider token", result["error"])
