"""The deployment pages show what the lifecycle really does.

The views tested for a "running_ansible" status that does not exist, so the panel install and backup
stages showed no progress and stopped polling, and a destroy in progress stopped polling on the detail
page. Retry was offered for any failed row, including one that needs reconciliation. A failure written
without an operation lease left the old status message.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service

User = get_user_model()


class ModelPredicateTests(TestCase):
    def test_every_polling_status_is_a_real_status(self) -> None:
        real = {code for code, _label in NodeDeployment.STATUS_CHOICES}

        self.assertLessEqual(set(NodeDeployment.POLLING_STATUSES), real)
        self.assertLessEqual(set(NodeDeployment.PROGRESS_PERCENT), real)
        self.assertIn("installing_panel", NodeDeployment.POLLING_STATUSES)
        self.assertIn("destroying", NodeDeployment.POLLING_STATUSES)

    def test_a_failed_deploy_can_be_retried(self) -> None:
        self.assertTrue(_create_deployment("failed").can_retry)

    def test_a_row_that_needs_reconciliation_cannot_be_retried(self) -> None:
        deployment = _create_deployment("failed")
        deployment.needs_reconciliation = True

        self.assertFalse(deployment.can_retry)


class DeploymentPagesTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="ui@test.com", password="testpass123"))

    def _detail(self, deployment: NodeDeployment) -> Any:
        return self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))

    def test_the_panel_install_shows_progress_and_polls(self) -> None:
        response = self._detail(_create_deployment("installing_panel"))

        self.assertTrue(response.context["is_in_progress"])
        self.assertGreater(response.context["progress_percentage"], 35)

    def test_a_destroy_in_progress_polls_on_the_detail_page(self) -> None:
        response = self._detail(_create_deployment("destroying"))

        self.assertTrue(response.context["is_in_progress"])

    def test_retry_is_not_offered_for_a_row_that_needs_reconciliation(self) -> None:
        deployment = _create_deployment("failed")
        NodeDeployment.objects.filter(pk=deployment.pk).update(needs_reconciliation=True)

        response = self._detail(deployment)

        self.assertFalse(response.context["can_retry"])

    def test_the_dashboard_counts_the_panel_install_as_in_progress(self) -> None:
        _create_deployment("installing_panel")

        response: Any = self.client.get(reverse("infrastructure:dashboard"))

        self.assertEqual(response.context["pending_deployments"], 1)


class FailureMessageTests(TestCase):
    def test_an_unowned_failure_records_its_message(self) -> None:
        deployment = _create_deployment("validating")

        _make_service()._mark_failed(deployment, "validation timed out")

        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.status_message), ("failed", "validation timed out"))
