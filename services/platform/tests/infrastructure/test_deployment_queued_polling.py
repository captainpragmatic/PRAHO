"""Reserved deployment operations keep both status renderings polling until a worker starts."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class QueuedDeploymentPollingTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(
            get_user_model().objects.create_superuser(email="queued-ui@test.com", password="testpass123")
        )

    def _assert_pages(
        self, deployment: NodeDeployment, *, polls: bool, queued: str = "", running: bool = False
    ) -> None:
        for view in ("deployment_detail", "deployment_status_partial"):
            with self.subTest(view=view):
                response = self.client.get(reverse(f"infrastructure:{view}", args=[deployment.pk]))
                if polls:
                    self.assertContains(response, 'hx-trigger="every 5s"')
                else:
                    self.assertNotContains(response, 'hx-trigger="every 5s"')
                if queued:
                    self.assertContains(response, queued)
                else:
                    self.assertNotContains(response, "Queued:")
                if running:
                    self.assertContains(response, "In progress...")
                    self.assertContains(response, "Deployment Progress")
                else:
                    self.assertNotContains(response, "In progress...")
                    self.assertNotContains(response, "Deployment Progress")
                self.assertEqual(response.context["is_in_progress"], polls)
                self.assertEqual(response.context["is_running"], running)
                self.assertEqual(response.context["operation_queued"], bool(queued))

    def test_destroyed_row_reserved_for_redeploy_polls_and_shows_queue(self) -> None:
        deployment = _create_deployment("destroyed")
        deployment.operation_token = uuid.uuid4()
        deployment.operation_kind = "redeploy"
        deployment.operation_reserved_at = timezone.now()
        deployment.save(update_fields=["operation_token", "operation_kind", "operation_reserved_at"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")
        self.assertNotIn(deployment.status, NodeDeployment.POLLING_STATUSES)
        self.assertIsNotNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "redeploy")
        self.assertIsNotNone(deployment.operation_reserved_at)

        self._assert_pages(deployment, polls=True, queued="Queued: Re-deploy")

    def test_destroyed_row_without_reservation_does_not_poll(self) -> None:
        deployment = _create_deployment("destroyed")
        self.assertEqual(deployment.status, "destroyed")
        self.assertNotIn(deployment.status, NodeDeployment.POLLING_STATUSES)
        self.assertIsNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "")
        self.assertIsNone(deployment.operation_reserved_at)

        self._assert_pages(deployment, polls=False)

    def test_failed_row_reserved_for_retry_polls_and_shows_queue(self) -> None:
        deployment = _create_deployment("failed")
        deployment.operation_token = uuid.uuid4()
        deployment.operation_kind = "retry"
        deployment.operation_reserved_at = timezone.now()
        deployment.save(update_fields=["operation_token", "operation_kind", "operation_reserved_at"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertNotIn(deployment.status, NodeDeployment.POLLING_STATUSES)
        self.assertIsNotNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "retry")
        self.assertIsNotNone(deployment.operation_reserved_at)

        self._assert_pages(deployment, polls=True, queued="Queued: Retry")

    def test_stale_reservation_still_shows_queue_without_polling(self) -> None:
        deployment = _create_deployment("destroyed")
        now = timezone.now()
        reserved_at = now - timedelta(hours=1)
        deployment.operation_token = uuid.uuid4()
        deployment.operation_kind = "redeploy"
        deployment.operation_reserved_at = reserved_at
        deployment.save(update_fields=["operation_token", "operation_kind", "operation_reserved_at"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")
        self.assertNotIn(deployment.status, NodeDeployment.POLLING_STATUSES)
        self.assertIsNotNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "redeploy")
        self.assertEqual(deployment.operation_reserved_at, reserved_at)
        self.assertLess(reserved_at, now - timedelta(minutes=15))

        with patch("apps.infrastructure.models.timezone.now", return_value=now):
            self._assert_pages(deployment, polls=False, queued="Queued: Re-deploy")

    def test_running_row_polls_without_showing_queue(self) -> None:
        deployment = _create_deployment("installing_panel")
        deployment.operation_token = uuid.uuid4()
        deployment.operation_kind = "redeploy"
        deployment.operation_reserved_at = None
        deployment.save(update_fields=["operation_token", "operation_kind", "operation_reserved_at"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "installing_panel")
        self.assertIn(deployment.status, NodeDeployment.POLLING_STATUSES)
        self.assertIsNotNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "redeploy")
        self.assertIsNone(deployment.operation_reserved_at)

        self._assert_pages(deployment, polls=True, running=True)

    def test_terminal_reservation_poll_window_is_inclusive(self) -> None:
        deployment = _create_deployment("destroyed")
        now = timezone.now()
        window = timedelta(minutes=15)
        cases = (
            (window - timedelta(microseconds=1), True),
            (window, True),
            (window + timedelta(microseconds=1), False),
        )
        for age, polls in cases:
            with self.subTest(age=age):
                reserved_at = now - age
                deployment.operation_token = uuid.uuid4()
                deployment.operation_kind = "redeploy"
                deployment.operation_reserved_at = reserved_at
                deployment.save(update_fields=["operation_token", "operation_kind", "operation_reserved_at"])
                deployment.refresh_from_db()
                self.assertEqual(deployment.status, "destroyed")
                self.assertNotIn(deployment.status, NodeDeployment.POLLING_STATUSES)
                self.assertIsNotNone(deployment.operation_token)
                self.assertEqual(deployment.operation_kind, "redeploy")
                self.assertEqual(deployment.operation_reserved_at, reserved_at)
                self.assertEqual(now - reserved_at, age)

                with patch("apps.infrastructure.models.timezone.now", return_value=now):
                    self.assertEqual(NodeDeployment.QUEUED_POLL_WINDOW, window)
                    self.assertTrue(deployment.operation_queued)
                    self.assertEqual(deployment.should_poll, polls)
                    self._assert_pages(deployment, polls=polls, queued="Queued: Re-deploy")
