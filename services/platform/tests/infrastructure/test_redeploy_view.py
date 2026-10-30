"""The re-deploy page, its queue task and the button on the deployment page.

Re-deploy needs both the deploy and the destroy permission, the hostname typed to confirm, and a size sold
in the deployment's region. It is queued like the other lifecycle operations: an operation token reserved
under the row lock, one run, and the deploy pipeline's timeout.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.common.types import Ok
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.tasks import NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS, queue_redeploy_node, redeploy_node_task
from tests.helpers.node_catalogue import make_size
from tests.infrastructure.test_redeploy import destroyed_row

User = get_user_model()
_QUEUE = "apps.infrastructure.views.queue_redeploy_node"


class RedeployPageTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_superuser(email="rd-admin@example.com", password="x")
        self.deployment = destroyed_row()
        self.sold = make_size(self.deployment.provider, "cx23", self.deployment.region)
        self.unsold = make_size(self.deployment.provider, "cpx11")
        self.url = reverse("infrastructure:deployment_redeploy", args=[self.deployment.pk])

    def _post(self, hostname: str, size_id: Any) -> Any:
        with mock.patch(_QUEUE, return_value="task-1") as queue, mock.patch(
            "apps.infrastructure.views.get_provider_token", return_value=Ok("tok")
        ):
            response = self.client.post(self.url, {"confirm_hostname": hostname, "new_size": size_id})
        return response, queue

    def test_the_page_offers_only_sizes_sold_in_the_region(self) -> None:
        self.client.force_login(self.admin)

        response: Any = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertIn(self.sold, response.context["available_sizes"])
        self.assertNotIn(self.unsold, response.context["available_sizes"])

    def test_a_confirmed_request_is_queued(self) -> None:
        self.client.force_login(self.admin)

        response, queue = self._post(self.deployment.hostname, self.sold.pk)

        self.assertEqual(response.status_code, 302)
        queue.assert_called_once_with(
            deployment_id=self.deployment.pk,
            provider_id=self.deployment.provider_id,
            new_size_id=self.sold.pk,
            user_id=self.admin.pk,
        )

    def test_a_wrong_hostname_queues_nothing(self) -> None:
        self.client.force_login(self.admin)

        response, queue = self._post("not-the-hostname", self.sold.pk)

        self.assertEqual(response.status_code, 200)
        queue.assert_not_called()

    def test_a_malformed_size_is_refused_without_an_error_page(self) -> None:
        self.client.force_login(self.admin)

        for malformed in ("abc", "²", "9" * 40):
            with self.subTest(malformed=malformed):
                response, queue = self._post(self.deployment.hostname, malformed)

                self.assertEqual(response.status_code, 200)
                queue.assert_not_called()

    def test_a_size_not_sold_in_the_region_queues_nothing(self) -> None:
        self.client.force_login(self.admin)

        _response, queue = self._post(self.deployment.hostname, self.unsold.pk)

        queue.assert_not_called()

    def test_deploying_without_the_destroy_permission_is_forbidden(self) -> None:
        deployer = User.objects.create_user(email="deployer@example.com", password="x", is_staff=True)
        self.client.force_login(deployer)

        # Allowed to deploy, not to destroy: the destroy check is the real one.
        with mock.patch("apps.infrastructure.permissions.can_deploy_nodes", return_value=True):
            response, queue = self._post(self.deployment.hostname, self.sold.pk)

        self.assertEqual(response.status_code, 403)
        queue.assert_not_called()

    def test_the_deployment_page_offers_re_deploy_only_when_eligible(self) -> None:
        self.client.force_login(self.admin)
        detail = reverse("infrastructure:deployment_detail", args=[self.deployment.pk])

        eligible: Any = self.client.get(detail)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(server_create_state="created")
        billed: Any = self.client.get(detail)

        self.assertTrue(eligible.context["can_redeploy"])
        self.assertFalse(billed.context["can_redeploy"])


class RedeployQueueTests(TestCase):
    def test_the_task_carries_its_reservation_and_runs_once(self) -> None:
        deployment = destroyed_row()
        size = make_size(deployment.provider, "cx23", deployment.region)

        with mock.patch("django_q.tasks.async_task", return_value="t") as async_task:
            queue_redeploy_node(deployment_id=deployment.pk, provider_id=deployment.provider_id, new_size_id=size.pk, user_id=None)

        deployment.refresh_from_db()
        self.assertEqual(
            async_task.call_args.args,
            ("apps.infrastructure.tasks.redeploy_node_task", deployment.pk, deployment.provider_id, size.pk, None,
             str(deployment.operation_token)),
        )
        self.assertEqual(async_task.call_args.kwargs["timeout"], NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS)
        self.assertTrue(async_task.call_args.kwargs["ack_failure"])

    def test_the_task_hands_the_reserved_token_and_size_to_the_service(self) -> None:
        deployment = destroyed_row()
        size = make_size(deployment.provider, "cx23", deployment.region)
        admin = User.objects.create_superuser(email="rd-task@example.com", password="x")
        service = mock.Mock()
        service.redeploy_node.return_value = Ok(mock.Mock(hostname=deployment.hostname, stages_completed=[], duration_seconds=1.0))
        token = "00000000-0000-0000-0000-000000000001"

        with (
            mock.patch("apps.infrastructure.tasks.get_deployment_service", return_value=service),
            mock.patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("tok")),
        ):
            result = redeploy_node_task(deployment.pk, deployment.provider_id, size.pk, admin.pk, token)

        self.assertTrue(result["success"], result)
        kwargs = service.redeploy_node.call_args.kwargs
        self.assertEqual((kwargs["new_size"], kwargs["user"], str(kwargs["expected_token"])), (size, admin, token))


class RedeployButtonPermissionTests(TestCase):
    def test_the_button_needs_the_deploy_permission_as_well_as_destroy(self) -> None:
        deployment = destroyed_row()
        destroyer = User.objects.create_user(email="destroyer@example.com", password="x", is_staff=True)
        self.client.force_login(destroyer)

        with (
            mock.patch("apps.infrastructure.views.can_destroy_nodes", return_value=True),
            mock.patch("apps.infrastructure.views.can_deploy_nodes", return_value=False),
            mock.patch("apps.infrastructure.permissions.can_view_infrastructure", return_value=True),
        ):
            response: Any = self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["can_redeploy"])
