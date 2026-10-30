"""Queued lifecycle tasks carry the operation they were enqueued for, run once, and are recovered by the app.

The queue helper reserves an operation token under the row lock and passes it to the task; the task's claim
requires it. Two clicks queue two tasks but only the later reservation runs, and a task queued long ago is
refused once anything newer touched the row. Each task runs once (ack_failure, explicit timeout): worker
death is recovered by the operation token and the sweeps, never by the broker replaying the task.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.tasks import (
    NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS,
    NODE_DESTROY_TASK_TIMEOUT_SECONDS,
    OperationReservationError,
    destroy_node_task,
    queue_deploy_node,
    queue_destroy_node,
    queue_retry_deployment,
    recover_stuck_deployments_task,
    retry_deployment_task,
)
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service


def _queued(queue: Any, deployment: NodeDeployment) -> tuple[tuple[Any, ...], dict[str, Any]]:
    with mock.patch("django_q.tasks.async_task", return_value="task-1") as async_task:
        queue(deployment.pk, deployment.provider_id, None)
    return tuple(async_task.call_args.args), dict(async_task.call_args.kwargs)


class TaskOptionsTests(TestCase):
    def test_deploy_runs_once_with_its_pipeline_timeout(self) -> None:
        deployment = _create_deployment("pending")

        args, kwargs = _queued(queue_deploy_node, deployment)

        self.assertEqual((kwargs["timeout"], kwargs["ack_failure"]), (NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS, True))
        deployment.refresh_from_db()
        self.assertEqual(args[-1], str(deployment.operation_token))

    def test_destroy_runs_once_with_an_explicit_timeout(self) -> None:
        _args, kwargs = _queued(queue_destroy_node, _create_deployment("completed"))

        self.assertEqual((kwargs["timeout"], kwargs["ack_failure"]), (NODE_DESTROY_TASK_TIMEOUT_SECONDS, True))

    def test_retry_runs_once(self) -> None:
        _args, kwargs = _queued(queue_retry_deployment, _create_deployment("failed"))

        self.assertTrue(kwargs["ack_failure"])

    def test_a_row_that_needs_reconciliation_is_not_queued_for_retry(self) -> None:
        deployment = _create_deployment("failed")
        NodeDeployment.objects.filter(pk=deployment.pk).update(needs_reconciliation=True, reconciliation_reason="x")

        with mock.patch("django_q.tasks.async_task") as async_task, self.assertRaises(OperationReservationError):
            queue_retry_deployment(deployment.pk, deployment.provider_id, None)
        async_task.assert_not_called()


def _run(task: Any, args: tuple[Any, ...], service: Any) -> dict[str, Any]:
    with (
        mock.patch("apps.infrastructure.tasks.get_deployment_service", return_value=service),
        mock.patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("tok")),
    ):
        return task(*args[1:])  # args[0] is the task's dotted path


class OnlyTheLatestReservationRunsTests(TestCase):
    def test_two_retry_clicks_run_one_pipeline(self) -> None:
        deployment = _create_deployment("failed")
        first, _ = _queued(queue_retry_deployment, deployment)
        second, _ = _queued(queue_retry_deployment, deployment)
        service = _make_service()

        with mock.patch.object(service, "deploy_node", return_value=Ok(mock.Mock(hostname="h"))) as pipeline:
            stale = _run(retry_deployment_task, first, service)
            fresh = _run(retry_deployment_task, second, service)

        self.assertFalse(stale["success"])
        self.assertTrue(fresh["success"], fresh)
        self.assertEqual(pipeline.call_count, 1)
        deployment.refresh_from_db()
        self.assertEqual(deployment.retry_count, 1)

    def test_a_stale_destroy_task_changes_nothing(self) -> None:
        deployment = _create_deployment("completed")
        stale, _ = _queued(queue_destroy_node, deployment)
        _queued(queue_destroy_node, deployment)

        result = _run(destroy_node_task, stale, _make_service())

        self.assertFalse(result["success"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "completed")


class WorkerDeathAndLostTasksTests(TestCase):
    def test_a_retry_refused_by_the_pipeline_is_not_left_pending(self) -> None:
        deployment = _create_deployment("failed")
        args, _ = _queued(queue_retry_deployment, deployment)
        service = _make_service()

        with mock.patch.object(service, "deploy_node", return_value=Err("deployment disabled")):
            _run(retry_deployment_task, args, service)

        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.operation_token), ("failed", None))

    def test_a_pending_row_whose_task_was_lost_is_failed_by_recovery(self) -> None:
        deployment = _create_deployment("pending")
        with (
            mock.patch("django_q.tasks.async_task", side_effect=ConnectionError("broker down")),
            self.assertRaises(ConnectionError),
        ):
            queue_deploy_node(deployment.pk, deployment.provider_id, None)
        NodeDeployment.objects.filter(pk=deployment.pk).update(updated_at=timezone.now() - timedelta(hours=4))

        recover_stuck_deployments_task()

        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.operation_token), ("failed", None))
