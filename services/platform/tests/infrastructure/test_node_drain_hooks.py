"""Round 2 stop/start and failover provenance contracts."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.forms import NodeDeploymentForm
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.tasks import queue_stop_node, start_node_task, stop_node_task
from apps.provisioning.virtualmin_migration_models import NodeDrain
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class NodeDrainHookTests(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.deployment = self.server.node_deployment
        self.deployment_service = NodeDeploymentService.__new__(NodeDeploymentService)

    def _deployment_status(self, status: str) -> None:
        # fsm-bypass: establish a deployment at the lifecycle boundary being tested.
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(status=status)
        self.deployment.refresh_from_db()

    def _disabled_draining_server(self) -> None:
        # fsm-bypass: establish a powered-off linked server awaiting verified activation.
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="disabled", is_draining=True)
        self.server.refresh_from_db()

    def _power_off(self, **kwargs):
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "disabled", "Admission must close before provider I/O")
        self.assertEqual(kwargs["operation"], "power_off")
        return Ok(SimpleNamespace(success=True))

    def test_stop_refuses_undrained_accounts(self) -> None:
        """RED: stop powers off a linked server containing active accounts."""
        self._deployment_status("completed")
        with patch("apps.infrastructure.deployment_service.run_provider_command") as power:
            result = self.deployment_service.stop_node(self.deployment, {"api_token": "test"}, self.staff)
        self.assertTrue(result.is_err(), result)
        self.assertIn("undrained", result.unwrap_err())
        power.assert_not_called()
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertTrue(AuditEvent.objects.filter(
            action="node_stop_failed", object_id=str(self.deployment.pk)
        ).exists())

    def test_force_stop_disables_before_power_off(self) -> None:
        """RED: force is unsupported and linked admission remains active."""
        self._deployment_status("completed")
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command", side_effect=self._power_off
        ):
            result = self.deployment_service.stop_node(
                self.deployment, {"api_token": "test"}, self.staff, force=True
            )
        self.assertTrue(result.is_ok(), result)
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "stopped")
        event = AuditEvent.objects.get(action="node_stop_started", object_id=str(self.deployment.pk))
        self.assertTrue(event.metadata["force"])

    def test_completed_finalized_drain_allows_stop(self) -> None:
        """RED: stopping does not disable the linked Virtualmin server."""
        self._deployment_status("completed")
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        NodeDrain.objects.create(
            server=self.server, status="completed", routing_confirmed=True,
            accounts_total=1, accounts_migrated=1,
        )
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command", side_effect=self._power_off
        ) as power:
            result = self.deployment_service.stop_node(self.deployment, {"api_token": "test"})
        self.assertTrue(result.is_ok(), result)
        power.assert_called_once()

    def test_start_verifies_activation_and_reports_task_outcome(self) -> None:
        """RED: start never verifies or clears the linked server's drain flag."""
        self._deployment_status("stopped")
        self._disabled_draining_server()

        def activate(server):
            # fsm-bypass: emulate the registration service's successful disabled-to-active CAS.
            VirtualminServer.objects.filter(pk=server.pk, status="disabled").update(status="active")
            server.refresh_from_db()
            return Ok(server)

        with (
            patch("apps.infrastructure.tasks.get_deployment_service", return_value=self.deployment_service),
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("test")),
            patch(
                "apps.infrastructure.deployment_service.run_provider_command",
                return_value=Ok(SimpleNamespace(success=True)),
            ),
            patch(
                "apps.infrastructure.registration_service.NodeRegistrationService.verify_and_activate",
                side_effect=activate,
            ) as verify,
        ):
            result = start_node_task(self.deployment.pk, self.deployment.provider_id)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["virtualmin_status"], "active")
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[0].pk, self.server.pk)
        self.server.refresh_from_db()
        self.assertFalse(self.server.is_draining)
        self.assertEqual(self.server.status, "active")

    def test_failed_start_activation_leaves_server_disabled(self) -> None:
        """RED: activation failure is neither attempted nor reported."""
        self._deployment_status("stopped")
        self._disabled_draining_server()
        with (
            patch(
                "apps.infrastructure.deployment_service.run_provider_command",
                return_value=Ok(SimpleNamespace(success=True)),
            ),
            patch(
                "apps.infrastructure.registration_service.NodeRegistrationService.verify_and_activate",
                return_value=Err("API not ready"),
            ),
        ):
            result = self.deployment_service.start_node(self.deployment, {"api_token": "test"})
        self.assertTrue(result.is_err(), result)
        self.assertIn("API not ready", result.unwrap_err())
        self.server.refresh_from_db()
        self.deployment.refresh_from_db()
        self.assertEqual(self.server.status, "disabled")
        self.assertTrue(self.server.is_draining)
        self.assertEqual(self.deployment.status, "completed")
        self.assertTrue(AuditEvent.objects.filter(
            action="node_start_failed", object_id=str(self.deployment.pk)
        ).exists())

    def test_stop_force_passes_through_view_queue_and_task(self) -> None:
        """RED: force is dropped by the stop view, queue wrapper, and task."""
        self._deployment_status("completed")
        self.client.force_login(self.staff)
        url = reverse("infrastructure:deployment_stop", args=[self.deployment.pk])
        for payload, expected in (({}, False), ({"force": "on"}, True)):
            with (
                self.subTest(payload=payload),
                patch("apps.infrastructure.views.get_provider_token", return_value=Ok("test")),
                patch("apps.infrastructure.views.queue_stop_node", return_value="task") as queue,
            ):
                response = self.client.post(url, payload)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(queue.call_args.kwargs["force"], expected)

        with patch("django_q.tasks.async_task", return_value="task") as enqueue:
            queue_stop_node(self.deployment.pk, self.deployment.provider_id, force=True)
        self.assertTrue(enqueue.call_args.kwargs["force"])

        service = MagicMock()
        service.stop_node.return_value = Ok(True)
        with (
            patch("apps.infrastructure.tasks.get_deployment_service", return_value=service),
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("test")),
        ):
            result = stop_node_task(self.deployment.pk, self.deployment.provider_id, force=True)
        self.assertTrue(result["success"])
        self.assertTrue(service.stop_node.call_args.kwargs["force"])

    def test_create_with_optional_source_stamps_failover_and_audit(self) -> None:
        """RED: create ignores source_node and never stamps replacement provenance."""
        self.staff.is_superuser = True
        self.staff.save(update_fields=["is_superuser"])
        self.client.force_login(self.staff)
        self.settings_values["node_deployment.dns_default_zone"] = "example.com"
        self.assertFalse(NodeDeploymentForm().fields["source_node"].required)
        base = {
            "environment": self.deployment.environment,
            "node_type": self.deployment.node_type,
            "provider": self.deployment.provider_id,
            "region": self.deployment.region_id,
            "node_size": self.deployment.node_size_id,
            "panel_type": self.deployment.panel_type_id,
            "backup_enabled": "on",
        }
        for source in (self.deployment.pk, ""):
            with self.subTest(source=source):
                previous = list(NodeDeployment.objects.values_list("pk", flat=True))
                with (
                    patch("apps.infrastructure.views.get_provider_token", return_value=Ok("test")),
                    patch("apps.infrastructure.views.queue_deploy_node", return_value="task"),
                ):
                    response = self.client.post(
                        reverse("infrastructure:deployment_create"), {**base, "source_node": source}
                    )
                self.assertEqual(response.status_code, 302)
                created = NodeDeployment.objects.exclude(pk__in=previous).get()
                self.assertEqual(created.source_node_id, source or None)
                self.assertEqual(created.triggered_by_failover, bool(source))
                event = AuditEvent.objects.get(action="node_deployment_created", object_id=str(created.pk))
                self.assertEqual(event.metadata["source_node_id"], source or None)
                self.assertEqual(event.metadata["triggered_by_failover"], bool(source))
                if source:
                    self.assertEqual(event.metadata["source_node_hostname"], self.deployment.hostname)
