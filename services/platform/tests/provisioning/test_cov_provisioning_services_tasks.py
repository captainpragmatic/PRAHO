"""Coverage additions for the generic provisioning task and its live enqueue path."""

from __future__ import annotations

from apps.provisioning.models import Service
from apps.provisioning.tasks import provision_service_task, queue_service_provisioning
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase
from tests.provisioning.test_virtualmin_credentials import create_test_server


class ProvisioningTaskCoverageTests(VirtualminCoverageCase):
    def test_task_without_server_persists_manual_assignment_requirement(self) -> None:
        force_status(self.service, "pending")
        self.service.provisioning_errors = "previous attempt"
        self.service.save(update_fields=["provisioning_errors"])
        result = provision_service_task(self.service.pk)
        self.assertEqual(
            result,
            {
                "status": "pending_manual",
                "message": "No server assigned - manual provisioning required",
                "requires_action": True,
            },
        )
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "provisioning")
        self.assertIsNotNone(self.service.last_provisioning_attempt)
        self.assertEqual(self.service.provisioning_errors, "No server assigned. Manual server assignment required.")

    def test_task_with_unconfigured_server_persists_manual_requirement(self) -> None:
        server = create_test_server(management_api_url="")
        force_status(self.service, "pending")
        self.service.server = server
        self.service.save(update_fields=["server"])
        result = provision_service_task(self.service.pk)
        detail = f"Server {server.name} has no API configured for {server.control_panel}"
        self.assertEqual(result["status"], "pending_manual")
        self.assertEqual(result["message"], f"Manual provisioning required - {detail}")
        self.assertEqual(result["server"], f"Server: {server.name} ({server.control_panel})")
        self.assertTrue(result["requires_action"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "provisioning")
        self.assertEqual(self.service.provisioning_errors, detail)

    def test_missing_service_task_returns_error_without_rows_or_enqueues(self) -> None:
        count = Service.objects.count()
        self.assertEqual(provision_service_task(0), {"status": "error", "error": "Service 0 not found"})
        self.assertEqual(Service.objects.count(), count)
        self.assertEqual(self.broker.queued(), [])

    def test_enqueue_persists_task_id_and_signed_worker_contract(self) -> None:
        force_status(self.service, "pending")
        task_id = queue_service_provisioning(self.service)
        self.service.refresh_from_db()
        self.assertEqual(self.service.provisioning_task_id, task_id)
        self.assertEqual(self.service.status, "pending")
        self.assertEqual(self.broker.queued(), [("apps.provisioning.tasks.provision_service_task", self.service.pk)])
        package = self._packages()[0]
        self.assertEqual(package["id"], task_id)
        self.assertEqual(package["timeout"], 300)
        self.assertEqual(package["hook"], "apps.provisioning.tasks.provisioning_complete_hook")
        self.assertEqual(package["kwargs"], {})

    def test_enqueue_retries_failed_service_and_preserves_diagnostic(self) -> None:
        force_status(self.service, "failed")
        self.service.provisioning_errors = "Previous diagnostic"
        self.service.save(update_fields=["provisioning_errors"])
        task_id = queue_service_provisioning(self.service)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "pending")
        self.assertEqual(self.service.provisioning_errors, "Previous diagnostic")
        self.assertEqual(self.service.provisioning_task_id, task_id)
        self.assertEqual(self.broker.queued(), [("apps.provisioning.tasks.provision_service_task", self.service.pk)])
