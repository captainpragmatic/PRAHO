"""Coverage additions for reachable provisioning lifecycle and management services."""

from __future__ import annotations

from decimal import Decimal

from apps.audit.models import AuditEvent
from apps.provisioning.models import Service
from apps.provisioning.provisioning_service import ProvisioningService
from apps.provisioning.services import ServiceManagementService
from tests.factories.core_factories import create_full_customer
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase

MISSING_SERVICE = "0"


class ServiceManagementCoverageTests(VirtualminCoverageCase):
    def test_actions_persist_lifecycle_and_return_previous_and_current_state(self) -> None:
        cases = (
            ("start", "pending", "active", ""),
            ("stop", "active", "suspended", "manual_stop"),
            ("restart", "active", "active", ""),
            ("suspend", "active", "suspended", "billing hold"),
            ("resume", "suspended", "active", ""),
            ("check_status", "active", "active", ""),
        )
        for action, before, after, reason in cases:
            with self.subTest(action=action):
                force_status(self.service, before)
                result = ServiceManagementService.manage_service(str(self.service.pk), action, reason="billing hold")
                self.assertEqual(
                    result.unwrap(),
                    {
                        "service_id": str(self.service.pk),
                        "action": action,
                        "previous_status": before,
                        "current_status": after,
                        "success": True,
                    },
                )
                self.service.refresh_from_db()
                self.assertEqual(self.service.status, after)
                self.assertEqual(self.service.suspension_reason, reason)
                if after == "suspended":
                    self.assertIsNotNone(self.service.suspended_at)
                else:
                    self.assertIsNone(self.service.suspended_at)
                    self.assertIsNotNone(self.service.activated_at)

    def test_invalid_action_preserves_service(self) -> None:
        result = ServiceManagementService.manage_service(str(self.service.pk), "delete")
        self.assertIn("Invalid action 'delete'", result.unwrap_err())
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertEqual(self.broker.queued(), [])

    def test_missing_service_returns_errors_without_review_events(self) -> None:
        managed = ServiceManagementService.manage_service(MISSING_SERVICE, "check_status")
        reviewed = ServiceManagementService.mark_service_for_review(MISSING_SERVICE, "billing hold")
        self.assertEqual(managed.unwrap_err(), f"Service {MISSING_SERVICE} not found")
        self.assertEqual(reviewed.unwrap_err(), f"Service {MISSING_SERVICE} not found")
        self.assertFalse(AuditEvent.objects.filter(action="service_marked_for_review").exists())

    def test_resume_refuses_service_that_is_not_suspended(self) -> None:
        result = ServiceManagementService.manage_service(str(self.service.pk), "resume")
        self.assertEqual(result.unwrap_err(), f"Service {self.service.pk} is not suspended")
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertIsNone(self.service.activated_at)

    def test_invalid_transition_returns_error_and_preserves_service(self) -> None:
        force_status(self.service, "terminated")
        result = ServiceManagementService.manage_service(str(self.service.pk), "start")
        self.assertIn("Failed to start service:", result.unwrap_err())
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "terminated")
        self.assertIsNone(self.service.activated_at)

    def test_review_prepends_note_without_changing_state_and_records_audit(self) -> None:
        self.service.admin_notes = "Existing investigation"
        self.service.save(update_fields=["admin_notes"])
        result = ServiceManagementService.mark_service_for_review(str(self.service.pk), "billing hold")
        self.assertEqual(
            result.unwrap(),
            {
                "service_id": str(self.service.pk),
                "status": "active",
                "review_requested": True,
                "reason": "billing hold",
                "success": True,
            },
        )
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertEqual(self.service.admin_notes, "[REVIEW REQUESTED] billing hold\nExisting investigation")
        event = self._event("service_marked_for_review", self.service.pk)
        self.assertEqual(event.metadata["reason"], "billing hold")
        self.assertEqual(event.metadata["service_id"], str(self.service.pk))
        self.assertEqual(event.metadata["source_app"], "provisioning")

    def test_review_without_reason_persists_default_note(self) -> None:
        result = ServiceManagementService.mark_service_for_review(str(self.service.pk))
        self.assertTrue(result.unwrap()["review_requested"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.admin_notes, "[REVIEW REQUESTED] No reason specified")
        self.assertEqual(self._event("service_marked_for_review", self.service.pk).metadata["reason"], "")

    def test_activation_persists_state_timestamp_and_audit(self) -> None:
        for before in ("pending", "provisioning", "suspended"):
            with self.subTest(before=before):
                force_status(self.service, before)
                result = ProvisioningService.activate_service(self.service, "invoice settled")
                self.assertIs(result.unwrap(), True)
                self.service.refresh_from_db()
                self.assertEqual(self.service.status, "active")
                self.assertIsNotNone(self.service.activated_at)
                event = AuditEvent.objects.filter(action="service_activated", object_id=str(self.service.pk)).latest(
                    "timestamp"
                )
                self.assertEqual(event.metadata["previous_status"], before)
                self.assertEqual(event.metadata["activation_reason"], "invoice settled")
                self.assertEqual(event.metadata["activated_at"], self.service.activated_at.isoformat())

    def test_activation_rejects_terminal_service_without_success_audit(self) -> None:
        force_status(self.service, "terminated")
        result = ProvisioningService.activate_service(self.service)
        self.assertIn(f"Failed to activate service {self.service.pk}:", result.unwrap_err())
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "terminated")
        self.assertFalse(AuditEvent.objects.filter(action="service_activated").exists())

    def test_customer_suspension_changes_only_active_services_of_that_customer(self) -> None:
        pending = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Pending hosting",
            username="pending",
            price=Decimal("10.00"),
            status="pending",
        )
        outsider = Service.objects.create(
            customer=create_full_customer(),
            service_plan=self.plan,
            currency=self.currency,
            service_name="Other customer hosting",
            username="outsider",
            price=Decimal("10.00"),
            status="active",
        )
        result = ProvisioningService.suspend_services_for_customer(self.customer.pk, "usage_exceeded")
        self.assertEqual(result["services_suspended"], 1)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["success"])
        self.service.refresh_from_db()
        pending.refresh_from_db()
        outsider.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")
        self.assertEqual(self.service.suspension_reason, "usage_exceeded")
        self.assertIsNotNone(self.service.suspended_at)
        self.assertEqual(pending.status, "pending")
        self.assertEqual(outsider.status, "active")
        event = self._event("customer_services_suspended", self.customer.pk)
        self.assertEqual(event.metadata["services_suspended"], 1)
        self.assertEqual(event.metadata["reason"], "usage_exceeded")

    def test_missing_customer_suspension_returns_error_without_state_change(self) -> None:
        result = ProvisioningService.suspend_services_for_customer(0)
        self.assertEqual(result, {"success": False, "error": "Customer not found", "services_suspended": 0})
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertFalse(AuditEvent.objects.filter(action="customer_services_suspended").exists())
