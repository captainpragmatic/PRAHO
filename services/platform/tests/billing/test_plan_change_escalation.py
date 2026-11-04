"""Overdue accepted downgrades become one urgent, private staff-review obligation."""

from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection
from django.test import TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService
from apps.billing.payment_models import Payment
from apps.billing.plan_change_lifecycle import _cancel_context, activate_scheduled_plan_change
from apps.billing.plan_change_operations import reconcile_plan_change_operation
from apps.billing.refund_models import Refund
from apps.notifications.models import EmailLog
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.users.models import CustomerMembership, User
from tests.billing import test_plan_change_lifecycle as lifecycle_tests
from tests.billing.test_plan_change_operations import PlanOperationFixture
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.provisioning.test_hosting_safety_observation import HostingSafetyObservationFixture

ACTION = "hosting_plan_change_attention"


class ScheduledDowngradeEscalationTests(PlanOperationFixture, TransactionTestCase):
    period_remaining = timedelta(days=10)
    scheduled = lifecycle_tests.ScheduledPlanChangeTests.scheduled
    transfer_to_another_customer = lifecycle_tests.PlanChangeCancellationTests.transfer_to_another_customer
    probe = HostingSafetyObservationFixture.probe
    safety_request = HostingSafetyObservationFixture.request
    run_observer = HostingSafetyObservationFixture.run_observer

    def attention_at_boundary(self):
        change = self.scheduled()
        target_plan = self.target.default_service_plan
        target_plan.features = {"changed_after_customer_acceptance": True}
        target_plan.save(update_fields=["features"])
        with patch("django.utils.timezone.now", return_value=change.effective_at):
            change = activate_scheduled_plan_change(change.pk)
        self.assertEqual(change.status, "limits_attention")
        return change

    def reconcile_due(self, change):
        with patch("django.utils.timezone.now", return_value=change.effective_at):
            return reconcile_plan_change_operation(change.pk)

    def test_public_scheduled_downgrade_failure_appears_once_in_actual_staff_review_queue(self):
        change = self.attention_at_boundary()
        mail_count = EmailLog.objects.count()
        money = (Payment.objects.count(), Refund.objects.count())
        before_status = (self.service.status, self.account.status)
        with (
            patch("apps.infrastructure.ansible_service.AnsibleService.run_server_playbook") as native,
            CaptureQueriesContext(connection) as queries,
        ):
            self.reconcile_due(change)
        native.assert_not_called()
        for query in queries.captured_queries:
            if "FOR UPDATE" in query["sql"] or "FOR NO KEY UPDATE" in query["sql"]:
                self.assertNotIn('"provisioning_virtualmin_accounts"', query["sql"])
                self.assertNotIn('"provisioning_virtualmin_servers"', query["sql"])
        self.assertEqual(AuditEvent.objects.filter(action=ACTION).count(), 1)
        event = AuditEvent.objects.get(action=ACTION)
        self.assertEqual((event.severity, event.requires_review, event.actor_type), ("high", True, "system"))
        self.assertEqual(event.object_id, str(change.pk))
        change.refresh_from_db()
        self.assertEqual(change.staff_escalated_at, change.effective_at)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.unit_price_cents, self.service.price), (4000, 40))
        self.assertIsNone(change.limit_application_id)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).disk_allowance_mib, 5120)
        self.assertEqual(EmailLog.objects.count(), mail_count)
        self.assertEqual((Payment.objects.count(), Refund.objects.count()), money)
        self.account.refresh_from_db()
        self.assertEqual((self.service.status, self.account.status), before_status)

        for _repeat in range(2):
            self.reconcile_due(change)
        self.assertEqual(AuditEvent.objects.filter(action=ACTION).count(), 1)
        staff = User.objects.create_user(email="plan-escalation-staff@example.test", staff_role="support")
        self.client.force_login(staff)
        page = self.client.get(reverse("audit:review_queue"))
        self.assertContains(page, event.description)
        self.client.force_login(self.actor)
        self.assertEqual(self.client.get(reverse("audit:review_queue")).status_code, 403)

    def test_no_due_boundary_does_not_create_an_urgent_staff_event(self):
        change = self.attention_at_boundary()
        self.assertEqual(reconcile_plan_change_operation(change.pk).status, "limits_attention")
        self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())
        change.refresh_from_db()
        self.assertIsNone(change.staff_escalated_at)

    def test_verified_completion_does_not_escalate_a_successful_scheduled_change(self):
        change = self.scheduled()
        with patch("django.utils.timezone.now", return_value=change.effective_at):
            change = activate_scheduled_plan_change(change.pk)
            self.apply(change)
            completed = reconcile_plan_change_operation(change.pk)
        self.assertEqual(completed.status, "completed")
        self.assertIsNone(completed.staff_escalated_at)
        self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())

    def test_upgrade_attention_does_not_claim_an_overdue_downgrade(self):
        change = self.paid_change()
        self.apply(change)
        self.server.api_port += 1
        self.server.save(update_fields=["api_port"])
        current = reconcile_plan_change_operation(change.pk)
        self.assertEqual(current.status, "limits_attention")
        self.assertIsNone(current.staff_escalated_at)
        self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())

    def test_actual_owner_transfer_requires_review_without_escalating_old_owner_details(self):
        change = self.attention_at_boundary()
        self.transfer_to_another_customer()
        current = self.reconcile_due(change)
        self.assertEqual(current.status, "paid_review")
        self.assertIsNone(current.staff_escalated_at)
        self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())

    def test_public_erasure_prevents_new_staff_escalation_with_old_customer_identity(self):
        change = self.attention_at_boundary()
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        CustomerMembership.objects.filter(customer=self.customer, user=self.actor).update(role="owner")
        request = GDPRDeletionService.create_deletion_request(user=self.actor)
        self.assertTrue(request.is_ok(), request)
        erased = GDPRDeletionService.process_deletion_request(request.unwrap())
        self.assertTrue(erased.is_ok(), erased)
        self.customer.refresh_from_db()
        self.assertIsNotNone(self.customer.anonymized_at)
        current = self.reconcile_due(change)
        self.assertEqual(current.status, "paid_review")
        self.assertIsNone(current.staff_escalated_at)
        self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())

    def test_staff_marker_cannot_be_cleared_and_prior_event_keeps_its_original_safe_scope(self):
        change = self.attention_at_boundary()
        self.reconcile_due(change)
        event = AuditEvent.objects.get(action=ACTION)
        original_values, original_description = dict(event.new_values), event.description
        self.assertEqual(
            set(event.new_values),
            {
                "plan_change_id",
                "service_id",
                "customer_id",
                "subscription_id",
                "effective_at",
                "target_plan_id",
                "agreed_period_price_cents",
            },
        )
        self.assertNotIn(self.customer.primary_email, str(event.new_values))
        change.refresh_from_db()
        change.staff_escalated_at = None
        with self.assertRaises(ValidationError):
            change.save(update_fields=["staff_escalated_at"])
        self.transfer_to_another_customer()
        self.reconcile_due(change)
        event.refresh_from_db()
        self.assertEqual((event.new_values, event.description), (original_values, original_description))
        self.assertEqual(AuditEvent.objects.filter(action=ACTION).count(), 1)

    @skipUnless(connection.vendor == "postgresql", "Exact independent-connection PostgreSQL lock proof")
    def test_two_actual_reconcilers_wait_on_the_same_commercial_boundary_and_emit_once(self):
        change = self.attention_at_boundary()
        gate = Event()

        def replay():
            if not gate.wait(10):
                raise AssertionError("The owner of the commercial boundary never admitted the replay")
            return reconcile_plan_change_operation(change.pk).status

        writer = backend_pid()
        with (
            patch("django.utils.timezone.now", return_value=change.effective_at),
            database_worker(replay) as (pid, pending),
        ):
            with _cancel_context(change.pk):
                self.assertEqual(reconcile_plan_change_operation(change.pk).status, "limits_attention")
                gate.set()
                query = wait_for_blocker(pid, writer, pending, table="customers")
                self.assertIn("FOR NO KEY UPDATE", query)
            self.assertEqual(pending.result(timeout=15), "limits_attention")
        self.assertEqual(AuditEvent.objects.filter(action=ACTION).count(), 1)
        change.refresh_from_db()
        self.assertIsNotNone(change.staff_escalated_at)

    @skipUnless(connection.vendor == "postgresql", "Actual PostgreSQL audit INSERT failure")
    def test_real_audit_insert_failure_leaves_marker_unset_and_existing_lower_price_intact(self):
        change = self.attention_at_boundary()
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE FUNCTION praho_test_plan_escalation_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.action = 'hosting_plan_change_attention' THEN
                        RAISE EXCEPTION 'fixture escalation audit write failure';
                    END IF;
                    RETURN NEW;
                END;
                $$;
                CREATE TRIGGER praho_test_plan_escalation_failure BEFORE INSERT ON audit_events
                FOR EACH ROW EXECUTE FUNCTION praho_test_plan_escalation_failure();
            """)
        try:
            with self.assertRaisesMessage(DatabaseError, "fixture escalation audit write failure"):
                self.reconcile_due(change)
            change.refresh_from_db()
            self.assertIsNone(change.staff_escalated_at)
            self.assertFalse(AuditEvent.objects.filter(action=ACTION).exists())
            self.subscription.refresh_from_db()
            self.assertEqual(self.subscription.unit_price_cents, 4000)
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TRIGGER praho_test_plan_escalation_failure ON audit_events")
                cursor.execute("DROP FUNCTION praho_test_plan_escalation_failure()")
        self.reconcile_due(change)
        change.refresh_from_db()
        self.assertIsNotNone(change.staff_escalated_at)
        self.assertEqual(AuditEvent.objects.filter(action=ACTION).count(), 1)
