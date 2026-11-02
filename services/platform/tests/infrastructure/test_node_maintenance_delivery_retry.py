"""Terminal notices recover configuration failures through the real scheduled sweep."""

from datetime import timedelta
from importlib import import_module
from unittest.mock import patch

from django.apps import apps
from django.core import mail
from django.core.mail.backends.locmem import EmailBackend
from django.db import connection
from django.test import Client, override_settings
from django.utils import timezone
from freezegun import freeze_time

from apps.infrastructure.node_maintenance_execution import create_emergency_window
from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy, NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.tasks import process_email_queue, send_email_task
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.users.models import CustomerMembership, User, UserProfile
from tests.api.test_node_maintenance_api import SUMMARY_PATH, _MaintenanceAPIFixture


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    Q_CLUSTER={"name": "maintenance-terminal-retry", "orm": "default", "retry": 100000, "sync": False},
)
class NodeMaintenanceDeliveryRetryTests(_MaintenanceAPIFixture):
    def setUp(self):
        self.clock_owner = freeze_time("2026-11-03T12:00:00Z")
        self.clock = self.clock_owner.start()
        self.addCleanup(self.clock_owner.stop)
        super().setUp()
        self.membership.is_primary = True
        self.membership.save(update_fields=["is_primary"])
        UserProfile.objects.update_or_create(user=self.user, defaults={"preferred_language": "en", "timezone": "UTC"})
        self.actor = User.objects.create_superuser(email="terminal-notice-operator@example.test", password=None)
        UserProfile.objects.update_or_create(user=self.actor, defaults={"preferred_language": "en", "timezone": "UTC"})
        self.staff_client = Client()
        self.staff_client.force_login(self.actor)
        self.seed_production_templates()

    def seed_production_templates(self):
        # Execute the actual data-migration seed against this test database. It only
        # uses the editor's connection alias; no schema operation/context is needed.
        migration = import_module("apps.infrastructure.migrations.0008_node_maintenance_templates")
        migration.seed_templates(apps, connection.schema_editor())

    def announce(self):
        with self.captureOnCommitCallbacks(execute=True):
            window_id = self._schedule(
                self.node, "Reviewed maintenance customer notice", starts_at=timezone.now() + timedelta(minutes=10)
            )
        window = NodeMaintenanceWindow.objects.get(pk=window_id)
        delivery = window.deliveries.get(kind="scheduled")
        self.assertIsNotNone(delivery.email_log_id)
        result = send_email_task(str(delivery.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertEqual(EmailLog.objects.get(pk=delivery.email_log_id).status, "sent")
        delivery.refresh_from_db()
        self.assertIsNotNone(delivery.first_dispatch_claimed_at)
        return window

    def finish_overrun(self, window):
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        self.clock.move_to(window.ends_at + timedelta(seconds=1))
        self.assertEqual(tick_node_maintenance()["overran"], 1)
        with self.captureOnCommitCallbacks(execute=True):
            self._action(
                str(window.pk),
                "finish",
                outcome="completed",
                attestation="on",
                public_outcome="Hosting recovery was checked after the work finished.",
            )
        window.refresh_from_db()
        self.assertEqual(window.status, "completed")

    def test_completed_configuration_failure_is_retried_by_normal_tick_after_templates_are_restored(self):
        window = self.announce()
        EmailTemplate.objects.filter(key="maintenance_completed").delete()
        self.finish_overrun(window)
        delivery = window.deliveries.get(kind="completed")
        original_intent = delivery.pk
        self.assertEqual(delivery.phase, "pending")
        self.assertIsNone(delivery.email_log_id)
        self.assertTrue(delivery.refusal_reason)
        self.seed_production_templates()
        self.clock.move_to(delivery.due_at - timedelta(seconds=1))
        tick_node_maintenance()
        delivery.refresh_from_db()
        self.assertIsNone(delivery.email_log_id, "A configuration retry ran before its recorded due time")
        self.clock.move_to(delivery.due_at + timedelta(seconds=1))

        with self.captureOnCommitCallbacks(execute=True):
            tick_node_maintenance()

        delivery.refresh_from_db()
        self.assertIsNotNone(delivery.email_log_id, "The normal sweep stranded a due terminal completion intent")
        self.assertEqual(delivery.pk, original_intent)
        result = send_email_task(str(delivery.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertIn("Hosting recovery was checked", mail.outbox[-1].body)
        log_id, count = delivery.email_log_id, EmailLog.objects.count()
        tick_node_maintenance()
        delivery.refresh_from_db()
        self.assertEqual(
            (delivery.pk, delivery.email_log_id, EmailLog.objects.count()), (original_intent, log_id, count)
        )

    def test_announced_cancellation_configuration_failure_is_retried_without_a_new_intent(self):
        window = self.announce()
        EmailTemplate.objects.filter(key="maintenance_correction").delete()
        with self.captureOnCommitCallbacks(execute=True):
            self._action(str(window.pk), "cancel")
        window.refresh_from_db()
        self.assertEqual(window.status, "cancelled")
        delivery = window.deliveries.get(kind="correction", revision=window.revision)
        original_intent = delivery.pk
        self.assertEqual(delivery.phase, "pending")
        self.assertIsNone(delivery.email_log_id)
        self.seed_production_templates()
        self.clock.move_to(delivery.due_at + timedelta(seconds=1))
        tick_node_maintenance([])
        delivery.refresh_from_db()
        self.assertIsNone(delivery.email_log_id, "An empty explicit tick scope expanded to another window")

        with self.captureOnCommitCallbacks(execute=True):
            tick_node_maintenance()

        delivery.refresh_from_db()
        self.assertIsNotNone(delivery.email_log_id, "The normal sweep stranded a due cancelled-window correction")
        self.assertEqual(delivery.pk, original_intent)
        result = send_email_task(str(delivery.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertIn("has been cancelled", mail.outbox[-1].body)
        self.assertEqual(window.deliveries.filter(kind="correction").count(), 1)

    def miss_announced_window(self):
        window = self.announce()
        self.assertEqual(set(window.audience.values_list("provenance", flat=True)), {"scheduled"})
        self.clock.move_to(window.start_by + timedelta(seconds=1))
        with self.captureOnCommitCallbacks(execute=True):
            outcome = tick_node_maintenance()
        self.assertEqual(outcome["not_run"], 1)
        window.refresh_from_db()
        self.assertEqual(window.status, "failed")
        self.assertIsNone(window.started_at)
        self.assertFalse(window.executions.exists())
        self.assertEqual(set(window.audience.values_list("provenance", flat=True)), {"not_run"})
        return window

    def test_announced_not_run_window_sends_a_truthful_outcome_without_a_fake_execution(self):
        window = self.miss_announced_window()
        delivery = window.deliveries.filter(kind="completed").first()
        self.assertIsNotNone(delivery, "The actual announced, not-run window has no customer outcome mail")
        self.assertEqual(delivery.selected_service_ids, [self.service.pk])
        result = send_email_task(str(delivery.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertIn("did not run", mail.outbox[-1].body)
        self.assertEqual(mail.outbox[-1].to, [self.customer.primary_email])
        self.assertFalse(window.executions.exists())

    def test_announced_not_run_window_retains_its_signed_customer_receipt_for_twenty_four_hours(self):
        window = self.miss_announced_window()
        for age, visible in (
            (timedelta(0), True),
            (timedelta(hours=24, seconds=-1), True),
            (timedelta(hours=24), False),
        ):
            self.clock.move_to(window.finished_at + age)
            for path in (SUMMARY_PATH, self.service_path):
                with self.subTest(age=age, path=path):
                    response = self.portal_post(path, self._identity())
                    self.assertEqual(response.status_code, 200, response.content)
                    receipt = response.json()["data"]["maintenance"]["last_completed"]
                    self.assertEqual(
                        receipt is not None, visible, "The announced plan vanished without its not-run receipt"
                    )
                    if visible:
                        self.assertEqual(receipt["id"], str(window.pk))
                        self.assertEqual(receipt["service_ids"], [self.service.pk])
                        self.assertIn("did not run", receipt["public_outcome"])

    def test_transferred_service_does_not_leak_its_not_run_receipt_or_queued_mail_to_the_former_owner(self):
        window = self.miss_announced_window()
        delivery = window.deliveries.filter(kind="completed").first()
        self.assertIsNotNone(delivery)
        self.assertIsNotNone(delivery.email_log_id)
        self.service.customer = self.other_customer
        self.service.save(update_fields=["customer", "updated_at"])

        summary = self.portal_post(SUMMARY_PATH, self._identity())
        self.assertEqual(summary.status_code, 200)
        self.assertIsNone(summary.json()["data"]["maintenance"]["last_completed"])
        self.assertEqual(self.portal_post(self.service_path, self._identity()).status_code, 404)
        result = send_email_task(str(delivery.email_log_id))
        self.assertFalse(result["success"])
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(
            len(mail.outbox), 1, "The former owner received a new service outcome after ownership transfer"
        )
        self.assertFalse(window.executions.exists())

    def test_service_arriving_after_the_not_run_outcome_does_not_inherit_an_unrelated_receipt(self):
        window = self.miss_announced_window()
        self.clock.move_to(window.finished_at + timedelta(minutes=1))
        CustomerMembership.objects.create(customer=self.other_customer, user=self.user, role="owner")
        VirtualminAccount.objects.create(
            service=self.foreign_service,
            server=self.node,
            domain=self.foreign_service.domain,
            virtualmin_username="arrived-after-not-run",
            status="active",
        )

        response = self.portal_post(SUMMARY_PATH, self._identity(customer_id=self.other_customer.pk))

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(
            response.json()["data"]["maintenance"]["last_completed"],
            "A newly arrived service inherited a plan which failed before it was on the node",
        )
        self.assertFalse(window.executions.exists())

    def test_service_arriving_before_the_not_run_outcome_keeps_its_truthful_planned_receipt(self):
        window = self.announce()
        self.clock.move_to(timezone.now() + timedelta(minutes=5))
        self.other_customer.primary_email = "arrived-before-outcome@example.test"
        self.other_customer.save(update_fields=["primary_email"])
        CustomerMembership.objects.create(customer=self.other_customer, user=self.user, role="owner")
        VirtualminAccount.objects.create(
            service=self.foreign_service,
            server=self.node,
            domain=self.foreign_service.domain,
            virtualmin_username="arrived-before-not-run",
            status="active",
        )
        self.clock.move_to(window.start_by + timedelta(seconds=1))
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(tick_node_maintenance()["not_run"], 1)

        response = self.portal_post(SUMMARY_PATH, self._identity(customer_id=self.other_customer.pk))

        self.assertEqual(response.status_code, 200, response.content)
        receipt = response.json()["data"]["maintenance"]["last_completed"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["service_ids"], [self.foreign_service.pk])
        self.assertIn("did not run", receipt["public_outcome"])
        delivery = window.deliveries.get(kind="completed", customer=self.other_customer)
        self.assertTrue(send_email_task(str(delivery.email_log_id))["success"])
        self.assertEqual(mail.outbox[-1].to, [self.other_customer.primary_email])
        self.assertFalse(window.executions.exists())

    def test_existing_transport_retry_keeps_the_original_log_and_claim_budget(self):
        window = self.announce()
        self.finish_overrun(window)
        delivery = window.deliveries.get(kind="completed")
        original_intent, log_id = delivery.pk, delivery.email_log_id
        with patch.object(EmailBackend, "send_messages", side_effect=OSError("Disposable provider interruption")):
            result = send_email_task(str(log_id))
        self.assertFalse(result["success"])
        self.assertTrue(result["retry_scheduled"])
        log = EmailLog.objects.get(pk=log_id)
        self.assertEqual(log.delivery_attempts, 1)
        count = EmailLog.objects.count()
        self.clock.move_to(log.next_attempt_at + timedelta(seconds=1))
        with self.captureOnCommitCallbacks(execute=True):
            tick_node_maintenance()
            process_email_queue()
        delivery.refresh_from_db()
        self.assertEqual(
            (delivery.pk, delivery.email_log_id, EmailLog.objects.count()), (original_intent, log_id, count)
        )
        result = send_email_task(str(log_id))
        self.assertTrue(result["success"], result)
        log.refresh_from_db()
        self.assertEqual(log.delivery_attempts, 2)
        self.assertEqual(log.status, "sent")
        self.assertEqual(len(mail.outbox), 2)

    def test_announced_move_sends_one_correction_without_a_second_scheduled_notice_on_next_tick(self):
        window = self.announce()
        with self.captureOnCommitCallbacks(execute=True):
            self._action(
                str(window.pk),
                "move",
                starts_at=(window.starts_at + timedelta(minutes=1)).isoformat(),
                ends_at=(window.ends_at + timedelta(minutes=1)).isoformat(),
                customer_note="The announced maintenance time has changed.",
            )
        window.refresh_from_db()
        correction = window.deliveries.get(kind="correction", revision=window.revision)
        self.assertTrue(send_email_task(str(correction.email_log_id))["success"])
        with self.captureOnCommitCallbacks(execute=True):
            tick_node_maintenance()
        for delivery in window.deliveries.filter(revision=window.revision, email_log__status="queued"):
            result = send_email_task(str(delivery.email_log_id))
            self.assertTrue(result["success"], result)

        self.assertEqual(
            len(mail.outbox), 2, "The next normal tick sent both a correction and a fresh schedule for one move"
        )
        self.assertEqual(
            set(window.deliveries.filter(revision=window.revision).values_list("kind", flat=True)), {"correction"}
        )

    def without_downtime(self, seconds):
        if not NodeMaintenancePolicy.objects.filter(node=self.node).exists():
            configured = self.staff_client.post(
                f"/infrastructure/maintenance/servers/{self.node.pk}/policy/",
                {
                    "timezone": "UTC",
                    "weekdays": [str(day) for day in range(7)],
                    "starts_time": "00:00",
                    "ends_time": "23:59",
                    "max_defer_minutes": "30",
                },
            )
            self.assertEqual(configured.status_code, 302, configured.content)
        starts = timezone.now() + timedelta(minutes=10)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.staff_client.post(
                f"/infrastructure/maintenance/servers/{self.node.pk}/create/",
                {
                    "kind": "panel_update",
                    "execution_mode": "manual",
                    "starts_at": starts.isoformat(),
                    "ends_at": (starts + timedelta(seconds=seconds)).isoformat(),
                    "expected_downtime_minutes": "0",
                    "customer_note": "Software updates without expected unavailability.",
                },
            )
        self.assertEqual(response.status_code, 302, response.content)
        return NodeMaintenanceWindow.objects.get(node=self.node, status="scheduled")

    def test_quiet_boundary_applies_to_actual_email_transport_at_four_fifty_nine_and_exactly_five(self):
        quiet = self.without_downtime(299)
        self.assertFalse(quiet.deliveries.exists())
        self.assertFalse(EmailLog.objects.exists())
        self._action(str(quiet.pk), "cancel")

        threshold = self.without_downtime(300)
        notice = threshold.deliveries.get(kind="scheduled")
        result = send_email_task(str(notice.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("No downtime is expected.", mail.outbox[0].body)

    def test_successful_ordinary_on_time_completion_does_not_create_a_completion_email(self):
        window = self.announce()
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        self.clock.move_to(window.starts_at + timedelta(minutes=1))
        self._action(
            str(window.pk), "finish", outcome="completed", attestation="on", public_outcome="On-time work was checked."
        )
        window.refresh_from_db()
        self.assertEqual(window.status, "completed")
        self.assertFalse(window.was_overrun)
        tick_node_maintenance()
        self.assertFalse(window.deliveries.filter(kind="completed").exists())
        self.assertEqual(EmailLog.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_failed_ordinary_work_sends_its_actual_outcome_even_before_the_planned_end(self):
        window = self.announce()
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        self.clock.move_to(window.starts_at + timedelta(minutes=1))
        self._action(
            str(window.pk),
            "finish",
            outcome="failed",
            attestation="on",
            public_outcome="The update failed and the original hosting state was checked.",
        )
        window.refresh_from_db()
        self.assertEqual(window.status, "failed")
        self.assertFalse(window.was_overrun)
        notice = window.deliveries.get(kind="completed")
        result = send_email_task(str(notice.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("The update failed and the original hosting state was checked.", mail.outbox[-1].body)

    def test_emergency_without_policy_sends_immediately_and_on_time_completion_still_notifies(self):
        self.assertFalse(NodeMaintenancePolicy.objects.filter(node=self.node).exists())
        with self.captureOnCommitCallbacks(execute=True):
            window = create_emergency_window(
                self.node.pk,
                reason="Private operator emergency diagnosis",
                timezone_name="UTC",
                duration_minutes=1,
                actor=self.actor,
            )
        notice = window.deliveries.get(kind="scheduled")
        self.assertLessEqual(notice.due_at, timezone.now())
        self.assertTrue(send_email_task(str(notice.email_log_id))["success"])
        self.assertIn("Emergency work is underway", mail.outbox[-1].body)
        self.assertNotIn("Private operator emergency diagnosis", mail.outbox[-1].body)
        self.clock.move_to(window.starts_at + timedelta(seconds=10))
        self._action(
            str(window.pk),
            "finish",
            outcome="completed",
            attestation="on",
            public_outcome="Emergency hosting recovery checked.",
        )
        window.refresh_from_db()
        self.assertFalse(window.was_overrun)
        completion = window.deliveries.get(kind="completed")
        self.assertTrue(send_email_task(str(completion.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("Emergency hosting recovery checked.", mail.outbox[-1].body)

    def test_announced_window_moved_to_a_quiet_interval_still_sends_only_its_correction(self):
        window = self.without_downtime(600)
        notice = window.deliveries.get(kind="scheduled")
        self.assertTrue(send_email_task(str(notice.email_log_id))["success"])
        replacement = window.starts_at + timedelta(minutes=1)
        self._action(
            str(window.pk),
            "move",
            starts_at=replacement.isoformat(),
            ends_at=(replacement + timedelta(seconds=299)).isoformat(),
            customer_note="Shorter maintenance without downtime.",
        )
        window.refresh_from_db()
        correction = window.deliveries.get(kind="correction", revision=window.revision)
        self.assertTrue(send_email_task(str(correction.email_log_id))["success"])
        tick_node_maintenance()
        self.assertEqual(
            set(window.deliveries.filter(revision=window.revision).values_list("kind", flat=True)), {"correction"}
        )
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("Shorter maintenance without downtime.", mail.outbox[-1].body)

    def test_transferred_announced_service_only_sends_a_generic_withdrawal_to_the_former_owner(self):
        window = self.announce()
        self.other_customer.primary_email = "new-service-owner@example.test"
        self.other_customer.save(update_fields=["primary_email"])
        self.service.customer = self.other_customer
        self.service.save(update_fields=["customer", "updated_at"])
        self._action(str(window.pk), "cancel")
        window.refresh_from_db()
        correction = window.deliveries.get(kind="correction", revision=window.revision)
        self.assertEqual(correction.selected_service_ids, [])
        self.assertIs(correction.public_snapshot["withdrawal"], True)
        self.assertTrue(send_email_task(str(correction.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[-1].to, [self.customer.primary_email])
        self.assertIn("no longer applies to your account", mail.outbox[-1].body)
        self.assertNotIn("Reviewed maintenance customer notice", mail.outbox[-1].body)
        self.assertFalse(window.deliveries.filter(customer=self.other_customer).exists())

    def test_same_owner_moving_service_off_node_still_receives_announced_cancellation(self):
        window = self.announce()
        destination = VirtualminServer.objects.create(hostname="moved-after-announcement.example.test")
        self.account.server = destination
        self.account.save(update_fields=["server", "updated_at"])
        self._action(str(window.pk), "cancel")
        window.refresh_from_db()
        correction = window.deliveries.get(kind="correction", revision=window.revision)
        self.assertEqual(correction.selected_service_ids, [self.service.pk])
        self.assertIs(correction.public_snapshot["withdrawal"], False)
        self.assertTrue(send_email_task(str(correction.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("has been cancelled", mail.outbox[-1].body)

    def queued_move_correction(self):
        window = self.announce()
        with self.captureOnCommitCallbacks(execute=True):
            self._action(
                str(window.pk),
                "move",
                starts_at=(window.starts_at + timedelta(minutes=1)).isoformat(),
                ends_at=(window.ends_at + timedelta(minutes=1)).isoformat(),
                customer_note="The announced maintenance time changed.",
            )
        window.refresh_from_db()
        self.assertEqual(window.revision, 2)
        correction = window.deliveries.get(kind="correction", revision=2)
        self.assertEqual(EmailLog.objects.get(pk=correction.email_log_id).status, "queued")
        return window, correction

    def test_current_move_correction_survives_public_start_without_a_revision_change(self):
        window, correction = self.queued_move_correction()
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        window.refresh_from_db()
        self.assertEqual((window.revision, window.status), (2, "running"))

        result = send_email_task(str(correction.email_log_id))

        correction.refresh_from_db()
        self.assertTrue(result["success"], {"worker": result, "refusal": correction.refusal_reason})
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("The announced maintenance time changed.", mail.outbox[-1].body)

    def test_current_move_correction_keeps_its_log_and_retry_when_work_finishes_on_time(self):
        window, correction = self.queued_move_correction()
        log_id = correction.email_log_id
        with patch.object(
            EmailBackend, "send_messages", side_effect=OSError("Disposable correction transport failure")
        ):
            first = send_email_task(str(log_id))
        self.assertFalse(first["success"])
        self.assertTrue(first["retry_scheduled"])
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        self.clock.move_to(window.starts_at + timedelta(seconds=30))
        self._action(
            str(window.pk),
            "finish",
            outcome="completed",
            attestation="on",
            public_outcome="On-time moved work was checked.",
        )
        window.refresh_from_db()
        self.assertEqual((window.revision, window.status), (2, "completed"))
        log = EmailLog.objects.get(pk=log_id)
        if log.next_attempt_at > timezone.now():
            self.clock.move_to(log.next_attempt_at + timedelta(seconds=1))
        with self.captureOnCommitCallbacks(execute=True):
            process_email_queue()

        result = send_email_task(str(log_id))

        correction.refresh_from_db()
        self.assertTrue(result["success"], {"worker": result, "refusal": correction.refusal_reason})
        self.assertEqual(correction.email_log_id, log_id)
        self.assertEqual(EmailLog.objects.get(pk=log_id).delivery_attempts, 2)
        self.assertEqual(len(mail.outbox), 2)
        self.assertFalse(window.deliveries.filter(kind="completed").exists())

    def test_cancelling_at_a_new_revision_refuses_the_older_move_correction(self):
        window, correction = self.queued_move_correction()
        self._action(str(window.pk), "cancel")
        window.refresh_from_db()
        self.assertEqual((window.revision, window.status), (3, "cancelled"))

        obsolete = send_email_task(str(correction.email_log_id))

        self.assertFalse(obsolete["success"])
        self.assertFalse(obsolete["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 1)
        current = window.deliveries.get(kind="correction", revision=3)
        self.assertTrue(send_email_task(str(current.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("has been cancelled", mail.outbox[-1].body)

    def test_starting_current_move_does_not_allow_old_owner_details_after_transfer(self):
        window, correction = self.queued_move_correction()
        self.clock.move_to(window.starts_at)
        self._action(str(window.pk), "start")
        self.service.customer = self.other_customer
        self.service.save(update_fields=["customer", "updated_at"])

        result = send_email_task(str(correction.email_log_id))

        self.assertFalse(result["success"])
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(EmailLog.objects.get(pk=correction.email_log_id).provider_response["permanent_failure"])
