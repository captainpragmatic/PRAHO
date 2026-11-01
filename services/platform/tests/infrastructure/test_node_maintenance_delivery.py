"""Public window events produce one durable, preference-aware normal email delivery."""

from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_delivery import (
    dispatch_due_notices,
    maintenance_dispatch_allowed,
    publish_window_notices,
)
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceAudience,
    NodeMaintenanceDelivery,
)
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.notifications.delivery import claim_delivery
from apps.notifications.models import EmailLog, EmailPreference, EmailTemplate
from apps.notifications.tasks import send_email_task
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-mail", "orm": "default", "retry": 100000})
class NodeMaintenanceDeliveryTests(MaintenanceAdmissionFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.customer.primary_email = "maintenance-delivery@example.test"
        self.customer.save(update_fields=["primary_email"])
        for key in ("maintenance_scheduled", "maintenance_completed", "maintenance_correction"):
            for locale in ("en", "ro"):
                EmailTemplate.objects.get_or_create(
                    key=key,
                    locale=locale,
                    defaults={
                        "subject": "{{ event_label }}",
                        "body_html": "<p>{{ customer_note }}</p>",
                        "body_text": "{{ customer_note }}",
                        "category": "maintenance",
                    },
                )

    def schedule(self, *, minutes: float = 30, downtime: bool = True) -> None:
        starts_at = timezone.now() + timedelta(minutes=10)
        create_window(
            self.node.pk,
            actor=self.actor,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=minutes),
            expects_downtime=downtime,
            expected_downtime_minutes=5 if downtime else 0,
            customer_note="Updates may briefly interrupt your website.",
        )

    def test_late_notice_deduplicates_several_accounts_for_one_customer(self) -> None:
        self.account_on_node("admission-two.example.test")

        self.schedule()

        self.assertEqual(NodeMaintenanceAudience.objects.count(), 2)
        self.assertEqual(NodeMaintenanceDelivery.objects.count(), 1)
        intent = NodeMaintenanceDelivery.objects.get()
        self.assertEqual(intent.customer_id, self.customer.pk)
        self.assertEqual(set(intent.selected_service_ids), set(self.customer.services.values_list("pk", flat=True)))
        self.assertIsNotNone(intent.email_log_id)
        self.assertEqual(EmailLog.objects.filter(pk=intent.email_log_id).count(), 1)
        self.assertEqual(intent.email_log.template_key, "maintenance_scheduled")

    def test_an_opted_out_customer_retains_audience_without_an_email(self) -> None:
        EmailPreference.objects.update_or_create(customer=self.customer, defaults={"service": False})

        self.schedule()

        self.assertEqual(NodeMaintenanceAudience.objects.count(), 1)
        self.assertEqual(NodeMaintenanceDelivery.objects.count(), 1)
        intent = NodeMaintenanceDelivery.objects.get()
        self.assertEqual(intent.phase, "refused")
        self.assertEqual(intent.refusal_reason, "maintenance_opt_out")
        self.assertIsNone(intent.email_log_id)
        self.assertFalse(EmailLog.objects.exists())

    def test_quiet_windows_under_five_minutes_do_not_send(self) -> None:
        self.schedule(minutes=4 + 59 / 60, downtime=False)
        self.assertEqual(NodeMaintenanceAudience.objects.count(), 1)
        self.assertFalse(NodeMaintenanceDelivery.objects.exists())
        self.assertFalse(EmailLog.objects.exists())

    def test_exactly_five_minutes_is_not_a_quiet_window(self) -> None:
        self.schedule(minutes=5, downtime=False)
        self.assertEqual(NodeMaintenanceDelivery.objects.count(), 1)
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_opt_out_after_queueing_stops_the_actual_worker_and_its_retry(self) -> None:
        self.schedule()
        intent = NodeMaintenanceDelivery.objects.get()
        EmailPreference.objects.update_or_create(customer=self.customer, defaults={"service": False})

        result = send_email_task(str(intent.email_log_id))

        self.assertFalse(result["success"])
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 0)
        log = EmailLog.objects.get(pk=intent.email_log_id)
        self.assertEqual(log.status, "failed")
        self.assertTrue(log.provider_response["permanent_failure"])
        self.assertIsNone(log.next_attempt_at)
        self.assertFalse(send_email_task(str(log.pk))["success"])

    def test_cancelled_unsent_notice_is_cleanly_refused_by_actual_worker(self) -> None:
        self.schedule()
        intent = NodeMaintenanceDelivery.objects.get()
        change_window(intent.window_id, actor=self.actor, revision=1, action="cancel", reason="Work no longer required")

        result = send_email_task(str(intent.email_log_id))

        self.assertEqual(result.get("error"), "Maintenance delivery is no longer permitted")
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(NodeMaintenanceDelivery.objects.filter(kind="correction").exists())

    def test_announced_cancel_creates_one_correction_for_the_existing_recipient(self) -> None:
        self.schedule()
        intent = NodeMaintenanceDelivery.objects.get()
        log, refusal = claim_delivery(str(intent.email_log_id))
        self.assertIsNone(refusal)
        self.assertIsNotNone(log)
        self.assertTrue(maintenance_dispatch_allowed(str(log.pk), log.claim_token))

        window = change_window(intent.window_id, actor=self.actor, revision=1, action="cancel", reason="Work withdrawn")
        publish_window_notices(window, "correction")

        correction = NodeMaintenanceDelivery.objects.get(kind="correction")
        self.assertEqual(correction.revision, 2)
        self.assertEqual(correction.customer_id, self.customer.pk)
        self.assertEqual(correction.selected_service_ids, [self.account.service_id])
        self.assertEqual(EmailLog.objects.count(), 2)

    def test_service_ownership_change_stops_previously_queued_details(self) -> None:
        self.schedule()
        intent = NodeMaintenanceDelivery.objects.get()
        from apps.customers.models import Customer  # noqa: PLC0415  # Ownership mutation fixture

        new_owner = Customer.objects.create(name="New maintenance owner", primary_email="new-owner@example.test")
        self.account.service.customer = new_owner
        self.account.service.save(update_fields=["customer", "updated_at"])

        result = send_email_task(str(intent.email_log_id))

        self.assertFalse(result["success"])
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(EmailLog.objects.get(pk=intent.email_log_id).provider_response["permanent_failure"])

    def test_due_notice_refreshes_customers_added_after_scheduling(self) -> None:
        window = self.window(future=True)
        first_customer = self.customer
        self.customer = Customer.objects.create(name="Later hosting customer", primary_email="later@example.test")
        self.account_on_node("later-customer.example.test")

        with patch("django.utils.timezone.now", return_value=window.starts_at - timedelta(hours=48)):
            dispatch_due_notices()

        self.assertEqual(
            set(NodeMaintenanceDelivery.objects.values_list("customer_id", flat=True)),
            {first_customer.pk, self.customer.pk},
        )
        self.assertEqual(EmailLog.objects.count(), 2)

    def test_unannounced_moved_service_does_not_receive_the_old_nodes_due_notice(self) -> None:
        window = self.window(future=True)
        new_node = VirtualminServer.objects.create(name="Later node", hostname="later-node.example.test")
        self.account.server = new_node
        self.account.save(update_fields=["server", "updated_at"])

        with patch("django.utils.timezone.now", return_value=window.starts_at - timedelta(hours=48)):
            dispatch_due_notices()

        self.assertFalse(EmailLog.objects.exists())
        self.assertEqual(NodeMaintenanceDelivery.objects.get().phase, "refused")

    def test_a_queued_upcoming_notice_is_refused_after_the_service_moves_off_the_node(self) -> None:
        self.schedule()
        intent = NodeMaintenanceDelivery.objects.get()
        self.assertEqual(intent.selected_service_ids, [self.account.service_id])
        other = VirtualminServer.objects.create(hostname="moved-dispatch-review.example.test")
        self.account.server = other
        self.account.save(update_fields=["server", "updated_at"])

        result = send_email_task(str(intent.email_log_id))

        self.assertFalse(result["success"], "The actual worker sent an obsolete upcoming notice for the old placement")
        self.assertEqual(len(mail.outbox), 0)

    def test_a_service_moved_before_execution_is_not_in_the_failed_completion_audience(self) -> None:
        window = self.window()
        new_node = VirtualminServer.objects.create(name="Unaffected node", hostname="unaffected-node.example.test")
        self.account.server = new_node
        self.account.save(update_fields=["server", "updated_at"])
        self.start(window)

        change_window(
            window.pk,
            actor=self.actor,
            revision=1,
            action="finish",
            reason="Actual manual work stopped",
            outcome="failed",
            public_outcome="The planned work did not complete.",
            attestation=True,
        )

        self.assertFalse(NodeMaintenanceDelivery.objects.filter(kind="completed").exists())
