"""Retained mail/DNS is a live customer dependency after website ownership moves."""

from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, override_settings
from django.utils.translation import override

from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_delivery import dispatch_due_notices
from apps.infrastructure.node_maintenance_models import NodeMaintenanceDelivery
from apps.infrastructure.node_maintenance_service import change_window
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from apps.infrastructure.node_maintenance_views import node_maintenance_context
from apps.notifications.models import EmailPreference
from apps.notifications.tasks import send_email_task
from tests.infrastructure.maintenance_retained_fixtures import RetainedMaintenanceFixture


@override_settings(Q_CLUSTER={"name": "retained-maintenance", "orm": "default", "retry": 100000})
class RetainedMaintenanceAudienceTests(RetainedMaintenanceFixture, TestCase):
    def test_public_source_window_captures_retained_service_and_sends_once(self) -> None:
        self.publish_retained_website()

        window = self.schedule_source()

        self.assertEqual(list(window.audience.values_list("service_id_snapshot", flat=True)), [self.account.service_id])
        intent = NodeMaintenanceDelivery.objects.get(window=window)
        self.assertEqual(intent.selected_service_ids, [self.account.service_id])
        self.assertTrue(send_email_task(str(intent.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Mail and DNS maintenance", mail.outbox[0].body)

    def test_staff_preview_distinguishes_retained_responsibility_from_web_placement(self) -> None:
        self.publish_retained_website()
        request = RequestFactory().get("/infrastructure/maintenance/")
        request.user = self.actor

        context = node_maintenance_context(self.node, request)

        self.assertEqual(context["maintenance_account_count"], 0)
        self.assertEqual(context["maintenance_customer_count"], 1)
        self.assertEqual(context["maintenance_retained_count"], 1)
        with override("en"):
            rendered = render_to_string(
                "infrastructure/partials/node_maintenance.html",
                {**context, "maintenance_full_controls": True},
                request=request,
            )
        self.assertIn("Retained source responsibilities:", rendered)
        self.assertIn(self.account.domain, rendered)
        self.assertIn("Mail, DNS, Authentication", rendered)

    def test_direct_placement_and_admitted_source_duty_deduplicate_before_cutover(self) -> None:
        window = self.schedule_source()
        self.component_start()

        dispatch_due_notices(window_ids=[str(window.pk)])

        self.assertEqual(window.audience.count(), 1)
        self.assertEqual(NodeMaintenanceDelivery.objects.filter(window=window).count(), 1)
        self.assertEqual(
            NodeMaintenanceDelivery.objects.get(window=window).selected_service_ids, [self.account.service_id]
        )

    def test_release_before_actual_worker_refuses_the_queued_notice(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source()
        intent = NodeMaintenanceDelivery.objects.get(window=window)
        self.release_retained_source()

        result = send_email_task(str(intent.email_log_id))

        self.assertFalse(result["success"])
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 0)
        intent.refresh_from_db()
        self.assertEqual(intent.refusal_reason, "maintenance_service_placement_changed")

    def test_release_before_start_does_not_promote_scheduled_history_to_execution(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source(due=True)
        self.release_retained_source()

        change_window(
            window.pk, actor=self.actor, revision=window.revision, action="start", reason="Perform source work"
        )

        self.assertFalse(window.audience.filter(provenance="execution").exists())

    def test_release_after_execution_keeps_truthful_completion_and_current_owner_scope(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source(due=True)
        change_window(
            window.pk, actor=self.actor, revision=window.revision, action="start", reason="Perform source work"
        )
        self.release_retained_source()

        change_window(
            window.pk,
            actor=self.actor,
            revision=window.revision,
            action="finish",
            reason="Document actual outcome",
            outcome="failed",
            public_outcome="Mail service checks need operator follow-up.",
            attestation=True,
        )

        self.assertEqual(
            list(window.audience.filter(provenance="execution").values_list("service_id_snapshot", flat=True)),
            [self.account.service_id],
        )
        completed = NodeMaintenanceDelivery.objects.get(window=window, kind="completed")
        self.assertEqual(completed.selected_service_ids, [self.account.service_id])
        self.assertTrue(send_email_task(str(completed.email_log_id))["success"])
        self.assertIn("Mail service checks", mail.outbox[-1].body)

    def test_opt_out_retains_independent_source_audience_and_late_opt_out_stops_delivery(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source()
        intent = NodeMaintenanceDelivery.objects.get(window=window)
        EmailPreference.objects.update_or_create(customer=self.customer, defaults={"service": False})

        self.assertFalse(send_email_task(str(intent.email_log_id))["success"])
        self.assertEqual(window.audience.count(), 1)
        self.assertFalse(mail.outbox)

    def test_existing_opt_out_keeps_retained_audience_without_queueing_provider_mail(self) -> None:
        self.publish_retained_website()
        EmailPreference.objects.update_or_create(customer=self.customer, defaults={"service": False})

        window = self.schedule_source()

        self.assertEqual(window.audience.count(), 1)
        intent = NodeMaintenanceDelivery.objects.get(window=window)
        self.assertEqual(intent.phase, "refused")
        self.assertEqual(intent.refusal_reason, "maintenance_opt_out")
        self.assertIsNone(intent.email_log_id)

    def test_service_transfer_refuses_previously_linked_retained_source_details(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source()
        intent = NodeMaintenanceDelivery.objects.get(window=window)
        current_owner = Customer.objects.create(name="New mail owner", primary_email="new-mail-owner@example.test")
        self.account.service.customer = current_owner
        self.account.service.save(update_fields=["customer", "updated_at"])

        result = send_email_task(str(intent.email_log_id))

        self.assertFalse(result["success"])
        self.assertFalse(result["retry_scheduled"])
        self.assertFalse(mail.outbox)
        intent.refresh_from_db()
        self.assertEqual(intent.refusal_reason, "maintenance_service_ownership_changed")

    def test_not_run_receipt_freezes_retained_membership_before_a_later_arrival(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source(due=True)
        deadline = window.start_by + timedelta(seconds=1)
        with patch("apps.infrastructure.node_maintenance_tasks.timezone.now", return_value=deadline):
            tick_node_maintenance(window_ids=[str(window.pk)])
        window.refresh_from_db()
        self.assertEqual(window.status, "failed")
        self.assertIsNone(window.started_at)
        self.assertFalse(window.executions.exists())
        later = self.account_on_node("later-retained-audience.example.test")
        self.assertNotEqual(later.service_id, self.account.service_id)
        self.assertEqual(
            list(window.audience.filter(provenance="not_run").values_list("service_id_snapshot", flat=True)),
            [self.account.service_id],
        )
