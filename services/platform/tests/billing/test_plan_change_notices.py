"""One durable delivery identity per phase, using actual rendering and EmailLog storage."""

from django.core import mail
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TransactionTestCase, override_settings

from apps.audit.services import GDPRDeletionService
from apps.billing.plan_change_notice_models import PlanChangeNotice
from apps.billing.plan_change_notices import (
    dispatch_plan_change_notices,
    process_plan_change_notice,
    publish_plan_change_notice,
)
from apps.billing.plan_change_operations import reconcile_plan_change_operation
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.services import ProformaConversionService
from apps.billing.signals import _send_invoice_issued_email, _send_payment_received_email
from apps.notifications.models import EmailLog, EmailPreference, EmailTemplate
from apps.notifications.tasks import send_email_task
from apps.users.models import CustomerMembership
from tests.billing import test_plan_change_lifecycle as lifecycle_tests
from tests.billing.test_plan_change_operations import PlanOperationFixture


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class PlanChangeNoticeTests(PlanOperationFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.customer.primary_email = "plan-owner@example.test"
        self.customer.save(update_fields=["primary_email"])
        for locale in ("en", "ro"):
            for phase in ("scheduled", "completed", "attention"):
                EmailTemplate.objects.create(
                    key=f"plan_change_{phase}",
                    locale=locale,
                    category="service",
                    is_active=True,
                    subject="Hosting plan {{ target_plan_name }}",
                    body_html="<p>{{ target_plan_name }}: disk {{ disk_allowance }}, bandwidth {{ bandwidth_allowance }}</p>",
                    body_text="{{ target_plan_name }}: disk {{ disk_allowance }}, bandwidth {{ bandwidth_allowance }}",
                )

    def completed_notice(self):
        change = self.paid_change()
        self.apply(change)
        completed = reconcile_plan_change_operation(change.pk)
        self.assertEqual(completed.status, "completed")
        return publish_plan_change_notice(completed, "completed")

    def test_verified_completion_renders_purchased_allowance_into_one_actual_email_log(self):
        notice = self.completed_notice()
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        self.assertEqual(notice.state, "linked")
        log = notice.email_log
        self.assertEqual(
            (log.customer_id, log.to_addr, log.status), (self.customer.pk, self.customer.primary_email, "queued")
        )
        body = log.get_decrypted_body_text()
        self.assertIn("Checkout target", body)
        self.assertIn("20 GiB", body)
        self.assertNotIn("22 GiB", body)
        self.assertNotIn(self.server.hostname, body)
        self.assertTrue(process_plan_change_notice(notice.pk))
        self.assertEqual(EmailLog.objects.filter(plan_change_notice=notice).count(), 1)

    def test_deleting_a_linked_email_log_never_authorizes_another_phase_send(self):
        notice = self.completed_notice()
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        notice.email_log.delete()
        notice.refresh_from_db()
        self.assertEqual((notice.state, notice.email_log_id), ("linked", None))
        self.assertTrue(process_plan_change_notice(notice.pk))
        self.assertFalse(EmailLog.objects.filter(plan_change_notice=notice).exists())

    def test_linked_phase_ownership_cannot_be_reset_or_deleted_for_another_send(self):
        notice = self.queued_notice()
        notice.state = "pending"
        with self.assertRaises(ValidationError):
            notice.save(update_fields=["state"])
        with self.assertRaises(ValidationError):
            PlanChangeNotice.objects.filter(pk=notice.pk).delete()

    def test_operational_service_opt_out_prevents_even_queueing_a_message(self):
        notice = self.completed_notice()
        EmailPreference.objects.create(customer=self.customer, service=False)
        self.assertFalse(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        self.assertEqual(notice.state, "suppressed")
        self.assertIsNone(notice.email_log_id)

    def test_lost_callback_is_recovered_from_the_durable_phase_intent(self):
        notice = self.completed_notice()
        self.assertEqual(notice.state, "pending")
        self.assertEqual(dispatch_plan_change_notices(), 1)
        notice.refresh_from_db()
        self.assertEqual(notice.state, "linked")
        self.assertIsNotNone(notice.email_log_id)
        self.assertEqual(dispatch_plan_change_notices(), 0)

    def queued_notice(self):
        notice = self.completed_notice()
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        return notice

    def test_actual_worker_sends_the_current_verified_completion_once(self):
        notice = self.queued_notice()
        result = send_email_task(str(notice.email_log_id))
        self.assertTrue(result["success"], result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertFalse(send_email_task(str(notice.email_log_id))["success"])
        self.assertEqual(len(mail.outbox), 1)

    def test_opt_out_after_queue_stops_actual_worker_and_its_retry(self):
        notice = self.queued_notice()
        EmailPreference.objects.create(customer=self.customer, service=False)
        result = send_email_task(str(notice.email_log_id))
        self.assertFalse(result["success"], result)
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(len(mail.outbox), 0)
        notice.email_log.refresh_from_db()
        self.assertTrue(notice.email_log.provider_response["permanent_failure"])
        self.assertFalse(send_email_task(str(notice.email_log_id))["success"])

    def test_changed_recipient_never_receives_or_retargets_the_queued_message(self):
        notice = self.queued_notice()
        self.customer.primary_email = "different-owner@example.test"
        self.customer.save(update_fields=["primary_email"])
        result = send_email_task(str(notice.email_log_id))
        self.assertFalse(result["success"], result)
        self.assertEqual(len(mail.outbox), 0)

    def test_old_connection_receipt_cannot_send_a_verified_completion_claim(self):
        notice = self.queued_notice()
        self.server.api_port += 1
        self.server.save(update_fields=["api_port"])
        result = send_email_task(str(notice.email_log_id))
        self.assertFalse(result["success"], result)
        self.assertEqual(len(mail.outbox), 0)


class FinancialPlanChangeNoticeTests(PlanOperationFixture, TransactionTestCase):
    transfer_to_another_customer = lifecycle_tests.PlanChangeCancellationTests.transfer_to_another_customer

    def setUp(self):
        super().setUp()
        call_command("setup_email_templates", verbosity=0)
        self.customer.primary_email = "plan-buyer@example.test"
        self.customer.save(update_fields=["primary_email"])

    def process_notices(self, change):
        for notice in change.phase_notices.filter(state="pending").order_by("created_at"):
            self.assertTrue(process_plan_change_notice(notice.pk), notice.phase)

    def test_actual_legal_issuance_sends_before_money_convergence_binds_the_plan_invoice(self):
        change = self.confirm(self.quote())
        converted = ProformaConversionService.convert_to_invoice(str(change.proforma_id))
        self.assertTrue(converted.is_ok(), converted)
        invoice = converted.unwrap()
        self.assertEqual(invoice.status, "issued")
        self.assertFalse(invoice.payments.exists())
        change.refresh_from_db()
        self.assertIsNone(change.invoice_id)
        self.assertIsNone(change.limit_application_id)
        notice = change.phase_notices.get(phase="invoice_issued")
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        body = notice.email_log.get_decrypted_body_text()
        self.assertIn(invoice.number, body)
        self.assertIn("Checkout target", body)
        sent = send_email_task(str(notice.email_log_id))
        self.assertTrue(sent["success"], sent)
        change.refresh_from_db()
        self.assertIsNone(change.invoice_id)
        self.assertIsNone(change.limit_application_id)

    def test_confirmation_and_actual_conversion_reuse_one_mail_per_financial_phase(self):
        change = self.confirm(self.quote())
        self.assertTrue(change.phase_notices.filter(phase="proforma").exists())
        self.process_notices(change)
        paid = ProformaPaymentService.record_payment_and_convert(str(change.proforma_id), change.total_cents, "bank")
        self.assertTrue(paid.is_ok(), paid)
        change.refresh_from_db()
        self.process_notices(change)
        _send_invoice_issued_email(change.invoice)
        _send_payment_received_email(change.invoice)
        self.process_notices(change)
        notices = list(change.phase_notices.order_by("phase"))
        self.assertEqual([notice.phase for notice in notices], ["invoice_issued", "payment_received", "proforma"])
        self.assertEqual(len({notice.email_log_id for notice in notices}), 3)
        for notice in notices:
            self.assertEqual(notice.email_log.customer_id, self.customer.pk)
        receipt = change.phase_notices.get(phase="payment_received").email_log.get_decrypted_body_text()
        self.assertIn("Checkout target", receipt)
        self.assertIn("20 GiB", receipt)
        self.assertFalse(EmailLog.objects.filter(customer=self.customer, template_key="payment_success").exists())

    def test_public_erasure_scrubs_the_rendered_identity_and_stops_queued_delivery(self):
        change = self.paid_change()
        self.apply(change)
        completed = reconcile_plan_change_operation(change.pk)
        notice = completed.phase_notices.get(phase="completed")
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        log = notice.email_log
        self.assertIn("Test SRL", log.get_decrypted_body_text())
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        membership = CustomerMembership.objects.get(user=self.actor, customer=self.customer)
        membership.role = "owner"
        membership.save(update_fields=["role"])
        request = GDPRDeletionService.create_deletion_request(user=self.actor)
        self.assertTrue(request.is_ok(), request)
        erased = GDPRDeletionService.process_deletion_request(request.unwrap())
        self.assertTrue(erased.is_ok(), erased)
        log.refresh_from_db()
        self.assertNotIn("Test SRL", log.get_decrypted_body_text())
        result = send_email_task(str(log.pk))
        self.assertFalse(result["success"], result)

    def test_public_owner_transfer_stops_previously_rendered_completion_mail(self):
        change = self.paid_change()
        self.apply(change)
        completed = reconcile_plan_change_operation(change.pk)
        notice = completed.phase_notices.get(phase="completed")
        self.assertTrue(process_plan_change_notice(notice.pk))
        notice.refresh_from_db()
        self.transfer_to_another_customer()
        result = send_email_task(str(notice.email_log_id))
        self.assertFalse(result["success"], result)
        notice.email_log.refresh_from_db()
        self.assertEqual(notice.email_log.provider_response["final_error"], "plan_change_customer_unavailable")
