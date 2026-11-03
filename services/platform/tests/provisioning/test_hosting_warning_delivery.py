"""Accepted canonical observations produce durable, policy-checked customer mail."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from django_q.models import Schedule

from apps.audit.services import GDPRDeletionService
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.notifications.models import EmailLog, EmailPreference, EmailSuppression, EmailTemplate, UnsubscribeToken
from apps.notifications.services import EmailService
from apps.notifications.tasks import process_email_queue, send_email_task
from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_node_policy import NOTIFICATION_EMITTERS, verify_notification_evidence
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_warning_delivery import (
    notification_handover_refusal,
    setup_warning_pipeline,
    sweep_hosting_warnings,
)
from apps.provisioning.hosting_warning_models import HostingWarningState
from apps.provisioning.models import HostingWarningDelivery, HostingWarningIntent, Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_usage_models import UsageInterval, UsageReading
from apps.settings.models import SystemSetting
from apps.users.models import CustomerMembership, User, UserProfile


class WarningFixture:
    def setUp(self):
        self.customer = Customer.objects.create(
            name="Warning customer", customer_type="company", status="active", primary_email="warning@example.test"
        )
        self.owner_user = User.objects.create_user("warning@example.test", "fixture-password")
        UserProfile.objects.update_or_create(user=self.owner_user, defaults={"preferred_language": "en"})
        CustomerMembership.objects.create(user=self.owner_user, customer=self.customer, role="owner", is_primary=True)
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.plan = ServicePlan.objects.create(
            name="One GiB", plan_type="shared_hosting", price_monthly=10, disk_space_gb=1, bandwidth_gb=1
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=currency,
            service_name="warning.example.test",
            domain="warning.example.test",
            username="warningfixture",
            status="active",
            price=10,
        )
        self.server = VirtualminServer.objects.create(
            name="Warning node", hostname="warning-node.example.test", api_username="praho-warning", status="active"
        )
        self.server.set_api_password("warning-fixture-only")
        self.server.save()
        identity = connection_identity(self.server)
        self.installation = uuid4()
        evidence = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": identity,
            "installation": str(self.installation),
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        # Native mail suppression is a fixture prerequisite, not a native execution claim.
        verify_notification_evidence(evidence, identity)
        NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=identity,
            notification_owner="platform",
            notifications_verified_at=timezone.now(),
            notification_evidence=evidence,
        )
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            server=self.server,
            domain=self.service.domain,
            virtualmin_username="warningfixture",
            status="active",
            praho_customer_id=self.customer.pk,
            praho_service_id=self.service.pk,
        )
        SystemSetting.objects.create(
            key="provisioning.quota_warnings_enabled",
            value=True,
            default_value=False,
            data_type="boolean",
            category="provisioning",
            name="Hosting usage warnings",
        )
        Schedule.objects.create(
            name="hosting-warning-deliveries",
            func="apps.provisioning.hosting_warning_delivery.sweep_hosting_warnings",
            schedule_type="I",
            minutes=5,
        )
        for locale in ("en", "ro"):
            EmailTemplate.objects.create(
                key="hosting_usage_warning",
                locale=locale,
                category="quota_warnings",
                subject="Hosting allowance warning",
                body_text="{% for entry in warning_entries %}{{ entry }}\n{% endfor %}",
                body_html="<ul>{% for entry in warning_entries %}<li>{{ entry }}</li>{% endfor %}</ul>",
            )

    def publish(self, disk_bytes, *, token=None, bandwidth_bytes=None, owner_start_known=True):
        state = usage.current_state(self.account)
        if bandwidth_bytes is not None:
            state.owner_start_known = owner_start_known
            state.save(update_fields=["owner_start_known"])
        observed = timezone.now()
        segments = []
        if bandwidth_bytes is not None:
            interval = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
            segments = [
                {
                    "id": str(interval.pk),
                    "bytes": bandwidth_bytes,
                    "start": max(usage.month(observed)[0], interval.started_at, state.owner_started_at).isoformat(),
                    "end": observed.isoformat(),
                    "complete": True,
                }
            ]
        payload = {
            "version": 1,
            "installation": str(self.installation),
            "observed_at": observed.isoformat(),
            "records": [
                {
                    "domain": self.account.domain,
                    "username": self.account.virtualmin_username,
                    "domain_id": "12345",
                    "scan_started_at": observed.isoformat(),
                    "scan_finished_at": observed.isoformat(),
                    "disk_files_bytes": disk_bytes,
                    "disk_db_bytes": 0,
                    "databases": 0,
                    "mailboxes": 0,
                    "segments": segments,
                }
            ],
        }
        published = usage.publish_snapshot(self.server.pk, payload, usage.capture(self.server), token=token)
        self.assertEqual(published, 1)
        self.assertEqual(
            UsageReading.objects.filter(account=self.account, disk_total_bytes__isnull=False)
            .latest("taken_at")
            .disk_total_bytes,
            disk_bytes,
        )
        return observed

    def queue_critical(self):
        observed = self.publish(1024**3)
        self.assertEqual(sweep_hosting_warnings(at=observed), {"linked": 1})
        return EmailLog.objects.get()


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class HostingWarningDeliveryTests(WarningFixture, TestCase):
    def test_accepted_critical_poll_creates_one_rendered_encrypted_email_log_on_replay(self):
        observed = self.publish(1024**3)
        self.assertEqual(EmailLog.objects.count(), 0, "Account publication must never create/send an EmailLog")
        sweep_hosting_warnings(at=observed + timedelta(minutes=10))
        self.assertEqual(EmailLog.objects.count(), 1)
        log = EmailLog.objects.get()
        self.assertEqual(
            (log.customer_id, log.to_addr, log.status), (self.customer.pk, self.customer.primary_email, "queued")
        )
        self.assertTrue(log.body_encrypted)
        self.assertIn("100%", log.get_decrypted_body_text())
        self.assertIn("disk", log.get_decrypted_body_text().lower())
        sweep_hosting_warnings(at=observed + timedelta(minutes=10))
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_quota_unsubscribe_link_changes_only_the_explicit_quota_preference(self):
        self.customer.marketing_consent = True
        self.customer.save(update_fields=["marketing_consent"])
        preference = EmailPreference.objects.create(customer=self.customer, quota_warnings=True)
        token = UnsubscribeToken.objects.create(email=self.customer.primary_email, template_key="hosting_usage_warning")
        response = self.client.get(reverse("notifications:unsubscribe", kwargs={"token_id": token.pk}))
        self.assertEqual(response.status_code, 200, response.content)
        preference.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertFalse(preference.quota_warnings)
        self.assertTrue(self.customer.marketing_consent)

    def test_stored_critical_body_reaches_provider_once_and_records_acceptance(self):
        log = self.queue_critical()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            result = send_email_task(str(log.pk))
            self.assertTrue(result["success"], result)
            self.assertEqual(provider.call_count, 1)
            message = provider.call_args.args[0]
            self.assertEqual(message.to, [self.customer.primary_email])
            self.assertIn("100%", message.body)
            self.assertFalse(send_email_task(str(log.pk))["success"])
            self.assertEqual(provider.call_count, 1)
        sweep_hosting_warnings()
        delivery = HostingWarningDelivery.objects.get(email_log=log)
        self.assertEqual((delivery.phase, delivery.certainty), ("accepted", "accepted"))
        self.assertIsNotNone(delivery.accepted_at)
        self.assertEqual(HostingWarningIntent.objects.get(threshold=100).phase, "delivered")

    def test_critical_bypasses_optional_preferences_and_global_marketing_opt_out(self):
        EmailPreference.objects.create(customer=self.customer, quota_warnings=False, global_unsubscribe=True)
        EmailSuppression.suppress(self.customer.primary_email, "unsubscribe")
        log = self.queue_critical()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            result = send_email_task(str(log.pk))
        self.assertTrue(result["success"], result)
        self.assertEqual(provider.call_count, 1)

    def test_hard_bounce_after_queue_refuses_critical_before_provider(self):
        log = self.queue_critical()
        EmailSuppression.suppress(self.customer.primary_email, "hard_bounce")
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            result = send_email_task(str(log.pk))
        self.assertFalse(result["success"], result)
        provider.assert_not_called()
        delivery = HostingWarningDelivery.objects.get(email_log=log)
        self.assertEqual((delivery.phase, delivery.certainty), ("refused", "never_dispatched"))
        self.assertEqual(delivery.refusal_reason, "warning_recipient_suppressed")

    def test_recipient_change_never_retargets_stored_body_and_fresh_poll_can_notify_new_recipient(self):
        log = self.queue_critical()
        original_body = log.get_decrypted_body_text()
        self.customer.primary_email = "changed@example.test"
        self.customer.save(update_fields=["primary_email"])
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(log.pk))["success"])
        provider.assert_not_called()
        sweep_hosting_warnings()
        self.assertEqual(EmailLog.objects.count(), 1)
        self.publish(1024**3)
        sweep_hosting_warnings()
        self.assertEqual(EmailLog.objects.count(), 2)
        log.refresh_from_db()
        self.assertEqual(log.to_addr, "warning@example.test")
        self.assertEqual(log.get_decrypted_body_text(), original_body)
        self.assertEqual(EmailLog.objects.exclude(pk=log.pk).get().to_addr, "changed@example.test")

    def test_unknown_assigned_allowance_preserves_valid_observation_without_warning(self):
        ServiceHostingLimits.objects.filter(service=self.service).delete()
        self.publish(1024**3)
        sweep_hosting_warnings()
        self.assertEqual(UsageReading.objects.filter(account=self.account).count(), 1)
        self.assertEqual(EmailLog.objects.count(), 0)
        self.assertFalse(HostingWarningIntent.objects.exists())

    def test_corrupt_episode_does_not_rollback_good_observation_or_restart_notification_latch(self):
        self.queue_critical()
        cursor = HostingWarningState.objects.get(account=self.account, resource="disk")
        cursor.policy_state = {"version": "corrupt"}
        cursor.save(update_fields=["policy_state"])
        self.publish(1024**3 + 1)
        sweep_hosting_warnings()
        self.assertEqual(UsageReading.objects.filter(account=self.account).count(), 2)
        self.assertEqual(HostingWarningIntent.objects.filter(threshold=100).count(), 1)
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_staggered_rollout_cannot_dispatch_before_its_durable_due_time(self):
        policy = NodeHostingPolicy.objects.get(server=self.server)
        policy.notifications_verified_at = timezone.now()
        policy.save(update_fields=["notifications_verified_at"])
        observed = self.publish(1024**3 * 95 // 100 + 1)
        intent = HostingWarningIntent.objects.get(threshold=95)
        self.assertEqual(intent.kind, "rollout")
        self.assertGreater(intent.due_at, observed)
        sweep_hosting_warnings(at=observed + timedelta(minutes=10))
        log = EmailLog.objects.get()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            result = send_email_task(str(log.pk))
        self.assertFalse(result["success"], result)
        provider.assert_not_called()
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=log).refusal_reason, "warning_not_due")

    def test_optional_opt_out_before_grouping_does_not_piggyback_disk_on_critical_bandwidth(self):
        EmailPreference.objects.create(customer=self.customer, quota_warnings=False)
        self.publish(1024**3 * 95 // 100 + 1, bandwidth_bytes=1024**3)
        self.assertEqual(HostingWarningIntent.objects.count(), 2)
        sweep_hosting_warnings()
        log = EmailLog.objects.get()
        self.assertIn("bandwidth", log.get_decrypted_body_text())
        self.assertNotIn("disk", log.get_decrypted_body_text())
        self.assertEqual(HostingWarningIntent.objects.get(resource="disk").phase, "cancelled")

    def test_mixed_body_becomes_immutable_refusal_and_critical_only_replacement_after_opt_out(self):
        preference = EmailPreference.objects.create(customer=self.customer)
        self.publish(1024**3 * 95 // 100 + 1, bandwidth_bytes=1024**3)
        sweep_hosting_warnings()
        original = EmailLog.objects.get()
        old_body = original.get_decrypted_body_text()
        self.assertIn("disk", old_body)
        self.assertIn("bandwidth", old_body)
        preference.quota_warnings = False
        preference.save(update_fields=["quota_warnings"])
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(original.pk))["success"])
            provider.assert_not_called()
            sweep_hosting_warnings()
            replacement = EmailLog.objects.exclude(pk=original.pk).get()
            self.assertNotIn("disk", replacement.get_decrypted_body_text())
            self.assertIn("bandwidth", replacement.get_decrypted_body_text())
            self.assertTrue(send_email_task(str(replacement.pk))["success"])
            self.assertEqual(provider.call_count, 1)
        original.refresh_from_db()
        self.assertEqual(original.get_decrypted_body_text(), old_body)
        refused = HostingWarningDelivery.objects.get(email_log=original)
        version = HostingWarningDelivery.objects.get(email_log=replacement)
        self.assertEqual(
            (refused.phase, refused.certainty, version.version, version.parent_id),
            ("refused", "never_dispatched", 2, refused.pk),
        )

    def test_uncertain_provider_acceptance_never_rebatches_after_opt_out(self):
        preference = EmailPreference.objects.create(customer=self.customer)
        self.publish(1024**3 * 95 // 100 + 1, bandwidth_bytes=1024**3)
        sweep_hosting_warnings()
        original = EmailLog.objects.get()
        with patch(
            "django.core.mail.EmailMultiAlternatives.send",
            autospec=True,
            side_effect=TimeoutError("lost provider response"),
        ) as provider:
            self.assertFalse(send_email_task(str(original.pk))["success"])
            self.assertEqual(provider.call_count, 1)
        self.assertIsNotNone(HostingWarningDelivery.objects.get(email_log=original).first_dispatch_claimed_at)
        preference.quota_warnings = False
        preference.save(update_fields=["quota_warnings"])
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=1)):
                self.assertFalse(send_email_task(str(original.pk))["success"])
            provider.assert_not_called()
        sweep_hosting_warnings()
        self.assertEqual(EmailLog.objects.count(), 1)
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=original).certainty, "uncertain")
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=original).parts.filter(active=True).count(), 2)

    def test_partial_first_month_lower_bound_can_warn_critical(self):
        self.publish(0, bandwidth_bytes=1024**3, owner_start_known=False)
        self.assertFalse(UsageReading.objects.filter(account=self.account, bandwidth_complete=True).exists())
        cursor = HostingWarningState.objects.get(account=self.account, resource="bandwidth")
        self.assertEqual((cursor.condition, cursor.availability), (100, "partial"))
        sweep_hosting_warnings()
        self.assertIn("bandwidth", EmailLog.objects.get().get_decrypted_body_text())

    def test_critical_reminder_needs_fresh_observation_and_is_once_48_hours_after_actual_delivery(self):
        log = self.queue_critical()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1):
            self.assertTrue(send_email_task(str(log.pk))["success"])
        sweep_hosting_warnings()
        accepted_at = HostingWarningDelivery.objects.get(email_log=log).accepted_at
        with patch("django.utils.timezone.now", return_value=accepted_at + timedelta(hours=48)):
            sweep_hosting_warnings()
            self.assertFalse(
                HostingWarningIntent.objects.filter(kind="reminder").exists(), "Stale observation cannot remind"
            )
            self.publish(1024**3)
            sweep_hosting_warnings()
            reminder = HostingWarningIntent.objects.get(kind="reminder")
            self.assertEqual(reminder.due_at, accepted_at + timedelta(hours=48))
            self.assertEqual(EmailLog.objects.count(), 2)
            sweep_hosting_warnings()
            self.assertEqual(EmailLog.objects.count(), 2)

    def test_public_gdpr_erasure_after_queue_refuses_stored_identity(self):
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        log = self.queue_critical()
        request = GDPRDeletionService.create_deletion_request(user=self.owner_user, deletion_type="anonymize").unwrap()
        with patch("django.core.mail.backends.smtp.EmailBackend.send_messages", autospec=True, return_value=1):
            result = GDPRDeletionService.process_deletion_request(request)
        self.assertTrue(result.is_ok(), result)
        self.assertIsNotNone(Customer.all_objects.get(pk=self.customer.pk).anonymized_at)
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(log.pk))["success"])
        provider.assert_not_called()

    def test_orphan_warning_template_logs_refuse_both_async_and_sync_provider_paths(self):
        for asynchronous in (True, False):
            with (
                self.subTest(asynchronous=asynchronous),
                patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider,
            ):
                result = EmailService.send_email(
                    to=self.customer.primary_email,
                    subject="Orphan warning",
                    body_text="100%",
                    template_key="hosting_usage_warning",
                    customer=self.customer,
                    async_send=asynchronous,
                )
                if asynchronous:
                    self.assertTrue(result.success, result)
                    self.assertFalse(send_email_task(str(result.email_log_id))["success"])
                else:
                    self.assertFalse(result.success, result)
                provider.assert_not_called()

    def test_linked_body_and_intent_binding_evidence_cannot_be_overwritten(self):
        log = self.queue_critical()
        delivery = HostingWarningDelivery.objects.get(email_log=log)
        intent = HostingWarningIntent.objects.get(threshold=100)
        delivery.intent_snapshot = {**delivery.intent_snapshot, "body_hash": "replacement"}
        with self.assertRaises(ValidationError):
            delivery.save(update_fields=["intent_snapshot"])
        with self.assertRaises(ValidationError):
            HostingWarningDelivery.objects.filter(pk=delivery.pk).update(recipient_hash="replacement")
        intent.scope_snapshot = {**intent.scope_snapshot, "customer_id": self.customer.pk + 1}
        with self.assertRaises(ValidationError):
            intent.save(update_fields=["scope_snapshot"])
        with self.assertRaises(ValidationError):
            HostingWarningIntent.objects.filter(pk=intent.pk).update(generation=2)

    def test_email_body_tamper_is_refused_and_only_one_active_delivery_is_allowed(self):
        log = self.queue_critical()
        delivery = HostingWarningDelivery.objects.get(email_log=log)
        intent = HostingWarningIntent.objects.get(threshold=100)
        with self.assertRaises(IntegrityError), transaction.atomic():
            delivery.parts.create(intent=intent)
        log.body_text = "Changed body"
        log.save(update_fields=["body_text"])
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(log.pk))["success"])
        provider.assert_not_called()
        self.assertEqual(HostingWarningDelivery.objects.get(pk=delivery.pk).refusal_reason, "warning_body_changed")

    def test_romanian_default_template_and_dynamic_warning_copy_are_stored_in_romanian(self):
        UserProfile.objects.filter(user=self.owner_user).update(preferred_language="ro")
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        log = self.queue_critical()
        body = log.get_decrypted_body_text()
        self.assertEqual(log.subject, "Avertizare privind limita găzduirii")
        self.assertIn("spațiu pe disc", body)
        self.assertIn("a atins cel puțin 100%", body)
        self.assertNotIn("has reached", body)
        self.assertNotIn("unsubscribe", body)

    def test_english_default_template_and_dynamic_warning_copy_are_stored_in_english(self):
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        log = self.queue_critical()
        self.assertEqual(log.subject, "Hosting allowance warning")
        self.assertIn("disk has reached at least 100%", log.get_decrypted_body_text())
        self.assertIn("Review your usage", log.get_decrypted_body_text())

    def test_queue_outage_after_commit_preserves_intent_and_stored_email_for_real_queue_sweep(self):
        with patch("django_q.tasks.async_task", side_effect=ConnectionError("queue unavailable")):
            with self.captureOnCommitCallbacks(execute=True):
                observed = self.publish(1024**3)
            self.assertEqual(HostingWarningIntent.objects.get(threshold=100).phase, "pending")
            self.assertFalse(EmailLog.objects.exists())
            with self.captureOnCommitCallbacks(execute=True):
                sweep_hosting_warnings()
            log = EmailLog.objects.get()
            self.assertEqual(log.status, "queued")
            self.assertEqual(HostingWarningIntent.objects.get(threshold=100).phase, "linked")
        with patch("django_q.tasks.async_task") as queue:
            with patch("django.utils.timezone.now", return_value=observed + timedelta(hours=1)):
                recovered = process_email_queue()
            self.assertEqual(recovered["processed"], 1, recovered)
            self.assertEqual(queue.call_count, 1)
            self.assertEqual(queue.call_args.kwargs["email_log_id"], str(log.pk))
        with (
            patch("django.utils.timezone.now", return_value=observed + timedelta(hours=1)),
            patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider,
        ):
            result = send_email_task(str(log.pk))
            self.assertTrue(result["success"], result)
            self.assertEqual(provider.call_count, 1)
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_fifty_imported_accounts_handover_coalesces_one_current_customer_digest_without_old_intents(self):
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        accounts = [self.account]
        for number in range(49):
            service = Service.objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.service.currency,
                service_name=f"rollout-{number}.example.test",
                domain=f"rollout-{number}.example.test",
                username=f"rollout{number}",
                status="active",
                price=10,
            )
            accounts.append(
                VirtualminAccount.objects.create(
                    service=service,
                    server=self.server,
                    domain=service.domain,
                    virtualmin_username=service.username,
                    status="active",
                    praho_customer_id=self.customer.pk,
                    praho_service_id=service.pk,
                )
            )
        policy = NodeHostingPolicy.objects.get(server=self.server)
        policy.notification_owner = "native"
        policy.save(update_fields=["notification_owner"])

        def poll_all():
            observed = timezone.now()
            records = [
                {
                    "domain": account.domain,
                    "username": account.virtualmin_username,
                    "domain_id": str(12345 + number),
                    "scan_started_at": observed.isoformat(),
                    "scan_finished_at": observed.isoformat(),
                    "disk_files_bytes": 1024**3,
                    "disk_db_bytes": 0,
                    "databases": 0,
                    "mailboxes": 0,
                    "segments": [],
                }
                for number, account in enumerate(accounts)
            ]
            self.assertEqual(
                usage.publish_snapshot(
                    self.server.pk,
                    {
                        "version": 1,
                        "installation": str(self.installation),
                        "observed_at": observed.isoformat(),
                        "records": records,
                    },
                    usage.capture(self.server),
                ),
                50,
            )
            return observed

        poll_all()
        sweep_hosting_warnings()
        self.assertFalse(EmailLog.objects.exists())
        self.assertEqual(HostingWarningIntent.objects.filter(phase="pending").count(), 50)
        policy.notification_owner, policy.notifications_verified_at = "platform", timezone.now()
        policy.save(update_fields=["notification_owner", "notifications_verified_at"])
        observed = poll_all()
        self.assertEqual(
            HostingWarningIntent.objects.filter(phase="cancelled", refusal_reason="warning_handover_baseline").count(),
            50,
        )
        pending = list(HostingWarningIntent.objects.filter(phase="pending"))
        self.assertEqual(len(pending), 50)
        self.assertTrue(
            all(
                intent.kind == "rollout" and observed <= intent.due_at < observed + timedelta(minutes=5)
                for intent in pending
            )
        )
        with CaptureQueriesContext(connection) as queries:
            sweep_hosting_warnings(at=observed + timedelta(minutes=10))
        preference_reads = [
            row["sql"] for row in queries.captured_queries if 'FROM "notification_email_preferences"' in row["sql"]
        ]
        self.assertLessEqual(
            len(preference_reads), 2, "Customer preference policy must be loaded once per coalesced audience"
        )
        overlay_reads = [
            row["sql"] for row in queries.captured_queries if 'FROM "provisioning_service_hosting_raise"' in row["sql"]
        ]
        self.assertLessEqual(len(overlay_reads), 2, "Temporary raise state must be loaded in a batch")
        self.assertEqual(EmailLog.objects.count(), 1)

        self.assertEqual(HostingWarningDelivery.objects.get().parts.filter(active=True).count(), 50)
        body = EmailLog.objects.get().get_decrypted_body_text()
        for account in accounts:
            self.assertIn(account.domain, body)
        sweep_hosting_warnings(at=observed + timedelta(minutes=10))
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_rejected_poll_does_not_invent_new_warning_from_preexisting_legacy_reading(self):
        self.publish(1024**3)
        # An observation that predates warning-state deployment has no episode.
        HostingWarningState.objects.filter(account=self.account).delete()
        observed = timezone.now()
        self.assertEqual(
            usage.publish_snapshot(
                self.server.pk,
                {
                    "version": 1,
                    "installation": str(self.installation),
                    "observed_at": observed.isoformat(),
                    "records": [],
                },
                usage.capture(self.server),
            ),
            0,
        )
        self.assertEqual(UsageReading.objects.filter(account=self.account).count(), 1)
        self.assertFalse(HostingWarningIntent.objects.exists())
        sweep_hosting_warnings()
        self.assertFalse(EmailLog.objects.exists())

    def test_handover_requires_delivery_transport_and_enabled_durable_sweep(self):
        self.assertIsNone(notification_handover_refusal(self.server))
        for backend in ("dummy", "console", "locmem", "filebased"):
            with (
                self.subTest(backend=backend),
                override_settings(EMAIL_BACKEND=f"django.core.mail.backends.{backend}.EmailBackend"),
            ):
                self.assertIsNotNone(notification_handover_refusal(self.server))
        schedule = Schedule.objects.get(name="hosting-warning-deliveries")
        schedule.repeats = 0
        schedule.save(update_fields=["repeats"])
        self.assertIsNotNone(notification_handover_refusal(self.server))

    def test_native_owned_accounts_do_not_starve_later_eligible_platform_warning(self):
        native = VirtualminServer.objects.create(
            name="Legacy native warning node",
            hostname="legacy-warning.example.test",
            status="active",
            api_username="praho-warning",
            legacy_security_admission=True,
        )
        native.set_api_password("legacy-warning-fixture-only")
        native.save()
        NodeHostingPolicy.objects.create(
            server=native, connection_identity=connection_identity(native), notification_owner="native"
        )
        accounts = []
        for number in range(100):
            service = Service.objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.service.currency,
                service_name=f"legacy-{number}.example.test",
                domain=f"legacy-{number}.example.test",
                username=f"legacy{number}",
                status="active",
                price=10,
            )
            accounts.append(
                VirtualminAccount.objects.create(
                    service=service,
                    server=native,
                    domain=service.domain,
                    virtualmin_username=service.username,
                    status="active",
                    praho_customer_id=self.customer.pk,
                    praho_service_id=service.pk,
                )
            )
        observed = timezone.now()
        records = [
            {
                "domain": account.domain,
                "username": account.virtualmin_username,
                "domain_id": str(90000 + number),
                "scan_started_at": observed.isoformat(),
                "scan_finished_at": observed.isoformat(),
                "disk_files_bytes": 1024**3,
                "disk_db_bytes": 0,
                "databases": 0,
                "mailboxes": 0,
                "segments": [],
            }
            for number, account in enumerate(accounts)
        ]
        self.assertEqual(
            usage.publish_snapshot(
                native.pk,
                {"version": 1, "installation": str(uuid4()), "observed_at": observed.isoformat(), "records": records},
                usage.capture(native),
            ),
            100,
        )
        accepted = self.publish(1024**3)
        self.assertGreater(accepted, observed)
        self.assertEqual(HostingWarningIntent.objects.filter(phase="pending").count(), 101)
        sweep_hosting_warnings()
        self.assertEqual(EmailLog.objects.count(), 1)
        body = EmailLog.objects.get().get_decrypted_body_text()
        self.assertIn(self.service.service_name, body)
        self.assertNotIn("legacy-", body)

    def test_bulk_write_cannot_claim_warning_delivery_without_its_fsm_transition(self):
        self.queue_critical()
        with self.assertRaises(ValidationError):
            HostingWarningIntent.objects.update(phase="delivered")
        with self.assertRaises(ValidationError):
            HostingWarningDelivery.objects.update(phase="accepted")

    def test_binding_guards_cover_foreign_key_field_names_as_well_as_id_names(self):
        self.queue_critical()
        intent = HostingWarningIntent.objects.get(threshold=100)
        with self.assertRaises(ValidationError):
            HostingWarningIntent.objects.filter(pk=intent.pk).update(state=intent.state)
        with self.assertRaises(ValidationError):
            HostingWarningDelivery.objects.update(email_log=EmailLog.objects.get())
