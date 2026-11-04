"""Actual default text/HTML and immutable pending-resource warning context."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import UUID, uuid4

from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.services import EmailService
from apps.notifications.tasks import send_email_task
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_node_policy import NOTIFICATION_EMITTERS
from apps.provisioning.hosting_warning_delivery import (
    _body_hash,
    _snapshot_parts,
    setup_warning_pipeline,
    sweep_hosting_warnings,
)
from apps.provisioning.hosting_warning_models import (
    HostingWarningDelivery,
    HostingWarningDeliveryPart,
    HostingWarningIntent,
)
from apps.provisioning.hosting_warning_observation import recipient_hash
from apps.provisioning.service_models import ServicePlan
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User, UserProfile
from tests.billing.test_plan_change_operations import PlanOperationFixture
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


def bodies(log):
    return log.get_decrypted_body_text(), log.get_decrypted_body_html()


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class WarningThresholdCopyTests(WarningFixture, TestCase):
    def check_threshold(self, locale, threshold, resource="disk"):
        UserProfile.objects.filter(user=self.owner_user).update(preferred_language=locale)
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        used = (1024**3 * threshold + 99) // 100
        observed = self.publish(
            used if resource == "disk" else 0, bandwidth_bytes=used if resource == "bandwidth" else None
        )
        if threshold == 80:
            observed += timedelta(hours=23, seconds=1)
            with patch("django.utils.timezone.now", return_value=observed):
                self.publish(
                    used if resource == "disk" else 0, bandwidth_bytes=used if resource == "bandwidth" else None
                )
        sweep_hosting_warnings(at=observed)
        log = EmailLog.objects.get()
        for body in bodies(log):
            self.assertIn(f"{threshold}%", body)
            self.assertIn(str(used), body)
            self.assertIn("1024 MiB", body)
            self.assertIn(
                ("trafic lunar" if locale == "ro" else "bandwidth")
                if resource == "bandwidth"
                else ("spațiu pe disc" if locale == "ro" else "disk"),
                body,
            )
            self.assertIn("prag de avertizare" if locale == "ro" else "warning threshold", body)
            self.assertNotIn("a atins o limită inclusă" if locale == "ro" else "reached an included allowance", body)

    def test_english_80(self):
        self.check_threshold("en", 80)

    def test_english_95(self):
        self.check_threshold("en", 95)

    def test_english_100(self):
        self.check_threshold("en", 100)

    def test_romanian_80(self):
        self.check_threshold("ro", 80)

    def test_romanian_95(self):
        self.check_threshold("ro", 95)

    def test_romanian_100(self):
        self.check_threshold("ro", 100)

    def test_english_bandwidth_80(self):
        self.check_threshold("en", 80, "bandwidth")

    def test_english_bandwidth_95(self):
        self.check_threshold("en", 95, "bandwidth")

    def test_english_bandwidth_100(self):
        self.check_threshold("en", 100, "bandwidth")

    def test_romanian_bandwidth_80(self):
        self.check_threshold("ro", 80, "bandwidth")

    def test_romanian_bandwidth_95(self):
        self.check_threshold("ro", 95, "bandwidth")

    def test_romanian_bandwidth_100(self):
        self.check_threshold("ro", 100, "bandwidth")

    def test_operator_custom_templates_survive_pipeline_setup(self):
        template = EmailTemplate.objects.get(key="hosting_usage_warning", locale="en")
        template.body_text = "Reviewed operator text: {% for entry in warning_entries %}{{ entry }}{% endfor %}"
        template.body_html = (
            "<p>Reviewed operator HTML</p>{% for entry in warning_entries %}<p>{{ entry }}</p>{% endfor %}"
        )
        template.save()
        setup_warning_pipeline()
        log = self.queue_critical()
        self.assertIn("Reviewed operator text", log.get_decrypted_body_text())
        self.assertIn("Reviewed operator HTML", log.get_decrypted_body_html())


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class PendingResourceWarningCopyTests(WarningFixture, TestCase):
    def check_bandwidth_pending(self, locale):
        self.assign(20)
        UserProfile.objects.filter(user=self.owner_user).update(preferred_language=locale)
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        observed = self.publish(0, bandwidth_bytes=1024**3)
        sweep_hosting_warnings(at=observed)
        for body in bodies(EmailLog.objects.get()):
            self.assertIn("1024 MiB", body)
            self.assertIn("20480 MiB", body)
            self.assertIn("traficul lunar" if locale == "ro" else "monthly bandwidth", body)
            self.assertNotIn("alegeți un abonament" if locale == "ro" else "choose a suitable hosting plan", body)

    def test_english_pending_bandwidth_allowance(self):
        self.check_bandwidth_pending("en")

    def test_romanian_pending_bandwidth_allowance(self):
        self.check_bandwidth_pending("ro")

    def assign(self, gib):
        actor, _ = User.objects.get_or_create(
            email="warning-resource-admin@example.test", defaults={"staff_role": "admin"}
        )
        ticket, _ = Ticket.objects.get_or_create(
            customer=self.customer,
            title="Explicit resource exception",
            defaults={"description": "Reviewed resource-only fixture"},
        )
        target = ServicePlan.objects.create(
            name=f"Requested {gib} GiB",
            plan_type=self.plan.plan_type,
            disk_space_gb=gib,
            bandwidth_gb=gib,
            price_monthly=10,
        )
        return grant_resource_override(
            user=actor,
            service=self.service,
            target_plan_id=target.pk,
            ticket_id=ticket.pk,
            reason="Explicit reviewed resource-only assignment",
            expected_revision=ServiceHostingLimits.objects.get(service=self.service).revision,
            submission_id=uuid4(),
            billing_unchanged=True,
        )

    def queue_pending(self):
        self.assign(20)
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()
        return self.queue_critical()

    def test_actual_pending_target_change_refuses_stored_body_and_rebatches_fresh_requested_amount(self):
        original = self.queue_pending()
        self.assign(30)
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(original.pk))["success"])
        provider.assert_not_called()
        refused = HostingWarningDelivery.objects.get(email_log=original)
        self.assertEqual((refused.refusal_reason, refused.certainty), ("warning_desired_changed", "never_dispatched"))
        sweep_hosting_warnings()
        replacement = EmailLog.objects.exclude(pk=original.pk).get()
        for body in bodies(replacement):
            self.assertIn("30720 MiB", body)
            self.assertNotIn("20480 MiB", body)
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=replacement).parent_id, refused.pk)

    def test_uncertain_provider_acceptance_keeps_original_ownership_after_requested_target_changes(self):
        original = self.queue_pending()
        with patch(
            "django.core.mail.EmailMultiAlternatives.send",
            autospec=True,
            side_effect=TimeoutError("lost provider response"),
        ):
            self.assertFalse(send_email_task(str(original.pk))["success"])
        self.assign(30)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=1)),
            patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider,
        ):
            self.assertFalse(send_email_task(str(original.pk))["success"])
        provider.assert_not_called()
        sweep_hosting_warnings()
        self.assertEqual(EmailLog.objects.count(), 1)
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=original).certainty, "uncertain")

    def test_snapshot_schema_two_is_explicit_and_schema_one_is_not_reinterpreted(self):
        log = self.queue_pending()
        delivery = HostingWarningDelivery.objects.get(email_log=log)
        self.assertEqual(delivery.intent_snapshot["version"], 2)
        self.assertIsNotNone(_snapshot_parts(delivery))
        legacy = {**delivery.intent_snapshot, "version": 1}
        legacy["parts"] = [{key: value for key, value in part.items() if key != "desired"} for part in legacy["parts"]]
        self.assertIsNone(_snapshot_parts(HostingWarningDelivery(intent_snapshot=legacy)))

    def test_desired_snapshot_rejects_extra_fields_invalid_types_and_revisions(self):
        delivery = HostingWarningDelivery.objects.get(email_log=self.queue_pending())
        for update in (
            {"disk_mib": True},
            {"bandwidth_mib": -1},
            {"operational_revision": 0},
            {"operational_revision": 20},
            {"payment_received": True},
        ):
            with self.subTest(update=update):
                raw = deepcopy(delivery.intent_snapshot)
                raw["parts"][0]["desired"].update(update)
                self.assertIsNone(_snapshot_parts(HostingWarningDelivery(intent_snapshot=raw)))

    def test_real_legacy_queued_delivery_is_refused_and_replaced_with_explicit_new_schema(self):
        self.assign(20)
        self.publish(1024**3)
        intent = HostingWarningIntent.objects.get()
        result = EmailService.send_template_email(
            template_key="hosting_usage_warning",
            recipient=self.customer.primary_email,
            context={"warning_entries": ["Historical 100% warning"], "critical_notice": True},
            customer=self.customer,
            locale="en",
            async_send=True,
            require_async=True,
            essential=True,
        )
        self.assertTrue(result.success)
        log = EmailLog.objects.get(pk=result.email_log_id)
        # Seed the historical protocol through valid pending→linked transitions,
        # without overwriting existing immutable evidence.
        legacy = HostingWarningDelivery.objects.create(
            customer_id_snapshot=self.customer.pk,
            recipient_hash=recipient_hash(self.customer.primary_email),
            email_log=log,
            intent_snapshot={
                "version": 1,
                "body_hash": _body_hash(log),
                "parts": [
                    {
                        "id": str(intent.pk),
                        "identity": intent.identity,
                        "threshold": intent.threshold,
                        "allowance_mib": 1024,
                        "scope": intent.scope_snapshot,
                        "raise": None,
                    }
                ],
            },
        )
        HostingWarningDeliveryPart.objects.create(delivery=legacy, intent=intent)
        intent.link()
        intent.save(update_fields=["phase", "updated_at"])
        legacy.link()
        legacy.save(update_fields=["phase", "updated_at"])
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            self.assertFalse(send_email_task(str(log.pk))["success"])
        provider.assert_not_called()
        legacy.refresh_from_db()
        self.assertEqual((legacy.refusal_reason, legacy.certainty), ("warning_snapshot_obsolete", "never_dispatched"))
        sweep_hosting_warnings()
        replacement = HostingWarningDelivery.objects.exclude(pk=legacy.pk).get()
        self.assertEqual(replacement.intent_snapshot["version"], 2)
        self.assertEqual(replacement.parent_id, legacy.pk)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class PaidPendingWarningCopyTests(PlanOperationFixture, TransactionTestCase):
    def configure_mail(self, locale):
        self.installation = UUID(self.native_identity["installation"])
        self.policy.notification_owner = "platform"
        self.policy.notifications_verified_at = timezone.now()
        self.policy.notification_evidence = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": self.policy.connection_identity,
            "installation": str(self.installation),
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        self.policy.save(update_fields=["notification_owner", "notifications_verified_at", "notification_evidence"])
        owner = User.objects.create_user("pending-copy-owner@example.test")
        UserProfile.objects.update_or_create(user=owner, defaults={"preferred_language": locale})
        CustomerMembership.objects.create(user=owner, customer=self.customer, role="owner", is_primary=True)
        self.assertTrue(SettingsService.update_setting("provisioning.quota_warnings_enabled", True).is_ok())
        EmailTemplate.objects.filter(key="hosting_usage_warning").delete()
        setup_warning_pipeline()

    def queue_paid_pending(self, locale="en"):
        change = self.paid_change()
        self.configure_mail(locale)
        observed = WarningFixture.publish(self, 5 * 1024**3)
        self.warning_at = observed + timedelta(minutes=10)
        sweep_hosting_warnings(at=self.warning_at)
        return change, EmailLog.objects.get(template_key="hosting_usage_warning")

    def check_paid_pending(self, locale):
        change, log = self.queue_paid_pending(locale)
        self.assertEqual(change.status, "applying_limits")
        for body in bodies(log):
            self.assertIn("5120 MiB", body)
            self.assertIn("20480 MiB", body)
            self.assertIn("limita operațională" if locale == "ro" else "operational allowance", body)
            self.assertIn("verificarea este în așteptare" if locale == "ro" else "verification is pending", body)
            self.assertNotIn("alegeți un abonament" if locale == "ro" else "choose a suitable hosting plan", body)

    def test_actual_paid_upgrade_english_keeps_old_operational_and_requested_allowances(self):
        self.check_paid_pending("en")

    def test_actual_paid_upgrade_romanian_keeps_old_operational_and_requested_allowances(self):
        self.check_paid_pending("ro")

    def test_verified_paid_upgrade_does_not_reuse_stale_pending_copy(self):
        change, original = self.queue_paid_pending()
        with patch("django.utils.timezone.now", return_value=self.warning_at):
            self.apply(change)
            with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
                self.assertFalse(send_email_task(str(original.pk))["success"])
            provider.assert_not_called()
            WarningFixture.publish(self, 20 * 1024**3)
            sweep_hosting_warnings(at=self.warning_at)
        replacement = EmailLog.objects.filter(template_key="hosting_usage_warning").exclude(pk=original.pk).get()
        for body in bodies(replacement):
            self.assertIn("20480 MiB", body)
            self.assertNotIn("verification is pending", body)

    def test_verified_revision_clears_pending_copy_even_when_disk_allowance_did_not_change(self):
        target = self.target.default_service_plan
        target.disk_space_gb = 5
        target.save(update_fields=["disk_space_gb"])
        change, original = self.queue_paid_pending()
        with patch("django.utils.timezone.now", return_value=self.warning_at):
            self.apply(change)
            with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
                self.assertFalse(send_email_task(str(original.pk))["success"])
            provider.assert_not_called()
            self.assertEqual(
                HostingWarningDelivery.objects.get(email_log=original).refusal_reason, "warning_desired_changed"
            )
            sweep_hosting_warnings(at=self.warning_at)
        replacement = EmailLog.objects.filter(template_key="hosting_usage_warning").exclude(pk=original.pk).get()
        for body in bodies(replacement):
            self.assertIn("5120 MiB", body)
            self.assertNotIn("verification is pending", body)
