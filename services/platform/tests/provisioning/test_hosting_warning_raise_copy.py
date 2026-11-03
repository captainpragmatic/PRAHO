"""Real raise acceptance/verification changes the immutable customer warning body."""

from datetime import timedelta
from unittest.mock import patch
from uuid import UUID

from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.notifications.tasks import send_email_task
from apps.provisioning.hosting_node_policy import NOTIFICATION_EMITTERS
from apps.provisioning.hosting_raise_service import raise_public_state
from apps.provisioning.hosting_warning_delivery import setup_warning_pipeline, sweep_hosting_warnings
from apps.provisioning.hosting_warning_models import HostingWarningDelivery
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User, UserProfile
from tests.provisioning import test_hosting_raises as raises
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class HostingWarningRaiseCopyTests(HostingLimitWorkerFixture, TransactionTestCase):
    # Reuse actual native-boundary fixtures, not successful business-service mocks.
    receipt = raises.HostingRaiseTests.receipt
    apply = raises.HostingRaiseTests.apply
    observe = raises.HostingRaiseTests.observe
    grant = raises.HostingRaiseTests.grant

    def setUp(self):
        raises.HostingRaiseTests.setUp(self)
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
        owner = User.objects.create_user(self.customer.primary_email, "fixture-password")
        UserProfile.objects.update_or_create(user=owner, defaults={"preferred_language": "en"})
        CustomerMembership.objects.create(user=owner, customer=self.customer, role="owner", is_primary=True)
        self.assertTrue(SettingsService.update_setting("provisioning.quota_warnings_enabled", True).is_ok())
        setup_warning_pipeline()

    def queue_warning(self):
        observed = WarningFixture.publish(self, 5 * 1024**3)
        # The native fixture predates its explicit mail handover.
        self.warning_at = observed + timedelta(minutes=10)
        sweep_hosting_warnings(at=self.warning_at)
        return EmailLog.objects.get(template_key="hosting_usage_warning")

    def test_requested_raise_is_not_advertised_as_available_space_and_keeps_purchased_warning(self):
        self.grant()
        self.assertEqual(raise_public_state(self.service.pk).state, "requested")
        log = self.queue_warning()
        body = log.get_decrypted_body_text()
        self.assertIn("100%", body)
        self.assertIn("5120 MiB", body)
        self.assertIn("additional capacity is not yet verified", body)
        self.assertIn("Warnings remain based on the purchased allowance", body)

    def test_raise_verified_after_queue_refuses_old_body_and_rebatches_current_expiry_copy(self):
        application = self.grant()
        original = self.queue_warning()
        self.assertEqual(self.apply(application), "completed")
        self.assertEqual(raise_public_state(self.service.pk).state, "verified")
        with (
            patch("django.utils.timezone.now", return_value=self.warning_at),
            patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider,
        ):
            result = send_email_task(str(original.pk))
            self.assertFalse(result["success"], result)
            provider.assert_not_called()
        self.assertEqual(HostingWarningDelivery.objects.get(email_log=original).refusal_reason, "warning_raise_changed")
        sweep_hosting_warnings(at=self.warning_at)
        replacement = EmailLog.objects.filter(template_key="hosting_usage_warning").exclude(pk=original.pk).get()
        self.assertIn("temporary disk raise is verified until its expiry", replacement.get_decrypted_body_text())
        self.assertIn("5120 MiB", replacement.get_decrypted_body_text())
