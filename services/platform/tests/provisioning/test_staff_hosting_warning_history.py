"""Staff history uses accepted observations and current-owner durable mail records."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.customers.models import Customer
from apps.notifications.models import EmailSuppression
from apps.notifications.tasks import send_email_task
from apps.provisioning.hosting_warning_delivery import sweep_hosting_warnings
from apps.provisioning.hosting_warning_models import (
    HostingWarningDelivery,
    HostingWarningDeliveryPart,
    HostingWarningIntent,
)
from apps.provisioning.hosting_warning_staff import staff_hosting_history
from apps.provisioning.virtualmin_usage_service import prime_service_usage
from apps.users.models import User
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class StaffHostingWarningHistoryTests(WarningFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.staff = User.objects.create_user("warning-support@example.test", staff_role="support")
        self.client.force_login(self.staff)
        self.url = reverse("provisioning:service_detail", args=[self.service.pk])

    def test_staff_page_shows_canonical_reading_trend_and_actual_provider_acceptance(self):
        log = self.queue_critical()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1):
            self.assertTrue(send_email_task(str(log.pk))["success"])
        sweep_hosting_warnings()

        page = self.client.get(self.url)
        self.assertContains(page, "Usage trend and warning history")
        self.assertContains(page, "Disk · 100%")
        self.assertContains(page, "Accepted by email provider")
        self.assertContains(page, "1.000 GiB")
        history = page.context["staff_hosting_history"]
        self.assertEqual(len(history.disk_trend), 1)
        self.assertEqual(history.disk_trend[0].gib, 1)
        self.assertEqual(history.warnings[0].attempts[0].accepted_at, log.__class__.objects.get(pk=log.pk).sent_at)
        self.assertNotContains(page, log.body_text)
        self.assertNotContains(page, log.get_decrypted_body_text())
        intent = HostingWarningIntent.objects.get()
        self.assertNotContains(page, intent.recipient_hash)
        self.assertNotContains(page, intent.identity)
        self.assertNotContains(page, str(self.installation))

    def test_refused_attempt_is_visible_without_raw_refusal_payload(self):
        log = self.queue_critical()
        EmailSuppression.suppress(self.customer.primary_email, "hard_bounce")
        self.assertFalse(send_email_task(str(log.pk))["success"])
        page = self.client.get(self.url)
        self.assertContains(page, "Recipient suppressed")
        self.assertContains(page, "Not dispatched")
        self.assertNotContains(page, "warning_recipient_suppressed")

    def test_unknown_refusal_payload_is_never_projected_into_staff_html(self):
        self.queue_critical()
        delivery = HostingWarningDelivery.objects.get()
        delivery.refuse("PRIVATE_REASON_DO_NOT_RENDER")
        delivery.save()
        page = self.client.get(self.url)
        self.assertContains(page, "Delivery refused; review notification status.")
        self.assertNotContains(page, "PRIVATE_REASON_DO_NOT_RENDER")

    def test_transfers_and_return_transfer_hide_previous_owner_scope(self):
        self.queue_critical()
        other = Customer.objects.create(name="New warning owner", status="active")
        for owner in (other, self.customer):
            self.service.customer = owner
            self.service.save(update_fields=["customer"])
            page = self.client.get(self.url)
            self.assertContains(page, "No warning history for the current ownership period.")
            history = page.context["staff_hosting_history"]
            self.assertEqual(history.warnings, ())
            self.assertEqual(history.disk_trend, ())

    def test_delivery_parts_refuse_customer_snapshot_mismatch(self):
        self.queue_critical()
        intent = HostingWarningIntent.objects.get()
        alien = HostingWarningDelivery.objects.create(
            customer_id_snapshot=self.customer.pk + 999,
            recipient_hash=intent.recipient_hash,
            intent_snapshot={},
            refusal_reason="private_operator_payload",
        )
        HostingWarningDeliveryPart.objects.create(intent=intent, delivery=alien, active=False)
        page = self.client.get(self.url)
        history = page.context["staff_hosting_history"]
        self.assertEqual(len(history.warnings[0].attempts), 1)
        self.assertNotContains(page, "private_operator_payload")

    def test_stale_current_reading_has_age_and_does_not_claim_freshness(self):
        observed = self.publish(1024**3)
        with patch("django.utils.timezone.now", return_value=observed + timedelta(hours=7)):
            page = self.client.get(self.url)
        self.assertContains(page, "Stale reading")
        self.assertContains(page, "7 hours ago")

    def test_customer_user_cannot_receive_staff_history(self):
        self.queue_critical()
        self.client.force_login(self.owner_user)
        page = self.client.get(self.url)
        self.assertNotIn("staff_hosting_history", page.context or {})
        self.assertNotContains(page, "Usage trend and warning history", status_code=page.status_code)

    def test_only_current_service_and_customer_intent_snapshots_are_selected(self):
        self.queue_critical()
        original = HostingWarningIntent.objects.get()
        fields = (
            "state_id",
            "service_id_snapshot",
            "customer_id_snapshot",
            "owner_scope",
            "resource",
            "generation",
            "threshold",
            "recipient_hash",
            "channel",
            "kind",
            "due_at",
            "scope_snapshot",
            "evidence_snapshot",
        )
        for changed in ("service_id_snapshot", "customer_id_snapshot"):
            values = {field: getattr(original, field) for field in fields}
            values[changed] += 999
            HostingWarningIntent.objects.create(**values, identity=uuid4().hex)
        page = self.client.get(self.url)
        self.assertEqual(len(page.context["staff_hosting_history"].warnings), 1)

    def test_accepted_monthly_bandwidth_warning_uses_its_own_resource(self):
        observed = self.publish(512 * 1024**2, bandwidth_bytes=1024**3)
        self.assertEqual(sweep_hosting_warnings(at=observed), {"linked": 1})
        page = self.client.get(self.url)
        self.assertContains(page, "Monthly bandwidth · 100%")
        self.assertContains(page, "0.500 GiB")
        self.assertContains(page, "1.000 GiB")
        self.assertEqual(page.context["staff_hosting_history"].warnings[0].resource, "Monthly bandwidth")

    def test_fifty_warning_rows_are_bounded_and_loaded_in_six_queries(self):
        self.queue_critical()
        original = HostingWarningIntent.objects.get()
        delivery = HostingWarningDelivery.objects.get()
        fields = (
            "state_id",
            "service_id_snapshot",
            "customer_id_snapshot",
            "owner_scope",
            "resource",
            "generation",
            "threshold",
            "recipient_hash",
            "channel",
            "kind",
            "due_at",
            "reading_id",
            "scope_snapshot",
            "evidence_snapshot",
        )
        for _index in range(50):
            values = {field: getattr(original, field) for field in fields}
            intent = HostingWarningIntent.objects.create(**values, identity=uuid4().hex)
            HostingWarningDeliveryPart.objects.create(intent=intent, delivery=delivery)
        prime_service_usage([self.service])
        with self.assertNumQueries(6):
            history = staff_hosting_history(self.service)
        self.assertEqual(len(history.warnings), 50)
        self.assertTrue(all(len(warning.attempts) == 1 for warning in history.warnings))
