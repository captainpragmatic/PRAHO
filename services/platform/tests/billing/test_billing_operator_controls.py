"""Operator-control coverage for retry policies and legal invoice series."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.billing.models import InvoiceSequence, PaymentRetryPolicy
from apps.billing.operator_controls import BillingControlActor, rotate_invoice_series
from apps.billing.services import InvoiceNumberingService
from tests.factories.core_factories import create_admin_user, create_staff_user


class BillingOperatorControlAccessTests(TestCase):
    def setUp(self) -> None:
        self.billing_user = create_staff_user(username="billing_control", staff_role="billing")
        self.support_user = create_staff_user(username="support_control", staff_role="support")
        self.manager_user = create_staff_user(username="manager_control", staff_role="manager")
        self.admin_user = create_admin_user(username="admin_control")

    def test_controls_require_admin_or_billing_role(self) -> None:
        url = reverse("billing:operator_controls")
        self.assertEqual(self.client.get(url).status_code, 302)

        for user in (self.support_user, self.manager_user):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                self.assertEqual(self.client.get(url).status_code, 403)

        for user in (self.billing_user, self.admin_user):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_billing_settings_links_to_both_domain_editors(self) -> None:
        self.client.force_login(self.billing_user)

        response = self.client.get(reverse("settings:group", args=["billing"]))

        self.assertContains(response, reverse("billing:operator_controls"))
        self.assertContains(response, reverse("billing:invoice_series_create"))

    def test_billing_settings_hides_control_links_from_unprivileged_staff(self) -> None:
        for user in (self.support_user, self.manager_user):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                response = self.client.get(reverse("settings:group", args=["billing"]))
                self.assertNotContains(response, reverse("billing:operator_controls"))
                self.assertNotContains(response, reverse("billing:invoice_series_create"))


class PaymentRetryPolicyEditorTests(TestCase):
    def setUp(self) -> None:
        self.user = create_staff_user(username="policy_editor", staff_role="billing")
        self.policy = PaymentRetryPolicy.objects.create(
            name="Standard",
            description="Default collection policy",
            retry_intervals_days=[1, 3, 7],
            max_attempts=3,
            suspend_service_after_days=14,
            terminate_service_after_days=30,
            send_dunning_emails=True,
            is_default=True,
            is_active=True,
        )
        self.client.force_login(self.user)

    def _post(self, **overrides: object):
        data: dict[str, object] = {
            "name": "Standard",
            "description": "Updated collection policy",
            "retry_intervals_days": "1, 3, 10",
            "max_attempts": 3,
            "suspend_service_after_days": 14,
            "terminate_service_after_days": 30,
            "send_dunning_emails": "on",
            "is_default": "on",
            "is_active": "on",
            "reason": "Align retries with the collection runbook",
            "baseline": self.policy.updated_at.isoformat(),
        }
        data.update(overrides)
        return self.client.post(reverse("billing:retry_policy_edit", args=[self.policy.pk]), data)

    def test_valid_change_is_persisted_and_attributed_in_audit(self) -> None:
        response = self._post()

        self.assertRedirects(response, reverse("billing:operator_controls"))
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.retry_intervals_days, [1, 3, 10])
        event = AuditEvent.objects.get(content_type__model="paymentretrypolicy", object_id=str(self.policy.pk))
        self.assertEqual(event.action, "configuration_changed")
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.metadata["reason"], "Align retries with the collection runbook")
        self.assertEqual(event.old_values["retry_intervals_days"], [1, 3, 7])
        self.assertEqual(event.new_values["retry_intervals_days"], [1, 3, 10])

    def test_editor_exposes_only_live_runtime_policy_fields(self) -> None:
        response = self.client.get(reverse("billing:retry_policy_edit", args=[self.policy.pk]))

        self.assertNotContains(response, 'name="suspend_service_after_days"')
        self.assertNotContains(response, 'name="terminate_service_after_days"')
        self.assertContains(response, "subscription grace-period controls")

    def test_invalid_timeline_and_missing_reason_do_not_mutate_policy(self) -> None:
        response = self._post(
            retry_intervals_days="1, 3, 3",
            suspend_service_after_days=3,
            reason="",
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "strictly increasing")
        self.assertContains(response, "reason")
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.retry_intervals_days, [1, 3, 7])
        self.assertFalse(
            AuditEvent.objects.filter(content_type__model="paymentretrypolicy", object_id=str(self.policy.pk)).exists()
        )

    def test_making_another_policy_default_demotes_the_previous_default(self) -> None:
        other = PaymentRetryPolicy.objects.create(
            name="VIP",
            retry_intervals_days=[1, 4],
            max_attempts=2,
            suspend_service_after_days=10,
            terminate_service_after_days=30,
            is_active=True,
        )
        response = self.client.post(
            reverse("billing:retry_policy_edit", args=[other.pk]),
            {
                "name": "VIP",
                "description": "",
                "retry_intervals_days": "1, 4",
                "max_attempts": 2,
                "suspend_service_after_days": 10,
                "terminate_service_after_days": 30,
                "send_dunning_emails": "on",
                "is_default": "on",
                "is_active": "on",
                "reason": "VIP is now the default",
                "baseline": other.updated_at.isoformat(),
            },
        )

        self.assertRedirects(response, reverse("billing:operator_controls"))
        self.policy.refresh_from_db()
        other.refresh_from_db()
        self.assertFalse(self.policy.is_default)
        self.assertTrue(other.is_default)

    @patch("apps.billing.operator_controls.PaymentRetryPolicy.objects.select_for_update")
    def test_policy_update_locks_every_policy_in_deterministic_order(self, select_for_update: MagicMock) -> None:
        """Concurrent default promotions must not lock their target rows in opposite order."""
        other = PaymentRetryPolicy.objects.create(
            name="VIP",
            retry_intervals_days=[1, 4],
            max_attempts=2,
            suspend_service_after_days=10,
            terminate_service_after_days=30,
            is_active=True,
        )
        locked_queryset = MagicMock()
        locked_queryset.order_by.return_value = sorted([self.policy, other], key=lambda policy: policy.pk)
        select_for_update.return_value = locked_queryset

        response = self.client.post(
            reverse("billing:retry_policy_edit", args=[other.pk]),
            {
                "name": "VIP",
                "description": "",
                "retry_intervals_days": "1, 4",
                "max_attempts": 2,
                "send_dunning_emails": "on",
                "is_default": "on",
                "is_active": "on",
                "reason": "Promote VIP without lock inversion",
                "baseline": other.updated_at.isoformat(),
            },
        )

        self.assertRedirects(response, reverse("billing:operator_controls"))
        locked_queryset.order_by.assert_called_once_with("id")
        locked_queryset.get.assert_not_called()
        self.policy.refresh_from_db()
        other.refresh_from_db()
        self.assertFalse(self.policy.is_default)
        self.assertTrue(other.is_default)

    def test_stale_policy_editor_cannot_overwrite_a_newer_change(self) -> None:
        original_baseline = self.policy.updated_at.isoformat()
        self.policy.description = "Changed by another operator"
        self.policy.save(update_fields=["description", "updated_at"])

        response = self._post(baseline=original_baseline)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "changed while you were editing")
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.description, "Changed by another operator")

    @patch("apps.audit.services.AuditService.log_simple_event", side_effect=RuntimeError("audit unavailable"))
    def test_audit_failure_rolls_back_policy_change(self, _mock_audit) -> None:
        with self.assertRaises(RuntimeError):
            self._post()

        self.policy.refresh_from_db()
        self.assertEqual(self.policy.retry_intervals_days, [1, 3, 7])


class InvoiceSeriesControlTests(TestCase):
    def setUp(self) -> None:
        self.user = create_admin_user(username="series_editor")
        self.current = InvoiceSequence.objects.create(scope="default", prefix="INV", last_value=42)
        self.client.force_login(self.user)

    def _post(self, **overrides: str):
        data = {
            "prefix": "INV-2027",
            "confirmation": "INV-2027",
            "reason": "Start the 2027 legal invoice series",
            "baseline": f"{self.current.prefix}:{self.current.last_value}",
        }
        data.update(overrides)
        return self.client.post(reverse("billing:invoice_series_create"), data)

    def test_rotation_archives_old_sequence_and_new_issuance_uses_new_prefix(self) -> None:
        response = self._post()

        self.assertRedirects(response, reverse("billing:operator_controls"))
        self.current.refresh_from_db()
        self.assertEqual(self.current.scope, "default")
        self.assertEqual(self.current.prefix, "INV-2027")
        self.assertEqual(self.current.last_value, 0)
        archived = InvoiceSequence.objects.get(scope="archived:INV")
        self.assertEqual(archived.prefix, "INV")
        self.assertEqual(archived.last_value, 42)
        self.assertEqual(InvoiceNumberingService.get_next_number(), "INV-2027-000001")

        event = AuditEvent.objects.get(content_type__model="invoicesequence", object_id=str(self.current.pk))
        self.assertEqual(event.action, "configuration_changed")
        self.assertEqual(event.metadata["reason"], "Start the 2027 legal invoice series")
        self.assertEqual(event.old_values["prefix"], "INV")
        self.assertEqual(event.old_values["last_value"], 42)
        self.assertEqual(event.new_values["prefix"], "INV-2027")
        self.assertEqual(event.new_values["last_value"], 0)

    def test_rotation_requires_matching_confirmation_and_reason(self) -> None:
        response = self._post(confirmation="INV-2026", reason="")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "confirmation")
        self.assertContains(response, "reason")
        self.current.refresh_from_db()
        self.assertEqual(self.current.scope, "default")
        self.assertEqual(self.current.last_value, 42)

    def test_rotation_confirmation_is_case_sensitive(self) -> None:
        response = self._post(confirmation="inv-2027")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "exactly match")
        self.current.refresh_from_db()
        self.assertEqual(self.current.prefix, "INV")

    def test_domain_service_rejects_a_blank_audit_reason(self) -> None:
        with self.assertRaisesMessage(ValidationError, "audit reason"):
            rotate_invoice_series(
                prefix="INV-2027",
                baseline="INV:42",
                actor=BillingControlActor(user=self.user, reason="  ", ip_address=None),
            )

        self.current.refresh_from_db()
        self.assertEqual(self.current.prefix, "INV")
        self.assertFalse(InvoiceSequence.objects.filter(scope="archived:INV").exists())

    def test_previously_used_prefix_cannot_be_reused(self) -> None:
        InvoiceSequence.objects.create(scope="archived-1", prefix="INV-2027", last_value=100)

        response = self._post()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")
        self.current.refresh_from_db()
        self.assertEqual(self.current.scope, "default")

    def test_form_never_exposes_the_legal_counter_as_an_input(self) -> None:
        response = self.client.get(reverse("billing:invoice_series_create"))

        self.assertNotContains(response, 'name="last_value"')
        self.assertContains(response, "last value")

    def test_controls_preview_each_active_series_without_advancing_counters(self) -> None:
        subscription = InvoiceSequence.objects.create(scope="subscription", prefix="SUB", last_value=9)

        response = self.client.get(reverse("billing:operator_controls"))

        self.assertContains(response, "INV-000043")
        self.assertContains(response, "SUB-000010")
        self.current.refresh_from_db()
        subscription.refresh_from_db()
        self.assertEqual(self.current.last_value, 42)
        self.assertEqual(subscription.last_value, 9)

    def test_first_series_can_be_created_when_no_default_exists(self) -> None:
        self.current.delete()

        response = self._post(baseline="missing")

        self.assertRedirects(response, reverse("billing:operator_controls"))
        active = InvoiceSequence.objects.get(scope="default")
        self.assertEqual(active.prefix, "INV-2027")
        self.assertEqual(active.last_value, 0)
        self.assertFalse(InvoiceSequence.objects.filter(scope__startswith="archived:").exists())

    def test_stale_rotation_is_rejected_after_an_invoice_number_is_issued(self) -> None:
        self.assertEqual(InvoiceNumberingService.get_next_number(), "INV-000043")

        response = self._post()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "active series changed")
        active = InvoiceSequence.objects.get(scope="default")
        self.assertEqual(active.prefix, "INV")
        self.assertEqual(active.last_value, 43)

    def test_stale_rotation_is_rejected_when_the_prefix_changed_at_the_same_counter(self) -> None:
        InvoiceSequence.objects.filter(pk=self.current.pk).update(prefix="INV-OTHER")

        response = self._post()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "active series changed")
        active = InvoiceSequence.objects.get(scope="default")
        self.assertEqual(active.prefix, "INV-OTHER")
        self.assertEqual(active.last_value, 42)

    @patch("apps.audit.services.AuditService.log_simple_event", side_effect=RuntimeError("audit unavailable"))
    def test_audit_failure_rolls_back_series_rotation(self, _mock_audit) -> None:
        with self.assertRaises(RuntimeError):
            self._post()

        self.current.refresh_from_db()
        self.assertEqual(self.current.scope, "default")
        self.assertEqual(self.current.prefix, "INV")
        self.assertEqual(self.current.last_value, 42)
        self.assertFalse(InvoiceSequence.objects.filter(scope="archived:INV").exists())
