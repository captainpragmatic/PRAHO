"""Real signed financial events must follow the purchased base through composed R."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TransactionTestCase, override_settings

from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_tasks import current_application
from apps.provisioning.hosting_raise_service import expire_hosting_raise
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.billing.test_plan_change_historical_authority import HistoricalAuthorityRestoreFixture
from tests.helpers.plan_change_financial import StripeCoverageFixture
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class CommercialRaiseFixture(StripeCoverageFixture):
    apply = HostingRaiseFixture.apply
    observe = HostingRaiseFixture.observe
    grant = HostingRaiseFixture.grant

    def receipt(self, **kwargs):
        value = HostingRaiseFixture.receipt(self, **kwargs)
        request = kwargs.get("request")
        if request:
            value["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
        return value

    def setUp(self):
        super().setUp()
        self.account.refresh_from_db()
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", True).is_ok())

    def settled_topup(self):
        change, attempt, sdk = self.ready_attempt()
        accepted, message, _event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        change.refresh_from_db()
        attempt.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        return change, attempt


class HostingRaiseFinancialTests(CommercialRaiseFixture, TransactionTestCase):
    def test_real_signed_dispute_blocks_new_composed_raise_before_any_native_observation(self):
        change, attempt = self.settled_topup()
        self.assertEqual(self.apply(change.limit_application, available=100 * 1024**3), "completed")
        raised = self.grant()
        self.dispute(attempt.gateway_intent_id, amount=change.total_cents)
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(cap=22528, available=100 * 1024**3),
            ) as probe,
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.receipt(
                    cap=request["disk_limit_kib"] // 1024, request=request
                ),
            ) as native,
        ):
            apply_hosting_limits(raised.pk)
        probe.assert_not_called()
        native.assert_not_called()
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).applied_overlay_revision, 0)

    def test_real_disputed_newer_desire_does_not_block_operational_only_expiry_cleanup(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        change, attempt = self.settled_topup()
        self.dispute(attempt.gateway_intent_id, amount=change.total_cents)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                cleanup = expire_hosting_raise(self.service.pk)
            self.assertIsNotNone(cleanup)
            self.assertEqual(cleanup.revision, raised.revision)
            self.assertEqual(self.apply(cleanup), "completed")
            self.assertEqual(self.account.effective_disk_quota_mb, 5632)
            pending = current_application(self.service.pk)
            self.assertEqual(pending.revision, change.limit_application.revision)
            self.assertEqual(pending.overlay_extra_mib, 0)
            with (
                patch(
                    "apps.provisioning.hosting_limit_transport.probe_account_quota",
                    return_value=self.receipt(cap=5632, available=100 * 1024**3),
                ) as probe,
                patch(
                    "apps.provisioning.hosting_limit_transport.run_quota_operation",
                    side_effect=lambda server, action, request: self.receipt(
                        cap=request["disk_limit_kib"] // 1024, request=request
                    ),
                ) as native,
            ):
                apply_hosting_limits(pending.pk)
        probe.assert_not_called()
        native.assert_not_called()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.operational_revision, raised.revision)
        self.assertEqual(limits.revision, change.limit_application.revision)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class ComposedAuthorityRestoreTests(HistoricalAuthorityRestoreFixture, TransactionTestCase):
    observe = HostingRaiseFixture.observe
    apply_raise = HostingRaiseFixture.apply

    def grant(self, **kwargs):
        self.account.refresh_from_db()
        return HostingRaiseFixture.grant(self, **kwargs)

    def setUp(self):
        super().setUp()
        self.staff = User.objects.get(email="restore-adoption@example.com")
        self.ticket = Ticket.objects.get(customer=self.customer)
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", True).is_ok())

    def receipt(self, cap=1024, request=None, available=100 * 1024**3):
        value = {**super().receipt(cap=cap, request=request, available=available), "quota_protocol": 2}
        if request:
            value["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
        return value

    def test_visible_dispute_before_new_public_composed_restore_never_issues_archive(self):
        self.completed_change()
        raised = self.grant()
        self.assertEqual(self.apply_raise(raised), "completed")
        self.dispute("pi_original_paid_coverage", amount=8000)
        job, outcome = self.execute_restore()
        self.assertNotEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(self.node_variables, [])
        self.assertFalse(job.parameters.get("hosting_limits_issued"))

    def test_signed_dispute_after_composed_archive_issuance_keeps_exact_bounded_repair(self):
        self.completed_change()
        raised = self.grant()
        self.assertEqual(self.apply_raise(raised), "completed")
        original = self.node_restore

        def issued(server, variables, **kwargs):
            result = original(server, variables, **kwargs)
            self.dispute("pi_original_paid_coverage", amount=8000)
            return result

        with patch.object(self, "node_restore", side_effect=issued):
            job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], (22528 + 1280) * 1024)

    def test_issued_old_base_parent_is_not_rebound_to_later_disputed_paid_desire(self):
        raised = self.grant()
        self.assertEqual(self.apply_raise(raised), "completed")
        change, attempt, sdk = self.ready_attempt()
        original = self.node_restore

        def issued(server, variables, **kwargs):
            result = original(server, variables, **kwargs)
            accepted, message, _event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
            self.assertTrue(accepted, message)
            change.refresh_from_db()
            attempt.refresh_from_db()
            self.assertEqual(change.status, "applying_limits")
            self.dispute(attempt.gateway_intent_id, amount=change.total_cents)
            return result

        with patch.object(self, "node_restore", side_effect=issued):
            job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], (5632 + 1280) * 1024)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.operational_revision, limits.revision), (raised.revision, raised.revision + 1))

    def test_expiry_cleanup_does_not_authorize_a_new_archive_after_visible_dispute(self):
        self.completed_change()
        raised = self.grant()
        self.assertEqual(self.apply_raise(raised), "completed")
        self.dispute("pi_original_paid_coverage", amount=8000)
        with patch("django.utils.timezone.now", return_value=raised.overlay_expires_at + timedelta(seconds=1)):
            with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                cleanup = expire_hosting_raise(self.service.pk)
            self.assertEqual(self.apply_raise(cleanup), "completed")
            job, outcome = self.execute_restore()
        self.assertNotEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(self.node_variables, [])
        self.assertFalse(job.parameters.get("hosting_limits_issued"))

    def test_later_currency_transition_keeps_composed_historical_restore_authority(self):
        change = self.completed_change()
        restore_at = self.change_currency_through_notified_renewals()
        with patch("django.utils.timezone.now", return_value=restore_at):
            self.publish_usage(1, 1)
            raised = self.grant()
            self.assertEqual(self.apply_raise(raised, available=100 * 1024**3), "completed")
            job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(len(self.node_variables), 1)
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], (22528 + 1280) * 1024)
        change.refresh_from_db()
        self.assertEqual(change.currency_id, "RON")
        self.assertEqual(self.service.currency_id, "EUR")
        self.assertEqual(VirtualminProvisioningJob.objects.get(pk=job.pk).status, "completed")
