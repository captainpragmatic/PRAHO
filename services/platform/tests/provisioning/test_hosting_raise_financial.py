"""Real signed financial events must follow the purchased base through composed R."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TransactionTestCase

from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_tasks import current_application
from apps.provisioning.hosting_raise_service import expire_hosting_raise
from apps.settings.services import SettingsService
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
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", True).is_ok())

    def settled_topup(self):
        change, attempt, sdk = self.ready_attempt()
        accepted, message, _event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        return change, attempt


class HostingRaiseFinancialTests(CommercialRaiseFixture, TransactionTestCase):
    def test_real_signed_dispute_blocks_new_composed_raise_before_any_native_observation(self):
        change, attempt = self.settled_topup()
        self.assertEqual(self.apply(change.limit_application, available=100 * 1024**3), "completed")
        raised = self.grant()
        self.dispute(attempt.gateway_intent_id, amount=change.total_cents)
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt(cap=22528, available=100 * 1024**3)) as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=lambda server, action, request: self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)) as native,
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
        with patch("apps.provisioning.hosting_raise_service.timezone.now", return_value=raised.overlay_expires_at + timedelta(seconds=1)):
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
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt(cap=5632, available=100 * 1024**3)) as probe,
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=lambda server, action, request: self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)) as native,
            ):
                apply_hosting_limits(pending.pk)
        probe.assert_not_called()
        native.assert_not_called()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.operational_revision, raised.revision)
        self.assertEqual(limits.revision, change.limit_application.revision)
