"""A scheduled downgrade may use only its clamped, still-valid temporary R."""

from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase

from apps.billing.plan_change_lifecycle import activate_scheduled_plan_change
from apps.billing.plan_change_safety import current_safety_used_bytes
from apps.products.models import ProductPrice, ProductRelationship
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_policy import effective_disk_limit
from tests.provisioning.test_hosting_raise_financial import CommercialRaiseFixture


class HostingRaiseDowngradeTests(CommercialRaiseFixture, TransactionTestCase):
    period_remaining = timedelta(days=2)

    def setUp(self):
        self.native_used_mib = 0
        super().setUp()
        plan = self.target.default_service_plan
        plan.disk_space_gb, plan.bandwidth_gb = 2, 10
        plan.save(update_fields=["disk_space_gb", "bandwidth_gb"])
        ProductPrice.objects.filter(product=self.target).update(monthly_price_cents=4000)
        ProductRelationship.objects.filter(source_product=self.product, target_product=self.target).delete()
        ProductRelationship.objects.create(
            source_product=self.target, target_product=self.product, relationship_type="upgrades_to"
        )

    def receipt(self, **kwargs):
        value = super().receipt(**kwargs)
        value["observation"] = {
            "files_bytes": self.native_used_mib * 1024**2,
            "database_bytes": 0,
            "total_bytes": self.native_used_mib * 1024**2,
        }
        return value

    def raised_usage(self, *, expires_at, used_mib=2304):
        raised = self.grant(expires_at=expires_at)
        self.assertEqual(self.apply(raised), "completed")
        self.native_used_mib = used_mib
        self.publish_usage(used_mib, 0)
        self.observe()
        self.assertEqual(current_safety_used_bytes(self.service), used_mib * 1024**2)
        return raised

    def test_quote_schedule_and_boundary_allow_assigned_plus_clamped_valid_raise(self):
        self.raised_usage(expires_at=self.subscription.current_period_end + timedelta(hours=1), used_mib=2560)
        change = self.confirm(self.quote())
        self.assertEqual(change.status, "scheduled")
        with patch("django.utils.timezone.now", return_value=change.effective_at):
            activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
            self.assertEqual(activated.status, "applying_limits")
            application = activated.limit_application
            self.assertEqual((application.disk_allowance_mib, application.overlay_extra_mib), (2048, 512))
            self.publish_usage(2560, 0)
            self.assertEqual(self.apply(application), "completed")
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.operational_disk_allowance_mib, limits.applied_overlay_revision), (2048, 2))
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.unit_price_cents, 4000)
        self.assertEqual(self.account.effective_disk_quota_mb, effective_disk_limit(2048, extra_mib=512))

    def test_raise_expiring_at_the_boundary_cannot_qualify_usage_above_target_assignment(self):
        self.raised_usage(expires_at=self.subscription.current_period_end)
        with self.assertRaisesMessage(ValidationError, "exceeds"):
            self.quote()

    def test_quote_fit_never_uses_hidden_headroom_above_assigned_plus_clamped_raise(self):
        self.raised_usage(expires_at=self.subscription.current_period_end + timedelta(hours=1), used_mib=2561)
        with self.assertRaisesMessage(ValidationError, "exceeds"):
            self.quote()

    def test_late_boundary_after_accepted_raise_expiry_keeps_lower_price_without_native_increase(self):
        raised = self.raised_usage(expires_at=self.subscription.current_period_end + timedelta(hours=1))
        change = self.confirm(self.quote())
        with patch("django.utils.timezone.now", return_value=raised.overlay_expires_at + timedelta(seconds=1)):
            activated = activate_scheduled_plan_change(change.pk, at=raised.overlay_expires_at + timedelta(seconds=1))
            self.assertEqual(activated.status, "applying_limits")
            self.assertEqual(activated.limit_application.overlay_extra_mib, 0)
            self.publish_usage(2304, 0)
            with (
                patch(
                    "apps.provisioning.hosting_limit_transport.probe_account_quota",
                    return_value=self.receipt(cap=self.account.effective_disk_quota_mb),
                ),
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            ):
                self.assertEqual(apply_hosting_limits(activated.limit_application_id), "pending")
            native.assert_not_called()
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.unit_price_cents, 4000)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).operational_disk_allowance_mib, 5120)
