"""Stored node reserve changes actual temporary-capacity admission."""

from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase

from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.hosting_raise_models import ServiceHostingRaise
from apps.provisioning.hosting_raise_service import grant_hosting_raise, raise_public_state
from apps.settings.services import SettingsService
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class HostingRaiseSettingsTests(HostingRaiseFixture, TransactionTestCase):
    def test_stored_disk_reserve_controls_raise_admission_without_publishing_refused_terms(self) -> None:
        self.observe(available=2 * 1024**3)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.disk_allowance_mib, self.account.effective_disk_quota_mb), (5120, 5632))
        original_price = self.service.price
        applications_before = HostingLimitApplication.objects.count()
        verified_before = limits.verified_at
        submission_id = uuid4()

        self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1024).is_ok())
        with patch("apps.provisioning.hosting_limit_tasks.async_task") as enqueue:
            with self.assertRaisesMessage(ValidationError, "Refresh sufficient unreserved node capacity"):
                grant_hosting_raise(
                    user=self.staff,
                    service=self.service,
                    extra_mib=1280,
                    ticket_id=self.ticket.pk,
                    reason="Temporary incident relief within the stored node reserve",
                    expected_base_revision=limits.revision,
                    expected_overlay_revision=0,
                    submission_id=submission_id,
                )
            enqueue.assert_not_called()
            self.assertFalse(ServiceHostingRaise.objects.filter(service=self.service).exists())
            self.assertEqual(HostingLimitApplication.objects.count(), applications_before)
            limits.refresh_from_db()
            self.assertEqual(limits.verified_at, verified_before)

            self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 512).is_ok())
            application = grant_hosting_raise(
                user=self.staff,
                service=self.service,
                extra_mib=1280,
                ticket_id=self.ticket.pk,
                reason="Temporary incident relief within the stored node reserve",
                expected_base_revision=limits.revision,
                expected_overlay_revision=0,
                submission_id=submission_id,
            )
            enqueue.assert_called_once()
            self.assertEqual(enqueue.call_args.args[1], str(application.pk))

        row = ServiceHostingRaise.objects.get(service=self.service)
        self.assertEqual((row.extra_mib, row.revision), (1280, 1))
        self.assertEqual((application.overlay_extra_mib, application.overlay_revision), (1280, 1))
        self.assertEqual(HostingLimitApplication.objects.count(), applications_before + 1)
        limits.refresh_from_db()
        self.assertIsNone(limits.verified_at)
        pending = raise_public_state(self.service.pk)
        self.assertIsNotNone(pending)
        assert pending is not None
        self.assertEqual((pending.state, pending.extra_mib), ("requested", 1280))
        self.account.refresh_from_db()
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)

        self.assertEqual(self.apply(application, available=2 * 1024**3), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 6912)
        limits.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(limits.disk_allowance_mib, 5120)
        self.assertEqual(self.service.price, original_price)
