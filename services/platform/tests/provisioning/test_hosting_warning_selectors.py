"""Batched customer warning output keeps purchased denominators and current scope."""

from datetime import timedelta

from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_warning_models import HostingWarningState
from apps.provisioning.hosting_warning_selectors import prime_hosting_warnings, service_warning_data
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_usage_service import month
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


@override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", LANGUAGE_CODE="en")
class HostingWarningSelectorTests(WarningFixture, TestCase):
    def test_fixed_three_query_batch_and_cached_output_for_multiple_real_services(self):
        observed = self.publish(1024**3)
        original = self.account
        services = [self.service]
        try:
            for number in range(4):
                service = Service.objects.create(
                    customer=self.customer,
                    service_plan=self.plan,
                    currency=self.service.currency,
                    service_name=f"warning-{number}.example.test",
                    domain=f"warning-{number}.example.test",
                    username=f"warning{number}",
                    status="active",
                    price=10,
                )
                services.append(service)
                self.account = VirtualminAccount.objects.create(
                    service=service,
                    server=self.server,
                    domain=service.domain,
                    virtualmin_username=service.username,
                    status="active",
                    praho_customer_id=self.customer.pk,
                    praho_service_id=service.pk,
                )
                observed = self.publish(1024**3)
        finally:
            self.account = original
        for subset in ([self.service], services):
            with self.assertNumQueries(3):
                prime_hosting_warnings(subset, at=observed)
            with self.assertNumQueries(0):
                for service in subset:
                    result = service_warning_data(service)["disk"]
                    self.assertEqual(
                        (result["condition"], result["availability"], result["operational_allowance_mib"]),
                        (100, "fresh", 1024),
                    )
                    self.assertNotIn("receipt", result)
                    self.assertNotIn("recipient_hash", result)

    def test_pending_upgrade_keeps_old_allowance_then_verified_upgrade_recomputes_still_high(self):
        observed = self.publish(2 * 1024**3 * 975 // 1000)
        ServiceHostingLimits.objects.filter(service=self.service).update(revision=2, disk_allowance_mib=2048)
        prime_hosting_warnings([self.service], at=observed)
        pending = service_warning_data(self.service)["disk"]
        self.assertEqual((pending["condition"], pending["operational_allowance_mib"]), (100, 1024))
        ServiceHostingLimits.objects.filter(service=self.service).update(
            operational_revision=2, operational_disk_allowance_mib=2048
        )
        prime_hosting_warnings([self.service], at=observed)
        applied = service_warning_data(self.service)["disk"]
        self.assertEqual((applied["condition"], applied["operational_allowance_mib"]), (95, 2048))
        self.assertEqual(applied["used_bytes"], pending["used_bytes"])

    def test_stale_outage_retains_annotated_condition_without_current_freshness(self):
        observed = self.publish(1024**3)
        prime_hosting_warnings([self.service], at=observed + timedelta(hours=7))
        stale = service_warning_data(self.service)["disk"]
        self.assertEqual((stale["condition"], stale["availability"], stale["used_bytes"]), (100, "stale", 1024**3))

    def test_new_bandwidth_month_cannot_reuse_old_critical_banner_or_bytes(self):
        observed = self.publish(0, bandwidth_bytes=1024**3, owner_start_known=False)
        prime_hosting_warnings([self.service], at=observed)
        self.assertEqual(service_warning_data(self.service)["bandwidth"]["condition"], 100)
        prime_hosting_warnings([self.service], at=month(observed)[1] + timedelta(minutes=1))
        new_month = service_warning_data(self.service)["bandwidth"]
        self.assertEqual(
            (new_month["condition"], new_month["availability"], new_month["used_bytes"]), (None, "unknown", None)
        )

    def test_stale_customer_instance_cannot_reveal_transferred_owner_warning(self):
        self.publish(1024**3)
        other = Customer.objects.create(name="Other warning owner")
        self.service.customer = other
        self.service.save(update_fields=["customer"])
        fresh = Service.objects.get(pk=self.service.pk)
        prime_hosting_warnings([fresh])
        self.assertEqual(service_warning_data(fresh)["disk"]["availability"], "unknown")

    def test_restore_coverage_gap_can_escalate_from_new_proven_lower_bound_despite_old_complete_pointer(self):
        self.publish(0, bandwidth_bytes=700 * 1024**2)
        previous = usage.current_state(self.account).bandwidth_reading_id
        # The production restore/recreation boundary closes the old interval;
        # its unobserved final tail prevents a new full-coverage reading.
        usage.rebind_created_account(self.account.pk)
        observed = self.publish(0, bandwidth_bytes=400 * 1024**2)
        state = usage.current_state(self.account)
        self.assertEqual(state.bandwidth_reading_id, previous)
        cursor = HostingWarningState.objects.get(account=self.account, resource="bandwidth")
        self.assertEqual((cursor.condition, cursor.availability), (100, "partial"))
        prime_hosting_warnings([self.service], at=observed)
        current = service_warning_data(self.service)["bandwidth"]
        self.assertEqual(
            (current["condition"], current["availability"], current["used_bytes"]), (100, "partial", 1100 * 1024**2)
        )
