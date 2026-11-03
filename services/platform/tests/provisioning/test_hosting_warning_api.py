"""Customer service APIs expose only current scoped warning presentation data."""

from django.test import TestCase, override_settings

from apps.api.services.serializers import ServiceDetailSerializer, ServiceListSerializer
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.virtualmin_usage_service import month
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class HostingWarningApiTests(WarningFixture, HMACTestMixin, TestCase):
    def test_service_serializers_expose_current_operational_warning_without_private_evidence(self) -> None:
        self.publish(1024**3)
        self.service.refresh_from_db()
        for serializer in (ServiceDetailSerializer, ServiceListSerializer):
            data = serializer(self.service).data
            self.assertIn("hosting_warnings", data)
            warning = data["hosting_warnings"]["disk"]
            self.assertEqual((warning["condition"], warning["operational_allowance_mib"]), (100, 1024))
            self.assertNotIn("receipt", str(warning))
            self.assertNotIn("recipient_hash", str(warning))

    def test_signed_customer_summary_counts_only_that_customers_active_high_conditions(self) -> None:
        self.publish(1024**3)
        summary = self.summary()
        self.assertEqual(summary.get("hosting_warning_counts"), {"critical": 1, "warning": 0})

    def test_bandwidth_warning_summary_expires_at_the_real_operator_month_boundary(self) -> None:
        observed = self.publish(0, bandwidth_bytes=1024**3, owner_start_known=False)
        summary = self.summary()
        self.assertEqual(summary.get("hosting_warning_counts"), {"critical": 1, "warning": 0})
        self.assertEqual(summary.get("hosting_warning_counts_valid_until"), month(observed)[1].isoformat())

    def test_prior_condition_with_unknown_or_unlimited_denominator_is_not_counted(self) -> None:
        self.publish(1024**3)
        for allowance in (None, 0):
            with self.subTest(allowance=allowance):
                ServiceHostingLimits.objects.filter(service=self.service).update(
                    operational_disk_allowance_mib=allowance
                )
                summary = self.summary()
                self.assertEqual(summary.get("hosting_warning_counts"), {"critical": 0, "warning": 0})

    def summary(self):
        user, _ = User.objects.get_or_create(email="warning-dashboard@example.test")
        CustomerMembership.objects.get_or_create(user=user, customer=self.customer, role="owner", is_active=True)
        response = self.portal_post("/api/services/summary/", {"customer_id": self.customer.pk, "user_id": user.pk})
        self.assertEqual(response.status_code, 200)
        return response.json()["data"]["summary"]
