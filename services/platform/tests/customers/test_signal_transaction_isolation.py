"""Customer profile saves survive optional audit failures."""

from apps.customers.models import Customer, CustomerBillingProfile
from tests.common._signal_isolation import SignalIsolationTestCase


class CustomerSignalIsolationTests(SignalIsolationTestCase):
    def test_billing_profile_creation_survives_failed_audit_write(self) -> None:
        customer = Customer.objects.create(name="Isolation", primary_email="profile-customer@example.com")
        profile = self.run_effect(
            "apps.audit.services.CustomersAuditService.log_billing_profile_event",
            lambda: CustomerBillingProfile.objects.create(customer=customer),
        )
        self.assertTrue(CustomerBillingProfile.objects.filter(pk=profile.pk).exists())
