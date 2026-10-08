"""Customer audit-only snapshots must not abort required changes."""

from django.test import override_settings

from apps.customers.models import Customer, CustomerBillingProfile, CustomerPaymentMethod, CustomerTaxProfile
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredCustomerPayloadTests(DeferredAuditReadTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.customer = Customer.objects.create(name="Deferred", primary_email="deferred-profile@example.com")

    def test_customer_update_commits_when_deferred_audit_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)
        customer.primary_email = "persisted@example.com"
        self.run_deferred_read(customer, lambda: customer.save(update_fields=["primary_email"]))
        self.assertEqual(Customer.objects.get(pk=customer.pk).primary_email, "persisted@example.com")

    def test_customer_deletion_commits_when_deferred_audit_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)
        customer_id = customer.pk
        self.run_deferred_read(customer, customer.delete)
        self.assertFalse(Customer.all_objects.filter(pk=customer_id).exists())

    def test_billing_profile_update_commits_when_deferred_audit_currency_fetch_fails(self) -> None:
        profile = CustomerBillingProfile.objects.create(customer=self.customer)
        profile = CustomerBillingProfile.objects.defer("preferred_currency").get(pk=profile.pk)
        profile.payment_terms = 45
        self.run_deferred_read(profile, lambda: profile.save(update_fields=["payment_terms"]))
        self.assertEqual(CustomerBillingProfile.objects.get(pk=profile.pk).payment_terms, 45)

    def test_tax_compliance_update_commits_when_deferred_customer_id_fetch_fails(self) -> None:
        profile = CustomerTaxProfile.objects.create(customer=self.customer, cui="RO18547290")
        profile = CustomerTaxProfile.objects.defer("customer_id").get(pk=profile.pk)
        profile.vat_rate_reason = "other"
        self.run_deferred_read(profile, lambda: profile.save(update_fields=["vat_rate_reason"]))
        self.assertEqual(CustomerTaxProfile.objects.get(pk=profile.pk).vat_rate_reason, "other")

    def test_customer_status_updates_commit_when_deferred_display_name_fetch_fails(self) -> None:
        for index, (source, transition, target) in enumerate(
            [
                ("prospect", "activate", "active"),
                ("active", "deactivate", "inactive"),
                ("active", "suspend", "suspended"),
                ("suspended", "unsuspend", "active"),
                ("inactive", "reactivate", "active"),
            ]
        ):
            with self.subTest(transition=transition):
                customer = Customer.objects.create(
                    name="Deferred", primary_email=f"deferred-status-{index}@example.com", status=source
                )
                customer = Customer.objects.defer("name").get(pk=customer.pk)
                getattr(customer, transition)()
                self.run_deferred_read(customer, lambda customer=customer: customer.save(update_fields=["status"]))
                self.assertEqual(Customer.objects.get(pk=customer.pk).status, target)

    def test_gdpr_consent_update_commits_when_deferred_display_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)
        customer.data_processing_consent = not customer.data_processing_consent
        expected = customer.data_processing_consent
        self.run_deferred_read(customer, lambda: customer.save(update_fields=["data_processing_consent"]))
        self.assertEqual(Customer.objects.get(pk=customer.pk).data_processing_consent, expected)

    def test_marketing_consent_update_commits_when_deferred_display_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)
        customer.marketing_consent = not customer.marketing_consent
        expected = customer.marketing_consent
        self.run_deferred_read(customer, lambda: customer.save(update_fields=["marketing_consent"]))
        self.assertEqual(Customer.objects.get(pk=customer.pk).marketing_consent, expected)

    def test_payment_method_deletion_commits_when_deferred_display_name_fetch_fails(self) -> None:
        method = CustomerPaymentMethod.objects.create(customer=self.customer, method_type="cash", display_name="Cash")
        method = CustomerPaymentMethod.objects.defer("display_name").get(pk=method.pk)
        method_id = method.pk
        self.run_deferred_read(method, method.delete)
        self.assertFalse(CustomerPaymentMethod.all_objects.filter(pk=method_id).exists())
