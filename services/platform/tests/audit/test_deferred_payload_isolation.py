"""Deferred optional audit payload reads preserve the caller's writes."""

from django.test import override_settings

from apps.audit.models import AuditEvent, CookieConsent
from apps.audit.signals import cookie_consent_updated, customer_context_switched
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User, UserProfile
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredAuditPayloadTests(DeferredAuditReadTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="deferred-audit@example.com", password="test")
        self.customer = Customer.objects.create(name="Deferred", primary_email="deferred-customer@example.com")

    def test_user_update_commits_when_deferred_last_name_fetch_fails(self) -> None:
        user = User.objects.only("id", "first_name").get(pk=self.user.pk)
        user.first_name = "Persisted"
        self.run_deferred_read(user, lambda: user.save(update_fields=["first_name"]))
        self.assertEqual(User.objects.get(pk=user.pk).first_name, "Persisted")

    def test_membership_creation_commits_when_deferred_customer_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)
        membership = CustomerMembership(user=self.user, customer=customer, role="owner")
        self.run_deferred_read(customer, membership.save)
        self.assertTrue(CustomerMembership.objects.filter(pk=membership.pk, role="owner").exists())

    def test_emergency_contact_update_commits_when_deferred_phone_fetch_fails(self) -> None:
        profile = UserProfile.objects.only("id", "user_id", "emergency_contact_name").get(user=self.user)
        profile.user = self.user
        profile.emergency_contact_name = "Persisted"
        self.run_deferred_read(profile, lambda: profile.save(update_fields=["emergency_contact_name"]))
        self.assertEqual(UserProfile.objects.get(pk=profile.pk).emergency_contact_name, "Persisted")

    def test_cookie_update_commits_when_deferred_category_fetch_fails(self) -> None:
        consent = CookieConsent.objects.create(cookie_id="deferred-cookie")
        consent = CookieConsent.objects.defer("analytics_cookies").get(pk=consent.pk)

        def trigger() -> None:
            consent.status = "withdrawn"
            consent.save(update_fields=["status"])
            cookie_consent_updated.send(sender=CookieConsent, consent=consent)

        self.run_deferred_read(consent, trigger)
        self.assertEqual(CookieConsent.objects.get(pk=consent.pk).status, "withdrawn")

    def test_context_switch_preserves_write_when_deferred_customer_name_fetch_fails(self) -> None:
        customer = Customer.objects.defer("name").get(pk=self.customer.pk)

        def trigger() -> None:
            self.user.first_name = "Switched"
            self.user.save(update_fields=["first_name"])
            customer_context_switched.send(sender=User, user=self.user, old_customer=None, new_customer=customer)

        self.run_deferred_read(customer, trigger)
        self.assertEqual(User.objects.get(pk=self.user.pk).first_name, "Switched")

    def test_failed_name_payload_does_not_skip_phone_event(self) -> None:
        user = User.objects.defer("last_name").get(pk=self.user.pk)
        user.first_name = "Persisted"
        user.phone = "+40722123456"
        self.run_deferred_read(user, lambda: user.save(update_fields=["first_name", "phone"]))
        persisted = User.objects.get(pk=user.pk)
        self.assertEqual(persisted.first_name, "Persisted")
        self.assertEqual(persisted.phone, "+40722123456")
        self.assertTrue(AuditEvent.objects.filter(action="phone_updated", object_id=str(user.pk)).exists())
