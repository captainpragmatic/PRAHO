"""Staff and GDPR operations write the user fields they change, and nothing else (#689).

Suspending or activating an account, withdrawing consent and anonymising an account each saved
the whole user row from an instance that could be stale, so an administrator's 2FA reset or a
role change landing meanwhile was written back. Each now locks the row and writes only its
own fields, and records what it did in the audit trail.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from apps.audit.actor_context import acting_as
from apps.audit.models import AuditEvent
from apps.audit.services import GDPRConsentService, GDPRDeletionService
from apps.customers import user_management_views
from apps.customers.models import Customer
from apps.users.mfa import MFAService, TOTPService
from apps.users.models import CustomerMembership, User
from apps.users.pending_totp import PendingTOTPEnrolment, get_or_create_pending

PASSWORD = "x-pass-123"  # test fixture, not a credential


def _enrolled(email: str, **extra: object) -> User:
    user = User.objects.create_user(email=email, password=PASSWORD, **extra)
    user.two_factor_secret = TOTPService.generate_secret()
    user.two_factor_enabled = True
    user.accepts_marketing = True
    user.save()
    return user


class ToggleUserStatusTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(
            email="staff@example.com", password=PASSWORD, is_staff=True, staff_role="admin"
        )
        self.customer = Customer.objects.create(
            name="Acme", company_name="Acme SRL", primary_email="office@acme.example", customer_type="company"
        )
        self.member = _enrolled("member@example.com")
        CustomerMembership.objects.create(customer=self.customer, user=self.member, role="viewer")
        self.client.force_login(self.staff)

    def toggle(self, active: bool) -> None:
        url = reverse("customers:toggle_user_status", args=[self.customer.id, self.member.id])
        self.client.post(url, {"is_active": "true" if active else "false"})

    def test_a_2fa_reset_landing_meanwhile_is_not_written_back(self) -> None:
        stale = User.objects.get(pk=self.member.pk)
        MFAService.apply_state_change(self.member, action="disable")
        real_lookup = user_management_views.get_object_or_404

        def stale_user_lookup(model: object, *args: object, **kwargs: object) -> object:
            return stale if model is User else real_lookup(model, *args, **kwargs)

        with patch("apps.customers.user_management_views.get_object_or_404", side_effect=stale_user_lookup):
            self.toggle(False)
        fresh = User.objects.get(pk=self.member.pk)
        self.assertFalse(fresh.is_active)
        self.assertFalse(fresh.two_factor_enabled)

    def test_the_change_is_audited_with_its_old_and_new_state(self) -> None:
        self.toggle(False)
        event = AuditEvent.objects.filter(object_id=str(self.member.pk), action="profile_updated").latest("timestamp")
        self.assertEqual(event.old_values, {"is_active": True})
        self.assertEqual(event.new_values, {"is_active": False})
        self.assertEqual(event.user, self.staff)


class ConsentWithdrawalTests(TestCase):
    def test_withdrawing_marketing_writes_only_that(self) -> None:
        user = _enrolled("consent@example.com")
        stale = User.objects.get(pk=user.pk)
        MFAService.apply_state_change(user, action="disable")

        with acting_as(user):  # self-service: the person withdrawing is the actor
            self.assertTrue(GDPRConsentService.withdraw_consent(stale, ["marketing"]).is_ok())

        fresh = User.objects.get(pk=user.pk)
        self.assertFalse(fresh.accepts_marketing)
        self.assertFalse(fresh.two_factor_enabled)
        self.assertTrue(AuditEvent.objects.filter(user=user, action="marketing_consent_withdrawn").exists())

    def test_data_processing_is_not_a_consent_to_withdraw(self) -> None:
        # Processing the account's data performs the contract, so it is a notice, not a consent;
        # erasure goes through the deletion request (AnonymisationTests below).
        user = _enrolled("erase-me@example.com")
        self.assertTrue(GDPRConsentService.withdraw_consent(user, ["data_processing"]).is_err())
        fresh = User.objects.get(pk=user.pk)
        self.assertEqual(fresh.email, "erase-me@example.com")
        self.assertTrue(fresh.is_active)


class AnonymisationTests(TestCase):
    def test_anonymising_writes_only_its_own_fields_and_drops_a_pending_setup(self) -> None:
        user = User.objects.create_user(email="anon@example.com", password=PASSWORD, staff_role="support")
        get_or_create_pending(user)
        stale = User.objects.get(pk=user.pk)
        User.objects.filter(pk=user.pk).update(staff_role="")

        self.assertTrue(GDPRDeletionService._anonymize_user_data(stale).is_ok())

        fresh = User.objects.get(pk=user.pk)
        self.assertEqual(fresh.staff_role, "")
        self.assertNotEqual(fresh.email, "anon@example.com")
        self.assertFalse(fresh.has_usable_password())
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=user).exists())
