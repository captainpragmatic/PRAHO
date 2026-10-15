"""The customer role validator accepts exactly the membership roles (CUSTOMER_ROLE_CHOICES).

It used to carry its own list (owner, admin, manager, viewer): "billing" and "tech" were
rejected, so an owner could never grant them through the invitation and linking services,
while "admin" and "manager" (no such membership role) were accepted.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.common.validators import SecureInputValidator
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from apps.users.services import (
    SecureCustomerUserService,
    UserInvitationRequest,
    UserLinkingRequest,
)

LOCMEM_TEST_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
MEMBERSHIP_ROLES = [value for value, _label in CustomerMembership.CUSTOMER_ROLE_CHOICES]


class CustomerRoleValidatorTests(TestCase):
    def test_every_membership_role_is_accepted(self) -> None:
        self.assertEqual(sorted(MEMBERSHIP_ROLES), ["billing", "owner", "tech", "viewer"])
        for role in MEMBERSHIP_ROLES:
            with self.subTest(role=role):
                self.assertEqual(SecureInputValidator.validate_customer_role(role), role)
                self.assertEqual(SecureInputValidator.validate_customer_role(role.upper()), role)

    def test_roles_that_are_not_membership_roles_are_refused(self) -> None:
        for role in ("admin", "manager", "superuser", "staff", ""):
            with self.subTest(role=role), self.assertRaises(ValidationError):
                SecureInputValidator.validate_customer_role(role)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class OwnerGrantsRoleTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Role Customer",
            company_name="Role Customer",
            primary_email="customer@example.test",
            customer_type="company",
        )
        self.owner = User.objects.create_user(email="owner@example.test", password="owner-password")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)

    @patch.object(SecureCustomerUserService, "_send_invitation_email_secure")
    def test_owner_can_invite_with_each_membership_role(self, _send) -> None:
        for index, role in enumerate(("billing", "tech", "viewer")):
            email = f"invitee{index}@example.test"
            with self.subTest(role=role):
                result = SecureCustomerUserService.invite_user_to_customer(
                    UserInvitationRequest(
                        inviter=self.owner,
                        invitee_email=email,
                        customer=self.customer,
                        role=role,
                        request_ip="192.0.2.10",
                    )
                )
                self.assertTrue(result.is_ok(), result)
                membership = CustomerMembership.objects.get(customer=self.customer, user__email=email)
                self.assertEqual(membership.role, role)

    def test_owner_can_link_an_existing_user_as_tech(self) -> None:
        existing = User.objects.create_user(email="existing@example.test", password="existing-password")
        result = SecureCustomerUserService.link_existing_user(
            UserLinkingRequest(user=existing, customer=self.customer, role="tech", created_by=self.owner)
        )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(CustomerMembership.objects.get(customer=self.customer, user=existing).role, "tech")

    @patch.object(SecureCustomerUserService, "_send_invitation_email_secure")
    def test_invitation_with_a_non_membership_role_is_refused(self, _send) -> None:
        result = SecureCustomerUserService.invite_user_to_customer(
            UserInvitationRequest(
                inviter=self.owner,
                invitee_email="manager@example.test",
                customer=self.customer,
                role="manager",
                request_ip="192.0.2.11",
            )
        )
        self.assertTrue(result.is_err())
        self.assertFalse(User.objects.filter(email="manager@example.test").exists())
