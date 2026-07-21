"""
Tests for GDPR marketing-consent propagation (#226).

`withdraw_consent`/`update_consent` wrote `User.accepts_marketing`, but the marketing send
audience (`notifications/tasks.py`) filters on `Customer.marketing_consent`. Nothing synced the
two, so withdrawing marketing consent was a functional no-op — the customer kept receiving it.
"""

from __future__ import annotations

import uuid

from django.test import TestCase

from apps.audit.services import GDPRConsentService
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


def _make_user() -> User:
    return User.objects.create_user(
        email=f"consent_{uuid.uuid4().hex[:8]}@example.com",
        password="testpass123",
        accepts_marketing=True,
    )


def _make_customer(user: User, *, marketing_consent: bool = True) -> Customer:
    customer = Customer.objects.create(
        name="Test SRL",
        company_name="Test SRL",
        customer_type="company",
        status="active",
        marketing_consent=marketing_consent,
    )
    CustomerMembership.objects.create(customer=customer, user=user, role="owner", is_primary=True)
    return customer


class WithdrawConsentPropagationTestCase(TestCase):
    """#226: withdrawing marketing consent must stop the sends it is supposed to stop."""

    def test_withdrawal_clears_marketing_consent_on_the_users_customers(self) -> None:
        """The send audience reads Customer.marketing_consent, so withdrawal must clear it there."""
        user = _make_user()
        customer = _make_customer(user)

        result = GDPRConsentService.withdraw_consent(user, ["marketing"])

        self.assertTrue(result.is_ok(), f"withdrawal failed: {result}")
        user.refresh_from_db()
        customer.refresh_from_db()
        self.assertFalse(user.accepts_marketing)
        self.assertFalse(customer.marketing_consent)

    def test_withdrawal_clears_every_customer_the_user_belongs_to(self) -> None:
        """A user can be a member of several customers; withdrawal covers all of them."""
        user = _make_user()
        c1 = _make_customer(user)
        c2 = _make_customer(user)

        GDPRConsentService.withdraw_consent(user, ["marketing"])

        c1.refresh_from_db()
        c2.refresh_from_db()
        self.assertFalse(c1.marketing_consent)
        self.assertFalse(c2.marketing_consent)

    def test_withdrawal_does_not_touch_other_users_customers(self) -> None:
        """Only customers the withdrawing user is a member of are affected."""
        user = _make_user()
        _make_customer(user)
        other_user = _make_user()
        other_customer = _make_customer(other_user)

        GDPRConsentService.withdraw_consent(user, ["marketing"])

        other_customer.refresh_from_db()
        self.assertTrue(other_customer.marketing_consent)

    def test_withdrawing_a_non_marketing_consent_leaves_marketing_intact(self) -> None:
        """Non-regression: withdrawing only analytics must not silently drop marketing consent."""
        user = _make_user()
        customer = _make_customer(user)

        GDPRConsentService.withdraw_consent(user, ["analytics"])

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)


class PropagateMarketingConsentTestCase(TestCase):
    """The shared helper used by both withdraw_consent and the update_consent view (#226)."""

    def test_propagation_grants_consent_across_the_users_customers(self) -> None:
        """update_consent can re-grant marketing consent, so propagation is bidirectional."""
        user = _make_user()
        customer = _make_customer(user, marketing_consent=False)

        GDPRConsentService._propagate_marketing_consent(user, consent=True)

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)

    def test_propagation_withdraws_consent_across_the_users_customers(self) -> None:
        user = _make_user()
        customer = _make_customer(user, marketing_consent=True)

        GDPRConsentService._propagate_marketing_consent(user, consent=False)

        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)
