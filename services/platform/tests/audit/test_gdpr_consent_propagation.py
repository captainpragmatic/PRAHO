"""
Tests for GDPR marketing-consent propagation (#226).

`withdraw_consent`/`update_consent` wrote `User.accepts_marketing`, but the marketing send
audience (`notifications/tasks.py`) filters on `Customer.marketing_consent`. Nothing synced the
two, so withdrawing marketing consent was a functional no-op — the customer kept receiving it.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.test import TestCase

from apps.audit.models import ComplianceLog
from apps.audit.services import GDPRConsentService, GDPRDeletionService
from apps.common.types import Err as ErrResult
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

    def test_grant_does_not_resubscribe_a_customer_where_another_member_withdrew(self) -> None:
        """#226 review (226-A): one member's opt-in must not silently re-subscribe a shared
        customer that another member had opted out of.

        Customer.marketing_consent is a single flag shared by all members; a blind grant would
        override the other member's withdrawal — a consent-integrity violation.
        """
        withdrawn_member = _make_user()
        withdrawn_member.accepts_marketing = False
        withdrawn_member.save(update_fields=["accepts_marketing"])
        customer = _make_customer(withdrawn_member, marketing_consent=False)

        # A second member of the SAME customer opts in.
        opting_in_member = _make_user()
        CustomerMembership.objects.create(customer=customer, user=opting_in_member, role="viewer")

        GDPRConsentService._propagate_marketing_consent(opting_in_member, consent=True)

        customer.refresh_from_db()
        self.assertFalse(
            customer.marketing_consent,
            "granting one member's consent must not re-enable marketing over another member's withdrawal",
        )

    def test_grant_re_enables_when_no_other_member_has_withdrawn(self) -> None:
        """The acting user's grant should re-enable a customer whose other members all consent."""
        member = _make_user()
        customer = _make_customer(member, marketing_consent=False)
        # A second, still-consenting member.
        other = _make_user()  # accepts_marketing=True by default
        CustomerMembership.objects.create(customer=customer, user=other, role="viewer")

        GDPRConsentService._propagate_marketing_consent(member, consent=True)

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)


class PropagationHardeningTestCase(TestCase):
    """Review hardening of the #226 propagation (membership state, audit, rollback)."""

    def test_withdrawal_ignores_inactive_memberships(self) -> None:
        """A deactivated membership no longer speaks for the customer: the user's
        withdrawal must not suppress a customer they were removed from."""
        user = _make_user()
        active_customer = _make_customer(user)
        former_customer = Customer.objects.create(
            name="Former SRL",
            company_name="Former SRL",
            customer_type="company",
            status="active",
            marketing_consent=True,
        )
        CustomerMembership.objects.create(
            customer=former_customer, user=user, role="viewer", is_active=False
        )

        GDPRConsentService.withdraw_consent(user, ["marketing"])

        active_customer.refresh_from_db()
        former_customer.refresh_from_db()
        self.assertFalse(active_customer.marketing_consent)
        self.assertTrue(former_customer.marketing_consent, "an inactive membership must not propagate")

    def test_inactive_withdrawn_member_does_not_block_regrant(self) -> None:
        """A deactivated member's old withdrawal must not permanently veto the
        customer's re-enable."""
        withdrawn_former_member = _make_user()
        withdrawn_former_member.accepts_marketing = False
        withdrawn_former_member.save(update_fields=["accepts_marketing"])
        customer = _make_customer(withdrawn_former_member, marketing_consent=False)
        CustomerMembership.objects.filter(customer=customer, user=withdrawn_former_member).update(is_active=False)

        acting_member = _make_user()
        CustomerMembership.objects.create(customer=customer, user=acting_member, role="viewer")

        GDPRConsentService._propagate_marketing_consent(acting_member, consent=True)

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent, "an inactive member's withdrawal must not block the grant")

    def test_data_processing_withdrawal_also_suppresses_marketing(self) -> None:
        """Sibling of #226: anonymization sets User.accepts_marketing=False, so it
        must propagate the suppression too — an erased user whose address is the
        customer contact must not keep receiving marketing."""
        user = _make_user()
        customer = _make_customer(user)

        result = GDPRConsentService.withdraw_consent(user, ["data_processing"])

        self.assertTrue(result.is_ok(), f"withdrawal failed: {result}")
        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)

    def test_gdpr_flip_writes_per_customer_compliance_record(self) -> None:
        """The per-customer consent trail (customers/signals.py, GDPR Art. 7
        attribution) must include GDPR-initiated flips — bulk update() left the
        customer's own trail blind to them."""
        user = _make_user()
        customer = _make_customer(user)

        GDPRConsentService.withdraw_consent(user, ["marketing"])

        record = ComplianceLog.objects.filter(
            compliance_type="marketing_consent", reference_id=f"customer_{customer.id}"
        ).first()
        self.assertIsNotNone(record, "the customer's consent trail must record the GDPR-initiated flip")

    def test_failed_anonymization_rolls_back_marketing_propagation(self) -> None:
        """withdraw_consent returns Err inside its transaction; the customer
        suppression written before the failure must roll back with it, never
        half-commit (user flag unsaved, customer flag flipped)."""
        user = _make_user()
        customer = _make_customer(user)

        with patch.object(
            GDPRDeletionService, "process_deletion_request", return_value=ErrResult("anonymization backend down")
        ):
            result = GDPRConsentService.withdraw_consent(user, ["marketing", "data_processing"])

        self.assertTrue(result.is_err())
        user.refresh_from_db()
        customer.refresh_from_db()
        self.assertTrue(user.accepts_marketing, "user flag must not persist on a failed withdrawal")
        self.assertTrue(customer.marketing_consent, "customer suppression must roll back with the failed withdrawal")
