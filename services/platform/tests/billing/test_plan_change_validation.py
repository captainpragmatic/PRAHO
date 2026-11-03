"""Real pre-claim facts, including current customer authority and native proof."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.billing.plan_change_validation import validate_payment_claim
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture


class PlanChangeClaimValidationTests(_PlanChangeSettlementFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", True).is_ok())
        self.membership = CustomerMembership.objects.create(
            customer=self.customer, user=self.actor, role="owner", is_active=True
        )
        self.accepted, self.document, _, _ = self.payable_change()

    def test_quote_ttl_is_checked_before_a_new_payment_can_be_reserved(self) -> None:
        with self.assertRaisesMessage(ValidationError, "expired"):
            validate_payment_claim(self.accepted, at=self.accepted.expires_at)

    def test_late_application_authority_cannot_reserve_money(self) -> None:
        with self.assertRaisesMessage(ValidationError, "expired"):
            validate_payment_claim(self.accepted, at=self.accepted.authority_expires_at)

    def test_revoked_membership_prevents_a_first_payment_claim(self) -> None:
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        with self.assertRaisesMessage(ValidationError, "billing authority"):
            validate_payment_claim(self.accepted)

    def test_non_billing_member_cannot_reserve_a_customer_charge(self) -> None:
        self.membership.role = "viewer"
        self.membership.save(update_fields=["role"])
        with self.assertRaisesMessage(ValidationError, "billing authority"):
            validate_payment_claim(self.accepted)

    def test_cancelled_at_period_end_blocks_new_charge_authority(self) -> None:
        self.subscription.cancel_at_period_end = True
        self.subscription.save(update_fields=["cancel_at_period_end"])
        with self.assertRaisesMessage(ValidationError, "commercial terms"):
            validate_payment_claim(self.accepted)

    def test_quantity_change_cannot_reuse_the_old_quote(self) -> None:
        self.subscription.quantity = 2
        self.subscription.save(update_fields=["quantity"])
        with self.assertRaisesMessage(ValidationError, "commercial terms"):
            validate_payment_claim(self.accepted)

    def test_changed_allowance_revision_prevents_a_first_claim(self) -> None:
        ServiceHostingLimits.objects.filter(service=self.service).update(revision=2)
        with self.assertRaisesMessage(ValidationError, "resource assignment"):
            validate_payment_claim(self.accepted)

    def test_an_unmanaged_service_cannot_accept_money_for_native_work(self) -> None:
        with self.assertRaisesMessage(ValidationError, "managed quota"):
            validate_payment_claim(self.accepted)

    def test_switching_off_new_acceptance_blocks_an_already_confirmed_first_claim(self) -> None:
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", False).is_ok())
        with self.assertRaisesMessage(ValidationError, "temporarily disabled"):
            validate_payment_claim(self.accepted)
