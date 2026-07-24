"""Tests for customer-controlled recurring-payment mandates."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import RecurringPaymentAuthorization
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer, CustomerPaymentMethod
from apps.products.models import Product
from apps.users.models import CustomerMembership, User


class RecurringPaymentAuthorizationServiceTestCase(TestCase):
    terms_text = RecurringPaymentAuthorizationService.TERMS_TEXT

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Mandate Customer SRL",
            customer_type="company",
            company_name="Mandate Customer SRL",
            primary_email="billing@example.test",
            status="active",
        )
        self.method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_mandate",
            stripe_payment_method_id="pm_mandate",
            display_name="Visa 4242",
            last_four="4242",
            is_default=True,
            is_active=True,
        )
        self.owner = User.objects.create_user(email="owner@example.test")
        CustomerMembership.objects.create(
            customer=self.customer,
            user=self.owner,
            role="owner",
            is_primary=True,
        )

    def _setup_intent_metadata(self, actor: User | None = None) -> dict[str, str]:
        return {
            "praho_customer_id": str(self.customer.id),
            "praho_payment_method_id": str(self.method.id),
            "praho_terms_version": RecurringPaymentAuthorizationService.TERMS_VERSION,
            "praho_terms_text_hash": hashlib.sha256(self.terms_text.encode("utf-8")).hexdigest(),
            "praho_actor_id": str((actor or self.owner).id),
        }

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_owner_can_complete_a_verified_versioned_auditable_mandate(self, factory: MagicMock) -> None:
        factory.return_value.retrieve_setup_intent.return_value = {
            "success": True,
            "setup_intent_id": "seti_mandate_1",
            "status": "succeeded",
            "customer_id": "cus_mandate",
            "payment_method_id": "pm_mandate",
            "usage": "off_session",
            "metadata": self._setup_intent_metadata(),
            "error": None,
        }

        result = RecurringPaymentAuthorizationService.complete(
            customer=self.customer,
            payment_method=self.method,
            setup_intent_id="seti_mandate_1",
            actor=self.owner,
            ip_address="192.0.2.10",
            user_agent="PRAHO test browser",
        )

        self.assertTrue(result.is_ok())
        authorization = result.unwrap()
        self.assertEqual(authorization.status, "active")
        self.assertEqual(authorization.granted_by, self.owner)
        self.assertEqual(authorization.granted_by_role, "owner")
        self.assertEqual(
            authorization.terms_text_hash,
            hashlib.sha256(self.terms_text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(authorization.terms_text, self.terms_text)
        self.assertEqual(authorization.setup_intent_id, "seti_mandate_1")
        self.assertEqual(authorization.terms_version, RecurringPaymentAuthorizationService.TERMS_VERSION)
        self.assertTrue(authorization.is_active)

    def test_mandate_status_cannot_bypass_lifecycle_transitions(self) -> None:
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.method,
            status="active",
            setup_intent_id="seti_protected_status",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=self.terms_text,
            terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
            granted_by=self.owner,
            granted_by_role="owner",
            granted_at=timezone.now(),
        )

        with self.assertRaises(AttributeError):
            authorization.status = "withdrawn"

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_begin_binds_setup_intent_to_exact_customer_method_and_terms(self, factory: MagicMock) -> None:
        factory.return_value.create_setup_intent.return_value = {
            "success": True,
            "setup_intent_id": "seti_begin_1",
            "client_secret": "seti_begin_1_secret_test",
            "error": None,
        }

        result = RecurringPaymentAuthorizationService.begin(
            customer=self.customer,
            payment_method=self.method,
            actor=self.owner,
            terms_accepted=True,
            accepted_terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
        )

        self.assertTrue(result.is_ok())
        payload = result.unwrap()
        self.assertEqual(payload["setup_intent_id"], "seti_begin_1")
        self.assertEqual(payload["client_secret"], "seti_begin_1_secret_test")
        self.assertEqual(payload["terms_version"], RecurringPaymentAuthorizationService.TERMS_VERSION)
        factory.return_value.create_setup_intent.assert_called_once_with(
            customer_id="cus_mandate",
            payment_method_id="pm_mandate",
            metadata=self._setup_intent_metadata(),
        )

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_begin_requires_current_terms_acceptance_before_creating_setup_intent(self, factory: MagicMock) -> None:
        missing_acceptance = RecurringPaymentAuthorizationService.begin(
            customer=self.customer,
            payment_method=self.method,
            actor=self.owner,
            terms_accepted=False,
            accepted_terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
        )
        stale_terms = RecurringPaymentAuthorizationService.begin(
            customer=self.customer,
            payment_method=self.method,
            actor=self.owner,
            terms_accepted=True,
            accepted_terms_version="2025-01-01",
        )

        self.assertTrue(missing_acceptance.is_err())
        self.assertTrue(stale_terms.is_err())
        self.assertIn("terms", missing_acceptance.unwrap_err().lower())
        self.assertIn("terms", stale_terms.unwrap_err().lower())
        factory.assert_not_called()

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_complete_rejects_unverified_or_mismatched_gateway_facts(self, factory: MagicMock) -> None:
        good_facts = {
            "success": True,
            "setup_intent_id": "seti_untrusted",
            "status": "succeeded",
            "customer_id": "cus_mandate",
            "payment_method_id": "pm_mandate",
            "usage": "off_session",
            "metadata": self._setup_intent_metadata(),
            "error": None,
        }
        mismatches = (
            {"status": "requires_action"},
            {"customer_id": "cus_other"},
            {"payment_method_id": "pm_other"},
            {"usage": "on_session"},
            {"metadata": {**good_facts["metadata"], "praho_customer_id": "999999"}},
        )

        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                factory.return_value.retrieve_setup_intent.return_value = {**good_facts, **mismatch}
                result = RecurringPaymentAuthorizationService.complete(
                    customer=self.customer,
                    payment_method=self.method,
                    setup_intent_id="seti_untrusted",
                    actor=self.owner,
                )
                self.assertTrue(result.is_err())
                self.assertFalse(
                    RecurringPaymentAuthorization.objects.filter(setup_intent_id="seti_untrusted").exists()
                )

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_complete_rejects_setup_intent_accepted_by_a_different_billing_principal(
        self,
        factory: MagicMock,
    ) -> None:
        billing_user = User.objects.create_user(email="billing-principal@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=billing_user, role="billing")
        factory.return_value.retrieve_setup_intent.return_value = {
            "success": True,
            "setup_intent_id": "seti_actor_bound",
            "status": "succeeded",
            "customer_id": "cus_mandate",
            "payment_method_id": "pm_mandate",
            "usage": "off_session",
            "metadata": self._setup_intent_metadata(self.owner),
            "error": None,
        }

        result = RecurringPaymentAuthorizationService.complete(
            customer=self.customer,
            payment_method=self.method,
            setup_intent_id="seti_actor_bound",
            actor=billing_user,
        )

        self.assertTrue(result.is_err())
        self.assertIn("principal", result.unwrap_err().lower())
        self.assertFalse(RecurringPaymentAuthorization.objects.filter(setup_intent_id="seti_actor_bound").exists())

    @patch("apps.billing.recurring_authorization_service.PaymentGatewayFactory.get_default_gateway")
    def test_complete_revalidates_saved_method_after_gateway_round_trip(self, factory: MagicMock) -> None:
        def retrieve_setup_intent(_setup_intent_id: str) -> dict[str, object]:
            CustomerPaymentMethod.objects.filter(pk=self.method.pk).update(is_active=False)
            return {
                "success": True,
                "setup_intent_id": "seti_deactivated_method",
                "status": "succeeded",
                "customer_id": "cus_mandate",
                "payment_method_id": "pm_mandate",
                "usage": "off_session",
                "metadata": self._setup_intent_metadata(),
                "error": None,
            }

        factory.return_value.retrieve_setup_intent.side_effect = retrieve_setup_intent

        result = RecurringPaymentAuthorizationService.complete(
            customer=self.customer,
            payment_method=self.method,
            setup_intent_id="seti_deactivated_method",
            actor=self.owner,
        )

        self.assertTrue(result.is_err())
        self.assertIn("not active", result.unwrap_err())
        self.assertFalse(
            RecurringPaymentAuthorization.objects.filter(setup_intent_id="seti_deactivated_method").exists()
        )

    def test_viewer_cannot_grant_a_mandate(self) -> None:
        viewer = User.objects.create_user(email="viewer@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=viewer, role="viewer")

        result = RecurringPaymentAuthorizationService.complete(
            customer=self.customer,
            payment_method=self.method,
            setup_intent_id="seti_forbidden",
            actor=viewer,
        )

        self.assertTrue(result.is_err())
        self.assertIn("billing principal", result.unwrap_err())
        self.assertFalse(RecurringPaymentAuthorization.objects.filter(setup_intent_id="seti_forbidden").exists())

    def test_staff_cannot_manufacture_customer_consent(self) -> None:
        staff = User.objects.create_user(email="staff@example.test", is_staff=True, staff_role="billing")

        result = RecurringPaymentAuthorizationService.complete(
            customer=self.customer,
            payment_method=self.method,
            setup_intent_id="seti_staff_forbidden",
            actor=staff,
        )

        self.assertTrue(result.is_err())
        self.assertIn("customer billing principal", result.unwrap_err())

    def test_database_rejects_active_mandate_without_verified_setup_intent(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            RecurringPaymentAuthorization.objects.create(
                customer=self.customer,
                payment_method=self.method,
                status="active",
                setup_intent_id=None,
                terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
                terms_text=self.terms_text,
                terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
                granted_by=self.owner,
                granted_by_role="owner",
                granted_at=None,
            )

    def test_database_rejects_auto_payment_without_method_and_mandate(self) -> None:
        from apps.billing.models import Currency  # noqa: PLC0415

        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        product = Product.objects.create(
            slug=f"unenrolled-{uuid.uuid4().hex[:8]}",
            name="Hosting",
            product_type="hosting",
        )
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=currency,
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2500,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            Subscription.objects.filter(pk=subscription.pk).update(auto_payment_enabled=True)

    def test_customer_withdrawal_is_immediate(self) -> None:
        from apps.billing.models import Currency  # noqa: PLC0415

        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.method,
            status="active",
            setup_intent_id="seti_withdraw",
            terms_version="2026-07-17",
            terms_text=self.terms_text,
            terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
            granted_by=self.owner,
            granted_by_role="owner",
            granted_at=timezone.now(),
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        product = Product.objects.create(
            slug=f"withdraw-{uuid.uuid4().hex[:8]}", name="Hosting", product_type="hosting"
        )
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=currency,
            subscription_number="SUB-WITHDRAW",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2500,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
            saved_payment_method=self.method,
            payment_authorization=authorization,
            auto_payment_enabled=True,
        )

        with patch("apps.billing.signals._log_billing_model_event") as lifecycle_audit:
            result = RecurringPaymentAuthorizationService.withdraw(
                authorization=authorization,
                actor=self.owner,
                reason="Customer disabled automatic collection",
            )

        self.assertTrue(result.is_ok())
        authorization.refresh_from_db()
        self.assertEqual(authorization.status, "withdrawn")
        self.assertEqual(authorization.withdrawn_by, self.owner)
        self.assertIsNotNone(authorization.withdrawn_at)
        self.assertFalse(authorization.is_active)
        subscription.refresh_from_db()
        self.assertFalse(subscription.auto_payment_enabled)
        self.assertIsNone(subscription.saved_payment_method_id)
        self.assertIsNone(subscription.payment_authorization_id)
        self.assertTrue(
            any(
                call.kwargs.get("event_type") == "subscription_model_updated"
                and call.kwargs.get("instance").pk == subscription.pk
                for call in lifecycle_audit.call_args_list
            ),
            "Disabling a subscription during mandate withdrawal must emit its normal lifecycle audit",
        )

    def test_billing_staff_can_revoke_but_not_withdraw_for_customer(self) -> None:
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.method,
            status="active",
            setup_intent_id="seti_revoke",
            terms_version="2026-07-17",
            terms_text=self.terms_text,
            terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
            granted_by=self.owner,
            granted_by_role="owner",
            granted_at=timezone.now(),
        )
        staff = User.objects.create_user(email="billing-staff@example.test", is_staff=True, staff_role="billing")

        withdrawal = RecurringPaymentAuthorizationService.withdraw(
            authorization=authorization,
            actor=staff,
            reason="Not customer authority",
        )
        revocation = RecurringPaymentAuthorizationService.revoke(
            authorization=authorization,
            actor=staff,
            reason="Payment method compromised",
        )

        self.assertTrue(withdrawal.is_err())
        self.assertTrue(revocation.is_ok())
        authorization.refresh_from_db()
        self.assertEqual(authorization.status, "revoked")
        self.assertEqual(authorization.revoked_by, staff)

    def test_service_less_subscription_cannot_enable_auto_payment(self) -> None:
        from apps.billing.models import Currency  # noqa: PLC0415

        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        product = Product.objects.create(
            slug=f"orphan-{uuid.uuid4().hex[:8]}",
            name="Orphan hosting",
            product_type="hosting",
        )
        now = timezone.now()
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.method,
            status="active",
            setup_intent_id="seti_orphan",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=self.terms_text,
            terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
            granted_by=self.owner,
            granted_by_role="owner",
            granted_at=now,
        )
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=currency,
            subscription_number="SUB-ORPHAN",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2500,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

        result = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=subscription,
            authorization=authorization,
            enabled=True,
            actor=self.owner,
        )

        self.assertTrue(result.is_err())
        self.assertIn("linked service", result.unwrap_err())
        subscription.refresh_from_db()
        self.assertFalse(subscription.auto_payment_enabled)

    def test_one_mandate_can_enroll_individual_subscriptions_without_coupling_cancellation(self) -> None:
        from apps.billing.models import Currency  # noqa: PLC0415
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        product = Product.objects.create(slug=f"mandate-{uuid.uuid4().hex[:8]}", name="Hosting", product_type="hosting")
        now = timezone.now()
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.method,
            status="active",
            setup_intent_id="seti_enroll",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=self.terms_text,
            terms_text_hash=hashlib.sha256(self.terms_text.encode()).hexdigest(),
            granted_by=self.owner,
            granted_by_role="owner",
            granted_at=now,
        )
        service_plan = ServicePlan.objects.create(
            name=f"Mandate hosting {uuid.uuid4().hex[:8]}",
            plan_type="shared_hosting",
            price_monthly=Decimal("25.00"),
        )
        services = [
            Service.objects.create(
                customer=self.customer,
                service_plan=service_plan,
                currency=currency,
                service_name=f"Mandate hosting {suffix}",
                username=f"mandate{suffix.lower()}{uuid.uuid4().hex[:6]}",
                billing_cycle="monthly",
                price=Decimal("25.00"),
                status="active",
                activated_at=now,
                expires_at=now + timedelta(days=30),
            )
            for suffix in ("A", "B")
        ]
        subscriptions = [
            Subscription.objects.create(
                customer=self.customer,
                product=product,
                service=services[index],
                currency=currency,
                subscription_number=f"SUB-{suffix}",
                status="active",
                billing_cycle="monthly",
                unit_price_cents=2500,
                current_period_start=now,
                current_period_end=now + timedelta(days=30),
                next_billing_date=now + timedelta(days=30),
            )
            for index, suffix in enumerate(("MANDATE-A", "MANDATE-B"))
        ]

        first = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=subscriptions[0], authorization=authorization, enabled=True, actor=self.owner
        )
        second = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=subscriptions[1], authorization=authorization, enabled=True, actor=self.owner
        )
        disabled = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=subscriptions[0], authorization=None, enabled=False, actor=self.owner
        )

        self.assertTrue(first.is_ok())
        self.assertTrue(second.is_ok())
        self.assertTrue(disabled.is_ok())
        subscriptions[0].refresh_from_db()
        subscriptions[1].refresh_from_db()
        self.assertFalse(subscriptions[0].auto_payment_enabled)
        self.assertIsNone(subscriptions[0].payment_authorization)
        self.assertTrue(subscriptions[1].auto_payment_enabled)
        self.assertEqual(subscriptions[1].payment_authorization, authorization)
