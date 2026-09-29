"""Original-tender refund I/O follows one durable identity and verified retrieval."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.billing.models import Currency, FXRate
from apps.billing.tasks import _stripe_refund_facts
from apps.customers.models import Customer
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase, record_bank_funding
from apps.promotions.gift_refunds import converge_gift_refund, refund_purchase, reserve_funding_refund
from apps.promotions.models import GiftCardFundingRefund, GiftCardTransaction
from apps.promotions.tasks import reconcile_gift_refunds, setup_gift_scheduled_tasks
from apps.settings.services import SettingsService
from apps.users.models import User


class GiftRefundProviderTests(TestCase):
    def setUp(self) -> None:
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        customer = Customer.objects.create(name="Refund buyer", primary_email="buyer@example.test")
        self.staff = User.objects.create_user(email="staff@example.test", staff_role="billing")
        self.purchase = create_purchase(customer, currency, 5000, "provider-refund")
        payment = self.purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_gift_original"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        self.purchase = activate_verified_purchase(self.purchase.pk)

    def facts(self, refund, *, status="succeeded", **extra):
        return {
            "success": True, "refund_id": "re_gift_original", "payment_intent_id": "pi_gift_original",
            "amount_cents": refund.amount_cents, "currency": "ron", "status": status,
            "metadata": {"gift_refund_id": str(refund.pk)}, **extra,
        }

    def test_unknown_submission_keeps_hold_and_exact_persisted_parameters(self) -> None:
        def uncertain(*args, **kwargs):
            refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
            self.assertEqual(refund.funding_intent_id, "pi_gift_original")
            self.assertIsNotNone(refund.first_submitted_at)
            self.purchase.gift_card.refresh_from_db()
            self.assertEqual(self.purchase.gift_card.refund_held_cents, 3000)
            self.assertEqual(args, ("pi_gift_original",))
            self.assertEqual(kwargs, {
                "amount_cents": 3000, "reason": "requested_by_customer",
                "idempotency_key": refund.idempotency_key, "metadata": {"gift_refund_id": str(refund.pk)},
            })
            return {"success": False, "refund_id": None}

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = uncertain
            refund = refund_purchase(self.purchase.pk, 3000, "uncertain", actor=self.staff)
        self.assertEqual(refund.status, "unknown")
        self.assertEqual(refund.held_cents, 3000)

    def test_submission_does_not_settle_until_retrieval_and_repeated_success_debits_once(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": True, "refund_id": "re_gift_original"}
            factory.return_value.retrieve_refund.side_effect = lambda _: self.facts(
                GiftCardFundingRefund.objects.get(purchase=self.purchase)
            )
            refund = refund_purchase(self.purchase.pk, 3000, "success", actor=self.staff)
            again = refund_purchase(self.purchase.pk, 3000, "success", actor=self.staff)
            factory.return_value.refund_payment.assert_called_once()
        self.assertEqual((refund.pk, refund.status), (again.pk, "succeeded"))
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual((self.purchase.gift_card.current_balance_cents, self.purchase.gift_card.refund_held_cents), (2000, 0))
        self.assertEqual(GiftCardTransaction.objects.filter(operation_key=f"funding-refund:{refund.pk}").count(), 1)

    def test_early_exact_callback_survives_an_uncertain_submission_response(self) -> None:
        def early(*args, **kwargs):
            refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
            self.assertEqual(kwargs["metadata"], {"gift_refund_id": str(refund.pk)})
            self.assertTrue(converge_gift_refund(self.facts(refund)).is_ok())
            raise TimeoutError("lost response")

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = early
            refund = refund_purchase(self.purchase.pk, 3000, "early", actor=self.staff)
        self.assertEqual(refund.status, "succeeded")
        self.assertEqual(refund.gateway_refund_id, "re_gift_original")
        self.assertEqual(refund.held_cents, 0)

    def test_expired_unbound_retry_keeps_hold_and_requires_review_without_io(self) -> None:
        now = timezone.now()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": False, "refund_id": None}
            with patch("django.utils.timezone.now", return_value=now):
                refund = refund_purchase(self.purchase.pk, 3000, "window", actor=self.staff)
            with (
                patch("django.utils.timezone.now", return_value=now + timedelta(hours=23)),
                self.assertRaises(ValidationError),
            ):
                refund_purchase(self.purchase.pk, 3000, "window", actor=self.staff)
            factory.return_value.refund_payment.assert_called_once()
        refund.refresh_from_db()
        self.assertEqual((refund.status, refund.held_cents), ("needs_review", 3000))

    def test_changed_original_intent_cannot_change_retry_parameters(self) -> None:
        refund = reserve_funding_refund(self.purchase.pk, 3000, "changed", actor=self.staff)
        payment = self.purchase.funding_payment
        payment.gateway_txn_id = "pi_different"
        payment.save(update_fields=["gateway_txn_id"])
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            with self.assertRaises(ValidationError):
                refund_purchase(self.purchase.pk, 3000, "changed", actor=self.staff)
            factory.assert_not_called()
        refund.refresh_from_db()
        self.assertEqual(refund.funding_intent_id, "pi_gift_original")
        self.assertEqual(refund.held_cents, 3000)

    def test_retrieval_must_match_the_exact_requested_refund_before_settlement(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": True, "refund_id": "re_gift_original"}
            factory.return_value.retrieve_refund.side_effect = lambda _: self.facts(
                GiftCardFundingRefund.objects.get(purchase=self.purchase), refund_id="re_wrong",
            )
            with self.assertRaises(ValidationError):
                refund_purchase(self.purchase.pk, 3000, "mismatch", actor=self.staff)
        refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
        self.assertEqual((refund.gateway_refund_id, refund.held_cents, refund.applied_cents), ("re_gift_original", 3000, 0))

    def test_bank_request_never_uses_a_gateway(self) -> None:
        purchase = create_purchase(self.purchase.customer, self.purchase.gift_card.currency, 5000, "bank", method="bank")
        record_bank_funding(purchase.pk, reference="QA-FUNDED", actor=self.staff)
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            refund = refund_purchase(purchase.pk, 3000, "bank", actor=self.staff)
            factory.assert_not_called()
        self.assertEqual(refund.status, "awaiting_bank_transfer")

    def test_reconciliation_recovers_same_uncertain_key_and_preserves_metadata(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": False, "refund_id": None}
            refund = refund_purchase(self.purchase.pk, 3000, "recover", actor=self.staff)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=11)),
            patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory,
        ):
            factory.return_value.refund_payment.return_value = {"success": True, "refund_id": "re_gift_original"}
            factory.return_value.retrieve_refund.return_value = self.facts(refund, status="pending")
            report = reconcile_gift_refunds()
            self.assertEqual(factory.return_value.refund_payment.call_args.kwargs["idempotency_key"], refund.idempotency_key)
            self.assertEqual((report["checked"], reconcile_gift_refunds()["checked"]), (1, 0))
        setup_gift_scheduled_tasks()
        setup_gift_scheduled_tasks()
        for name, func in (("gift-refund-reconciliation", "reconcile_gift_refunds"),
                           ("gift-delivery-reconciliation", "reconcile_gift_delivery")):
            schedule = Schedule.objects.get(name=name)
            self.assertEqual(schedule.func, f"apps.promotions.tasks.{func}")
        facts = _stripe_refund_facts(self.facts(refund), "re_gift_original")
        self.assertEqual(facts["metadata"], {"gift_refund_id": str(refund.pk)})

    def test_bound_pending_refund_is_retrieved_after_23_hours_without_new_submission(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": True, "refund_id": "re_gift_original"}
            factory.return_value.retrieve_refund.side_effect = lambda _: self.facts(
                GiftCardFundingRefund.objects.get(purchase=self.purchase), status="pending",
            )
            refund = refund_purchase(self.purchase.pk, 3000, "bound", actor=self.staff)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(days=2)),
            patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory,
        ):
            factory.return_value.retrieve_refund.return_value = self.facts(refund, status="failed")
            self.assertEqual(reconcile_gift_refunds()["checked"], 1)
            factory.return_value.refund_payment.assert_not_called()
        refund.refresh_from_db()
        self.assertEqual((refund.status, refund.held_cents), ("failed", 0))

    def test_original_tender_snapshot_cannot_be_edited_by_model_or_queryset(self) -> None:
        refund = reserve_funding_refund(self.purchase.pk, 3000, "identity", actor=self.staff)
        refund.funding_intent_id = "pi_different"
        with self.assertRaises(ValidationError):
            refund.save(update_fields=["funding_intent_id"])
        with self.assertRaises(ValidationError):
            GiftCardFundingRefund.objects.filter(pk=refund.pk).update(funding_intent_id="pi_different")
        refund.refresh_from_db()
        self.assertEqual(refund.funding_intent_id, "pi_gift_original")

    def test_legacy_submitted_request_without_original_intent_requires_review(self) -> None:
        refund = GiftCardFundingRefund.objects.create(
            purchase=self.purchase, amount_cents=3000, currency_id="RON", idempotency_key="legacy-request",
            created_by=self.staff, held_cents=3000, status="unknown", first_submitted_at=timezone.now(),
        )
        card = self.purchase.gift_card
        card.refund_held_cents = 3000
        card.save(update_fields=["refund_held_cents"])
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            self.assertEqual(reconcile_gift_refunds()["needs_review"], 1)
            factory.assert_not_called()
        refund.refresh_from_db()
        self.assertEqual((refund.funding_intent_id, refund.held_cents), ("", 3000))

    def test_external_pending_refund_without_local_metadata_can_be_reconciled(self) -> None:
        facts = {
            "success": True, "refund_id": "re_dashboard", "payment_intent_id": "pi_gift_original",
            "amount_cents": 3000, "currency": "ron", "status": "pending", "metadata": {},
        }
        imported = converge_gift_refund(facts).unwrap()
        self.assertIsNone(imported.created_by_id)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=11)),
            patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory,
        ):
            factory.return_value.retrieve_refund.return_value = {**facts, "status": "succeeded"}
            self.assertEqual(reconcile_gift_refunds()["settled"], 1)
            factory.return_value.refund_payment.assert_not_called()
        imported.refresh_from_db()
        self.assertEqual((imported.status, imported.held_cents, imported.applied_cents), ("succeeded", 0, 3000))

    def test_unbound_record_without_an_authorized_full_hold_never_submits(self) -> None:
        for actor in (None, self.staff):
            with self.subTest(actor=actor):
                refund = GiftCardFundingRefund.objects.create(
                    purchase=self.purchase, amount_cents=1000, currency_id="RON", idempotency_key=f"orphan-{actor}",
                    created_by=actor, held_cents=0, status="reserved", funding_intent_id="pi_gift_original",
                )
                with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
                    factory.return_value.refund_payment.return_value = {"success": False, "refund_id": None}
                    self.assertEqual(reconcile_gift_refunds()["needs_review"], 1)
                    factory.assert_not_called()
                refund.refresh_from_db()
                self.assertEqual(refund.status, "needs_review")

    def test_all_original_currencies_survive_a_real_selling_currency_switch(self) -> None:
        currencies = {"RON": self.purchase.gift_card.currency}
        purchases = {"RON": self.purchase}
        for code in ("EUR", "USD"):
            currencies[code] = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            FXRate.objects.create(
                base_code=currencies[code], quote_code=currencies["RON"], rate=Decimal("5"),
                as_of=timezone.localdate(), source="bnr", source_reference="https://bnr.ro/rate", fetched_at=timezone.now(),
            )
            purchase = create_purchase(self.purchase.customer, currencies[code], 5000, code)
            payment = purchase.funding_payment
            payment.succeed()
            payment.gateway_txn_id = f"pi_original_{code}"
            payment.meta = {"stripe_amount_received": 5000, "stripe_currency": code.lower()}
            payment.save()
            purchases[code] = activate_verified_purchase(purchase.pk)
        SettingsService.update_setting("billing.default_currency", "EUR")
        for code, purchase in purchases.items():
            with self.subTest(currency=code), patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
                factory.return_value.refund_payment.return_value = {"success": True, "refund_id": f"re_{code}"}
                factory.return_value.retrieve_refund.side_effect = lambda _id, item=purchase: self.facts(
                    GiftCardFundingRefund.objects.get(purchase=item), refund_id=f"re_{item.gift_card.currency_id}",
                    currency=item.gift_card.currency_id.lower(), payment_intent_id=item.funding_payment.gateway_txn_id,
                )
                refund = refund_purchase(purchase.pk, 3000, code, actor=self.staff)
                self.assertEqual((refund.status, refund.currency_id), ("succeeded", code))
                self.assertEqual(factory.return_value.refund_payment.call_args.args, (purchase.funding_payment.gateway_txn_id,))
                purchase.gift_card.refresh_from_db()
                self.assertEqual(purchase.gift_card.current_balance_cents, 2000)
