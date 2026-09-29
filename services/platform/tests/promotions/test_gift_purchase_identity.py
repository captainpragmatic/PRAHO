"""A purchased bearer voucher keeps the value and recipient funded by its buyer."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase
from apps.promotions.models import GiftCard
from apps.users.models import User


class GiftPurchaseIdentityTests(TestCase):
    def setUp(self) -> None:
        self.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        self.customer = Customer.objects.create(
            name="Voucher buyer", customer_type="individual", primary_email="buyer@example.test"
        )
        self.actor = User.objects.create_user(email="buyer@example.test")

    def _purchase(self, key="identity", recipient=None):
        return create_purchase(
            self.customer, self.ron, 5000, key,
            recipient=recipient or {"email": "recipient@example.test", "name": "Recipient", "message": "Happy day"},
            actor=self.actor,
        )

    def _fund(self, purchase):
        payment = purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = f"pi_{purchase.pk.hex}"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        return activate_verified_purchase(purchase.pk)

    def test_replay_checks_recipient_name_email_and_message(self) -> None:
        purchase = self._purchase()
        for field, replacement in (("email", "other@example.test"), ("name", "Other"), ("message", "Different")):
            with self.subTest(field=field):
                recipient = {"email": "recipient@example.test", "name": "Recipient", "message": "Happy day"}
                recipient[field] = replacement
                with self.assertRaises(ValidationError):
                    self._purchase(recipient=recipient)
        self.assertEqual(self._purchase().pk, purchase.pk)

    def test_funded_currency_value_and_bearer_code_cannot_change(self) -> None:
        purchase = self._fund(self._purchase())
        for field, value in (("currency", self.eur), ("initial_value_cents", 7500), ("code", "REPLACED-CODE")):
            with self.subTest(field=field):
                card = GiftCard.objects.get(pk=purchase.gift_card_id)
                setattr(card, field, value)
                with self.assertRaises(ValidationError):
                    card.save(update_fields=[field])

    def test_queryset_updates_cannot_relabel_a_funded_balance(self) -> None:
        purchase = self._fund(self._purchase())
        for changes in ({"currency": self.eur}, {"initial_value_cents": 7500}, {"code": "REPLACED-CODE"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                GiftCard.objects.filter(pk=purchase.gift_card_id).update(**changes)

    def test_purchase_recipient_fields_cannot_be_edited_after_creation(self) -> None:
        purchase = self._purchase()
        card = purchase.gift_card
        card.recipient_email = "replacement@example.test"
        with self.assertRaises(ValidationError):
            card.save(update_fields=["recipient_email"])

    def test_audit_and_model_labels_never_copy_the_bearer_code(self) -> None:
        purchase = self._fund(self._purchase())
        code = purchase.gift_card.code
        self.assertNotIn(code, str(purchase.gift_card))
        for entry in purchase.gift_card.transactions.all():
            self.assertNotIn(code, str(entry))
        for event in AuditEvent.objects.all():
            self.assertNotIn(code, str(event.new_values))
            self.assertNotIn(code, event.description)
