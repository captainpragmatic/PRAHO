"""Staff gift controls keep bearer reveal and original-tender refunds deliberate."""

from decimal import Decimal
from unittest.mock import patch

from django.contrib import admin
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import path, reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency, FXRate
from apps.customers.models import Customer
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase, record_bank_funding
from apps.promotions.gift_refunds import reserve_funding_refund
from apps.promotions.models import GiftCardFundingRefund
from apps.users.models import User
from tests.helpers.task_queue import quiet_task_queue

urlpatterns = [path("qa-admin/", admin.site.urls)]


class GiftStaffFixture:
    def setUp(self) -> None:
        super().setUp()
        self.queue = quiet_task_queue(self)
        ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        FXRate.objects.get_or_create(
            base_code=eur,
            quote_code=ron,
            as_of=timezone.localdate(),
            defaults={
                "rate": Decimal("5"),
                "source": "bnr",
                "source_reference": "https://bnr.ro/rate",
                "fetched_at": timezone.now(),
            },
        )
        self.customer = Customer.objects.create(name="Staff gift buyer", primary_email="buyer@example.test")
        self.staff = User.objects.create_user(email="billing@example.test", staff_role="billing")
        self.support = User.objects.create_user(email="support@example.test", staff_role="support")
        self.purchase = create_purchase(self.customer, eur, 5000, "staff-gift", method="bank")
        self.purchase = record_bank_funding(self.purchase.pk, reference="QA-FUND", actor=self.staff)
        self.card = self.purchase.gift_card
        self.client.force_login(self.staff)

    def url(self, name, **extra):
        return reverse(f"promotions:gift_card_{name}", kwargs={"pk": self.card.pk, **extra})

    def refund_payload(self, client=None):
        response = (client or self.client).get(self.url("detail"))
        return {
            "amount": "30.00",
            "reason": "requested_by_customer",
            "request_key": str(response.context["refund_form"].initial["request_key"]),
        }


class GiftStaffActionTests(GiftStaffFixture, TestCase):
    def test_staff_gets_are_masked_and_held_balance_is_separate(self) -> None:
        reserve_funding_refund(self.purchase.pk, 3000, "held", actor=self.staff)
        response = self.client.get(self.url("detail"))
        self.assertNotContains(response, self.card.code)
        self.assertContains(response, self.card.masked_code)
        self.assertContains(response, "20,00 EUR")
        self.assertContains(response, "30,00 EUR")
        self.assertContains(response, "50,00 EUR")
        self.assertContains(response, "Delivery")
        listing = self.client.get(reverse("promotions:gift_card_list"))
        self.assertNotContains(listing, self.card.code)
        self.assertContains(listing, self.card.masked_code)

    def test_reveal_requires_financial_post_csrf_and_creates_safe_audit(self) -> None:
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.staff)
        strict.get(self.url("detail"))
        self.assertEqual(strict.get(self.url("reveal")).status_code, 405)
        self.assertEqual(strict.post(self.url("reveal")).status_code, 403)
        response = strict.post(self.url("reveal"), HTTP_X_CSRFTOKEN=strict.cookies["csrftoken"].value)
        self.assertContains(response, self.card.code)
        self.assertIn("no-store", response["Cache-Control"])
        events = AuditEvent.objects.filter(
            content_type=ContentType.objects.get_for_model(self.card),
            object_id=str(self.card.pk),
            action="gift_card_code_revealed",
        )
        self.assertEqual(events.count(), 1)
        self.assertNotIn(self.card.code, str(list(events.values("description", "metadata", "new_values"))))

    def test_support_staff_cannot_mutate_or_reveal(self) -> None:
        refund = reserve_funding_refund(self.purchase.pk, 3000, "support-restrictions", actor=self.staff)
        self.client.force_login(self.support)
        response = self.client.get(self.url("detail"))
        self.assertNotContains(response, "Reveal code")
        self.assertNotContains(response, "Request refund")
        for action in ("reveal", "resend", "refund"):
            with self.subTest(action=action):
                self.assertEqual(self.client.post(self.url(action)).status_code, 403)
        for action in ("refund_refresh", "refund_bank_confirm"):
            self.assertEqual(
                self.client.post(self.url(action, refund_id=refund.pk), {"reference": "FORGED"}).status_code, 403
            )
        refund.refresh_from_db()
        self.assertEqual(refund.status, "awaiting_bank_transfer")
        self.assertEqual(GiftCardFundingRefund.objects.count(), 1)

    def test_all_financial_routes_require_post_and_csrf(self) -> None:
        refund = reserve_funding_refund(self.purchase.pk, 3000, "csrf-refund", actor=self.staff)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.staff)
        routes = [self.url(action) for action in ("reveal", "resend", "refund")]
        routes += [self.url(action, refund_id=refund.pk) for action in ("refund_refresh", "refund_bank_confirm")]
        for route in routes:
            with self.subTest(route=route):
                self.assertEqual(strict.get(route).status_code, 405)
                self.assertEqual(strict.post(route, {"reference": "NO-CSRF"}).status_code, 403)

    @override_settings(ROOT_URLCONF=__name__)
    def test_admin_change_page_masks_the_code(self) -> None:
        self.staff.is_superuser = True
        self.staff.is_staff = True
        self.staff.save(update_fields=["is_superuser", "is_staff"])
        response = self.client.get(reverse("admin:promotions_giftcard_change", args=[self.card.pk]))
        self.assertNotContains(response, self.card.code)
        self.assertContains(response, self.card.masked_code)

    def test_bank_refund_form_replays_once_and_requires_separate_confirmation(self) -> None:
        payload = self.refund_payload()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            for _ in range(2):
                self.assertEqual(self.client.post(self.url("refund"), payload).status_code, 302)
            factory.assert_not_called()
        refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
        self.assertEqual(
            (refund.status, refund.held_cents, refund.currency_id), ("awaiting_bank_transfer", 3000, "EUR")
        )
        self.assertEqual(self.client.post(self.url("refund"), {**payload, "amount": "20.00"}).status_code, 409)
        confirm = self.url("refund_bank_confirm", refund_id=refund.pk)
        self.assertEqual(self.client.post(confirm, {"reference": ""}).status_code, 400)
        self.assertEqual(self.client.post(confirm, {"reference": "QA-RETURN"}).status_code, 302)
        refund.refresh_from_db()
        self.assertEqual((refund.status, refund.applied_cents), ("succeeded", 3000))

    def test_unissued_or_other_card_submission_key_never_reserves_money(self) -> None:
        payload = self.refund_payload()
        other = create_purchase(self.customer, self.card.currency, 5000, "other-card", method="bank")
        record_bank_funding(other.pk, reference="QA-OTHER", actor=self.staff)
        wrong_route = reverse("promotions:gift_card_refund", kwargs={"pk": other.gift_card_id})
        self.assertEqual(self.client.post(wrong_route, payload).status_code, 409)
        self.assertEqual(
            self.client.post(
                self.url("refund"), {**payload, "request_key": "00000000-0000-4000-8000-000000000001"}
            ).status_code,
            409,
        )
        self.assertFalse(GiftCardFundingRefund.objects.exists())

    def test_resend_only_queues_record_ids_and_respects_dispute_freeze(self) -> None:
        voucher = self.purchase.deliveries.get(purpose="voucher")
        voucher.status = "failed"
        voucher.save(update_fields=["status"])
        queued_before = len(self.queue.packages)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self.client.post(self.url("resend")).status_code, 302)
        self.assertEqual(
            self.queue.queued()[queued_before:], [("apps.promotions.gift_delivery.deliver_gift_card", str(voucher.pk))]
        )
        self.card.spending_frozen_at = timezone.now()
        self.card.save(update_fields=["spending_frozen_at"])
        self.assertEqual(self.client.post(self.url("resend")).status_code, 400)
        self.assertEqual(self.client.post(self.url("reveal")).status_code, 400)


class GiftStaffTransactionTests(GiftStaffFixture, TransactionTestCase):
    def test_stripe_refund_view_commits_hold_before_provider_and_keeps_retry_key(self) -> None:
        purchase = create_purchase(self.customer, self.card.currency, 5000, "stripe-staff")
        payment = purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_staff_refund"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "eur"}
        payment.save()
        self.purchase = activate_verified_purchase(purchase.pk)
        self.card = purchase.gift_card
        payload = self.refund_payload()
        calls = []

        def uncertain(*args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            refund = GiftCardFundingRefund.objects.get(purchase=purchase)
            self.assertEqual(refund.held_cents, 3000)
            self.assertEqual(kwargs["metadata"], {"gift_refund_id": str(refund.pk)})
            calls.append((args, kwargs))
            return {"success": False, "refund_id": None}

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = uncertain
            for _ in range(2):
                self.assertEqual(self.client.post(self.url("refund"), payload).status_code, 302)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(GiftCardFundingRefund.objects.filter(purchase=purchase).count(), 1)
