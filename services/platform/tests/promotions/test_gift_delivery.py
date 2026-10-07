"""Voucher delivery retries keep one bearer code and never queue its contents."""

from datetime import timedelta
from decimal import Decimal
from smtplib import SMTPException
from unittest.mock import patch

from django.apps import apps
from django.core import mail
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone
from requests.exceptions import HTTPError, Timeout

from apps.billing.models import Currency, FXRate
from apps.customers.models import Customer
from apps.notifications.models import EmailLog
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase
from apps.promotions.gift_delivery import (
    MAX_DELIVERY_ATTEMPTS,
    _send,
    deliver_gift_card,
    purchase_delivery_summary,
    queue_purchase_delivery,
)
from apps.promotions.tasks import reconcile_gift_delivery
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class GiftDeliveryTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        FXRate.objects.get_or_create(
            base_code=self.currency,
            quote_code=ron,
            as_of=timezone.localdate(),
            defaults={
                "rate": Decimal("5"),
                "source": "bnr",
                "source_reference": "https://bnr.ro/rate",
                "fetched_at": timezone.now(),
            },
        )
        self.customer = Customer.objects.create(
            name="Delivery buyer", customer_type="individual", primary_email="buyer@example.test"
        )
        self.actor = User.objects.create_user(email="buyer@example.test")
        self.purchase = create_purchase(
            self.customer,
            self.currency,
            5000,
            "delivery",
            actor=self.actor,
            is_gift=True,
            buyer_email=self.actor.email,
            recipient={"email": "recipient@example.test", "name": "Recipient", "message": "Enjoy your gift"},
        )

    def _fund(self):
        payment = self.purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_delivery"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "eur"}
        payment.save()
        self.purchase = activate_verified_purchase(self.purchase.pk)

    @override_settings(
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
        DEFAULT_FROM_EMAIL="deployment@example.test",
    )
    def test_gift_sender_uses_row_then_deployment_default(self) -> None:
        from django.core.cache import cache  # noqa: PLC0415

        cache.clear()
        self.addCleanup(cache.clear)
        self._fund()
        rows = {row.purpose: row for row in queue_purchase_delivery(self.purchase.pk)}
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("company.email_noreply", "runtime@example.test")
        self.assertTrue(result.is_ok(), result)
        mail.outbox.clear()
        self.assertTrue(deliver_gift_card(str(rows["receipt"].pk)))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "runtime@example.test")
        self.assertEqual(mail.outbox[0].to, [self.purchase.buyer_email])

        with self.captureOnCommitCallbacks(execute=True):
            SystemSetting.objects.filter(key="company.email_noreply").delete()
        mail.outbox.clear()
        self.assertTrue(deliver_gift_card(str(rows["voucher"].pk)))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "deployment@example.test")
        self.assertEqual(mail.outbox[0].to, ["recipient@example.test"])

    def test_activation_persists_delivery_rows_and_queues_only_ids_after_commit(self) -> None:
        with patch("django_q.tasks.async_task") as queued, self.captureOnCommitCallbacks(execute=True):
            self._fund()
            self.assertFalse(queued.called)
        deliveries = list(apps.get_model("promotions", "GiftCardDelivery").objects.filter(purchase=self.purchase))
        self.assertEqual(
            {row.purpose: row.target_email for row in deliveries},
            {
                "voucher": "recipient@example.test",
                "receipt": "buyer@example.test",
            },
        )
        self.assertEqual(queued.call_count, 2)
        for call in queued.call_args_list:
            self.assertEqual(call.args[0], "apps.promotions.gift_delivery.deliver_gift_card")
            self.assertIn(call.args[1], [str(row.pk) for row in deliveries])
            self.assertEqual(len(call.args), 2)
            self.assertNotIn(self.purchase.gift_card.code, str(call))

    def test_programming_errors_propagate_from_message_building_and_delivery(self) -> None:
        self._fund()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        for target in ("apps.promotions.gift_delivery._message", "django.core.mail.EmailMessage.send"):
            for error_type in (TypeError, NameError, RuntimeError):
                with (
                    self.subTest(target=target, error_type=error_type.__name__),
                    patch(target, side_effect=error_type("programming bug")),
                    self.assertRaisesRegex(error_type, "programming bug"),
                ):
                    _send(voucher, self.purchase)

    def test_retry_delivers_original_code_once_and_buyer_receipt_has_no_code(self) -> None:
        self._fund()
        rows = {row.purpose: row for row in queue_purchase_delivery(self.purchase.pk)}
        for error_type in (OSError, SMTPException, HTTPError, Timeout):
            with (
                self.subTest(error_type=error_type.__name__),
                patch("django.core.mail.EmailMessage.send", side_effect=error_type("provider unavailable")),
            ):
                self.assertEqual(_send(rows["voucher"], self.purchase), "provider_unavailable")
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("provider unavailable")):
            self.assertFalse(deliver_gift_card(str(rows["voucher"].pk)))
        rows["voucher"].refresh_from_db()
        self.assertEqual(rows["voucher"].status, "failed")
        self.assertEqual(rows["voucher"].error_code, "provider_unavailable")
        self.assertIsNotNone(rows["voucher"].next_attempt_at)
        self.assertIsNone(rows["voucher"].lease_until)
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=11)):
            self.assertTrue(deliver_gift_card(str(rows["voucher"].pk)))
        self.assertTrue(deliver_gift_card(str(rows["voucher"].pk)))
        self.assertTrue(deliver_gift_card(str(rows["receipt"].pk)))
        self.assertEqual(len(mail.outbox), 2)
        messages = {message.to[0]: message for message in mail.outbox}
        self.assertIn(self.purchase.gift_card.code, messages["recipient@example.test"].body)
        self.assertIn("50.00 EUR", messages["recipient@example.test"].body)
        self.assertNotIn(self.purchase.gift_card.code, messages["buyer@example.test"].body)
        self.assertFalse(EmailLog.objects.exists())

    def test_for_me_uses_buyer_address_snapshot_after_customer_changes(self) -> None:
        self.purchase = create_purchase(
            self.customer,
            self.currency,
            5000,
            "for-me",
            actor=self.actor,
            buyer_email=self.actor.email,
            is_gift=False,
        )
        self.customer.primary_email = "new-address@example.test"
        self.customer.save(update_fields=["primary_email"])
        self._fund()
        deliveries = queue_purchase_delivery(self.purchase.pk)
        self.assertEqual([(row.purpose, row.target_email) for row in deliveries], [("voucher", "buyer@example.test")])

    def test_rate_limit_release_failure_is_visible_without_leaking_delivery_contents(self) -> None:
        self._fund()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        secret = self.purchase.gift_card.code
        with (
            patch("django.core.mail.EmailMessage.send", side_effect=OSError(secret)),
            patch("apps.notifications.services.EmailRateLimiter.release_counter", side_effect=OSError(secret)),
            self.assertLogs("apps.promotions.gift_delivery", level="WARNING") as captured,
        ):
            self.assertFalse(deliver_gift_card(voucher.pk))
        self.assertNotIn(secret, str(captured.output))
        self.assertNotIn(voucher.target_email, str(captured.output))
        voucher.refresh_from_db()
        self.assertEqual(voucher.status, "failed")
        self.assertEqual(voucher.error_code, "provider_unavailable")

    def test_suppression_and_rate_limits_prevent_delivery_without_generic_email_log(self) -> None:
        self._fund()
        voucher = next(row for row in queue_purchase_delivery(self.purchase.pk) if row.purpose == "voucher")
        with patch("apps.notifications.services.EmailSuppressionService.is_suppressed", return_value=True):
            self.assertFalse(deliver_gift_card(str(voucher.pk)))
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=6)):
            queue_purchase_delivery(self.purchase.pk, resend=True)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=6)),
            patch("apps.notifications.services.EmailRateLimiter.check_rate_limit", return_value=(False, 0)),
        ):
            self.assertFalse(deliver_gift_card(str(voucher.pk)))
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(EmailLog.objects.exists())

    def test_refund_hold_and_dispute_freeze_block_reveal_and_voucher_delivery(self) -> None:
        self._fund()
        voucher = next(row for row in queue_purchase_delivery(self.purchase.pk) if row.purpose == "voucher")
        self.purchase.refresh_from_db()
        self.assertTrue(self.purchase.can_reveal_code)
        card = self.purchase.gift_card
        card.refund_held_cents = 5000
        card.save(update_fields=["refund_held_cents"])
        self.purchase.refresh_from_db()
        self.assertFalse(self.purchase.can_reveal_code)
        self.assertFalse(deliver_gift_card(str(voucher.pk)))
        card.refund_held_cents = 0
        card.spending_frozen_at = timezone.now()
        card.spending_freeze_reason = "dispute:dp_test"
        card.save(update_fields=["refund_held_cents", "spending_frozen_at", "spending_freeze_reason"])
        self.purchase.refresh_from_db()
        self.assertFalse(self.purchase.can_reveal_code)
        with self.assertRaises(ValidationError):
            queue_purchase_delivery(self.purchase.pk, resend=True)

    def test_safe_delivery_summary_never_returns_bearer_code_or_email_contents(self) -> None:
        self._fund()
        summary = purchase_delivery_summary(self.purchase)
        self.assertEqual(summary["status"], "pending")
        self.assertEqual(len(summary["deliveries"]), 2)
        self.assertNotIn(self.purchase.gift_card.code, str(summary))
        self.assertNotIn("Enjoy your gift", str(summary))

    def test_worker_respects_retry_due_time_and_bounds_automatic_attempts(self) -> None:
        self._fund()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        now = timezone.now()
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("offline")) as send:
            self.assertFalse(deliver_gift_card(voucher.pk))
            self.assertFalse(deliver_gift_card(voucher.pk))
            self.assertEqual(send.call_count, 1)
            for attempt in range(1, MAX_DELIVERY_ATTEMPTS):
                with patch("django.utils.timezone.now", return_value=now + timedelta(days=attempt)):
                    self.assertFalse(deliver_gift_card(voucher.pk))
            with patch("django.utils.timezone.now", return_value=now + timedelta(days=20)):
                self.assertFalse(deliver_gift_card(voucher.pk))
            self.assertEqual(send.call_count, MAX_DELIVERY_ATTEMPTS)
        voucher.refresh_from_db()
        self.assertIsNone(voucher.next_attempt_at)
        self.assertEqual(voucher.error_code, "retry_limit_reached")

    def test_resend_has_a_cooldown_and_does_not_duplicate_queued_or_sending_jobs(self) -> None:
        self._fund()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        with patch("django_q.tasks.async_task") as queued, self.captureOnCommitCallbacks(execute=True):
            queue_purchase_delivery(self.purchase.pk, resend=True)
        queued.assert_not_called()
        self.assertTrue(deliver_gift_card(voucher.pk))
        with self.assertRaises(ValidationError):
            queue_purchase_delivery(self.purchase.pk, resend=True)
        with (
            patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=6)),
            patch("django_q.tasks.async_task") as queued,
            self.captureOnCommitCallbacks(execute=True),
        ):
            queue_purchase_delivery(self.purchase.pk, resend=True)
            queue_purchase_delivery(self.purchase.pk, resend=True)
        self.assertEqual(queued.call_count, 1)

    def test_repair_recovers_missing_rows_and_expired_worker_lease(self) -> None:
        self._fund()
        self.purchase.deliveries.filter(purpose="receipt").delete()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        voucher.status = "sending"
        voucher.lease_until = timezone.now() - timedelta(minutes=1)
        voucher.save(update_fields=["status", "lease_until"])
        with patch("django_q.tasks.async_task"):
            result = reconcile_gift_delivery()
        self.assertEqual(result["repaired"], 1)
        self.assertEqual(result["sent"], 2)
        self.assertEqual(self.purchase.deliveries.filter(status="sent").count(), 2)
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(len(queue_purchase_delivery(self.purchase.pk)), 2)
        self.assertEqual(reconcile_gift_delivery()["checked"], 0)

    def test_backend_exception_does_not_persist_sensitive_error_text(self) -> None:
        self._fund()
        voucher = self.purchase.deliveries.get(purpose="voucher")
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError(self.purchase.gift_card.code)):
            self.assertFalse(deliver_gift_card(voucher.pk))
        voucher.refresh_from_db()
        self.assertEqual(voucher.error_code, "provider_unavailable")
        self.assertFalse(EmailLog.objects.exists())
