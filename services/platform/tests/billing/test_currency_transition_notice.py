"""The notice promises an exact price and thirty days before document preparation."""

from datetime import UTC, datetime, timedelta

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.billing import currency_transition_notice as notice
from apps.billing.subscription_currency_models import SubscriptionCurrencyTransition
from apps.notifications.models import EmailLog
from tests.billing import test_cycle_terms as cycle_fixtures


class CurrencyNoticeTests(SimpleTestCase):
    def test_preparation_waits_thirty_full_days_from_acceptance(self) -> None:
        accepted = datetime(2026, 9, 29, 13, 41, tzinfo=UTC)
        self.assertFalse(notice.notice_allows_preparation(accepted, accepted + timedelta(days=30, microseconds=-1)))
        self.assertTrue(notice.notice_allows_preparation(accepted, accepted + timedelta(days=30)))
        self.assertFalse(notice.notice_allows_preparation(None, accepted + timedelta(days=90)))

    def test_snapshot_order_is_stable_but_any_charge_or_allowance_change_is_new_offer(self) -> None:
        old = {"currency": "EUR", "quantity": 1, "unit_price_cents": 1099, "meters": {"storage": {
            "unit_price_cents": 2, "included_allowance": "10", "rounding_increment": "1",
        }}}
        reordered = {"meters": old["meters"], "unit_price_cents": 1099, "quantity": 1, "currency": "EUR"}
        self.assertEqual(notice.terms_fingerprint(old), notice.terms_fingerprint(reordered))
        for key, value in (("unit_price_cents", 3), ("included_allowance", "9"), ("rounding_increment", "10")):
            new = {**old, "meters": {"storage": {**old["meters"]["storage"], key: value}}}
            self.assertNotEqual(notice.terms_fingerprint(old), notice.terms_fingerprint(new))

    def test_notice_lists_original_and_target_base_and_usage_terms(self) -> None:
        old = {"currency": "RON", "quantity": 2, "unit_price_cents": 1234, "billing_cycle": "monthly", "meters": {}}
        target = {"currency": "EUR", "quantity": 2, "unit_price_cents": 499, "billing_cycle": "monthly", "meters": {
            "meter": {"name": "storage", "is_billable": True, "currency": "EUR", "source": "pricing_tier",
                      "pricing_model": "per_unit", "unit_price_cents": 3, "included_allowance": "10",
                      "rounding_mode": "up", "rounding_increment": "1", "minimum_charge_cents": 5,
                      "brackets": []},
        }}
        subject, body = notice.render_notice("SUB-42", "Hosting", old, target)
        self.assertIn("SUB-42", subject)
        for value in ("24.68 RON", "9.98 EUR", "storage", "0.03 EUR", "10", "30 days"):
            self.assertIn(value, body)
        self.assertIn("invoices", body)
        self.assertNotIn("conversion", body.lower())


class CurrencyNoticeLedgerTests(TestCase):
    def setUp(self) -> None:
        fixture = cycle_fixtures.FrozenTariffTests()
        fixture.setUp()
        self.customer = fixture.customer
        old = {"currency": "RON", "quantity": 1, "unit_price_cents": 1000, "meters": {}}
        target = {"currency": "EUR", "quantity": 1, "unit_price_cents": 300, "meters": {}}
        subject, body = notice.render_notice(fixture.subscription.subscription_number, fixture.product.name, old, target)
        self.offer = SubscriptionCurrencyTransition.objects.create(
            subscription=fixture.subscription, policy_revision=2, old_terms=old, target_terms=target,
            target_fingerprint=notice.terms_fingerprint(target), notice_recipient="buyer@example.test",
            notice_subject=subject, notice_body=body,
        )

    def email_proof(self, status: str = "sent", **overrides: str) -> EmailLog:
        fields = {
            "customer": self.customer, "to_addr": self.offer.notice_recipient,
            "subject": self.offer.notice_subject, "body_text": self.offer.notice_body,
            "status": status, "body_encrypted": False,
        }
        fields.update(overrides)
        log = EmailLog.objects.create(**fields)
        self.offer.notice_email = log
        # An unsafe caller cannot substitute an earlier clock for actual acceptance.
        self.offer.notice_accepted_at = timezone.now() - timedelta(days=90)
        self.offer.preparation_not_before = timezone.now() - timedelta(days=60)
        return log

    def test_queued_email_cannot_start_notice_period(self) -> None:
        self.email_proof(status="queued")
        with self.assertRaises(ValidationError):
            self.offer.accept_notice()

    def test_only_matching_accepted_email_starts_thirty_day_clock(self) -> None:
        log = self.email_proof()
        self.offer.accept_notice()
        self.offer.save()
        stored = SubscriptionCurrencyTransition.objects.get(pk=self.offer.pk)
        self.assertEqual(stored.status, "notified")
        self.assertEqual(stored.notice_accepted_at, log.sent_at)
        self.assertEqual(stored.preparation_not_before, log.sent_at + timedelta(days=30))

    def test_different_notice_text_is_not_proof_of_this_offer(self) -> None:
        self.email_proof(body_text="An unrelated marketing email")
        with self.assertRaises(ValidationError):
            self.offer.accept_notice()

    def test_accepted_price_and_recipient_cannot_be_rewritten(self) -> None:
        self.email_proof()
        self.offer.accept_notice()
        self.offer.save()
        self.offer.target_terms = {**self.offer.target_terms, "unit_price_cents": 999}
        with self.assertRaises(ValidationError):
            self.offer.save(update_fields=["target_terms"])
        self.offer = SubscriptionCurrencyTransition.objects.get(pk=self.offer.pk)
        self.offer.notice_recipient = "another@example.test"
        with self.assertRaises(ValidationError):
            self.offer.save(update_fields=["notice_recipient"])
