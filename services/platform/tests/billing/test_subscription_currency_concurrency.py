"""Real PostgreSQL ordering of prepared renewals, explicit prices and selling policy."""

from unittest import skipUnless
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.common.types import Ok
from apps.products.models import ProductPrice
from apps.settings.services import SettingsService
from tests.billing.test_currency_renewal_workflow import _CurrencyRenewalWorkflowFixture
from tests.orders import test_selling_currency_concurrency as race_helpers


@skipUnless(connection.vendor == "postgresql", "PostgreSQL lock visibility is required")
@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SubscriptionCurrencyConcurrencyTests(_CurrencyRenewalWorkflowFixture, TransactionTestCase):
    # Reuse the observer that proves a FOR UPDATE wait through pg_blocking_pids;
    # both competing operations below still execute their complete production paths.
    _assert_policy_wait = race_helpers.SellingCurrencyConcurrencyTests._assert_policy_wait
    _interleave = race_helpers.SellingCurrencyConcurrencyTests._interleave

    def setUp(self) -> None:
        queue = patch("django_q.tasks.async_task")
        queue.start()
        self.addCleanup(queue.stop)
        cache.clear()
        self.addCleanup(cache.clear)
        super().setUp()

    def prepare_result(self):
        return RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)

    def test_competing_preparation_commits_exactly_one_notified_document(self) -> None:
        offer = self.offer(accepted_days=30)
        first, second = self._interleave(
            self.prepare_result, self.prepare_result,
            lambda sql: sql.startswith('INSERT INTO "billing_proforma_invoices"'),
        )
        self.assertEqual(first["errors"], [])
        self.assertEqual(second["errors"], [])
        self.assertEqual((first["cycles_prepared"], second["cycles_prepared"]), (1, 0))
        self.assertEqual(self.subscription.billing_cycles.filter(proforma__isnull=False).count(), 1)
        offer.refresh_from_db()
        self.assertEqual(offer.status, "committed")
        self.assertEqual(offer.committed_cycle.currency_id, "EUR")

    def test_preparation_rechecks_notice_after_competing_price_write_commits(self) -> None:
        old = self.offer(accepted_days=30)
        price = ProductPrice.objects.get(product=self.product, currency_id="EUR")

        def change_price():
            price.monthly_price_cents = 2500
            price.save(update_fields=["monthly_price_cents"])

        _changed, prepared = self._interleave(
            change_price, self.prepare_result,
            lambda sql: sql.startswith('UPDATE "product_prices"'),
        )
        self.assertEqual(prepared["errors"], [])
        cycle = self.subscription.billing_cycles.get(proforma__isnull=False)
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents), ("RON", 10000))
        old.refresh_from_db()
        self.assertEqual(old.status, "superseded")

    def test_currency_switch_cannot_rewrite_an_already_prepared_notified_document(self) -> None:
        offer = self.offer(accepted_days=30)
        prepared, switched = self._interleave(
            self.prepare_result, lambda: SettingsService.update_setting("billing.default_currency", "USD"),
            lambda sql: sql.startswith('INSERT INTO "billing_proforma_invoices"'),
        )
        self.assertEqual(prepared["errors"], [])
        self.assertIsInstance(switched, Ok)
        offer.refresh_from_db()
        self.assertEqual(offer.status, "committed")
        self.assertEqual((offer.committed_cycle.currency_id, offer.committed_cycle.unit_price_cents), ("EUR", 2200))

    def test_competing_notice_claims_send_once_without_holding_database_locks(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        original_send = mail.EmailMessage.send

        def local_delivery(message, *args, **kwargs):
            self.assertFalse(connection.in_atomic_block, "Email delivery must happen outside database locks")
            return original_send(message, *args, **kwargs)

        with patch("django.core.mail.EmailMessage.send", new=local_delivery):
            first, second = self._interleave(
                lambda: send_currency_notice(offer.pk), lambda: send_currency_notice(offer.pk),
                lambda sql: sql.startswith('UPDATE "billing_subscription_currency_transitions"')
                and '"notice_attempted_at"' in sql,
            )
        # The competing worker may recover the accepted log before the sender
        # reacquires its offer lock; either way only one worker records acceptance.
        self.assertCountEqual([first, second], [True, False])
        self.assertEqual(len(mail.outbox), 1)
        offer.refresh_from_db()
        self.assertEqual(offer.status, "notified")

    def test_price_change_during_notice_delivery_cannot_commit_the_old_offer(self) -> None:
        from apps.billing.currency_transitions import prepare_currency_offer, send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        original_send = mail.EmailMessage.send

        def local_delivery(message, *args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            price = ProductPrice.objects.get(product=self.product, currency_id="EUR")
            price.monthly_price_cents = 2500
            price.save(update_fields=["monthly_price_cents"])
            replacement = prepare_currency_offer(self.subscription.pk)
            self.assertNotEqual(replacement.pk, offer.pk)
            return original_send(message, *args, **kwargs)

        with patch("django.core.mail.EmailMessage.send", new=local_delivery):
            self.assertFalse(send_currency_notice(offer.pk))
        offer.refresh_from_db()
        self.assertEqual(offer.status, "superseded")
        self.assertIsNone(offer.notice_accepted_at)
        self.assertEqual(self.prepare().currency_id, "RON")
