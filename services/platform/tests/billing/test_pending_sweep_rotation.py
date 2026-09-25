"""A permanently stuck issuance held the head of the sweep queue forever.

`sweep_pending_issuances` takes the oldest `limit` candidates by `created_at`. A row that can
never succeed - a credit note with no original to reverse, say, or one whose enqueue keeps
failing - stays a candidate indefinitely, so a handful of them occupy every run while a
genuinely recoverable issuance behind them is never reached. The invoice behind that one has no
legal number and no automated path to getting one.

`sweep_owed_reversals` solved exactly this and wrote down why. Its MECHANISM does not transfer:
it pages `pk__gt=cursor` because `Invoice.pk` is an autoincrement integer that is also its
ordering key, whereas `ProviderIssuance.id` is a UUID and this sweep orders by `created_at`. So
the cursor here is a `(created_at, pk)` keyset - the pk tiebreaker is what stops a page boundary
falling between two rows that share a timestamp and dropping one of them.

Every test here runs under a real cache. Test settings use `DummyCache`, where `cache.set` is a
no-op and `cache.get` always returns `None`: the sweep still works, degrading to always scanning
from the oldest row, so a rotation test without this override passes no matter what the code
does - and so does the mutation that removes the cursor.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.tasks import sweep_pending_issuances
from config.settings.test import LOCMEM_TEST_CACHE
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class PendingSweepRotationTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _candidate(self, *, age_minutes: int) -> ProviderIssuance:
        """A `pending` issuance whose invoice has no number: exactly what the sweep takes."""
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name=f"Customer {self._seq}",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        issuance = ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)
        ProviderIssuance.objects.filter(pk=issuance.pk).update(
            state=IssuanceState.PENDING.value,
            created_at=timezone.now() - timedelta(minutes=age_minutes),
        )
        return ProviderIssuance.objects.get(pk=issuance.pk)

    @staticmethod
    def _swept_invoice_ids(calls: list[object]) -> list[object]:
        return [call.args[0] for call in calls]

    def test_a_second_run_reaches_past_what_the_first_examined(self) -> None:
        """The whole point: a stuck row at the head must not be all any run ever sees."""
        oldest = self._candidate(age_minutes=30)
        newer = self._candidate(age_minutes=20)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value=None) as queued:
            sweep_pending_issuances(limit=1)
            first = self._swept_invoice_ids(queued.call_args_list)
            queued.reset_mock()
            sweep_pending_issuances(limit=1)
            second = self._swept_invoice_ids(queued.call_args_list)

        self.assertEqual(first, [oldest.invoice_id])
        self.assertEqual(second, [newer.invoice_id], "the stuck oldest row held the queue head")

    def test_the_rotation_wraps_back_to_the_start(self) -> None:
        oldest = self._candidate(age_minutes=30)
        self._candidate(age_minutes=20)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value=None) as queued:
            sweep_pending_issuances(limit=1)
            sweep_pending_issuances(limit=1)
            queued.reset_mock()
            sweep_pending_issuances(limit=1)
            third = self._swept_invoice_ids(queued.call_args_list)

        self.assertEqual(third, [oldest.invoice_id])

    def test_rows_sharing_a_timestamp_are_not_skipped(self) -> None:
        """The pk tiebreaker: a page boundary between two equal timestamps must not lose one."""
        stamp = timezone.now() - timedelta(minutes=30)
        first = self._candidate(age_minutes=30)
        second = self._candidate(age_minutes=30)
        ProviderIssuance.objects.filter(pk__in=[first.pk, second.pk]).update(created_at=stamp)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value=None) as queued:
            sweep_pending_issuances(limit=1)
            sweep_pending_issuances(limit=1)
            reached = self._swept_invoice_ids(queued.call_args_list)

        self.assertCountEqual(reached, [first.invoice_id, second.invoice_id])

    def test_a_single_candidate_is_still_swept_every_run(self) -> None:
        """Rotation must not starve the only candidate there is."""
        only = self._candidate(age_minutes=30)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value=None) as queued:
            sweep_pending_issuances(limit=1)
            queued.reset_mock()
            sweep_pending_issuances(limit=1)
            second = self._swept_invoice_ids(queued.call_args_list)

        self.assertEqual(second, [only.invoice_id])

    def test_a_run_that_fits_every_candidate_still_sees_them_all(self) -> None:
        one = self._candidate(age_minutes=30)
        two = self._candidate(age_minutes=20)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value=None) as queued:
            result = sweep_pending_issuances(limit=10)
            reached = self._swept_invoice_ids(queued.call_args_list)

        self.assertCountEqual(reached, [one.invoice_id, two.invoice_id])
        self.assertEqual(result["skipped"], 2)
