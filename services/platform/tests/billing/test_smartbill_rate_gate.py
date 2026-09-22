"""Pacing SmartBill calls so the token is never blocked.

SmartBill allows 30 calls per 10 seconds and blocks the token for TEN MINUTES if
that is exceeded. During an hourly recurring-billing run that is an outage.

`TransactionTestCase`, not `TestCase`: `acquire()` uses `transaction.atomic(durable=True)`
so it REFUSES to run inside an enclosing transaction, and `TestCase` wraps every test
in one. That refusal is the ADR-0045 guarantee — the schedule must commit before the
network call — so testing it requires real commits.
"""

from __future__ import annotations

from datetime import timedelta

from django.db import transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.issuers.models import SmartBillRateGate

TOKEN = "test-token-value"


class RateGateTests(TransactionTestCase):
    def tearDown(self) -> None:
        SmartBillRateGate.objects.all().delete()
        super().tearDown()

    def test_the_token_itself_is_never_stored(self) -> None:
        """Only a fingerprint, so a database dump does not leak API credentials."""
        SmartBillRateGate.acquire(TOKEN)

        gate = SmartBillRateGate.objects.get()
        self.assertNotIn(TOKEN, gate.token_fingerprint)
        self.assertEqual(len(gate.token_fingerprint), 64)

    def test_the_first_call_is_granted(self) -> None:
        self.assertIsNone(SmartBillRateGate.acquire(TOKEN))

    def test_an_immediate_second_call_is_deferred(self) -> None:
        """THE property the previous design got wrong.

        It handed out a future timeslot and trusted the caller to wait. Callers did
        not, so thirteen requests could fire at once while the schedule looked
        correct. Anything other than None must prevent the call.
        """
        SmartBillRateGate.acquire(TOKEN)
        retry_at = SmartBillRateGate.acquire(TOKEN)

        self.assertIsNotNone(retry_at)
        assert retry_at is not None
        self.assertGreater(retry_at, timezone.now())

    def test_deferral_consumes_nothing(self) -> None:
        """A deferred caller must not push its own slot further out each attempt.

        The old reserve-a-slot design starved a backlogged task: every retry took a
        new, later reservation.
        """
        SmartBillRateGate.acquire(TOKEN)
        first_retry = SmartBillRateGate.acquire(TOKEN)
        second_retry = SmartBillRateGate.acquire(TOKEN)

        self.assertEqual(first_retry, second_retry)

    def test_a_call_is_granted_again_once_the_interval_has_passed(self) -> None:
        SmartBillRateGate.acquire(TOKEN)
        gate = SmartBillRateGate.objects.get()
        gate.next_allowed_at = timezone.now() - timedelta(seconds=1)
        gate.save(update_fields=["next_allowed_at"])

        self.assertIsNone(SmartBillRateGate.acquire(TOKEN))

    def test_throttling_suppresses_every_worker_not_just_the_one_that_saw_it(self) -> None:
        """A 429 handed only to its caller leaves the rest spending the same token."""
        blocked_until = SmartBillRateGate.record_throttled(TOKEN, retry_after_seconds=300)

        retry_at = SmartBillRateGate.acquire(TOKEN)
        self.assertEqual(retry_at, blocked_until)

    def test_a_throttle_without_retry_after_assumes_the_documented_block(self) -> None:
        """SmartBill documents ten minutes; probing early would only extend it."""
        before = timezone.now()
        blocked_until = SmartBillRateGate.record_throttled(TOKEN)

        self.assertGreaterEqual(blocked_until - before, timedelta(minutes=9))

    def test_a_longer_block_is_never_shortened(self) -> None:
        long_block = SmartBillRateGate.record_throttled(TOKEN, retry_after_seconds=600)
        SmartBillRateGate.record_throttled(TOKEN, retry_after_seconds=5)

        self.assertEqual(SmartBillRateGate.objects.get().blocked_until, long_block)

    def test_different_tokens_are_paced_independently(self) -> None:
        """The limit is per token, so one account must not throttle another."""
        self.assertIsNone(SmartBillRateGate.acquire(TOKEN))
        self.assertIsNone(SmartBillRateGate.acquire("a-different-token"))
        self.assertEqual(SmartBillRateGate.objects.count(), 2)

    def test_it_refuses_to_run_inside_a_transaction(self) -> None:
        """ADR-0045 fail-closed: the schedule must commit BEFORE the network call.

        Inside an enclosing transaction the inner block is only a savepoint, so an
        outer rollback would erase our record of a call the provider already saw,
        and the row lock would be held open across HTTP.
        """
        with self.assertRaises(RuntimeError), transaction.atomic():
            SmartBillRateGate.acquire(TOKEN)

    def test_a_burst_of_grants_never_exceeds_the_provider_limit(self) -> None:
        """Walk the schedule forward and count how many grants fit in ten seconds."""
        granted = 0
        for _ in range(60):
            if SmartBillRateGate.acquire(TOKEN) is None:
                granted += 1
            gate = SmartBillRateGate.objects.get()
            # Advance time by pulling the schedule back, simulating the clock moving.
            gate.next_allowed_at -= SmartBillRateGate.INTERVAL / 2
            gate.save(update_fields=["next_allowed_at"])

        # 60 attempts at half-interval steps covers ~12s of simulated time.
        self.assertLessEqual(granted, 30, msg=f"{granted} grants would block the token")
