"""The deferred-read helper must be able to fail when a trigger poisons the transaction."""

from __future__ import annotations

import contextlib

from django.db import OperationalError, transaction

from apps.billing.models import Currency
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


class DeferredAuditReadHelperTests(DeferredAuditReadTestCase):
    def test_a_trigger_that_swallows_the_failure_without_a_savepoint_is_caught(self) -> None:
        currency = Currency(code="ZZZ", symbol="z", decimals=2)

        def swallows_without_a_savepoint() -> None:
            # The failed statement has already marked the transaction for rollback.
            with contextlib.suppress(OperationalError):
                currency.refresh_from_db(fields=["symbol"])

        with self.assertRaises(AssertionError) as caught:
            self.run_deferred_read(currency, swallows_without_a_savepoint)

        self.assertIn("marked for rollback", str(caught.exception))

    def test_a_trigger_that_isolates_the_read_in_a_savepoint_passes(self) -> None:
        currency = Currency(code="ZZZ", symbol="z", decimals=2)

        def isolates_the_read() -> None:
            with contextlib.suppress(OperationalError), transaction.atomic():
                currency.refresh_from_db(fields=["symbol"])

        self.run_deferred_read(currency, isolates_the_read)
