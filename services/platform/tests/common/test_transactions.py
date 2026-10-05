"""Behavioral proof of optional-effect transaction boundaries."""

import logging
from unittest.mock import patch

from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.transaction import TransactionManagementError
from django.test import TestCase, TransactionTestCase

from apps.billing.models import Currency
from apps.common.transactions import best_effort_atomic

logger = logging.getLogger(__name__)


class BestEffortAtomicTests(TestCase):
    def test_body_failure_rolls_back_before_logging_and_outer_transaction_remains_usable(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})

        def assert_rolled_back(*args: object, **kwargs: object) -> None:
            self.assertFalse(Currency.objects.filter(code="XOP").exists())

        with transaction.atomic(), patch.object(logger, "exception", side_effect=assert_rolled_back) as log:
            with best_effort_atomic(logger=logger, scope="Test", message="optional write failed"):
                Currency.objects.create(code="XOP", symbol="$")
                Currency.objects.create(code="RON", symbol="duplicate")
            self.assertFalse(connection.needs_rollback)
            Currency.objects.create(code="XOK", symbol="€")
            self.assertTrue(Currency.objects.filter(code="XOK").exists())
            log.assert_called_once_with("🔥 [Test] optional write failed")
        self.assertTrue(Currency.objects.filter(code="XOK").exists())

    def test_entering_with_needs_rollback_raises_and_preserves_cause(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        with transaction.atomic():
            with self.assertRaises(IntegrityError) as failed_write:
                Currency.objects.create(code="RON", symbol="duplicate")
            self.assertTrue(connection.needs_rollback)
            with (
                self.assertRaises(TransactionManagementError) as blocked,
                best_effort_atomic(logger=logger, scope="Test", message="must not run"),
            ):
                self.fail("the body must not run in a broken transaction")
            self.assertIs(blocked.exception.__cause__, failed_write.exception)

    def test_a_failed_callback_registration_is_discarded_but_other_callbacks_survive(self) -> None:
        seen: list[str] = []
        with self.captureOnCommitCallbacks(execute=True):
            with best_effort_atomic(logger=logger, scope="Test", message="callback discarded"):
                transaction.on_commit(lambda: seen.append("discarded"))
                raise RuntimeError("optional effect failed")
            transaction.on_commit(lambda: seen.append("survived"))
        self.assertEqual(seen, ["survived"])


class BestEffortAtomicPostgresTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("aborted PostgreSQL transactions require PostgreSQL")

    def test_failed_savepoint_entry_propagates_database_error(self) -> None:
        with transaction.atomic():
            with self.assertRaises(DatabaseError), connection.cursor() as cursor:
                cursor.execute("SELECT 1 / 0")
            # Raw SQL does not set Django's flag; SAVEPOINT itself must raise.
            self.assertFalse(connection.needs_rollback)
            with (
                self.assertRaises(DatabaseError),
                best_effort_atomic(logger=logger, scope="Test", message="must not run"),
            ):
                self.fail("a failed SAVEPOINT must never yield")
