"""Behavioral proof of optional-effect transaction boundaries."""

import logging
from unittest.mock import patch

from django.db import DatabaseError, IntegrityError, OperationalError, connection, transaction
from django.db.transaction import TransactionManagementError
from django.test import TestCase, TransactionTestCase

from apps.billing import signals
from apps.billing.models import Currency, Invoice
from apps.common.transactions import best_effort_atomic, swallow_application_errors

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

    def test_failed_rollback_propagates_body_error_instead_of_silently_losing_outer_write(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        with self.assertRaises(IntegrityError), transaction.atomic():
            Currency.objects.create(code="XIV", symbol="invoice")
            with (
                patch.object(connection, "savepoint_rollback", side_effect=OperationalError("rollback failed")),
                swallow_application_errors(logger=logger, scope="Dispatch", message="must propagate"),
                best_effort_atomic(logger=logger, scope="Test", message="must propagate"),
            ):
                Currency.objects.create(code="RON", symbol="duplicate")
        self.assertFalse(connection.needs_rollback)
        self.assertFalse(Currency.objects.filter(code="XIV").exists())

    def test_failed_rollback_after_a_swallowed_write_error_propagates(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        with self.assertRaises(TransactionManagementError), transaction.atomic():
            Currency.objects.create(code="XIV", symbol="invoice")
            with (
                patch.object(connection, "savepoint_rollback", side_effect=OperationalError("rollback failed")),
                best_effort_atomic(logger=logger, scope="Test", message="must propagate"),
                self.assertRaises(IntegrityError),
            ):
                Currency.objects.create(code="RON", symbol="duplicate")
        self.assertFalse(connection.needs_rollback)
        self.assertFalse(Currency.objects.filter(code="XIV").exists())


class SwallowApplicationErrorsTests(TestCase):
    def test_plain_value_error_is_swallowed_and_logged_without_a_savepoint(self) -> None:
        failure = ValueError("dispatch failed")
        with (
            patch.object(logger, "exception") as log,
            patch.object(connection, "savepoint") as savepoint,
            swallow_application_errors(logger=logger, scope="Dispatch", message="required dispatch failed"),
        ):
            raise failure
        savepoint.assert_not_called()
        self.assertFalse(connection.needs_rollback)
        log.assert_called_once_with("🔥 [Dispatch] required dispatch failed")

    def test_database_errors_propagate_unchanged_without_logging(self) -> None:
        for failure in (
            DatabaseError("database failed"),
            IntegrityError("constraint failed"),
            OperationalError("connection failed"),
        ):
            with self.subTest(error=type(failure).__name__), patch.object(logger, "exception") as log:
                with (
                    self.assertRaises(type(failure)) as raised,
                    swallow_application_errors(logger=logger, scope="Dispatch", message="must propagate"),
                ):
                    raise failure
                self.assertIs(raised.exception, failure)
                log.assert_not_called()

    def test_transaction_management_error_propagates_unchanged(self) -> None:
        failure = TransactionManagementError("transaction is unusable")
        with (
            patch.object(logger, "exception") as log,
            self.assertRaises(TransactionManagementError) as raised,
            swallow_application_errors(logger=logger, scope="Dispatch", message="must propagate"),
        ):
            raise failure
        self.assertIs(raised.exception, failure)
        log.assert_not_called()

    def test_value_error_after_failed_orm_write_propagates_and_rolls_back(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        failure = ValueError("service replaced the database error")

        def failed_lookup(*args: object, **kwargs: object) -> bool:
            Currency.objects.create(code="XRP", symbol="probe")
            with self.assertRaises(IntegrityError):
                Currency.objects.create(code="RON", symbol="duplicate")
            self.assertTrue(connection.needs_rollback)
            raise failure

        # Check both the helper contract and its use by a production dispatcher.
        for through_handler in (False, True):
            with self.subTest(through_handler=through_handler):
                with (
                    patch.object(logger, "exception") as log,
                    patch.object(signals.logger, "exception") as signal_log,
                    self.assertRaises(ValueError) as raised,
                    transaction.atomic(),
                ):
                    if through_handler:
                        with patch.object(signals, "_is_receivable", side_effect=failed_lookup):
                            signals._handle_invoice_paid(Invoice())
                    else:
                        with swallow_application_errors(logger=logger, scope="Dispatch", message="must propagate"):
                            failed_lookup()
                self.assertIs(raised.exception, failure)
                log.assert_not_called()
                signal_log.assert_not_called()
                self.assertFalse(connection.needs_rollback)
                self.assertFalse(Currency.objects.filter(code="XRP").exists())

    def test_rollback_check_uses_the_requested_database_alias(self) -> None:
        failure = ValueError("broken secondary transaction")
        with (
            patch("apps.common.transactions.transaction.get_connection") as get_connection,
            patch.object(logger, "exception") as log,
            self.assertRaises(ValueError) as raised,
            swallow_application_errors(logger=logger, scope="Dispatch", message="must propagate", using="secondary"),
        ):
            get_connection.return_value.needs_rollback = True
            raise failure
        self.assertIs(raised.exception, failure)
        get_connection.assert_called_once_with("secondary")
        log.assert_not_called()


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
