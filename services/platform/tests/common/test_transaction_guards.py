"""ADR-0045 no-transaction guard: an atomic block AND disabled autocommit both refuse the work."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import MagicMock

from django.db import connection, transaction
from django.test import TransactionTestCase

from apps.billing.issuers.service import IssuanceTransactionError, issue_invoice_externally
from apps.common.transactions import is_outside_transaction
from apps.domains.operation_services import require_autocommit
from apps.infrastructure.drift_remediation import DriftRemediationService


@contextmanager
def autocommit_disabled() -> Iterator[None]:
    """Turn autocommit off the way a caller can, without opening an atomic block."""
    connection.set_autocommit(False)
    try:
        yield
    finally:
        connection.rollback()
        connection.set_autocommit(True)


class TransactionGuardTests(TransactionTestCase):
    """TransactionTestCase: autocommit cannot be changed inside TestCase's wrapping transaction."""

    def test_helper_accepts_plain_autocommit(self) -> None:
        self.assertTrue(is_outside_transaction())

    def test_helper_refuses_an_atomic_block(self) -> None:
        with transaction.atomic():
            self.assertFalse(is_outside_transaction())
        self.assertTrue(is_outside_transaction())

    def test_helper_refuses_disabled_autocommit_outside_an_atomic_block(self) -> None:
        with autocommit_disabled():
            self.assertFalse(connection.in_atomic_block)
            self.assertFalse(is_outside_transaction())
        self.assertTrue(is_outside_transaction())

    def test_domain_operations_refuse_disabled_autocommit(self) -> None:
        with autocommit_disabled():
            self.assertFalse(require_autocommit())
        self.assertTrue(require_autocommit())

    def test_drift_snapshot_refuses_disabled_autocommit_before_any_side_effect(self) -> None:
        service = DriftRemediationService()
        with autocommit_disabled():
            result = service._take_snapshot(MagicMock())
        self.assertTrue(result.is_err())
        self.assertIn("autocommit", result.unwrap_err())

    def test_external_issuance_refuses_disabled_autocommit(self) -> None:
        with autocommit_disabled(), self.assertRaises(IssuanceTransactionError):
            issue_invoice_externally(1)
