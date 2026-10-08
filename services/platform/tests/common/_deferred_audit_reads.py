"""Inject deferred-field fetch failures at the model's database boundary."""

from collections.abc import Callable
from unittest.mock import patch

from django.db import OperationalError, transaction
from django.db.models import Model

from tests.common._signal_isolation import SignalIsolationTestCase


class DeferredAuditReadTestCase(SignalIsolationTestCase):
    def run_deferred_read(self, instance: Model, trigger: Callable[[], object]) -> None:
        reads: list[str] = []
        error: Exception | None = None

        def fail_fetch(*args: object, **kwargs: object) -> None:
            reads.append(str(kwargs.get("fields")))
            # Model the aborted connection left by a failed PostgreSQL statement,
            # including on SQLite: a plain mocked exception would not poison it.
            with transaction.mark_for_rollback_on_error():
                raise OperationalError("Deferred audit payload read failed")

        try:
            with patch.object(instance, "refresh_from_db", side_effect=fail_fetch), transaction.atomic():
                trigger()
        except Exception as exc:
            error = exc

        self.assertIsNone(error, "Optional payload reads must not abort the caller's transaction")
        self.assertTrue(reads, "The audit payload must attempt the deferred database fetch")
        self.assertFalse(transaction.get_connection().needs_rollback)
