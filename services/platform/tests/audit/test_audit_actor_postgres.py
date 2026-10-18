"""PostgreSQL savepoint behaviour of the audit change-snapshot and the write-failure counter.

On PostgreSQL a failed statement aborts the whole transaction unless it ran in its own savepoint.
Both paths here run inside the caller's transaction, so each is proved to leave it usable.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

from django.db import connection, transaction
from django.db.models.query import QuerySet
from django.test import TransactionTestCase, override_settings

from apps.audit.actor_context import acting_as
from apps.audit.models import AuditEvent
from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.common import audit_failures, counters
from apps.common.transactions import best_effort_atomic
from apps.users.models import User

logger = logging.getLogger(__name__)


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class AuditSavepointPostgresTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("statement-aborts-transaction behaviour requires PostgreSQL")
        self.admin = User.objects.create_user(
            email="pg-admin@example.test", password="pw-1234-abcd", staff_role="admin"
        )
        self.subject = User.objects.create_user(
            email="pg-subject@example.test", password="pw-1234-abcd", staff_role="support"
        )
        counters.reset(audit_failures.AUDIT_WRITE_FAILURES_KEY)

    def test_a_failed_snapshot_read_neither_aborts_the_save_nor_loses_the_event(self) -> None:
        original_first = QuerySet.first

        def first(queryset: QuerySet[Any], *args: Any, **kwargs: Any) -> Any:
            if queryset.model is User and getattr(queryset, "_fields", None) == ("staff_role",):
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 / 0")  # a real PostgreSQL statement error
            return original_first(queryset, *args, **kwargs)

        with (
            patch.object(QuerySet, "first", first),
            self.assertLogs("apps.audit.signals", level="ERROR"),
            acting_as(self.admin),
            transaction.atomic(),
        ):
            self.subject.staff_role = "billing"
            self.subject.save(update_fields=["staff_role"])
            self.assertFalse(transaction.get_connection().needs_rollback)

        self.assertEqual(User.objects.get(pk=self.subject.pk).staff_role, "billing")
        (event,) = AuditEvent.objects.filter(action="staff_role_changed")
        self.assertEqual((event.user, event.old_values), (self.admin, {}))

    def test_a_failed_audit_insert_is_counted_and_leaves_the_transaction_usable(self) -> None:
        with transaction.atomic():
            with (
                self.assertLogs("apps.audit.services", level="ERROR"),
                best_effort_atomic(logger=logger, scope="test", message="audit write failed"),
            ):
                # request_id is varchar(36): a real DataError at INSERT, not a mock.
                AuditService.log_event(AuditEventData(event_type="view"), AuditContext(request_id="x" * 80))

            self.assertEqual(audit_failures.count(), 0, "counted after commit, outside this transaction")
            self.assertFalse(transaction.get_connection().needs_rollback)
            self.assertEqual(User.objects.filter(pk=self.admin.pk).count(), 1)
        self.assertEqual(audit_failures.count(), 1)
