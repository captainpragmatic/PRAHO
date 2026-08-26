"""#246: the APIToken expiry access patterns, tested at their PRODUCTION query shapes.

Two candidate patterns were unindexed — only ``(user, created_at)`` existed:

* the daily purge, ``APIToken.objects.filter(expires_at__lte=now)`` (users/tasks.py),
  scanned the whole table — the genuinely unbounded query; ``apitoken_expires_at_idx``
  now serves it, asserted on the actual plan below;
* the per-user live-token cap check (users/services.py) runs
  ``filter(user=...).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))`` —
  and EXPLAIN shows a ``(user, expires_at)`` composite is NOT used for that shape:
  the OR arm defeats range use of the second column and the planner picks the plain
  user FK index. Since per-user rows are bounded by the token cap itself, the
  composite was dropped as pure write amplification. The tests below pin BOTH halves
  of that decision: the production shape must not full-scan, and the composite must
  stay absent (re-adding it without re-validating the plan is the regression).

Declaring an index is not the same as the planner choosing it — an index test that
only checks the declaration passes just as happily when the query is shaped so the
index can never be used. Hence the plan assertions, run at the real query shapes.
"""

from __future__ import annotations

from django.db import connection
from django.db.models import Q
from django.test import TestCase
from django.utils import timezone

from apps.users.models import APIToken, User


class APITokenExpiryIndexTests(TestCase):
    def test_expiry_index_declarations_match_the_decision(self) -> None:
        index_fields = [tuple(idx.fields) for idx in APIToken._meta.indexes]

        self.assertIn(("expires_at",), index_fields)
        # The pre-existing index must survive — it serves the token-listing view.
        self.assertIn(("user", "created_at"), index_fields)
        # Deliberately ABSENT: EXPLAIN showed the cap check's null-OR-future shape
        # never uses it (see module docstring). Re-adding it must be a conscious,
        # plan-validated decision, not a drive-by "more indexes are better".
        self.assertNotIn(("user", "expires_at"), index_fields)

    def _plan(self, queryset) -> str:
        """Return the query plan text for a queryset."""
        sql, params = queryset.query.sql_with_params()
        prefix = "EXPLAIN QUERY PLAN " if connection.vendor == "sqlite" else "EXPLAIN "
        with connection.cursor() as cursor:
            cursor.execute(prefix + sql, params)
            return " ".join(str(cell) for row in cursor.fetchall() for cell in row)

    def test_purge_query_uses_the_expiry_index_not_a_table_scan(self) -> None:
        """users/tasks.py: APIToken.objects.filter(expires_at__lte=now).delete()"""
        queryset = APIToken.objects.filter(expires_at__lte=timezone.now())

        plan = self._plan(queryset)
        self.assertIn("apitoken_expires_at_idx", plan, "purge query is not using the expiry index")

    def test_cap_check_production_shape_does_not_full_scan(self) -> None:
        """users/services.py:116 — the cap check at its REAL null-or-future shape.

        Asserting a simplified ``expires_at__gt``-only shape here would be classic
        test-vs-production divergence: the simple shape planned through a composite
        index while the real OR query ignored it — which is exactly how the dropped
        ``(user, expires_at)`` index shipped unused in the first draft. The real
        shape must resolve through a user index (bounded by the token cap), never a
        table scan.
        """
        user = User.objects.create_user(email="idx@example.test", password="testpass123")
        queryset = APIToken.objects.filter(user=user).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )

        plan = self._plan(queryset)
        if connection.vendor == "sqlite":
            self.assertNotIn("SCAN users_api_tokens", plan, f"cap check fell back to a table scan: {plan}")
        self.assertIn("user_id", plan, f"cap check is not resolving through a user index: {plan}")
