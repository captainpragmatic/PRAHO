"""#246: the APIToken expiry access patterns, tested at their PRODUCTION statements.

Two candidate patterns were unindexed — only ``(user, created_at)`` existed:

* the daily purge, ``APIToken.objects.filter(expires_at__lte=now)`` (users/tasks.py),
  scanned the whole table — the genuinely unbounded query; ``apitoken_expires_at_idx``
  now serves it, asserted on the actual plan below;
* the per-user live-token cap check (users/services.py) runs
  ``filter(user=...).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).count()``.
  A ``(user, expires_at)`` composite for it was DROPPED after two independent EXPLAIN
  experiments (PG16 @ 20k rows: identical plan and cost either way; PG16 @ 200k rows:
  the COUNT can go Index-Only on it) — a real-at-scale but marginal, contingent
  benefit against per-user rows kept small by the cap plus the purge, not worth a
  third index now; re-add CONCURRENTLY on production EXPLAIN evidence.
  The tests pin BOTH halves: the production statement must resolve through a
  USER index (asserted by index NAME — an anonymous "some index was used" assertion
  passes even when the planner BitmapOrs the expiry index with user_id as a heap
  filter), and the composite must stay absent; re-adding it must start with EXPLAIN on
  PostgreSQL at realistic row counts, not a drive-by "more indexes are better".

Declaring an index is not the same as the planner choosing it — hence plan assertions,
run on the exact SQL production executes (captured from the real ``.count()`` call,
not a hand-built lookalike: a SELECT-all-columns stand-in demonstrably plans
differently from ``COUNT(*)`` on SQLite).
"""

from __future__ import annotations

from django.db import connection
from django.db.models import Q
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.users.models import APIToken, User


class APITokenExpiryIndexTests(TestCase):
    def test_expiry_index_declarations_match_the_decision(self) -> None:
        index_fields = [tuple(idx.fields) for idx in APIToken._meta.indexes]

        self.assertIn(("expires_at",), index_fields)
        # The pre-existing index must survive — it serves the token-listing view.
        self.assertIn(("user", "created_at"), index_fields)
        # Deliberately ABSENT — see the module docstring for the cross-engine EXPLAIN
        # rationale. Re-adding it must be a conscious, plan-validated decision.
        self.assertNotIn(("user", "expires_at"), index_fields)

    def _plan_sql(self, sql: str) -> str:
        """EXPLAIN a raw SQL statement, deterministically.

        On cost-based planners (PostgreSQL) a tiny test table gets a Seq Scan even
        when a perfectly usable index exists, so ``SET LOCAL enable_seqscan = off``
        (transaction-local — valid because TestCase wraps each test in an atomic
        block; a TransactionTestCase conversion would silently downgrade it to a
        warning) turns the EXPLAIN into an index-USABILITY probe. That is the limit
        of what these tests prove on PostgreSQL: an index can serve the statement —
        not that a cost-based production plan will always pick it.
        """
        with connection.cursor() as cursor:
            if connection.vendor == "sqlite":
                cursor.execute("EXPLAIN QUERY PLAN " + sql)
            else:
                cursor.execute("SET LOCAL enable_seqscan = off")
                cursor.execute("EXPLAIN " + sql)
            return " ".join(str(cell) for row in cursor.fetchall() for cell in row)

    def _production_plan(self, run_query) -> str:
        """Run the real query, capture the exact SQL it executed, and EXPLAIN that."""
        with CaptureQueriesContext(connection) as ctx:
            run_query()
        return self._plan_sql(ctx.captured_queries[-1]["sql"])

    def test_purge_query_uses_the_expiry_index(self) -> None:
        """users/tasks.py: APIToken.objects.filter(expires_at__lte=now) — positive
        assertion on the index NAME (a negative 'no SCAN' assertion degrades silently
        when planner wording changes across SQLite versions)."""
        plan = self._production_plan(
            lambda: list(APIToken.objects.filter(expires_at__lte=timezone.now()).values_list("id", flat=True))
        )
        self.assertIn("apitoken_expires_at_idx", plan, f"purge shape is not served by the expiry index: {plan}")

    def test_cap_check_production_statement_resolves_through_a_user_index(self) -> None:
        """users/services.py:116 — the cap check's EXACT statement (.count()).

        The first draft asserted a simplified ``expires_at__gt``-only queryset — which
        planned through the composite while the real OR statement ignored it. The
        second draft asserted "some index node exists" — which PostgreSQL satisfies by
        BitmapOr-ing the EXPIRY index with user_id as a heap filter even with every
        user index dropped. Both were test-vs-production divergence; this asserts the
        real statement resolves through an index whose name says it is a USER index.
        """
        user = User.objects.create_user(email="idx@example.test", password="testpass123")
        plan = self._production_plan(
            lambda: APIToken.objects.filter(user=user)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
            .count()
        )
        # Django's user indexes on this table all carry "user_id" in their names
        # (FK auto-index and the (user, created_at) Meta index alike).
        if connection.vendor == "sqlite":
            self.assertRegex(
                plan,
                r"USING (?:COVERING )?INDEX \S*user_id",
                f"cap-check statement is not resolving through a user index: {plan}",
            )
        else:
            self.assertRegex(
                plan,
                r"(?:Index(?: Only)? Scan using|Bitmap Index Scan on) \S*user_id",
                f"cap-check statement is not resolving through a user index: {plan}",
            )
