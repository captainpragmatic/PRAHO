"""#246: the two APIToken expiry access patterns must actually be indexed.

Both queries the issue cites were unindexed — only ``(user, created_at)`` existed:

* the daily purge, ``APIToken.objects.filter(expires_at__lte=now)`` (users/tasks.py),
  scanned the whole table;
* the per-user live-token count enforcing the cap (users/services.py) could use only the
  ``user`` prefix of that composite, then filtered expiry in memory.

Declaring an index is not the same as the planner choosing it, so these assert on the
query plan as well as on ``Meta.indexes``. An index test that only checks the
declaration passes just as happily when the query is shaped so it can never be used.

Caveat worth knowing before trusting these: the test database is built from the current
models (``--nomigrations``), so reverting the model does NOT reproduce the pre-#246
schema — the plan assertions still pass against a stashed model file. They were instead
verified by dropping each index against a real test database and re-planning the same
query:

    without apitoken_expires_at_idx:  SCAN users_api_tokens
    with    apitoken_expires_at_idx:  SEARCH users_api_tokens USING INDEX
                                      apitoken_expires_at_idx (expires_at<?)

Doing that drop inline as part of the test proved unreliable (under ``TestCase`` the DDL
does not change the plan SQLite reports), so it is recorded here rather than asserted.
"""

from __future__ import annotations

from django.db import connection
from django.test import TestCase
from django.utils import timezone

from apps.users.models import APIToken, User


class APITokenExpiryIndexTests(TestCase):
    def test_expiry_indexes_are_declared(self) -> None:
        index_fields = [tuple(idx.fields) for idx in APIToken._meta.indexes]

        self.assertIn(("expires_at",), index_fields)
        self.assertIn(("user", "expires_at"), index_fields)
        # The pre-existing index must survive — it serves the token-listing view.
        self.assertIn(("user", "created_at"), index_fields)

    def _plan(self, queryset) -> str:
        """Return the query plan text for a queryset."""
        sql, params = queryset.query.sql_with_params()
        prefix = "EXPLAIN QUERY PLAN " if connection.vendor == "sqlite" else "EXPLAIN "
        with connection.cursor() as cursor:
            cursor.execute(prefix + sql, params)
            return " ".join(str(cell) for row in cursor.fetchall() for cell in row)

    def test_purge_query_uses_an_index_not_a_table_scan(self) -> None:
        """users/tasks.py: APIToken.objects.filter(expires_at__lte=now).delete()"""
        queryset = APIToken.objects.filter(expires_at__lte=timezone.now())

        self.assertIn(
            "apitoken_expires_at_idx",
            self._plan(queryset),
            "purge query is not using the expiry index",
        )

    def test_per_user_live_token_count_uses_the_composite_index(self) -> None:
        """users/services.py: the cap check, filter(user=…) + expiry null-or-future."""
        user = User.objects.create_user(email="idx@example.test", password="testpass123")
        queryset = APIToken.objects.filter(user=user, expires_at__gt=timezone.now())

        self.assertIn(
            "apitoken_user_expires_idx",
            self._plan(queryset),
            "per-user live-token count is not using the (user, expires_at) index",
        )
