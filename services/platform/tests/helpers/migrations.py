"""Helpers for tests that drive the migration executor.

A migration test rewinds the schema to an earlier node, asserts the migration under
test behaves, and must then put the database BACK before the next test runs — these
are ``TransactionTestCase``s, so nothing is rolled back for them.

Restoring to a hardcoded ``MIGRATE_TO`` is the trap this module exists to close: that
name is the leaf only on the day the test is written. Every migration added afterwards
widens a silent gap, and the schema every later test sees is missing those columns.
That is not hypothetical — it produced ``no such column: billing_invoice_sequences.prefix``
in unrelated billing tests once ``0043_billing_operator_controls`` shipped, presenting
as an order-dependent flake that passed whenever the module ran alone.

Always restore to the app's CURRENT leaf, resolved from the migration graph at runtime.
"""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader


def leaf_migration(app_label: str) -> tuple[str, str]:
    """Return the app's current leaf migration node, as the executor expects it."""
    loader = MigrationLoader(connection)
    leaves = [node for node in loader.graph.leaf_nodes() if node[0] == app_label]
    if not leaves:
        raise AssertionError(f"No leaf migration found for app {app_label!r}")
    if len(leaves) > 1:
        raise AssertionError(f"App {app_label!r} has multiple migration leaves: {leaves}")
    return leaves[0]


def restore_to_leaf(app_label: str) -> None:
    """Migrate ``app_label`` forward to its current leaf.

    Call this from a migration test's ``tearDown``, in place of migrating to a
    hardcoded target, so adding a migration can never strand the schema again.
    """
    MigrationExecutor(connection).migrate([leaf_migration(app_label)])
