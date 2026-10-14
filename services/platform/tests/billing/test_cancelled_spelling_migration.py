"""Payments stored as "canceled" survive the migration that drops that spelling.

Migration 0012 narrows the status CHECK to the single spelling "cancelled". A row still holding
"canceled" would make adding that constraint fail, so the migration converts those rows between
removing the old constraint and adding the new one.
"""

from __future__ import annotations

import importlib

from django.db import migrations
from django.test import SimpleTestCase

migration_module = importlib.import_module("apps.billing.migrations.0012_payment_status_one_cancelled_spelling")


class CancelledSpellingMigrationTests(SimpleTestCase):
    def test_rows_are_converted_after_the_old_check_is_removed_and_before_the_new_one(self) -> None:
        operations = migration_module.Migration.operations
        kinds = [type(operation) for operation in operations]
        convert = next(
            index
            for index, operation in enumerate(operations)
            if isinstance(operation, migrations.RunPython)
            and operation.code is migration_module.adopt_one_cancelled_spelling
        )
        self.assertLess(kinds.index(migrations.RemoveConstraint), convert)
        self.assertLess(convert, kinds.index(migrations.AddConstraint))
