"""Make SQLite test runs refuse a CharField value longer than its column, as PostgreSQL does.

SQLite stores any length in a varchar, while PostgreSQL raises DataError. PR CI runs ordinary tests on
SQLite and the full suite reaches PostgreSQL only at nightly, so an over-long fixture value passed every
PR gate (#895). This pre_save check closes that gap for Model.save(); queryset.update() and
bulk_create() do not send pre_save and are not checked.
"""

from __future__ import annotations

from typing import Any

from django.db import DataError, connection, models
from django.db.models.signals import pre_save

RECEIVER_UID = "tests.field_lengths.refuse_overlong_char_values"


def _refuse_overlong_char_values(sender: type[models.Model], instance: models.Model, **kwargs: Any) -> None:
    # A deferred field was never loaded and this save does not write it; reading it here would make the
    # check fetch it, changing what the save under test does.
    deferred = instance.get_deferred_fields()
    for field in sender._meta.concrete_fields:
        if not isinstance(field, models.CharField) or field.max_length is None or field.attname in deferred:
            continue
        value = getattr(instance, field.attname)
        if isinstance(value, str) and len(value) > field.max_length:
            raise DataError(
                f"value too long for {sender.__name__}.{field.name}: {len(value)} characters, "
                f"column is varchar({field.max_length}); PostgreSQL rejects this"
            )


def install_sqlite_length_check() -> None:
    """Connect the check when the test database is SQLite (idempotent, per process)."""
    if connection.vendor == "sqlite":
        pre_save.connect(_refuse_overlong_char_values, dispatch_uid=RECEIVER_UID, weak=False)
