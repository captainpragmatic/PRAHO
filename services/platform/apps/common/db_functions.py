"""Portable database defaults for immutable encryption contexts."""

from typing import Any

from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models import Func, UUIDField
from django.db.models.sql.compiler import SQLCompiler


class RandomContextUUID(Func):
    """Supply an identity for raw inserts; ORM writes still preallocate uuid4()."""

    function = "GEN_RANDOM_UUID"
    arity = 0
    output_field = UUIDField()

    def as_sqlite(
        self, compiler: SQLCompiler, connection: BaseDatabaseWrapper, **extra_context: Any
    ) -> tuple[str, list[Any]]:
        # SQLite's UUIDField stores hex text. This is an identity, not a secret key.
        return "lower(hex(randomblob(16)))", []
