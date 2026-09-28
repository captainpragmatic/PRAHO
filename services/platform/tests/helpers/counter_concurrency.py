"""Run counter concurrency checks on PostgreSQL or an isolated SQLite file."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.db import connections

from apps.common.models import Counter


@contextmanager
def counter_database() -> Iterator[None]:
    """Use only from TransactionTestCase, with all workers joined before exit."""
    original = connections["default"]
    if original.vendor != "sqlite":
        yield
        return

    # Shared in-memory SQLite cannot wait for concurrent writers. Give this
    # test a file and its own connection settings without changing production.
    with TemporaryDirectory(prefix="counter-tests-") as directory:
        database = deepcopy(original.settings_dict)
        database["NAME"] = str(Path(directory) / "counters.sqlite3")
        database["OPTIONS"] = {"timeout": 30}
        with patch.dict(connections.databases, {"default": database}):
            isolated = type(original)(database, alias="default")
            connections["default"] = isolated
            try:
                with isolated.schema_editor() as editor:
                    editor.create_model(Counter)
                yield
            finally:
                isolated.close()
                connections["default"] = original
