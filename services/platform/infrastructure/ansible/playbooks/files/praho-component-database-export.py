#!/usr/bin/env python3
"""Export exact selected schemas under their SQL fence, with private password-hash evidence."""

from __future__ import annotations

import importlib.util
import os
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO

DUMP_TIMEOUT_SECONDS = 1800


def _module(filename: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Selected native database export is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fences = _module("praho-component-database-fence.py", "component_export_sql_fences")
archives = _module("praho-component-archive.py", "component_export_private_archive")
capacity = _module("praho-component-capacity.py", "component_export_capacity")


def native_dump(database: str, stream: BinaryIO) -> None:
    if fences.mysql.DATABASE.fullmatch(database) is None:
        raise ValueError("Only an exact qualified native database may be exported")
    process = subprocess.Popen(  # noqa: S603 -- literal options and strictly qualified schema; local DBA config only
        [
            "/usr/bin/mysqldump",
            "--single-transaction",
            "--quick",
            "--routines",
            "--events",
            "--triggers",
            "--hex-blob",
            "--no-tablespaces",
            "--skip-add-locks",
            "--skip-lock-tables",
            "--skip-comments",
            "--databases",
            database,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                selector.register(pipe, selectors.EVENT_READ)
            deadline = time.monotonic() + DUMP_TIMEOUT_SECONDS
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("The selected native database dump exceeded its bounded deadline")
                for key, _events in selector.select(min(remaining, 0.2)):
                    content = os.read(key.fd, 64 * 1024)
                    if not content:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        stream.write(content)
                    # Drain stderr without accumulating native errors or secrets.
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise ValueError("The selected native database export did not finish; inspect before retrying")
            completed = True
    finally:
        if not completed:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def export_databases(
    fence: Any,
    directory: Path,
    *,
    dump: Callable[[str, BinaryIO], None] = native_dump,
    budget: Any = None,
) -> dict[str, Any]:
    """No overwrite after an uncertain dump. Credentials go only into the private component archive."""
    fence.verify()
    info = directory.lstat()
    if (
        directory.resolve() != directory
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("Selected SQL exports require private operation-owned staging")
    principals = (
        fences.mysql.private_credentials(list(fence.principals.values()), execute=fence.execute)
        if fence.principals
        else []
    )
    archives._private_principals({"databases": fence.reviewed}, principals)
    dumps = {}
    if budget is None:
        budget = capacity.OutputBudget(
            capacity.sql_dump_budget({"paths": [], "databases": fence.reviewed}), (directory,)
        )
    operation = fence.journal.identity["operation_id"]
    for database in fence.selected:
        fence.verify()
        budget.check()
        path = directory / ("migration_" + operation + ".db_" + database + ".sql")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            dump(database, budget.writer(stream))
            stream.flush()
            os.fsync(stream.fileno())
        if path.stat().st_size <= 0:
            raise ValueError("The selected native SQL export is unexpectedly empty")
        dumps[database] = path
    fence.verify()
    return {"dumps": dumps, "principals": principals}
