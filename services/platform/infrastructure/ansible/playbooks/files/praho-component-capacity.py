#!/usr/bin/env python3
"""Read-only selected export capacity admission for native and sanitizer workspaces."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

RETAINED_RESERVE_BYTES = 1024 * 1024 * 1024
METADATA_WORKSPACE_BYTES = 512 * 1024 * 1024
FILE_WORKING_COPIES = 4
SQL_EXPANSION_COPIES = 8
SQL_METADATA_BYTES = METADATA_WORKSPACE_BYTES // 8


def sql_dump_budget(manifest: dict[str, Any]) -> int:
    required_bytes(manifest)  # Validate the same reviewed byte evidence as admission.
    # Dumps and their copy inside the published archive share the admitted 8x
    # SQL workspace. A compressed schema may exceed this explicit ceiling; it
    # must then park while the source holds and retained services remain intact.
    return SQL_EXPANSION_COPIES // 2 * sum(row["bytes"] for row in manifest["databases"]) + SQL_METADATA_BYTES


def native_archive_budget(manifest: dict[str, Any]) -> int:
    required_bytes(manifest)
    return 2 * sum(row["bytes"] for row in manifest["paths"]) + METADATA_WORKSPACE_BYTES // 4


def run_limited(  # noqa: PLR0913 -- isolated command, input, deadline and independent native file/workspace bounds.
    arguments: list[str],
    *,
    paths: tuple[Path, ...],
    file_limit: int,
    data: str | None = None,
    timeout: float = 1800,
    workspace_limit: int | None = None,
) -> str:
    """Linux child-only hard file ceiling plus ongoing actual-filesystem reserve checks."""
    required = file_limit if workspace_limit is None else workspace_limit
    budget = OutputBudget(required, paths)
    budget.check(required)
    # A new process group includes native tar/gzip descendants. prlimit changes
    # only this isolated child, never the source's shared service or Python parent.
    process = subprocess.Popen(  # noqa: S603 -- fixed Linux prlimit and qualified native argv; no shell.
        ["/usr/bin/prlimit", "--fsize=" + str(file_limit) + ":" + str(file_limit), "--", *arguments],
        stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout
    completed = False
    try:
        pending = data
        while True:
            budget.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Selected native export workspace exceeded its bounded deadline")
            try:
                output, _errors = process.communicate(input=pending, timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                pending = None
        budget.check()
        if process.returncode or len(output.encode()) > 1024 * 1024:
            raise ValueError(
                "Selected native export exceeded its file budget or did not complete; preserve source holds"
            )
        completed = True
        return output
    finally:
        if not completed:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()


class OutputBudget:
    """One shared byte ceiling, checked against current retained-service reserve before every write."""

    def __init__(
        self,
        limit: int,
        paths: tuple[Path, ...],
        *,
        reserve_bytes: int = RETAINED_RESERVE_BYTES,
        usage: Callable[[Path], Any] | None = None,
    ) -> None:
        if type(limit) is not int or limit < 0 or type(reserve_bytes) is not int or reserve_bytes < 0:
            raise ValueError("Native export output needs an exact nonnegative byte budget")
        self.limit, self.written, self.reserve = limit, 0, reserve_bytes
        self.paths = tuple(dict.fromkeys(_existing_directory(path) for path in paths))
        if not self.paths:
            raise ValueError("Native output budget needs its actual staging filesystem")
        self.usage = usage or shutil.disk_usage

    def check(self, size: int = 0) -> None:
        if size < 0 or self.written + size > self.limit:
            raise ValueError("Selected native SQL output exceeds its approved byte budget; preserve source holds")
        for path in self.paths:
            free = self.usage(path).free
            if type(free) is not int or free < self.reserve + size:
                raise ValueError("Selected export must preserve the retained-service filesystem reserve")

    def writer(self, stream: BinaryIO) -> Any:
        budget = self

        class BoundedWriter:
            def write(self, content: bytes) -> int:
                budget.check(len(content))
                written = stream.write(content)
                if written != len(content):
                    raise OSError("Selected native export had an incomplete private staging write")
                budget.written += written
                stream.flush()
                return written

        return BoundedWriter()


def required_bytes(manifest: dict[str, Any]) -> int:
    files = [row["bytes"] for row in manifest["paths"]]
    databases = [row["bytes"] for row in manifest["databases"]]
    if any(type(size) is not int or size < 0 for size in [*files, *databases]):
        raise ValueError("Selected export capacity requires bounded nonnegative native byte evidence")
    # Four hard-capped native working copies plus four dump allowances cover
    # both extracted and published sanitizer files, even on its failure path.
    # Require both workspaces independently; they may be different filesystems.
    return (
        2 * FILE_WORKING_COPIES * sum(files)
        + 2 * SQL_EXPANSION_COPIES * sum(databases)
        + METADATA_WORKSPACE_BYTES
        + 4 * SQL_METADATA_BYTES
        + RETAINED_RESERVE_BYTES
    )


def _existing_directory(path: Path) -> Path:
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Source temporary storage needs an absolute canonical directory without symlinks")
    ancestor = path
    while not ancestor.exists():
        ancestor = ancestor.parent
    if not ancestor.is_dir():
        raise ValueError("Source temporary storage is not an existing directory or creatable descendant")
    return ancestor


def require_capacity(
    manifest: dict[str, Any],
    staging: Path,
    native_temp: Path,
    *,
    usage: Callable[[Path], Any] = shutil.disk_usage,
) -> None:
    required = required_bytes(manifest)
    for path in dict.fromkeys((_existing_directory(staging), _existing_directory(native_temp))):
        free = usage(path).free
        if type(free) is not int or free < required:
            raise ValueError(
                "Prepare native temporary and selected export storage with at least "
                + str((required + 1024 * 1024 - 1) // (1024 * 1024))
                + " MiB free, including the retained-service reserve, before migration"
            )
