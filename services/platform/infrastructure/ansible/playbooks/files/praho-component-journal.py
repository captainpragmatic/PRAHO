#!/usr/bin/env python3
"""Private, fsynced operation receipts shared by native component migration steps."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

MAX_JOURNAL_BYTES = 1024 * 1024


class ComponentJournal:
    def __init__(self, directory: Path, domain_id: str, identity: dict[str, str]) -> None:
        if re.fullmatch(r"[0-9]{1,30}", domain_id) is None:
            raise ValueError("A native domain identity is required for component operation receipts")
        if str(UUID(identity["operation_id"])) != identity["operation_id"]:
            raise ValueError("A canonical operation UUID is required")
        if str(UUID(identity["boot_id"])) != identity["boot_id"]:
            raise ValueError("A canonical source boot identity is required")
        if re.fullmatch(r"[0-9a-f]{64}", identity["scope_digest"]) is None:
            raise ValueError("An exact component authority digest is required")
        self.directory, self.path = directory, directory / f"{domain_id}.json"
        self.identity = {**identity, "domain_id": domain_id}

    @staticmethod
    def _private(info: os.stat_result, *, directory: bool = False) -> None:
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Component receipts must be private and owned by their executing identity")

    @contextmanager
    def locked(self) -> Iterator[None]:
        if not self.directory.is_absolute() or self.directory.resolve() != self.directory:
            raise ValueError("Component receipt directory must be absolute without symlinked ancestors")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private(self.directory.lstat(), directory=True)
        descriptor = os.open(self.path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+") as lock:
            self._private(os.fstat(lock.fileno()))
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def read(self) -> dict[str, Any] | None:
        try:
            descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor) as stream:
            self._private(os.fstat(stream.fileno()))
            encoded = stream.read(MAX_JOURNAL_BYTES + 1)
        if len(encoded.encode()) > MAX_JOURNAL_BYTES:
            raise ValueError("Component operation receipts exceed their bound")
        state = json.loads(encoded)
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ValueError("Component operation receipt schema is unsupported")
        return state

    def assert_owned(self, state: dict[str, Any]) -> None:
        if any(state.get(key) != value for key, value in self.identity.items()):
            raise ValueError("Component receipt belongs to another attempt, scope or source boot")

    def create(self, fields: dict[str, Any]) -> dict[str, Any]:
        state = {**fields, **self.identity, "schema": 1}
        self.write(state)
        return state

    def write(self, state: dict[str, Any]) -> None:
        self.assert_owned(state)
        encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_JOURNAL_BYTES:
            raise ValueError("Component operation receipts exceed their bound")
        descriptor, temporary = tempfile.mkstemp(dir=self.directory, prefix=".component-")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            Path(temporary).unlink(missing_ok=True)
