#!/usr/bin/env python3
"""Durable native quota lane. A matching probe cannot release an uncertain command."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

MAX_STATE_BYTES = 16384
MAX_QUANTITY = (1 << 63) - 1
COMMAND_ARGUMENT_COUNT = 2


class QuotaBackend(Protocol):
    def apply(self, request: dict[str, object], *, lock_fd: int) -> None: ...

    def probe(self, request: dict[str, object]) -> dict[str, object]: ...


def _private_directory(path: Path) -> None:
    if path.resolve() != path:
        raise ValueError("Quota state cannot traverse a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Quota state must be an owned private directory")


def _read(path: Path) -> dict[str, object] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Quota state must be an owned private regular file")
        content = stream.read(MAX_STATE_BYTES + 1)
    if len(content.encode()) > MAX_STATE_BYTES:
        raise ValueError("Quota state exceeds its bound")
    result = json.loads(content)
    if not isinstance(result, dict):
        raise ValueError("Quota state has an invalid shape")
    return result


def _write(path: Path, state: dict[str, object]) -> None:
    content = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(content) > MAX_STATE_BYTES:
        raise ValueError("Quota state exceeds its bound")
    temporary = path.with_name(".quota-" + str(uuid4()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class QuotaCoordinator:
    def __init__(self, root: Path, backend: QuotaBackend, *, lock_root: Path | None = None) -> None:
        self.root, self.backend = root, backend
        self.lock_root = lock_root or root / "locks"
        _private_directory(root)
        _private_directory(self.lock_root)

    @contextmanager
    def _locked(self, domain_id: str, *, wait_seconds: float = 30) -> Iterator[int]:
        # Production uses /run/praho, sharing the existing chain-backup lock.
        descriptor = os.open(
            self.lock_root / ("chain-" + domain_id + ".lock"),
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("The native account lock is not private")
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("The native quota lane is busy") from None
                    time.sleep(0.01)
            yield descriptor
        finally:
            os.close(descriptor)

    def _scope(self, request: dict[str, object]) -> tuple[Path, str, str, int, str]:
        if set(request) != {"identity", "token", "generation", "disk_limit_kib", "bandwidth_limit_bytes"}:
            raise ValueError("The quota application has unsupported terms")
        identity = request["identity"]
        if not isinstance(identity, dict):
            raise ValueError("An exact native quota identity is required")
        installation, domain_id = identity.get("installation"), identity.get("domain_id")
        if not isinstance(installation, str) or str(UUID(installation)) != installation:
            raise ValueError("An exact native installation is required")
        if not isinstance(domain_id, str) or re.fullmatch(r"[0-9]{1,30}", domain_id) is None:
            raise ValueError("An exact native domain is required")
        token, generation = request["token"], request["generation"]
        if not isinstance(token, str) or str(UUID(token)) != token:
            raise ValueError("An exact quota application token is required")
        for name in ("generation", "disk_limit_kib", "bandwidth_limit_bytes"):
            value = request[name]
            if type(value) is not int or not 0 <= value <= MAX_QUANTITY:
                raise ValueError("Quota application quantities must be explicit nonnegative integers")
        if generation == 0:
            raise ValueError("The quota application generation must be positive")
        scope = self.root / installation / domain_id
        _private_directory(scope)
        digest = hashlib.sha256(
            json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return scope, domain_id, token, int(generation), digest

    def perform(self, action: str, request: dict[str, object]) -> dict[str, object]:
        if action not in {"probe", "apply", "fence"}:
            raise ValueError("Unsupported native quota action")
        scope, domain_id, token, generation, digest = self._scope(request)
        with self._locked(domain_id) as descriptor:
            path = scope / "current.json"
            cancelled = scope / ("cancelled-" + token + ".json")
            state = _read(path)
            if action == "probe":
                return self.backend.probe(request)
            if action == "fence":
                # Never expire these markers: a command queued before a reboot may
                # arrive later. The same lock proves the old mutation has exited.
                _write(cancelled, {"token": token, "generation": generation})
                if state and state.get("token") == token and state.get("generation") == generation:
                    _write(path, {**state, "phase": "fenced"})
                return {"outcome": "fenced", "token": token, "generation": generation}
            if _read(cancelled) is not None:
                raise ValueError("The quota application token was permanently cancelled")
            if state is not None:
                previous = state.get("generation")
                if type(previous) is not int or generation < previous:
                    raise ValueError("The quota application generation is obsolete")
                if generation == previous:
                    if state.get("token") != token or state.get("digest") != digest:
                        raise ValueError("The quota application generation has different terms")
                    if state.get("phase") == "completed":
                        return {**self.backend.probe(request), "token": token, "generation": generation}
                if state.get("phase") not in {"completed", "fenced"}:
                    raise ValueError("The previous quota application is uncertain; fence it before retrying")
            _write(path, {"generation": generation, "token": token, "digest": digest, "phase": "running"})
            self.backend.apply(request, lock_fd=descriptor)
            result = {**self.backend.probe(request), "token": token, "generation": generation}
            _write(
                path,
                {"generation": generation, "token": token, "digest": digest, "phase": "completed", "receipt": result},
            )
            return result


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != COMMAND_ARGUMENT_COUNT or sys.argv[1] not in {"probe", "apply", "fence"}:
        raise ValueError("A root-owned native quota operation is required")
    raw = sys.stdin.buffer.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("The native quota request exceeds its bound")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("The native quota request has an invalid shape")
    from praho_quota_native import NativeQuotaBackend  # noqa: PLC0415 -- Root-owned sibling installed together.

    coordinator = QuotaCoordinator(Path("/var/lib/praho/quotas"), NativeQuotaBackend(), lock_root=Path("/run/praho"))
    print(json.dumps(coordinator.perform(sys.argv[1], request), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
