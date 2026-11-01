#!/usr/bin/env python3
"""Serialize component restore/sealing with the existing qualified private usage writer."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from types import TracebackType
from uuid import UUID

METADATA_SHA256 = "2eae317a85bdf7ea2e4264bc2f1d87a73d05837929193c0a023106bfdeddd1bd"
WRAPPER_SHA256 = "008d8f3108ceb0b1f1ad33ad1a10b61cadee0ddec8044984ff498a56440145d0"
COLLECTOR_SHA256 = "d8dcb8e0d9408579bb2b2d5cf3733074f5ac7b27a78efae55983d427608e2d9f"
HOOK = "/usr/local/libexec/praho-usage-hook"
MAX_PROFILE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024
Executor = Callable[[list[str], float], str]


def command(arguments: list[str], timeout: float) -> str:
    """Bound output/time and stop the owned writer group before returning an error."""
    process = subprocess.Popen(  # noqa: S603 -- fixed qualified Perl writer/action in production
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True
    )
    completed = False
    try:
        assert process.stdout is not None
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Usage reconciliation timed out; inspect its private state")
                for _key, _events in selector.select(min(0.1, remaining)):
                    chunk = os.read(descriptor, MAX_OUTPUT_BYTES + 1)
                    if not chunk:
                        selector.unregister(descriptor)
                        break
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT_BYTES:
                        raise ValueError("Usage reconciliation output exceeds its qualification bound")
        try:
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise TimeoutError("Usage reconciliation timed out; inspect its private state") from None
        if code:
            raise ValueError("Usage reconciliation failed; inspect its private state")
        try:
            value = output.decode("ascii")
        except UnicodeError:
            raise ValueError("Usage reconciliation returned an unsupported receipt") from None
        completed = True
        return value
    finally:
        if not completed:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
        if process.stdout is not None:
            process.stdout.close()


class UsageWriterGuard:
    def __init__(
        self,
        *,
        root: Path = Path("/"),
        owner_uid: int = 0,
        executor: Executor = command,
        lock_timeout: float = 20,
        command_timeout: float = 60,
    ) -> None:
        if type(owner_uid) is not int or owner_uid < 0:
            raise ValueError("Usage profile needs an exact executing identity")
        for value, maximum in ((lock_timeout, 20), (command_timeout, 60)):
            if type(value) not in (int, float) or not 0 < value <= maximum:
                raise ValueError("Usage coordination timeout is outside its bound")
        self.root, self.owner_uid, self.executor = root, owner_uid, executor
        self.lock_timeout, self.command_timeout = lock_timeout, command_timeout
        self.state = root / "var/lib/praho/usage"
        self.lock = self.state / "lock"
        self.config = root / "etc/webmin/virtual-server/config"
        self.programs = {
            root / "usr/local/libexec/praho-usage-metadata.pl": METADATA_SHA256,
            root / "usr/local/libexec/praho-usage-hook": WRAPPER_SHA256,
            root / "usr/local/libexec/praho_usage.py": COLLECTOR_SHA256,
        }
        self.installed = False
        self._active = False
        self._descriptor: int | None = None
        self._installation: str | None = None

    @staticmethod
    def _exists(path: Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        return True

    def _directory(self, path: Path, *, private: bool = False) -> None:
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise ValueError("Usage profile directory is not safely owned")

    def _parents(self, path: Path) -> None:
        current = self.root
        self._directory(current)
        for part in path.relative_to(self.root).parts[:-1]:
            current /= part
            if not self._exists(current):
                break
            self._directory(current)

    def _file(self, info: os.stat_result, mode: int | None) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_nlink != 1
            or (stat.S_IMODE(info.st_mode) != mode if mode is not None else bool(info.st_mode & 0o022))
        ):
            raise ValueError("Usage profile file is not safely owned")

    def _read(self, path: Path, mode: int | None, limit: int = MAX_PROFILE_BYTES) -> bytes:
        self._parents(path)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ValueError("Usage profile file is unavailable or unsupported") from None
        with os.fdopen(descriptor, "rb") as stream:
            self._file(os.fstat(stream.fileno()), mode)
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Usage profile file exceeds its qualification bound")
        return value

    def _selected_hook(self) -> str:
        hook = ""
        if self._exists(self.config):
            try:
                lines = self._read(self.config, None).decode("utf-8").splitlines()
            except UnicodeError:
                raise ValueError("Native usage hook selection is unsupported") from None
            selections = [line.split("=", 1)[1] for line in lines if line.startswith("post_command=")]
            if len(selections) > 1 or any("\0" in line for line in lines):
                raise ValueError("Native usage hook selection is ambiguous")
            hook = selections[0] if selections else ""
        if hook not in ("", HOOK):
            raise ValueError("An unknown native post-command requires operator review")
        return hook

    def _qualify(self) -> str | None:
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise ValueError("Usage profile root must be canonical")
        for path in (*self.programs, self.state / "installation", self.config):
            self._parents(path)
        hook = self._selected_hook()
        present = [self._exists(path) for path in (*self.programs, self.state)]
        if not any(present) and not hook:
            return None
        if not all(present) or hook != HOOK:
            raise ValueError("The private usage writer profile is incomplete")
        self._directory(self.state, private=True)
        for path, expected in self.programs.items():
            if hashlib.sha256(self._read(path, 0o700)).hexdigest() != expected:
                raise ValueError("The private usage writer version is unsupported")
        raw = self._read(self.state / "installation", 0o600, 64)
        try:
            installation = str(UUID(raw.decode("ascii").rstrip("\n")))
        except (ValueError, UnicodeError):
            raise ValueError("Usage installation identity is malformed") from None
        if raw not in (installation.encode(), installation.encode() + b"\n"):
            raise ValueError("Usage installation identity is not canonical")
        previous = self.state / "previous-hook"
        if self._exists(previous) and self._read(previous, 0o600, 4096):
            raise ValueError("An opaque previous usage hook requires operator review")
        if not self._exists(self.lock):
            raise ValueError("The initialized private usage lock is missing")
        return installation

    def _held_profile(self) -> None:
        if self._qualify() != self._installation:
            raise ValueError("Usage profile changed during component restoration")
        if self._descriptor is not None:
            info = os.fstat(self._descriptor)
            self._file(info, None)
            current = self.lock.lstat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("The held usage lock identity changed")

    def __enter__(self) -> UsageWriterGuard:
        if self._active or self._descriptor is not None:
            raise ValueError("Usage coordination cannot be reentered")
        self._installation = self._qualify()
        self.installed = self._installation is not None
        if not self.installed:
            self._active = True
            return self
        try:
            self._descriptor = os.open(self.lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            # Collector open("a") may create 0644; the private parent and no foreign writes protect this nonsecret lock.
            self._file(os.fstat(self._descriptor), None)
            deadline = time.monotonic() + self.lock_timeout
            while True:
                try:
                    fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Usage collection is busy; no lock was stolen") from None
                    time.sleep(min(0.05, remaining))
            self._held_profile()
            self._active = True
            return self
        except TimeoutError:
            raise
        except OSError:
            raise ValueError("Private usage lock is unavailable or unsafe") from None
        finally:
            if not self._active:
                self._close()

    def _close(self) -> None:
        if self._descriptor is not None:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._descriptor)
                self._descriptor = None
        self._active = False

    def __exit__(
        self, exc_type: type[BaseException] | None, error: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self._close()

    def reconcile(self) -> int:
        if not self._active or (self.installed and self._descriptor is None):
            raise ValueError("Usage reconciliation requires its held guard")
        self._held_profile()
        if not self.installed:
            return 0
        value = self.executor(
            ["/usr/bin/perl", str(self.root / "usr/local/libexec/praho-usage-metadata.pl"), "reconcile-locked"],
            self.command_timeout,
        )
        self._held_profile()
        match = re.fullmatch(r"PRAHO_USAGE_RECONCILED changed=(0|[1-9][0-9]{0,8})\n?", value)
        if len(value.encode()) > MAX_OUTPUT_BYTES or match is None:
            raise ValueError("Usage reconciliation did not return its qualified receipt")
        return int(match[1])
