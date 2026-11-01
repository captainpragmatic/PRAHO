#!/usr/bin/env python3
"""Move an exact, prepared website-only cron.d file into private operation storage.

Shared owner crontabs need preparation into this independent schedule before the
move. No user crontab, retained job, cron authorization or Unix login is changed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_CRON_BYTES = 64 * 1024
MAX_JOBS = 100
CRON_FIELDS = 7
CALENDAR_BOUNDS = (59, 23, 31, 12, 7)


def _journals() -> Any:
    path = Path(__file__).with_name("praho-component-journal.py")
    spec = importlib.util.spec_from_file_location("component_cron_receipts", path)
    if spec is None or spec.loader is None:
        raise ValueError("Native component receipts are unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _calendar(fields: list[str]) -> None:
    atom = r"(?:\*|[0-9]+(?:-[0-9]+)?)(?:/[0-9]+)?"
    for field, maximum in zip(fields, CALENDAR_BOUNDS, strict=True):
        if re.fullmatch(atom + r"(?:," + atom + r")*", field) is None:
            raise ValueError("Prepare a qualified explicit five-field website schedule")
        for part in field.split(","):
            interval, separator, step = part.partition("/")
            if separator and int(step) <= 0:
                raise ValueError("The website schedule has an invalid interval")
            if interval != "*" and any(int(number) > maximum for number in interval.split("-")):
                raise ValueError("The website schedule exceeds its native calendar bound")


def selected_jobs(content: str, owner: str) -> tuple[str, ...]:
    """Environment directives and shared schedules cannot silently change the moved jobs."""
    if len(content.encode()) > MAX_CRON_BYTES or any(character in content for character in ("\0", "\r")):
        raise ValueError("The website schedule is oversized or contains unsupported control characters")
    if content and not content.endswith("\n"):
        raise ValueError("The native website schedule needs its required final newline")
    result = []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(None, CRON_FIELDS - 1)
        if len(fields) != CRON_FIELDS or fields[5] != owner or "=" in fields[0]:
            raise ValueError("Prepare website jobs independently of retained owners and environment directives")
        _calendar(fields[:5])
        result.append(" ".join([*fields[:5], fields[6]]))
    if len(result) > MAX_JOBS or len(set(result)) != len(result):
        raise ValueError("Prepare a bounded, unambiguous independent website schedule")
    return tuple(result)


class CronFileFence:
    def __init__(  # noqa: PLR0913 -- exact native owner, reviewed jobs, attempt identity and storage boundaries
        self,
        domain_id: str,
        operation_id: str,
        owner: str,
        digests: tuple[str, ...],
        *,
        cron_dir: Path = Path("/etc/cron.d"),
        state_dir: Path = Path("/var/lib/praho/component-cron-fences"),
        boot_id: str | None = None,
    ) -> None:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", owner) is None:
            raise ValueError("The website schedule has an invalid native owner")
        if (
            len(digests) > MAX_JOBS
            or len(set(digests)) != len(digests)
            or any(re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in digests)
        ):
            raise ValueError("The reviewed website schedule is incomplete")
        self.owner, self.digests = owner, tuple(sorted(digests))
        authority = hashlib.sha256((owner + "\n" + "\n".join(self.digests)).encode()).hexdigest()
        self.journal = _journals().ComponentJournal(
            state_dir,
            domain_id,
            {
                "operation_id": operation_id,
                "scope_digest": authority,
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )
        self.path = cron_dir / ("praho-component-" + domain_id)
        self.saved = state_dir / (domain_id + "." + operation_id + ".cron")

    def _read(self, path: Path, *, private: bool = False, links: int = 1) -> bytes:
        if path.parent.resolve() != path.parent:
            raise ValueError("Website schedule storage traverses an unqualified symlink")
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != links
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise ValueError("Website schedule is not an independently owned regular file")
        with path.open("rb") as stream:
            value = stream.read(MAX_CRON_BYTES + 1)
        jobs = selected_jobs(value.decode(), self.owner)
        if tuple(sorted(hashlib.sha256(job.encode()).hexdigest() for job in jobs)) != self.digests:
            raise ValueError("The independent website schedule differs from its reviewed selected jobs")
        return value

    def _state(self) -> dict[str, Any]:
        state = self.journal.read()
        if state is None:
            raise ValueError("Website schedule has no durable ownership receipt")
        self.journal.assert_owned(state)
        if state.get("phase") not in {
            "removing",
            "held",
            "releasing",
            "released",
            "retiring",
            "retired",
        } or not isinstance(state.get("original_sha256"), str):
            raise ValueError("Website schedule receipt is unrecognized")
        return state

    def _held(self, state: dict[str, Any]) -> None:
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("A website schedule was recreated; inspect before proceeding")
        if state["present"]:
            original = self._read(self.saved, private=True)
            if hashlib.sha256(original).hexdigest() != state["original_sha256"]:
                raise ValueError("The private original website schedule changed")
        elif self.digests or self.saved.exists() or self.saved.is_symlink():
            raise ValueError("The absent original website schedule has conflicting evidence")

    def apply(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is not None and state.get("operation_id") != self.journal.identity["operation_id"]:
                if state.get("phase") != "released":
                    raise ValueError("Another operation still owns the independent website schedule")
                state = None
            if state is None:
                present = self.path.exists() or self.path.is_symlink()
                original = self._read(self.path) if present else b""
                if not present and self.digests:
                    raise ValueError("The reviewed independent website schedule disappeared")
                if self.saved.exists() or self.saved.is_symlink():
                    raise ValueError("An unreceipted original website schedule needs inspection")
                state = self.journal.create(
                    {
                        "phase": "removing",
                        "present": present,
                        "mode": self.path.stat().st_mode & 0o777 if present else 0o644,
                        "original_sha256": hashlib.sha256(original).hexdigest(),
                    }
                )
            state = self._state()
            if state["phase"] not in {"removing", "held"}:
                raise ValueError("A compensated website schedule cannot be fenced again with the same attempt")
            if state["phase"] == "removing" and state["present"] and self.path.exists():
                if (
                    self.saved.exists()
                    or self.saved.is_symlink()
                    or hashlib.sha256(self._read(self.path)).hexdigest() != state["original_sha256"]
                ):
                    raise ValueError("Website schedule identity changed before removal")
                os.rename(self.path, self.saved)
            if state["phase"] == "removing" and state["present"]:
                if hashlib.sha256(self._read(self.saved)).hexdigest() != state["original_sha256"]:
                    raise ValueError("Private website schedule identity changed during removal")
                self.saved.chmod(0o600)
                self._sync()
            self._held(state)
            state["phase"] = "held"
            self.journal.write(state)

    def _sync(self) -> None:
        path = self.saved if self.saved.exists() else self.path
        if path.exists():
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory in (self.path.parent, self.saved.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def verify(self) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] != "held":
                raise ValueError("The independent website schedule is not held")
            self._held(state)

    def selected_cron(self) -> tuple[str, ...]:
        with self.journal.locked():
            state = self.journal.read()
            if state is None or state.get("phase") == "released":
                value = self._read(self.path) if self.path.exists() or self.path.is_symlink() else b""
            else:
                state = self._state()
                self._held(state)
                value = self._read(self.saved, private=True) if state["present"] else b""
            return selected_jobs(value.decode(), self.owner)

    def _restore_saved(self, state: dict[str, Any]) -> None:
        published = self.path.exists() or self.path.is_symlink()
        if published:
            saved, restored = self.saved.lstat(), self.path.lstat()
            if (saved.st_dev, saved.st_ino) != (restored.st_dev, restored.st_ino):
                raise ValueError("A different actor recreated the website schedule during compensation")
        original = self._read(self.saved, private=True, links=2 if published else 1)
        if hashlib.sha256(original).hexdigest() != state["original_sha256"]:
            raise ValueError("The private original website schedule changed")
        if not published:
            os.link(self.saved, self.path)
        self.saved.unlink()
        self.path.chmod(state["mode"])
        self._sync()

    def release(self) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] == "released":
                return
            if state["phase"] not in {"held", "releasing"}:
                raise ValueError("Unconfirmed schedule removal needs operator inspection")
            if state["phase"] == "held":
                self._held(state)
                state["phase"] = "releasing"
                self.journal.write(state)
            if state["present"]:
                if self.saved.exists():
                    self._restore_saved(state)
                elif hashlib.sha256(self._read(self.path)).hexdigest() != state["original_sha256"]:
                    raise ValueError("Restored website schedule cannot be independently verified")
                else:
                    self.path.chmod(state["mode"])
                    self._sync()
            elif self.path.exists() or self.path.is_symlink():
                raise ValueError("A foreign schedule appeared during compensation")
            state["phase"] = "released"
            self.journal.write(state)

    def retire(self) -> None:
        """Discard only the receipted selected schedule after source web retirement."""
        with self.journal.locked():
            state = self._state()
            if state["phase"] == "retired":
                if any(path.exists() or path.is_symlink() for path in (self.path, self.saved)):
                    raise ValueError("The retired website schedule namespace was reused")
                return
            if state["phase"] != "held":
                raise ValueError("Website schedule retirement was interrupted; inspect before replay")
            self._held(state)
            state["phase"] = "retiring"
            self.journal.write(state)
            if state["present"]:
                self.saved.unlink()
                self._sync()
            state["phase"] = "retired"
            self.journal.write(state)
