#!/usr/bin/env python3
"""Retire a captured source inode closure without trusting mutable customer paths.

Capture runs while source RO holds still apply. Retirement runs after native web
writers stop and those owned mounts release. Root-private quarantine precedes
verification, selected-directory fencing, and FD-relative deletion. Uncertain
mutation receipts always require review; absence is never adopted as ownership.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

STATE_DIR = Path("/var/lib/praho/component-file-retire")
QUARANTINE_DIR = Path("/home/.praho-component-retired")
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 128
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
RECEIPT_FIELDS = {"schema", "domain_id", "operation_id", "scope_digest", "capture_path", "capture_sha256", "boot_id"}


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native selected file retirement support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


paths = _module("praho-component-paths.py", "component_retire_paths")
journals = _module("praho-component-journal.py", "component_retire_journal")


@contextmanager
def _opened(descriptor: int) -> Any:
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino]


def _absolute(path: Path) -> int:
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Retirement paths must be absolute without symlinked ancestors")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    transferred = False
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        transferred = True
        return descriptor
    finally:
        if not transferred:
            os.close(descriptor)


def _private_directory(path: Path, owner_uid: int) -> int:
    if os.geteuid() != owner_uid or not path.is_absolute() or path.resolve() != path:
        raise ValueError("Selected file receipts and quarantine require their executing root identity")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    transferred = False
    try:
        for index, part in enumerate(path.parts[1:]):
            parent = os.fstat(descriptor)
            sticky_root = parent.st_uid == 0 and bool(parent.st_mode & stat.S_ISVTX)
            if parent.st_uid not in {0, owner_uid} or (parent.st_mode & 0o022 and not sticky_root):
                raise ValueError("Retirement storage has an unprotected ancestor")
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if index == len(path.parts) - 2:
                info = os.fstat(descriptor)
                if info.st_uid != owner_uid or info.st_mode & 0o077:
                    raise ValueError("Retirement storage must be a private owned directory")
        transferred = True
        return descriptor
    finally:
        if not transferred:
            os.close(descriptor)


def _parent(home_fd: int, relative: str, ancestors: dict[str, list[int]] | None = None) -> tuple[int, str]:
    parts = PurePosixPath(relative).parts
    descriptor = os.dup(home_fd)
    transferred = False
    try:
        for depth, part in enumerate(parts[:-1], 1):
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            name = PurePosixPath(*parts[:depth]).as_posix()
            if ancestors is not None and _identity(os.fstat(descriptor)) != ancestors.get(name):
                raise ValueError("A captured application ancestor changed")
        transferred = True
        return descriptor, parts[-1]
    finally:
        if not transferred:
            os.close(descriptor)


def _record(relative: str, info: os.stat_result, link: str = "") -> list[Any]:
    return [
        relative,
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        link,
        info.st_ctime_ns,
    ]


def _walk(descriptor: int, relative: str, rows: list[list[Any]], *, depth: int = 0) -> None:
    if depth > MAX_DEPTH or len(rows) >= paths.MAX_ENTRIES:
        raise ValueError("The captured file closure exceeds retirement bounds")
    rows.append(_record(relative, os.fstat(descriptor)))
    with os.scandir(descriptor) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        child_relative = relative + "/" + name
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            with _opened(os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)) as child:
                if _identity(os.fstat(child)) != _identity(info):
                    raise ValueError("The selected file closure changed during capture")
                _walk(child, child_relative, rows, depth=depth + 1)
        else:
            if len(rows) >= paths.MAX_ENTRIES:
                raise ValueError("The captured file closure exceeds retirement bounds")
            rows.append(
                _record(
                    child_relative, info, os.readlink(name, dir_fd=descriptor) if stat.S_ISLNK(info.st_mode) else ""
                )
            )


def _capture(home: Path, selected: tuple[str, ...]) -> dict[str, Any]:
    qualified = paths.scan_paths(home, selected)
    with _opened(_absolute(home)) as home_fd:
        home_info = os.fstat(home_fd)
        rows: list[list[Any]] = []
        ancestors = {"": _identity(home_info)}
        for relative in selected:
            parts = PurePosixPath(relative).parts
            for depth in range(1, len(parts)):
                parent = PurePosixPath(*parts[:depth]).as_posix()
                with _opened(_absolute(home / parent)) as descriptor:
                    ancestors[parent] = _identity(os.fstat(descriptor))
            parent_fd, name = _parent(home_fd, relative, ancestors)
            with _opened(parent_fd), _opened(os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)) as root:
                _walk(root, relative, rows)
        projection = json.dumps(sorted(row[:8] for row in rows), separators=(",", ":")).encode()
        if hashlib.sha256(projection).hexdigest() != qualified["tree_digest"]:
            raise ValueError("The selected file closure changed after qualification")
        if any(row[4] not in {0, home_info.st_uid} for row in rows):
            raise ValueError("The selected file closure includes foreign ownership")
        return {
            "home": str(home),
            "home_identity": _identity(home_info),
            "roots": list(selected),
            "ancestors": ancestors,
            "entries": sorted(rows),
        }


def _context(domain_id: str, operation_id: str, scope_digest: str, boot_id: str | None) -> dict[str, str]:
    boot = boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if (
        str(UUID(operation_id)) != operation_id
        or str(UUID(boot)) != boot
        or re.fullmatch(r"[0-9]{1,30}", domain_id) is None
        or re.fullmatch(r"[0-9a-f]{64}", scope_digest) is None
    ):
        raise ValueError("Exact operation, native domain, source boot and scope identities are required")
    return {"domain_id": domain_id, "operation_id": operation_id, "scope_digest": scope_digest, "boot_id": boot}


def _read_private(directory_fd: int, name: str, owner_uid: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("The captured file closure is not private owned evidence")
        encoded = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(encoded) > MAX_CAPTURE_BYTES:
        raise ValueError("The captured file closure exceeds its private evidence bound")
    return encoded


def capture(  # noqa: PLR0913 -- native identity and private storage are independently bound.
    home: Path,
    selected: tuple[str, ...],
    domain_id: str,
    operation_id: str,
    scope_digest: str,
    *,
    state_dir: Path = STATE_DIR,
    owner_uid: int = 0,
    boot_id: str | None = None,
) -> dict[str, object]:
    """Capture under RO holds; return only a small reference suitable for the parent journal."""
    context = _context(domain_id, operation_id, scope_digest, boot_id)
    directory = state_dir / operation_id
    with _opened(_private_directory(directory, owner_uid)) as descriptor:
        snapshot = {"schema": 1, **context, **_capture(home, selected)}
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_CAPTURE_BYTES:
            raise ValueError("The captured file closure exceeds its private evidence bound")
        name = domain_id + ".capture.json"
        try:
            created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        except FileExistsError:
            if _read_private(descriptor, name, owner_uid) != encoded:
                raise ValueError(
                    "An existing captured file closure changed; never overwrite its ownership evidence"
                ) from None
        else:
            with os.fdopen(created, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
    return {
        "schema": 1,
        **context,
        "capture_path": str(directory / name),
        "capture_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _rename(source: str, destination: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
    os.rename(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


def _unlink(name: str, *, dir_fd: int) -> None:
    os.unlink(name, dir_fd=dir_fd)


class Retirement:
    def __init__(
        self, receipt: dict[str, object], state_dir: Path, quarantine_dir: Path, owner_uid: int, boot_id: str | None
    ):
        if set(receipt) != RECEIPT_FIELDS or receipt.get("schema") != 1:
            raise ValueError("An exact captured file closure receipt is required")
        self.context = _context(
            str(receipt["domain_id"]), str(receipt["operation_id"]), str(receipt["scope_digest"]), boot_id
        )
        if any(receipt[key] != value for key, value in self.context.items()):
            raise ValueError("Captured file evidence belongs to another source boot or operation")
        self.owner_uid, self.operation = owner_uid, self.context["operation_id"]
        self.directory = state_dir / self.operation
        with _opened(_private_directory(self.directory, owner_uid)) as descriptor:
            name = self.context["domain_id"] + ".capture.json"
            if receipt["capture_path"] != str(self.directory / name):
                raise ValueError("The captured file evidence path is outside this operation")
            encoded = _read_private(descriptor, name, owner_uid)
        if hashlib.sha256(encoded).hexdigest() != receipt["capture_sha256"]:
            raise ValueError("The captured file closure digest changed")
        self.snapshot = json.loads(encoded)
        if any(self.snapshot.get(key) != value for key, value in self.context.items()):
            raise ValueError("The captured file closure belongs to another native operation")
        self.home = Path(self.snapshot["home"])
        self.roots = tuple(self.snapshot["roots"])
        self.expected = {row[0]: row for row in self.snapshot["entries"]}
        self.quarantine = quarantine_dir / self.operation
        self.capture_sha256 = str(receipt["capture_sha256"])
        self.journal = journals.ComponentJournal(
            self.directory,
            self.context["domain_id"],
            {
                "operation_id": self.operation,
                "boot_id": self.context["boot_id"],
                "scope_digest": hashlib.sha256(
                    (self.context["scope_digest"] + self.capture_sha256).encode()
                ).hexdigest(),
            },
        )

    def _home(self) -> int:
        descriptor = _absolute(self.home)
        if _identity(os.fstat(descriptor)) != self.snapshot["home_identity"]:
            os.close(descriptor)
            raise ValueError("The captured native home identity changed")
        return descriptor

    def _check(self, relative: str, info: os.stat_result, link: str, state: dict[str, Any], *, frozen: bool) -> None:
        actual = _record(relative, info, link)
        if actual != self._expected_row(relative, actual, state, frozen=frozen):
            raise ValueError("The captured file closure identity or metadata changed")

    def _expected_row(self, relative: str, actual: list[Any], state: dict[str, Any], *, frozen: bool) -> list[Any]:
        expected = self.expected.get(relative)
        if expected is None:
            raise ValueError("The captured file closure changed: an unapproved entry appeared")
        wanted = expected.copy()
        if relative in state.get("root_ctimes", {}):
            wanted[8] = state["root_ctimes"][relative]
        if frozen and stat.S_ISDIR(wanted[3]):
            wanted[3], wanted[4], wanted[8] = stat.S_IFDIR | 0o700, self.owner_uid, actual[8]
        return wanted

    def _verify(self, quarantine_fd: int, state: dict[str, Any], *, frozen: bool = False) -> None:
        actual: list[list[Any]] = []
        expected_slots = {f"root-{index:06d}" for index in range(len(self.roots))}
        if set(os.listdir(quarantine_fd)) != expected_slots:
            raise ValueError("The private quarantine closure changed")
        for index, relative in enumerate(self.roots):
            with _opened(os.open(f"root-{index:06d}", DIRECTORY_FLAGS, dir_fd=quarantine_fd)) as descriptor:
                _walk(descriptor, relative, actual)
        if {row[0] for row in actual} != self.expected.keys():
            raise ValueError("The captured file closure changed after quarantine")
        for row in actual:
            if row != self._expected_row(row[0], row, state, frozen=frozen):
                raise ValueError("The captured file closure identity or metadata changed")

    def _absent(self, home_fd: int) -> None:
        for relative in self.roots:
            parent_fd, name = _parent(home_fd, relative, self.snapshot["ancestors"])
            with _opened(parent_fd):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("The retired source namespace has been reused or changed")

    def _quarantine(self, home_fd: int) -> dict[str, Any]:
        # Verify the complete source closure before moving any source namespace.
        fresh = _capture(self.home, self.roots)
        if any(fresh[key] != self.snapshot[key] for key in fresh):
            raise ValueError("The source file capture changed before quarantine")
        with _opened(_private_directory(self.quarantine.parent, self.owner_uid)) as base_fd:
            if os.fstat(base_fd).st_dev != self.snapshot["home_identity"][0]:
                raise ValueError("Private retirement quarantine must share the selected source filesystem")
            state = self.journal.create({"phase": "creating", "quarantine": str(self.quarantine), "root_ctimes": {}})
            os.mkdir(self.operation, 0o700, dir_fd=base_fd)
            os.fsync(base_fd)
        with _opened(_private_directory(self.quarantine, self.owner_uid)) as quarantine_fd:
            state.update(phase="quarantining", quarantine_identity=_identity(os.fstat(quarantine_fd)))
            self.journal.write(state)
            for index, relative in enumerate(self.roots):
                parent_fd, name = _parent(home_fd, relative, self.snapshot["ancestors"])
                with _opened(parent_fd), _opened(os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)) as original:
                    self._check(relative, os.fstat(original), "", state, frozen=False)
                    state["root_intent"] = relative
                    self.journal.write(state)
                    _rename(name, f"root-{index:06d}", src_dir_fd=parent_fd, dst_dir_fd=quarantine_fd)
                    os.fsync(parent_fd)
                    os.fsync(quarantine_fd)
                    with _opened(os.open(f"root-{index:06d}", DIRECTORY_FLAGS, dir_fd=quarantine_fd)) as moved:
                        if _identity(os.fstat(moved)) != _identity(os.fstat(original)):
                            raise ValueError("A foreign inode raced the captured root rename; preserve quarantine")
                        state["root_ctimes"][relative] = os.fstat(moved).st_ctime_ns
                    self.journal.write(state)
            self._absent(home_fd)
            self._verify(quarantine_fd, state)
            state.update(phase="quarantined", root_intent=None)
            self.journal.write(state)
            return state

    def _freeze(self, descriptor: int, relative: str, state: dict[str, Any]) -> None:
        self._check(relative, os.fstat(descriptor), "", state, frozen=False)
        os.fchown(descriptor, self.owner_uid, -1)
        # nosemgrep: insecure-file-permissions — 0700 restricts verified directory-fd traversal to its owner, with no group/other access.
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
        children = sorted(
            name
            for name, row in self.expected.items()
            if PurePosixPath(name).parent.as_posix() == relative and stat.S_ISDIR(row[3])
        )
        for child in children:
            with _opened(os.open(PurePosixPath(child).name, DIRECTORY_FLAGS, dir_fd=descriptor)) as nested:
                self._freeze(nested, child, state)

    def _delete(self, descriptor: int, relative: str, links: dict[tuple[int, int], int]) -> None:
        expected_names = {
            PurePosixPath(name).name for name in self.expected if PurePosixPath(name).parent.as_posix() == relative
        }
        if set(os.listdir(descriptor)) != expected_names:
            raise ValueError("The frozen file closure changed; preserve all remaining entries")
        for name in sorted(expected_names):
            child = relative + "/" + name
            expected = self.expected[child]
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _identity(info) != expected[1:3] or stat.S_IFMT(info.st_mode) != stat.S_IFMT(expected[3]):
                raise ValueError("A frozen captured inode changed before deletion")
            if stat.S_ISDIR(info.st_mode):
                with _opened(os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)) as nested:
                    if _identity(os.fstat(nested)) != expected[1:3]:
                        raise ValueError("A frozen directory identity changed before deletion")
                    self._delete(nested, child, links)
                os.rmdir(name, dir_fd=descriptor)
            else:
                key = (info.st_dev, info.st_ino)
                if stat.S_ISREG(info.st_mode):
                    if info.st_nlink != links[key]:
                        raise ValueError("Captured hardlink closure changed before deletion")
                    links[key] -= 1
                _unlink(name, dir_fd=descriptor)
        os.fsync(descriptor)

    def retire(self) -> dict[str, object]:
        result = {
            "phase": "retired",
            "operation_id": self.operation,
            "domain_id": self.context["domain_id"],
            "capture_sha256": self.capture_sha256,
        }
        with self.journal.locked(), _opened(self._home()) as home_fd:
            state = self.journal.read()
            if state is None:
                state = self._quarantine(home_fd)
            self.journal.assert_owned(state)
            if state.get("quarantine") != str(self.quarantine) or state.get("phase") not in {
                "quarantined",
                "frozen",
                "retired",
            }:
                raise ValueError("Selected file cleanup was interrupted; inspect its exact private receipts")
            with _opened(_private_directory(self.quarantine, self.owner_uid)) as quarantine_fd:
                if _identity(os.fstat(quarantine_fd)) != state.get("quarantine_identity"):
                    raise ValueError("The private retirement quarantine identity changed")
                self._absent(home_fd)
                if state["phase"] == "retired":
                    if os.listdir(quarantine_fd):
                        raise ValueError("A retired private quarantine namespace was reused")
                    return result
                self._verify(quarantine_fd, state, frozen=state["phase"] == "frozen")
                if state["phase"] == "quarantined":
                    state["phase"] = "freezing"
                    self.journal.write(state)
                    for index, relative in enumerate(self.roots):
                        with _opened(os.open(f"root-{index:06d}", DIRECTORY_FLAGS, dir_fd=quarantine_fd)) as descriptor:
                            self._freeze(descriptor, relative, state)
                    self._verify(quarantine_fd, state, frozen=True)
                    state["phase"] = "frozen"
                    self.journal.write(state)
                state["phase"] = "deleting"
                self.journal.write(state)
                links = {(row[1], row[2]): row[6] for row in self.expected.values() if stat.S_ISREG(row[3])}
                for index, relative in enumerate(self.roots):
                    slot = f"root-{index:06d}"
                    with _opened(os.open(slot, DIRECTORY_FLAGS, dir_fd=quarantine_fd)) as descriptor:
                        if _identity(os.fstat(descriptor)) != self.expected[relative][1:3]:
                            raise ValueError("The captured root changed before deletion")
                        self._delete(descriptor, relative, links)
                    os.rmdir(slot, dir_fd=quarantine_fd)
                    os.fsync(quarantine_fd)
                self._absent(home_fd)
                state["phase"] = "retired"
                self.journal.write(state)
                return result


def retire(
    receipt: dict[str, object],
    *,
    state_dir: Path = STATE_DIR,
    quarantine_dir: Path = QUARANTINE_DIR,
    owner_uid: int = 0,
    boot_id: str | None = None,
) -> dict[str, object]:
    return Retirement(receipt, state_dir, quarantine_dir, owner_uid, boot_id).retire()
