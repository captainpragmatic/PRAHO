#!/usr/bin/env python3
"""Repair native restore_dir's recursive chown before a component target can activate.

Call only while the migration-owned target ingress, Unix login, cron and SQL holds
remain verified. All traversal uses no-follow directory descriptors. Source root
ownership stays root; only the exact source customer UID/GID map to the new owner.
"""

from __future__ import annotations

import os
import posixpath
import stat
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

MAX_FILES = 200000
MAX_RESTORED_MODE = 0o1777
RECORD_FIELDS = {"relative", "uid", "gid", "mode", "kind", "target"}


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or value == "." or "\0" in value:
        raise ValueError("Component file restoration has an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("Component file restoration cannot leave its selected website")
    return value


def _records(metadata: dict[str, Any], home: Path) -> list[dict[str, Any]]:
    if metadata["manifest"]["source"]["home"] != str(home):
        raise ValueError("The restored website home differs from its exact source owner name")
    roots = tuple(_relative(row["relative"]) for row in metadata["manifest"]["paths"])
    records = metadata["files"]
    if not roots or not isinstance(records, list) or not records or len(records) > MAX_FILES:
        raise ValueError("Component ownership restoration needs bounded original file evidence")
    seen = set()
    for row in records:
        if not isinstance(row, dict) or set(row) != RECORD_FIELDS:
            raise ValueError("Component file metadata is incomplete")
        relative = _relative(row["relative"])
        if relative in seen or not any(relative == root or relative.startswith(root + "/") for root in roots):
            raise ValueError("Component ownership restoration includes duplicated or unselected files")
        if (
            type(row["mode"]) is not int
            or not 0 <= row["mode"] <= MAX_RESTORED_MODE
            or row["kind"] not in {"file", "directory", "symlink", "hardlink"}
            or type(row["uid"]) is not int
            or row["uid"] not in {0, metadata["source_uid"]}
            or type(row["gid"]) is not int
            or row["gid"] not in {0, metadata["source_gid"]}
        ):
            raise ValueError("Component file permissions or original ownership are unqualified")
        seen.add(relative)
    return records


def _owner(info: os.stat_result, uid: int, gid: int) -> None:
    if info.st_uid not in {0, uid} or info.st_gid not in {0, gid}:
        raise ValueError("A target path has foreign ownership; inspect before repairing component files")


@contextmanager
def _parent(root: int, relative: str, uid: int, gid: int) -> Iterator[tuple[int, str]]:
    current = os.dup(root)
    try:
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
            _owner(os.fstat(current), uid, gid)
        yield current, parts[-1]
    finally:
        os.close(current)


def _entry(root: int, row: dict[str, Any], home: Path, uid: int, gid: int) -> os.stat_result:
    with _parent(root, row["relative"], uid, gid) as (parent, name):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _owner(info, uid, gid)
        expected = {"file": stat.S_ISREG, "hardlink": stat.S_ISREG, "directory": stat.S_ISDIR, "symlink": stat.S_ISLNK}
        if not expected[row["kind"]](info.st_mode):
            raise ValueError("The restored component file type differs from its archive receipt")
        if row["kind"] == "symlink":
            link = PurePosixPath(os.readlink(name, dir_fd=parent))
            target = (
                str(link.relative_to(home))
                if link.is_absolute()
                else posixpath.normpath(str(PurePosixPath(row["relative"]).parent / link))
            )
            if target != row["target"]:
                raise ValueError("The restored component symlink target changed")
        return info


def _inspect(root: int, rows: list[dict[str, Any]], home: Path, uid: int, gid: int) -> dict[str, os.stat_result]:
    result = {row["relative"]: _entry(root, row, home, uid, gid) for row in rows}
    links = Counter((info.st_dev, info.st_ino) for info in result.values() if stat.S_ISREG(info.st_mode))
    for row in rows:
        info = result[row["relative"]]
        if stat.S_ISREG(info.st_mode) and links[info.st_dev, info.st_ino] != info.st_nlink:
            raise ValueError("A restored component file has an unselected hardlink alias")
        if row["kind"] == "hardlink":
            target = result.get(row["target"])
            if target is None or (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino):
                raise ValueError("A restored component hardlink no longer matches its exact target")
    return result


def _repair(root: int, row: dict[str, Any], original: os.stat_result, uid: int, gid: int) -> None:
    owner = 0 if row["uid"] == 0 else uid
    group = 0 if row["gid"] == 0 else gid
    with _parent(root, row["relative"], uid, gid) as (parent, name):
        if row["kind"] == "symlink":
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("A restored component symlink was replaced during repair")
            os.chown(name, owner, group, dir_fd=parent, follow_symlinks=False)
            return
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("A restored component inode was replaced during repair")
            os.fchown(descriptor, owner, group)
            os.fchmod(descriptor, row["mode"])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def repair_component_files(home: Path, metadata: dict[str, Any], target_uid: int, target_gid: int) -> None:
    """Idempotent while held. Unknown types, identities, links and traversal stop activation."""
    if any(
        type(value) is not int or value <= 0
        for value in (target_uid, target_gid, metadata["source_uid"], metadata["source_gid"])
    ):
        raise ValueError("Component ownership mapping requires non-root source and target owners")
    if not home.is_absolute() or home.resolve() != home:
        raise ValueError("The held target home must not traverse a symlink")
    rows = _records(metadata, home)
    root = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _owner(os.fstat(root), target_uid, target_gid)
        before = _inspect(root, rows, home, target_uid, target_gid)
        # Children first: restoring a root-owned directory's restrictive mode cannot hide its children.
        for row in sorted(rows, key=lambda row: len(PurePosixPath(row["relative"]).parts), reverse=True):
            _repair(root, row, before[row["relative"]], target_uid, target_gid)
        after = _inspect(root, rows, home, target_uid, target_gid)
        for row in rows:
            info = after[row["relative"]]
            expected_owner = 0 if row["uid"] == 0 else target_uid
            expected_group = 0 if row["gid"] == 0 else target_gid
            if (info.st_uid, info.st_gid) != (expected_owner, expected_group) or (
                row["kind"] != "symlink" and stat.S_IMODE(info.st_mode) != row["mode"]
            ):
                raise ValueError("Original component file ownership and permissions did not independently verify")
    finally:
        os.close(root)
