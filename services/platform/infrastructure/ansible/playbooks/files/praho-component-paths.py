#!/usr/bin/env python3
"""Read-only path qualification shared by imported website inspection and its fence.

The inode set is local evidence for /proc writer detection, never persisted in a review.
No files, ownership, access controls, mail paths or authentication state are changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import TypedDict

MAX_ENTRIES = 200000
MAX_ROOTS = 100
MAX_RELATIVE_LENGTH = 1024
MAX_PROCESSES = 65536
MAX_PROCESS_DESCRIPTORS = 8192
MAX_PROCESS_FILE_BYTES = 4 * 1024 * 1024
MAX_MOUNTS = 8192
MAX_MOUNT_NAMESPACES = 1024
MAX_NAMESPACE_MOUNT_FACTS = 65536
MOUNT_REQUIRED_FIELDS = 6
LOCAL_FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs", "overlay"})
MAP_FIELD_COUNT = 5
MAP_PERMISSION_LENGTH = 4
DEVICE_FIELD_COUNT = 2
STAT_START_TIME_INDEX = 19  # Field22 after removing pid and parenthesized comm.
STAT_FLAGS_INDEX = 6  # Field9 in the same projection.
PF_KTHREAD = 0x00200000  # Linux include/linux/sched.h; no userspace mount namespace.
RESERVED_ROOTS = frozenset({"mail", "maildir", "homes", "domains", "logs", "etc", "tmp", "cgi-bin"})


class PathScope(TypedDict):
    bytes: int
    files: tuple[str, ...]
    entries: tuple[str, ...]
    inodes: set[tuple[int, int]]
    tree_digest: str


def _roots(home: Path, selected: tuple[str, ...]) -> tuple[Path, ...]:
    if not selected or len(selected) > MAX_ROOTS or home.is_symlink() or home.resolve() != home:
        raise ValueError("Select bounded paths under the native home, without symlinked ancestors")
    roots: list[Path] = []
    for relative in selected:
        parts = PurePosixPath(relative).parts
        if (
            not parts
            or len(relative) > MAX_RELATIVE_LENGTH
            or PurePosixPath(relative).is_absolute()
            or PurePosixPath(relative).as_posix() != relative
            or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part) or part in {".", ".."} for part in parts)
            or parts[0].lower() in RESERVED_ROOTS
        ):
            raise ValueError("Select application paths, excluding the entire home, mail, authentication and traversal")
        path = home
        for part in parts:
            path /= part
            if path.is_symlink():
                raise ValueError("Selected paths must not have symlinked ancestors")
        if not path.is_dir():
            raise ValueError("Prepare a separate application directory before migration")
        if any(path == root or path.is_relative_to(root) or root.is_relative_to(path) for root in roots):
            raise ValueError("Selected application roots must not overlap")
        roots.append(path)
    return tuple(roots)


def scan_paths(home: Path, selected: tuple[str, ...]) -> PathScope:  # noqa: C901, PLR0912 -- bounded native filesystem qualification
    roots = _roots(home, selected)
    home_device = home.stat().st_dev
    inodes: set[tuple[int, int]] = set()
    file_links: Counter[tuple[int, int]] = Counter()
    expected_links: dict[tuple[int, int], int] = {}
    records: list[tuple[object, ...]] = []
    files: list[str] = []
    total = 0
    pending = list(roots)
    while pending:
        path = pending.pop()
        if len(records) >= MAX_ENTRIES:
            raise ValueError("Selected application tree exceeds the qualification limit")
        relative = path.relative_to(home).as_posix()
        info = path.lstat()
        identity = (info.st_dev, info.st_ino)
        if info.st_dev != home_device:
            raise ValueError("Selected application crosses a mount or device; prepare a bounded independent tree")
        inodes.add(identity)
        link = ""
        if stat.S_ISLNK(info.st_mode):
            link = os.readlink(path)
            resolved = path.resolve(strict=True)
            if not any(resolved.is_relative_to(root) for root in roots):
                raise ValueError("A selected link resolves outside the website into retained or unrelated data")
            files.append(relative)
        elif stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    if len(pending) + len(records) >= MAX_ENTRIES:
                        raise ValueError("Selected application tree exceeds the qualification limit")
                    pending.append(Path(entry.path))
        elif stat.S_ISREG(info.st_mode):
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ValueError("Selected application has a privileged executable; prepare it before migration")
            file_links[identity] += 1
            expected_links[identity] = info.st_nlink
            if file_links[identity] == 1:
                total += info.st_size
            files.append(relative)
        else:
            raise ValueError("Selected application contains a socket, pipe or device; classify its writer first")
        records.append(
            (relative, info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, link)
        )
    if any(file_links[identity] != links for identity, links in expected_links.items()):
        raise ValueError("Selected files have shared hardlinks outside the website")
    digest = hashlib.sha256(json.dumps(sorted(records), separators=(",", ":")).encode()).hexdigest()
    return {
        "bytes": total,
        "files": tuple(sorted(files)),
        "entries": tuple(sorted(str(row[0]) for row in records)),
        "inodes": inodes,
        "tree_digest": digest,
    }


class PathWriter(TypedDict):
    pid: int
    start_time: str
    mount_namespace: str
    kind: str
    identity: str
    uid: int


def _read_process(path: Path) -> str:
    with path.open("r", encoding="utf-8", errors="strict") as stream:
        value = stream.read(MAX_PROCESS_FILE_BYTES + 1)
    if len(value) > MAX_PROCESS_FILE_BYTES:
        raise ValueError("Process writer evidence exceeds its qualification limit")
    return value


class QualifiedMount(TypedDict):
    mount_namespace: str
    mount_id: int
    parent_id: int
    device: str
    root: str
    mountpoint: str
    filesystem: str
    read_only: bool


class MountNamespace(TypedDict):
    pid: int
    start_time: str
    mount_namespace: str
    roots: list[str]


class MountQualification(TypedDict):
    namespaces: list[MountNamespace]
    mounts: list[QualifiedMount]


def _mount_path(value: str) -> str:
    decoded = re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)
    if not decoded.startswith("/") or ".." in PurePosixPath(decoded).parts or len(decoded) > MAX_PROCESS_FILE_BYTES:
        raise ValueError("Native mount path is unclassified")
    return PurePosixPath(decoded).as_posix()


def _mount_table(process: Path, namespace: str) -> list[QualifiedMount]:
    mounts: list[QualifiedMount] = []
    identifiers = set()
    for line in _read_process(process / "mountinfo").splitlines():
        fields = line.split()
        separator = fields.index("-") if "-" in fields else -1
        if (
            len(mounts) >= MAX_MOUNTS
            or separator < MOUNT_REQUIRED_FIELDS
            or len(fields) != separator + 4
            or not fields[0].isdecimal()
            or not fields[1].isdecimal()
            or not re.fullmatch(r"\d+:\d+", fields[2])
            or fields[0] in identifiers
            or len(set(fields[5].split(",")) & {"ro", "rw"}) != 1
        ):
            raise ValueError("Native mount namespace evidence is incomplete or unclassified")
        identifiers.add(fields[0])
        mounts.append(
            {
                "mount_namespace": namespace,
                "mount_id": int(fields[0]),
                "parent_id": int(fields[1]),
                "device": fields[2],
                "root": _mount_path(fields[3]),
                "mountpoint": _mount_path(fields[4]),
                "filesystem": fields[separator + 1],
                "read_only": "ro" in fields[5].split(","),
            }
        )
    if not mounts:
        raise ValueError("Native mount namespace evidence is empty")
    return mounts


def _mount_witness(process: Path) -> tuple[str, str]:
    namespace = re.fullmatch(r"mnt:\[(\d+)\]", os.readlink(process / "ns/mnt"))
    fields = _read_process(process / "stat").rpartition(")")[2].split()
    if namespace is None or len(fields) <= STAT_START_TIME_INDEX or not fields[STAT_START_TIME_INDEX].isdigit():
        raise ValueError("Native mount namespace process identity is incomplete")
    return namespace[1], fields[STAT_START_TIME_INDEX]


def _held_mount_namespaces(process: Path) -> set[str]:
    namespaces = set()
    with os.scandir(process / "fd") as descriptors:
        for count, descriptor in enumerate(descriptors, 1):
            if count > MAX_PROCESS_DESCRIPTORS:
                raise ValueError("Mount namespace descriptor inventory exceeds its qualification limit")
            try:
                namespace = re.fullmatch(r"mnt:\[(\d+)\]", os.readlink(descriptor.path))
            except FileNotFoundError:
                continue  # A descriptor may close while its process remains alive.
            if namespace:
                namespaces.add(namespace[1])
    return namespaces


def _no_live_mount_namespace(process: Path) -> bool:
    try:
        fields = _read_process(process / "stat").rpartition(")")[2].split()
    except FileNotFoundError:
        return not process.exists()
    if len(fields) <= STAT_FLAGS_INDEX or not fields[STAT_FLAGS_INDEX].isdecimal():
        raise ValueError("Process without a native mount namespace could not be classified")
    return fields[0] == "Z" or bool(int(fields[STAT_FLAGS_INDEX]) & PF_KTHREAD)


def _mount_namespaces(proc: Path) -> list[tuple[Path, str, str, list[QualifiedMount]]]:
    namespaces = {}
    held = set()
    total_mounts = 0
    with os.scandir(proc) as processes:
        for count, entry in enumerate(processes, 1):
            if count > MAX_PROCESSES:
                raise ValueError("Mount namespace process inventory exceeds its limit")
            if not entry.name.isdecimal():
                continue
            process = Path(entry.path)
            try:
                namespace, started = _mount_witness(process)
                held.update(_held_mount_namespaces(process))
                if namespace in namespaces:
                    continue
                mounts = _mount_table(process, namespace)
                total_mounts += len(mounts)
                if total_mounts > MAX_NAMESPACE_MOUNT_FACTS:
                    raise ValueError("Mount namespace facts exceed their aggregate qualification limit")
                if (namespace, started) != _mount_witness(process):
                    raise ValueError("Mount namespace process changed during qualification")
                namespaces[namespace] = (process, namespace, started, mounts)
            except FileNotFoundError:
                if not _no_live_mount_namespace(process):
                    raise ValueError("A live mount namespace could not be inspected") from None
            if len(namespaces) > MAX_MOUNT_NAMESPACES:
                raise ValueError("Mount namespace inventory exceeds its qualification limit")
    if not namespaces:
        raise ValueError("No native mount namespace could be inspected")
    if held - set(namespaces):
        raise ValueError("A descriptor-held mount namespace has no live process witness; prepare it before migration")
    return sorted(namespaces.values(), key=lambda item: int(item[0].name))


def _covering_mount(mounts: list[QualifiedMount], path: Path) -> QualifiedMount:
    covering = [mount for mount in mounts if path.is_relative_to(mount["mountpoint"])]
    if not covering:
        raise ValueError("Selected path has no classified covering mount")
    # mountinfo lists stacked mounts in mount order; prefer the last equally deep mount.
    return max(enumerate(covering), key=lambda item: (len(PurePosixPath(item[1]["mountpoint"]).parts), item[0]))[1]


def _mount_source(root: Path, mounts: list[QualifiedMount]) -> tuple[str, PurePosixPath]:
    mount = _covering_mount(mounts, root)
    info = root.stat()
    device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    if mount["device"] != device or mount["filesystem"] not in LOCAL_FILESYSTEMS:
        raise ValueError("Selected application requires a classified local ext4/xfs/btrfs/overlay filesystem")
    return device, PurePosixPath(mount["root"]) / root.relative_to(mount["mountpoint"])


def _project_mount(root: Path, source: PurePosixPath, mount: QualifiedMount) -> tuple[Path, Path] | None:
    native_root = PurePosixPath(mount["root"])
    point = Path(mount["mountpoint"])
    if source.is_relative_to(native_root):
        return point / source.relative_to(native_root), root
    if native_root.is_relative_to(source):
        return point, root / native_root.relative_to(source)
    return None


def _same_namespace_inode(process: Path, visible: Path, original: Path) -> bool:
    try:
        info = (process / "root" / visible.relative_to("/")).stat()
        source = original.stat()
    except FileNotFoundError:
        return False  # PrivateTmp/chroot may hide this entire selected subtree.
    return (info.st_dev, info.st_ino) == (source.st_dev, source.st_ino)


def _qualify_namespace_mounts(
    process: Path,
    mounts: list[QualifiedMount],
    sources: list[tuple[Path, str, PurePosixPath]],
    owned: set[int],
) -> tuple[list[str], list[QualifiedMount]]:
    visible_roots: set[str] = set()
    relevant: dict[int, QualifiedMount] = {}
    for root, device, source in sources:
        for mount in mounts:
            if mount["device"] != device:
                continue
            projected = _project_mount(root, source, mount)
            if projected is None or not _same_namespace_inode(process, *projected):
                continue
            visible, original = projected
            if mount["filesystem"] not in LOCAL_FILESYSTEMS or visible != original:
                raise ValueError("Selected application has an unclassified filesystem or external bind mount alias")
            relevant[mount["mount_id"]] = mount
            if original == root:
                visible_roots.add(str(root))
    for root in visible_roots:
        for mount in mounts:
            point = Path(mount["mountpoint"])
            if point.is_relative_to(root):
                if str(point) != root or mount["mount_id"] not in owned or not mount["read_only"]:
                    raise ValueError("Selected application contains an unowned or non-read-only nested mount")
                relevant[mount["mount_id"]] = mount
    if owned - set(relevant) or any(
        mount["mount_id"] in owned and (mount["mountpoint"] not in visible_roots or not mount["read_only"])
        for mount in relevant.values()
    ):
        raise ValueError("An owned read-only selected mount receipt no longer matches")
    return sorted(visible_roots), sorted(relevant.values(), key=lambda item: item["mount_id"])


def qualify_mounts(
    home: Path,
    selected: tuple[str, ...],
    *,
    owned_mounts: dict[str, list[int]] | None = None,
    proc: Path = Path("/proc"),
) -> MountQualification:
    """Read-only preflight/verification of all process-visible source mount namespaces.

    Returned PID/start-time/namespace witnesses must be revalidated before entering a
    namespace. Only exact locally recorded, read-only self-bind IDs may be supplied
    during verification; this function never creates, remounts or removes a mount.
    This is topology qualification: final fencing must separately require an owned
    read-only mount for every returned namespace/root, including newly visible ones.
    Unreadable or unsupported namespaces/filesystems require operator preparation.
    """
    roots = _roots(home, selected)
    owned_mounts = owned_mounts or {}
    if any(
        not isinstance(namespace, str)
        or not namespace.isdecimal()
        or not isinstance(identifiers, list)
        or any(type(identifier) is not int or identifier <= 0 for identifier in identifiers)
        or len(identifiers) != len(set(identifiers))
        for namespace, identifiers in owned_mounts.items()
    ):
        raise ValueError("Owned mount receipts are malformed")
    try:
        current_namespace = _mount_witness(proc / "self")[0]
        inventories = _mount_namespaces(proc)
        current = next((item[3] for item in inventories if item[1] == current_namespace), None)
        if current is None:
            raise ValueError("The current mount namespace is missing from inspection")
        sources = [(root, *_mount_source(root, current)) for root in roots]
        result: MountQualification = {"namespaces": [], "mounts": []}
        seen = set()
        for process, namespace, started, mounts in inventories:
            visible, relevant = _qualify_namespace_mounts(
                process, mounts, sources, set(owned_mounts.get(namespace, []))
            )
            if (namespace, started) != _mount_witness(process):
                raise ValueError("Mount namespace witness changed during qualification")
            if mounts != _mount_table(process, namespace):
                raise ValueError("Mount topology changed during qualification")
            seen.add(namespace)
            if visible:
                result["namespaces"].append(
                    {"pid": int(process.name), "start_time": started, "mount_namespace": namespace, "roots": visible}
                )
                result["mounts"].extend(relevant)
        if set(owned_mounts) - seen or not result["namespaces"]:
            raise ValueError("Owned or selected mount namespaces are missing")
        return result
    except (OSError, UnicodeError) as error:
        raise ValueError("Native mount namespaces are unreadable; prepare the source before migration") from error


def _selected_handle(path: Path, inodes: set[tuple[int, int]]) -> os.stat_result | None:
    try:
        info = path.stat()
    except FileNotFoundError:
        return None  # A descriptor may close between enumeration and stat.
    return info if (info.st_dev, info.st_ino) in inodes else None


def _has_open_writer(process: Path, inodes: set[tuple[int, int]]) -> bool:
    writer = any(_selected_handle(process / kind, inodes) is not None for kind in ("cwd", "root"))
    with os.scandir(process / "fd") as descriptors:
        for count, descriptor in enumerate(descriptors, 1):
            if count > MAX_PROCESS_DESCRIPTORS:
                raise ValueError("Process descriptor evidence exceeds its qualification limit")
            info = _selected_handle(Path(descriptor.path), inodes)
            if info is None:
                continue
            flags = re.search(r"^flags:\s+([0-7]+)$", _read_process(process / "fdinfo" / descriptor.name), re.MULTILINE)
            if flags is None:
                raise ValueError("Selected descriptor writer access is unrecognized")
            if stat.S_ISDIR(info.st_mode) or int(flags[1], 8) & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}:
                writer = True
    identities = {(os.major(device), os.minor(device), inode) for device, inode in inodes}
    for line in _read_process(process / "maps").splitlines():
        fields = line.split(None, 5)
        if len(fields) < MAP_FIELD_COUNT:
            raise ValueError("Process writer mapping is unrecognized")
        if len(fields[1]) != MAP_PERMISSION_LENGTH or fields[1][1] != "w" or fields[1][3] != "s":
            continue
        device = fields[3].split(":")
        if len(device) != DEVICE_FIELD_COUNT:
            raise ValueError("Process writer mapping device is unrecognized")
        identity = (int(device[0], 16), int(device[1], 16), int(fields[4]))
        writer = writer or identity in identities
    return writer


def _native_php_parent(process: Path, status: str) -> bool:
    """Process titles are mutable; require the protected native binary and its privileged FPM parent."""
    parent_id = re.search(r"^PPid:\s+([0-9]+)$", status, re.MULTILINE)
    if parent_id is None:
        return False
    parent = process.parent / parent_id[1]
    try:
        binary = Path(os.readlink(process / "exe"))
        version = re.fullmatch(r"php-fpm([0-9]+\.[0-9]+)", binary.name)
        child_binary, parent_binary = (process / "exe").stat(), (parent / "exe").stat()
        master = re.fullmatch(
            r"php-fpm: master process \((/[^\r\n\x00]+)\)", _read_process(parent / "cmdline").rstrip("\0 ")
        )
        if master is None or ".." in Path(master[1]).parts:
            return False
        configuration = (parent / "root" / Path(master[1]).relative_to("/")).stat()
        parent_status = _read_process(parent / "status")
        identities = re.search(r"^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$", parent_status, re.MULTILINE)
        return (
            version is not None
            and stat.S_ISREG(child_binary.st_mode)
            and child_binary.st_uid == os.geteuid()
            and not child_binary.st_mode & 0o022
            and (child_binary.st_dev, child_binary.st_ino) == (parent_binary.st_dev, parent_binary.st_ino)
            and identities is not None
            and all(int(identities[index]) == os.geteuid() for index in range(1, 5))
            and stat.S_ISREG(configuration.st_mode)
            and configuration.st_uid == os.geteuid()
            and not configuration.st_mode & 0o022
        )
    except OSError:
        return False  # Missing/unreadable ancestry is unclassified; it never authorizes a signal.


def _writer_identity(process: Path, domain_id: str, owner_uid: int) -> PathWriter:
    status = _read_process(process / "status")
    uid = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", status, re.MULTILINE)
    namespace = re.fullmatch(r"mnt:\[(\d+)\]", os.readlink(process / "ns/mnt"))
    stat_line = _read_process(process / "stat").rpartition(")")
    fields = stat_line[2].split()
    if (
        uid is None
        or namespace is None
        or not stat_line[1]
        or len(fields) <= STAT_START_TIME_INDEX
        or not fields[STAT_START_TIME_INDEX].isdigit()
    ):
        raise ValueError("Selected writer identity is incomplete")
    command = _read_process(process / "cmdline").rstrip("\0 ")
    known_pool = (
        command == "php-fpm: pool " + domain_id
        and all(int(uid[index]) == owner_uid for index in range(1, 5))
        and _native_php_parent(process, status)
    )
    return {
        "pid": int(process.name),
        "start_time": fields[STAT_START_TIME_INDEX],
        "mount_namespace": namespace[1],
        "kind": "php_fpm_pool" if known_pool else "unknown",
        "identity": domain_id if known_pool else "unknown",
        "uid": int(uid[4]),
    }


def path_writers(
    inodes: set[tuple[int, int]], domain_id: str, owner_uid: int, *, proc: Path = Path("/proc")
) -> list[PathWriter]:
    """No signals: classify old writable handles before authorizing any source mutation.

    A read-only directory descriptor or cwd can traverse the old mount. Shared writable
    mappings can change files without a descriptor. Unclassified holders require preparation;
    command lines and credentials never leave this helper.
    """
    if not re.fullmatch(r"[0-9]{1,30}", domain_id) or type(owner_uid) is not int or owner_uid <= 0:
        raise ValueError("A native domain and non-root owner are required for writer qualification")
    writers: list[PathWriter] = []
    with os.scandir(proc) as processes:
        for count, entry in enumerate(processes, 1):
            if count > MAX_PROCESSES:
                raise ValueError("Process writer inventory exceeds its qualification limit")
            if not entry.name.isdecimal():
                continue
            process = Path(entry.path)
            try:
                if _has_open_writer(process, inodes):
                    writers.append(_writer_identity(process, domain_id, owner_uid))
            except FileNotFoundError:
                if process.exists():
                    raise ValueError("A live process writer could not be qualified") from None
            except (PermissionError, UnicodeError) as error:
                raise ValueError(
                    "Process writer evidence is unreadable; prepare the source before migration"
                ) from error
    return sorted(writers, key=lambda item: item["pid"])
