#!/usr/bin/env python3
"""Root-only ext4 quota adapter. Never enables quotas or changes filesystem format."""

from __future__ import annotations

import ctypes
import json
import os
import pwd
import re
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

LIMIT = 65536
IDENTITY_FIELDS = frozenset({"installation", "domain_id", "domain", "uid", "gid", "filesystem_uuid", "boot_id"})
CAP_SYS_RESOURCE = 24
KERNEL_QUOTA_REQUIRED_FIELDS = 15  # QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES
DATABASE_PROBE_COLUMNS = 2
MAX_DATABASE_TABLES = 1000
DOMAIN_ROOT = Path("/etc/webmin/virtual-server/domains")


def _read(path: Path) -> str:
    if path.resolve() != path:
        raise ValueError("Native quota metadata cannot traverse symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Native quota metadata must be root-owned and protected")
        result = stream.read(LIMIT + 1)
    if len(result.encode()) > LIMIT or "\0" in result:
        raise ValueError("Native quota metadata exceeds its qualification bound")
    return result


def _fields(path: Path) -> dict[str, str]:
    result = {}
    for line in _read(path).splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise ValueError("Native quota metadata is malformed or duplicated")
        result[key] = value
    return result


def _run(arguments: list[str], *, timeout: int = 20, lock_fd: int | None = None, payload: str | None = None) -> str:
    # All executables/options are fixed here; tenant metadata is passed as argv,
    # never shell text. Diagnostics remain on the node and never enter a receipt.
    result = subprocess.run(  # noqa: S603 -- Fixed executables and validated identities, no shell.
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        input=payload,
        pass_fds=() if lock_fd is None else (lock_fd,),
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode or len(result.stdout.encode()) > LIMIT:
        raise ValueError("The native quota operation did not complete")
    return result.stdout.strip()


def _integer(value: str | None) -> int:
    if value is None or re.fullmatch(r"[0-9]{1,19}", value) is None:
        raise ValueError("A native quota quantity is unknown or invalid")
    result = int(value)
    if result > (1 << 63) - 1:
        raise ValueError("A native quota quantity exceeds its bound")
    return result


class _Quota(ctypes.Structure):
    _fields_ = [
        ("hard", ctypes.c_uint64),
        ("soft", ctypes.c_uint64),
        ("space", ctypes.c_uint64),
        ("inode_hard", ctypes.c_uint64),
        ("inode_soft", ctypes.c_uint64),
        ("inodes", ctypes.c_uint64),
        ("block_time", ctypes.c_uint64),
        ("inode_time", ctypes.c_uint64),
        ("valid", ctypes.c_uint32),
    ]


def _kernel_quota(device: str, identity: int, *, group: bool) -> _Quota:
    # Linux's generic if_dqblk ABI uses KiB limits and byte-valued curspace.
    library = ctypes.CDLL("libc.so.6", use_errno=True)
    call = library.quotactl
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    call.restype = ctypes.c_int
    result = _Quota()
    command = (0x800007 << 8) | int(group)  # QCMD(Q_GETQUOTA, USRQUOTA/GRPQUOTA)
    if (
        call(command, device.encode(), identity, ctypes.byref(result)) != 0
        or result.valid & KERNEL_QUOTA_REQUIRED_FIELDS != KERNEL_QUOTA_REQUIRED_FIELDS
    ):
        raise ValueError("The kernel quota accounting and limits could not be read")
    return result


def _set_kernel_quota(device: str, identity: int, limit_kib: int, *, group: bool) -> None:
    """Synchronous syscall in the lock-owning process; no delayed setquota child exists."""
    library = ctypes.CDLL("libc.so.6", use_errno=True)
    call = library.quotactl
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    call.restype = ctypes.c_int
    value = _Quota(hard=limit_kib, soft=limit_kib, inode_hard=0, inode_soft=0, valid=5)
    command = (0x800008 << 8) | int(group)  # QCMD(Q_SETQUOTA, USRQUOTA/GRPQUOTA)
    if call(command, device.encode(), identity, ctypes.byref(value)) != 0:
        raise ValueError("The kernel quota update did not complete")


def _database_writer_qualified() -> None:
    pid = _integer(_run(["/usr/bin/systemctl", "show", "mariadb", "--property=MainPID", "--value"]))
    if pid <= 1:
        raise ValueError("The local database writer is not running")
    # Procfs status belongs to the running non-root writer, rather than root-owned
    # configuration. Its PID is obtained only from the fixed mariadb unit.
    descriptor = os.open(Path("/proc") / str(pid) / "status", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        status = stream.read(LIMIT + 1)
    if len(status.encode()) > LIMIT:
        raise ValueError("The database writer status exceeds its bound")
    capabilities = re.findall(r"^CapEff:\s*([0-9a-fA-F]+)$", status, re.MULTILINE)
    identities = re.findall(r"^Uid:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", status, re.MULTILINE)
    bounding = _run(["/usr/bin/systemctl", "show", "mariadb", "--property=CapabilityBoundingSet", "--value"])
    if (
        len(capabilities) != 1
        or int(capabilities[0], 16) & (1 << CAP_SYS_RESOURCE)
        or len(identities) != 1
        or any(int(value) == 0 for value in identities[0])
        or "cap_sys_resource" in bounding.lower().split()
    ):
        raise ValueError("The database writer may bypass quota enforcement")


def qualify_table_storage(directory: Path, rows: list[dict[str, object]], *, gid: int, device: int) -> None:
    """Check existing tables, not merely the setting used for future CREATE TABLE."""
    if len(rows) > MAX_DATABASE_TABLES:
        raise ValueError("The tenant database exceeds its qualification budget")
    seen = set()
    for row in rows:
        name = row.get("table")
        space = row.get("space")
        path = row.get("path")
        if (
            set(row) != {"table", "engine", "space", "space_type", "space_name", "path"}
            or not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) is None
            or name in seen
            or row["engine"] != "InnoDB"
            or type(space) is not int
            or space <= 0
            or row["space_type"] != "Single"
            or row["space_name"] != directory.name + "/" + name
            or not isinstance(path, str)
            or ".." in Path(path).parts
        ):
            raise ValueError("Qualify existing tenant tables in isolated per-table tablespaces")
        seen.add(name)
        candidate = Path(path) if Path(path).is_absolute() else directory.parent / path
        expected = directory / (name + ".ibd")
        if candidate != expected or candidate.resolve() != expected:
            raise ValueError("A tenant table uses external or redirected database storage")
        try:
            info = candidate.lstat()
        except OSError as error:
            raise ValueError("A tenant table's physical datafile is unavailable") from error
        if not stat.S_ISREG(info.st_mode) or info.st_gid != gid or info.st_dev != device:
            raise ValueError("A tenant table's physical datafile is outside the group quota")


def _table_inventory(schema: str) -> list[dict[str, object]]:
    if re.fullmatch(r"[A-Za-z0-9_]{1,64}", schema) is None:
        raise ValueError("The tenant database name is unsupported")
    # MariaDB 10.6+ exposes the physical FILENAME in INNODB_SYS_TABLESPACES;
    # INNODB_SYS_DATAFILES was removed. SPACE_TYPE belongs to SYS_TABLES, not
    # SYS_TABLESPACES, on the managed MariaDB 11.8 version. LEFT joins retain tables
    # in system/shared/unknown spaces, which qualification must refuse.
    query = (
        "SELECT JSON_OBJECT('table',t.TABLE_NAME,'engine',t.ENGINE,'space',s.SPACE,"  # noqa: S608 -- Schema is a bounded ASCII identifier, never arbitrary SQL.
        "'space_type',s.SPACE_TYPE,'space_name',p.NAME,'path',p.FILENAME) "
        "FROM information_schema.TABLES t "
        "LEFT JOIN information_schema.INNODB_SYS_TABLES s ON s.NAME=CONCAT(t.TABLE_SCHEMA,'/',t.TABLE_NAME) "
        "LEFT JOIN information_schema.INNODB_SYS_TABLESPACES p ON p.SPACE=s.SPACE "
        f"WHERE t.TABLE_SCHEMA='{schema}' AND t.TABLE_TYPE='BASE TABLE' LIMIT {MAX_DATABASE_TABLES + 1}"
    )
    output = _run(
        [
            "/usr/bin/mariadb",
            "--protocol=socket",
            "--batch",
            "--raw",
            "--skip-column-names",
            "--execute",
            query,
        ]
    )
    result = [json.loads(line) for line in output.splitlines()]
    if any(not isinstance(row, dict) for row in result):
        raise ValueError("The tenant database inventory has an invalid shape")
    return result


class NativeQuotaBackend:
    def __init__(self) -> None:
        if os.geteuid() != 0:
            raise ValueError("Native quota qualification requires root")

    def _domain(self, request: dict[str, object]) -> tuple[dict[str, str], pwd.struct_passwd]:
        expected = request["identity"]
        if not isinstance(expected, dict):
            raise ValueError("An exact native quota identity is required")
        identifier = expected.get("domain_id")
        if not isinstance(identifier, str) or re.fullmatch(r"[0-9]{1,30}", identifier) is None:
            raise ValueError("An exact native domain ID is required")
        domain = _fields(DOMAIN_ROOT / identifier)
        owner = domain.get("user", "")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", owner) is None:
            raise ValueError("A qualified native Unix owner is required")
        account = pwd.getpwnam(owner)
        if (
            domain.get("id") != identifier
            or domain.get("parent")
            or domain.get("alias")
            or any(domain.get(key) != "1" for key in ("unix", "dir", "web"))
            or domain.get("mail") == "1"
            or min(account.pw_uid, account.pw_gid) <= 0
            or domain.get("home") != "/home/" + owner
            or account.pw_dir != domain.get("home")
            or (str(account.pw_uid), str(account.pw_gid)) != (domain.get("uid"), domain.get("gid"))
        ):
            raise ValueError("Qualify a standalone web-only quota owner before managed limits")
        for path in DOMAIN_ROOT.iterdir():
            if path.name == identifier or re.fullmatch(r"[0-9]{1,30}", path.name) is None:
                continue
            other = _fields(path)
            if not other.get("alias") and (
                other.get("uid") == domain["uid"]
                or other.get("gid") == domain["gid"]
                or other.get("parent") == identifier
            ):
                raise ValueError("One quota-bearing service must own the complete native UID/GID scope")
        return domain, account

    def _storage(self, domain: dict[str, str], account: pwd.struct_passwd) -> tuple[str, str]:
        home = Path(account.pw_dir)
        if home.resolve() != home or home.stat().st_uid != account.pw_uid or home.stat().st_gid != account.pw_gid:
            raise ValueError("The native home filesystem or ownership changed")
        mount = json.loads(
            _run(["/usr/bin/findmnt", "--json", "--target", str(home), "--output", "SOURCE,FSTYPE,UUID,TARGET"])
        )
        filesystems = mount.get("filesystems", [])
        if len(filesystems) != 1:
            raise ValueError("The quota filesystem is ambiguous")
        filesystem = filesystems[0]
        source = filesystem.get("source", "")
        filesystem_uuid = filesystem.get("uuid", "")
        if (
            filesystem.get("fstype") != "ext4"
            or filesystem.get("target") != "/"
            or not re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", source)
            or str(UUID(filesystem_uuid)) != filesystem_uuid
        ):
            raise ValueError("Managed quotas require the qualified root ext4 filesystem")
        configuration = _fields(Path("/etc/webmin/virtual-server/config"))
        if configuration.get("hard_quotas") != "1":
            raise ValueError("Virtualmin must preserve hard quota mode")
        # Inspect the real writer and the unit that will restart it. A group-owned
        # data directory alone is insufficient when mysqld can bypass EDQUOT.
        _database_writer_qualified()
        database = _run(
            [
                "/usr/bin/mariadb",
                "--protocol=socket",
                "--batch",
                "--skip-column-names",
                "--execute",
                "SELECT @@datadir, @@innodb_file_per_table",
            ]
        ).split("\t")
        if len(database) != DATABASE_PROBE_COLUMNS or database[1] != "1":
            raise ValueError("Qualify tenant-local per-table database storage first")
        datadir = Path(database[0].rstrip("/"))
        if datadir.resolve() != datadir or datadir.stat().st_dev != home.stat().st_dev:
            raise ValueError("Home and tenant database data must share the quota filesystem")
        for name in domain.get("db_mysql", "").split():
            if re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) is None:
                raise ValueError("The database storage name is unsupported")
            directory = datadir / name
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or directory.resolve() != directory
                or info.st_dev != home.stat().st_dev
                or info.st_gid != account.pw_gid
                or not info.st_mode & stat.S_ISGID
            ):
                raise ValueError("Database group ownership/setgid is not qualified")
            for path in directory.iterdir():
                item = path.lstat()
                if not stat.S_ISREG(item.st_mode) or item.st_gid != account.pw_gid or item.st_dev != info.st_dev:
                    raise ValueError("Tenant database files are outside the group quota")
            qualify_table_storage(directory, _table_inventory(name), gid=account.pw_gid, device=home.stat().st_dev)
        return source, filesystem_uuid

    def probe(self, request: dict[str, object]) -> dict[str, object]:
        domain, account = self._domain(request)
        device, filesystem_uuid = self._storage(domain, account)
        installation = _read(Path("/var/lib/praho/usage/installation")).strip()
        identity = {
            "installation": installation,
            "domain_id": domain["id"],
            "domain": domain["dom"],
            "uid": account.pw_uid,
            "gid": account.pw_gid,
            "filesystem_uuid": filesystem_uuid,
            "boot_id": _read(Path("/proc/sys/kernel/random/boot_id")).strip(),
        }
        expected = request["identity"]
        if not isinstance(expected, dict) or any(identity.get(key) != value for key, value in expected.items()):
            raise ValueError("The native quota owner, installation or filesystem changed")
        for kind, flag in (("user", "-u"), ("group", "-g")):
            state = _run(["/usr/sbin/quotaon", "-p", flag, "/"])
            if re.fullmatch(kind + r" quota on [^\r\n]+ is on", state) is None:
                raise ValueError("Both kernel user and group quota enforcement must already be on")
        user_quota = _kernel_quota(device, account.pw_uid, group=False)
        group_quota = _kernel_quota(device, account.pw_gid, group=True)
        if any(quota.inode_hard or quota.inode_soft for quota in (user_quota, group_quota)):
            raise ValueError("Inode caps require separate reviewed support")
        space = os.statvfs(account.pw_dir)
        return {
            "schema": 1,
            "identity": identity,
            "observed_at": datetime.now(UTC).isoformat(),
            "filesystem": "ext4",
            "storage_qualified": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "uid_soft_kib": user_quota.soft,
            "uid_hard_kib": user_quota.hard,
            "gid_soft_kib": group_quota.soft,
            "gid_hard_kib": group_quota.hard,
            "uid_used_bytes": user_quota.space,
            "gid_used_bytes": group_quota.space,
            "available_bytes": space.f_bavail * space.f_frsize,
            "configured_quota_kib": _integer(domain.get("quota")),
            "configured_uquota_kib": _integer(domain.get("uquota")),
            "configured_bandwidth_bytes": _integer(domain.get("bw_limit")),
        }

    def apply(self, request: dict[str, object], *, lock_fd: int) -> None:
        identity = request["identity"]
        if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
            raise ValueError("A mutation requires the complete reviewed native identity")
        before = self.probe(request)
        limit = request["disk_limit_kib"]
        bandwidth = request["bandwidth_limit_bytes"]
        if type(limit) is not int or type(bandwidth) is not int or min(limit, bandwidth) < 0:
            raise ValueError("Native limits must be explicit nonnegative integers")
        if limit and max(before["uid_used_bytes"], before["gid_used_bytes"]) > limit * 1024:
            raise ValueError("Current native usage exceeds the requested cap")
        # Only this fixed, synchronous metadata helper may mutate in a child. It
        # inherits the lane FD, rechecks the permanent fence under that lock, and
        # performs no quota CLI/post-action hooks or asynchronous work. A killed
        # coordinator therefore cannot release the lane before this child exits.
        _run(
            ["/usr/bin/perl", str(Path(__file__).with_name("praho-quota-metadata.pl")), str(lock_fd)],
            lock_fd=lock_fd,
            payload=json.dumps(request, sort_keys=True, separators=(",", ":")),
        )
        domain, account = self._domain(request)
        device, _ = self._storage(domain, account)
        _set_kernel_quota(device, account.pw_uid, limit, group=False)
        _set_kernel_quota(device, account.pw_gid, limit, group=True)
