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
import time
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

LIMIT = 65536
IDENTITY_FIELDS = frozenset({"installation", "domain_id", "domain", "uid", "gid", "filesystem_uuid", "boot_id"})
CAP_SYS_RESOURCE = 24
KERNEL_QUOTA_REQUIRED_FIELDS = 15  # QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES
DATABASE_PROBE_COLUMNS = 2
MAX_DATABASE_TABLES = 1000
MAX_NATIVE_DOMAINS = 1000
MAX_DATABASES = 32
MAX_DATABASE_FILES = 4096
PROBE_BUDGET_SECONDS = 60
APPLY_BUDGET_SECONDS = 240
_PROBE_DEADLINE: ContextVar[float | None] = ContextVar("quota_probe_deadline", default=None)
DOMAIN_ROOT = Path("/etc/webmin/virtual-server/domains")


def _overlay_window(request: dict[str, object]) -> bool:
    """Recheck after long probes and before each native mutation phase."""
    policy = request.get("policy")
    if policy is None:
        return False
    if not isinstance(policy, dict) or type(policy.get("expiry_reduction")) is not bool:
        raise ValueError("An exact temporary quota policy is required")
    if type(policy.get("monotonic_reduction")) is not bool or (
        policy["monotonic_reduction"] and not policy["expiry_reduction"]
    ):
        raise ValueError("An exact native expiry decrease policy is required")
    expiry = datetime.fromisoformat(policy["expires_at"])
    if expiry.tzinfo is None:
        raise ValueError("An exact temporary quota expiry is required")
    expired = expiry <= datetime.now(UTC)
    if policy.get("extra_mib") and expired:
        raise ValueError("The temporary quota overlay expired before native mutation")
    if policy["expiry_reduction"] and (policy.get("extra_mib") != 0 or not expired):
        raise ValueError("A preauthorized quota expiry requires an expired zero-extra overlay")
    return policy["expiry_reduction"]


def _no_cap_increase(limit: int, user_hard: object, group_hard: object) -> None:
    if limit <= 0 or any(type(value) is not int or value < limit for value in (user_hard, group_hard)):
        raise ValueError("Expiry cannot increase either independently observed native hard cap")


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


def _run(
    arguments: list[str],
    *,
    timeout: int = 20,
    lock_fd: int | None = None,
    payload: str | None = None,
    returncodes: frozenset[int] = frozenset({0}),
) -> str:
    # All executables/options are fixed here; tenant metadata is passed as argv,
    # never shell text. Diagnostics remain on the node and never enter a receipt.
    deadline = _PROBE_DEADLINE.get()
    remaining = timeout if deadline is None else min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("The bounded native quota probe budget expired")
    result = subprocess.run(  # noqa: S603 -- Fixed executables and validated identities, no shell.
        arguments,
        capture_output=True,
        text=True,
        timeout=remaining,
        check=False,
        input=payload,
        pass_fds=() if lock_fd is None else (lock_fd,),
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode not in returncodes or len(result.stdout.encode()) > LIMIT:
        raise ValueError("The native quota operation did not complete")
    return result.stdout.strip()


def _quota_class_on(kind: str, flag: str) -> bool:
    """Whether one kernel quota class is on for /. quotaon -p exits 1 when it is on (quota-tools 4.09), so the
    printed state decides; any other non-zero exit is still a failed operation."""
    state = _run(["/usr/sbin/quotaon", "-p", flag, "/"], returncodes=frozenset({0, 1}))
    return re.fullmatch(kind + r" quota on [^\r\n]+ is on", state) is not None


def _integer(value: str | None) -> int:
    if value is None or re.fullmatch(r"[0-9]{1,19}", value) is None:
        raise ValueError("A native quota quantity is unknown or invalid")
    result = int(value)
    if result > (1 << 63) - 1:
        raise ValueError("A native quota quantity exceeds its bound")
    return result


def _configured_bandwidth(domain: dict[str, str]) -> int:
    # Virtualmin8.3 virtual-server-lib-funcs.pl:8139 treats both absent/empty
    # bw_limit and literal0 as unlimited. This is a root-owned LOCAL domain file,
    # never missing transport fields; malformed/nonempty values still refuse.
    return _configured_limit(domain, "bw_limit")


def _configured_limit(domain: dict[str, str], field: str) -> int:
    # The same pinned native aggregate uses empty/absent quota and uquota as
    # unlimited at8133; these are local config values, not missing RPC evidence.
    if field not in {"quota", "uquota", "bw_limit"}:
        raise ValueError("Unsupported native quota metadata field")
    return _integer(domain.get(field) or "0")


def _bandwidth_actions_safe(domain: dict[str, str], config: dict[str, str]) -> bool:
    # Pinned8.3 bw.pl uses Perl truth: only absent/empty/literal0 are off.
    # Require our exact repaired per-domain value, independently of mail ownership.
    return domain.get("bw_no_disable") == "1" and all(
        config.get(key, "") in {"", "0"} for key in ("bw_disable", "bw_enable")
    )


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


class DatabaseStorageRefusalError(ValueError):
    """A database still charged to its account. Carries only validated names, so staff can be told which one."""


def _database_writer_qualified() -> tuple[int, int]:
    """Return the running server's effective UID and GID, which must own every tenant database file.

    Database files are outside the kernel quota (ADR-0075), so CAP_SYS_RESOURCE no longer matters to enforcement.
    It stays refused as least privilege: a shared server has no reason to override resource limits.
    """
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
    groups = re.findall(r"^Gid:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", status, re.MULTILINE)
    bounding = _run(["/usr/bin/systemctl", "show", "mariadb", "--property=CapabilityBoundingSet", "--value"])
    if (
        len(capabilities) != 1
        or int(capabilities[0], 16) & (1 << CAP_SYS_RESOURCE)
        or len(identities) != 1
        or len(groups) != 1
        or any(int(value) == 0 for value in (*identities[0], *groups[0]))
        or "cap_sys_resource" in bounding.lower().split()
    ):
        raise ValueError("The database writer exceeds its least privilege: it is root or may override resource limits")
    return int(identities[0][1]), int(groups[0][1])


def _database_policy_qualified() -> None:
    """A template that still enables mysql_chgrp would recharge the next database to its account's group."""
    adapter = str(Path(__file__).with_name("praho-notification-policy.pl"))
    answer = json.loads(_run(["/usr/bin/perl", adapter, "database_policy"]))
    overrides = answer.get("overrides") if isinstance(answer, dict) else None
    if not isinstance(overrides, list) or any(type(item) is not int for item in overrides):
        raise ValueError("The effective Virtualmin database policy could not be read")
    if overrides:
        listed = ", ".join(str(item) for item in overrides[:32])
        raise DatabaseStorageRefusalError(f"Virtualmin templates would charge databases to their account: {listed}")


def _entry_label(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]", "?", name)[:96]


def qualify_database_directory(
    directory: Path, *, writer: tuple[int, int], tenant: tuple[int, int], device: int
) -> None:
    """A tenant UID or GID on a database file would put it back under the kernel cap that can abort MariaDB."""
    name = directory.name
    if writer[0] == tenant[0] or writer[1] == tenant[1]:
        raise DatabaseStorageRefusalError(f"Database {name}: the account shares MariaDB's identity")
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or directory.resolve() != directory
        or info.st_dev != device
        or (info.st_uid, info.st_gid) != writer
        or info.st_mode & (stat.S_ISGID | stat.S_IWOTH)
    ):
        raise DatabaseStorageRefusalError(f"Database {name}: its directory is not MariaDB-owned without setgid")
    for number, path in enumerate(directory.iterdir()):
        deadline = _PROBE_DEADLINE.get()
        if number >= MAX_DATABASE_FILES or (deadline is not None and time.monotonic() >= deadline):
            raise ValueError("The native database files exceed the bounded qualification budget")
        item = path.lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or (item.st_uid, item.st_gid) != writer
            or item.st_dev != info.st_dev
            or item.st_mode & stat.S_IWOTH
        ):
            raise DatabaseStorageRefusalError(f"Database {name}: {_entry_label(path.name)} is not a MariaDB-owned file")


def repair_database_directory(
    directory: Path, *, writer: tuple[int, int], tenant: tuple[int, int], device: int
) -> None:
    """Move one quiesced database to MariaDB. Refuses before changing anything unless every entry is expected."""
    name = directory.name
    if writer[0] == tenant[0] or writer[1] == tenant[1]:
        raise DatabaseStorageRefusalError(f"Database {name}: the account shares MariaDB's identity")
    uids, gids = {writer[0], tenant[0]}, {writer[1], tenant[1]}
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or directory.resolve() != directory
        or info.st_dev != device
        or info.st_uid not in uids
        or info.st_gid not in gids
        or info.st_mode & stat.S_IWOTH
    ):
        raise DatabaseStorageRefusalError(f"Database {name}: its directory has an unexpected owner or layout")
    entries = []
    for number, path in enumerate(directory.iterdir()):
        if number >= MAX_DATABASE_FILES:
            raise ValueError("The native database files exceed the bounded qualification budget")
        item = path.lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid not in uids
            or item.st_gid not in gids
            or item.st_dev != device
            or item.st_mode & stat.S_IWOTH
        ):
            raise DatabaseStorageRefusalError(
                f"Database {name}: {_entry_label(path.name)} has an unexpected owner or type"
            )
        entries.append(path)
    # Clear setgid first so no new file can inherit the account's group while the rest is changed.
    os.chmod(directory, stat.S_IMODE(info.st_mode) & ~stat.S_ISGID)
    for path in entries:
        os.chown(path, *writer, follow_symlinks=False)
    os.chown(directory, *writer, follow_symlinks=False)


def qualify_table_layout(directory: Path, rows: list[dict[str, object]]) -> list[tuple[str, Path]]:
    """Check existing tables, not merely the setting used for future CREATE TABLE."""
    if len(rows) > MAX_DATABASE_TABLES:
        raise ValueError("The tenant database exceeds its qualification budget")
    seen = set()
    tables = []
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
        tables.append((name, candidate))
    return tables


def qualify_table_storage(directory: Path, rows: list[dict[str, object]], *, uid: int, gid: int, device: int) -> None:
    for name, candidate in qualify_table_layout(directory, rows):
        try:
            info = candidate.lstat()
        except OSError as error:
            raise ValueError("A tenant table's physical datafile is unavailable") from error
        if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid) or info.st_dev != device:
            raise DatabaseStorageRefusalError(f"Database {directory.name}: {name}.ibd is not a MariaDB-owned file")


def repairable_database_layout(directory: Path) -> None:
    """Refuse what an ownership repair can't fix, before the repair stops anyone's writes."""
    try:
        qualify_table_layout(directory, _table_inventory(directory.name))
    except ValueError as error:
        raise DatabaseStorageRefusalError(f"Database {directory.name}: {error}") from error


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
        self._database_policy_verified = False

    def require_database_policy(self) -> None:
        # Once per backend: an inspection probes every domain, and the adapter loads all of Virtualmin.
        if not self._database_policy_verified:
            _database_policy_qualified()
            self._database_policy_verified = True

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
        for number, path in enumerate(DOMAIN_ROOT.iterdir()):
            if number >= MAX_NATIVE_DOMAINS or (
                _PROBE_DEADLINE.get() is not None and time.monotonic() >= _PROBE_DEADLINE.get()
            ):
                raise ValueError("The native domain inventory exceeds the bounded qualification budget")
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

    def _storage(
        self,
        domain: dict[str, str],
        account: pwd.struct_passwd,
    ) -> tuple[str, str]:
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
        self.require_database_policy()
        # The real writer's identity, not an assumed account name, must own every database file below.
        writer = _database_writer_qualified()
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
        names = domain.get("db_mysql", "").split()
        if len(names) > MAX_DATABASES:
            raise ValueError("The native database inventory exceeds the bounded qualification budget")
        for name in names:
            if re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) is None:
                raise ValueError("The database storage name is unsupported")
            directory = datadir / name
            device_id = home.stat().st_dev
            qualify_database_directory(
                directory, writer=writer, tenant=(account.pw_uid, account.pw_gid), device=device_id
            )
            qualify_table_storage(directory, _table_inventory(name), uid=writer[0], gid=writer[1], device=device_id)
        self._qualified_databases = tuple(datadir / name for name in names)
        return source, filesystem_uuid

    def probe(self, request: dict[str, object]) -> dict[str, object]:
        deadline = time.monotonic() + PROBE_BUDGET_SECONDS
        outer = _PROBE_DEADLINE.get()
        token = _PROBE_DEADLINE.set(deadline if outer is None else min(outer, deadline))
        try:
            return self._probe(request)
        finally:
            _PROBE_DEADLINE.reset(token)

    def _probe(self, request: dict[str, object]) -> dict[str, object]:
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
            if not _quota_class_on(kind, flag):
                raise ValueError("Both kernel user and group quota enforcement must already be on")
        user_quota = _kernel_quota(device, account.pw_uid, group=False)
        group_quota = _kernel_quota(device, account.pw_gid, group=True)
        if any(quota.inode_hard or quota.inode_soft for quota in (user_quota, group_quota)):
            raise ValueError("Inode caps require separate reviewed support")
        space = os.statvfs(account.pw_dir)
        # Reuse ADR0068's canonical allocated-home + tenant-local DB measurement,
        # independently of the kernel's UID/GID accounting used for safety.
        from praho_usage import allocated_bytes, disk_measurement  # noqa: PLC0415 -- Root-owned installed sibling.

        deadline = _PROBE_DEADLINE.get()
        databases = []
        for directory in self._qualified_databases:
            budget = 20 if deadline is None else min(20, deadline - time.monotonic())
            databases.append((directory, allocated_bytes(directory, budget_seconds=budget)))
        budget = 20 if deadline is None else min(20, deadline - time.monotonic())
        observation = disk_measurement(Path(account.pw_dir), databases, budget_seconds=budget)
        return {
            "schema": 1,
            "quota_protocol": 2,
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
            "configured_quota_kib": _configured_limit(domain, "quota"),
            "configured_uquota_kib": _configured_limit(domain, "uquota"),
            "configured_bandwidth_bytes": _configured_bandwidth(domain),
            "bandwidth_actions_safe": _bandwidth_actions_safe(
                domain, _fields(Path("/etc/webmin/virtual-server/config"))
            ),
            "observation": {
                "files_bytes": observation["disk_files_bytes"],
                "database_bytes": observation["disk_db_bytes"],
                "total_bytes": observation["disk_total_bytes"],
            },
        }

    def apply(self, request: dict[str, object], *, lock_fd: int) -> None:
        token = _PROBE_DEADLINE.set(time.monotonic() + APPLY_BUDGET_SECONDS)
        try:
            self._apply(request, lock_fd=lock_fd)
        finally:
            _PROBE_DEADLINE.reset(token)

    def _apply(self, request: dict[str, object], *, lock_fd: int) -> None:
        identity = request["identity"]
        if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
            raise ValueError("A mutation requires the complete reviewed native identity")
        before = self.probe(request)
        limit = request["disk_limit_kib"]
        bandwidth = request["bandwidth_limit_bytes"]
        if type(limit) is not int or type(bandwidth) is not int or min(limit, bandwidth) < 0:
            raise ValueError("Native limits must be explicit nonnegative integers")
        expiry_reduction = _overlay_window(request)
        policy = request.get("policy")
        monotonic_reduction = isinstance(policy, dict) and policy["monotonic_reduction"] is True
        if monotonic_reduction:
            _no_cap_increase(limit, before.get("uid_hard_kib"), before.get("gid_hard_kib"))
        if (
            limit
            and not expiry_reduction
            and max(before["uid_used_bytes"], before["gid_used_bytes"], before["observation"]["files_bytes"])
            > limit * 1024
        ):
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
        device, filesystem_uuid = self._storage(domain, account)
        if (
            domain.get("id") != identity["domain_id"]
            or domain.get("dom") != identity["domain"]
            or account.pw_uid != identity["uid"]
            or account.pw_gid != identity["gid"]
            or filesystem_uuid != identity["filesystem_uuid"]
        ):
            raise ValueError("The native quota owner or filesystem changed before the kernel update")
        _overlay_window(request)
        if monotonic_reduction:
            _no_cap_increase(
                limit,
                _kernel_quota(device, identity["uid"], group=False).hard,
                _kernel_quota(device, identity["gid"], group=True).hard,
            )
        # Always target the immutable reviewed numeric owner, never a newly
        # retargeted UID/GID obtained from a later local metadata read.
        _set_kernel_quota(device, identity["uid"], limit, group=False)
        _set_kernel_quota(device, identity["gid"], limit, group=True)
