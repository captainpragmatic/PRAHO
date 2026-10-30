#!/usr/bin/python3
"""Private node usage primitives. Python 3.10+, standard library only.

Log records contain no request identifiers or customer-supplied host names:
``v1 <installation> <domain-id> <completion-epoch-us> <body-bytes>``.
Offsets and observations commit together. A failed transaction can be replayed.
This module deliberately has no Django dependency.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

RECORD = re.compile(rb"v1 ([A-Za-z0-9-]{1,64}) ([0-9]{1,30}) ([0-9]{1,20}) ([0-9]{1,20})\n")
MAX_INTEGER = (1 << 63) - 1
MAX_REPLAY_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 256
MONTHS_PER_YEAR = 12
STATE_ROOT = Path("/var/lib/praho/usage")
LOG_ROOT = Path("/var/log/praho")
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_INTERVALS = 2000
MAX_TELEMETRY_BYTES = 1024 * 1024 * 1024
MAX_DATABASE_BYTES = MAX_TELEMETRY_BYTES // 2
MAX_QUERY_ROWS = 500_000
MAX_INGEST_RECORDS = 10_000
PRUNE_BATCH = 10_000
COLLECTION_SECONDS = 210
# The end of each collection belongs to retention and traffic ingestion. Disk scans stop this
# early and resume from their cursor next time, so large homes can never starve traffic.
TRAFFIC_RESERVE_SECONDS = 60
# Within that reserve, age pruning stops this early, so ingestion itself always gets time.
INGEST_RESERVE_SECONDS = 40
HOME_SCAN_SECONDS = 20
RETENTION_SECONDS = 90 * 86400


def operator_month(instant: datetime, zone: str) -> tuple[datetime, datetime]:
    """UTC endpoints of the operator's calendar month, including offset changes."""
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("Usage instants must be timezone aware")
    local = instant.astimezone(ZoneInfo(zone))
    start = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == MONTHS_PER_YEAR
        else start.replace(month=start.month + 1)
    )
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def allocated_bytes(root: Path, *, budget_seconds: float = 20, max_entries: int = 1_000_000) -> int:
    """Physical, same-device walk using directory descriptors and O_NOFOLLOW.

    Disappearing/unreadable entries are an incomplete measurement, not zero.
    Directory replacement cannot redirect a privileged walk outside the home.
    """
    deadline = time.monotonic() + budget_seconds
    seen: set[tuple[int, int]] = set()
    count = 0
    total = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    first = os.open(root, flags)
    device = os.fstat(first).st_dev

    def walk(descriptor: int) -> None:
        nonlocal count, total
        info = os.fstat(descriptor)
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            return
        seen.add(identity)
        total += info.st_blocks * 512
        with os.scandir(descriptor) as entries:
            for entry in entries:
                count += 1
                if count > max_entries or time.monotonic() > deadline:
                    raise TimeoutError("Filesystem measurement budget exceeded")
                metadata = entry.stat(follow_symlinks=False)
                identity = (metadata.st_dev, metadata.st_ino)
                if metadata.st_dev != device or identity in seen:
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(entry.name, flags, dir_fd=descriptor)
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != identity:
                            raise OSError("Directory changed during measurement")
                        walk(child)
                    finally:
                        os.close(child)
                else:
                    seen.add(identity)
                    total += metadata.st_blocks * 512

    try:
        walk(first)
    finally:
        os.close(first)
    return total


def disk_measurement(home: Path, databases: list[tuple[Path, int]], *, budget_seconds: float = 20) -> dict[str, int]:
    """Add physically separate database allocations once, never quota totals.

    Database locations must come from the trusted Virtualmin adapter. This is
    deliberately not an API for measuring customer-supplied filesystem paths.
    """
    canonical_home = home.resolve(strict=True)
    unique: dict[Path, int] = {}
    for path, size in databases:
        if type(size) is not int or not 0 <= size <= MAX_INTEGER:
            raise ValueError("Database allocation must be a nonnegative integer")
        canonical = path.resolve(strict=True)
        if (
            canonical == canonical_home
            or canonical.is_relative_to(canonical_home)
            or canonical_home.is_relative_to(canonical)
        ):
            raise ValueError("Database and home storage overlap")
        if canonical in unique and unique[canonical] != size:
            raise ValueError("Conflicting database allocation observations")
        if any(
            canonical.is_relative_to(other) or other.is_relative_to(canonical) for other in unique if other != canonical
        ):
            raise ValueError("Database storage overlaps another database")
        unique[canonical] = size
    files = allocated_bytes(home, budget_seconds=budget_seconds)
    database_bytes = sum(unique.values())
    if files + database_bytes > MAX_INTEGER:
        raise ValueError("Disk allocation exceeds the protocol bound")
    return {
        "disk_files_bytes": files,
        "disk_db_bytes": database_bytes,
        "disk_total_bytes": files + database_bytes,
        "databases": len(unique),
    }


class Ledger:
    """Transactional ingestion with stable inode offsets and explicit coverage loss."""

    def __init__(self, path: Path):
        if path.is_symlink():
            raise ValueError("Usage ledger must not be a symlink")
        self.path = path
        self.connection = sqlite3.connect(path, timeout=5)
        try:
            os.chmod(path, 0o600)
            # Reclaim pruned history without a second database-sized VACUUM file.
            self.connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
            page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
            # SQLite PRAGMA values cannot be bound parameters. Both operands are
            # local integers; no request, path or metadata text enters this SQL.
            # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query, python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
            self.connection.execute(f"PRAGMA max_page_count={max(32, MAX_DATABASE_BYTES // page_size)}")
            self._initialize_schema()
        except (OSError, sqlite3.Error):
            self.connection.close()
            raise

    def _initialize_schema(self) -> None:
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS files ("
            "device INTEGER, inode INTEGER, offset INTEGER NOT NULL, tail BLOB NOT NULL,"
            "PRIMARY KEY(device,inode));"
            "CREATE TABLE IF NOT EXISTS traffic ("
            "installation TEXT NOT NULL, domain TEXT NOT NULL, completed INTEGER NOT NULL, bytes INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS traffic_interval ON traffic(installation,domain,completed);"
            "CREATE INDEX IF NOT EXISTS traffic_age ON traffic(completed);"
            "CREATE TABLE IF NOT EXISTS gaps (reason TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS gauges (domain TEXT PRIMARY KEY, payload TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS inventory (domain TEXT PRIMARY KEY, seen_at INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS inventory_epoch ON inventory(seen_at,domain);"
        )

    def close(self) -> None:
        self.connection.close()

    @property
    def complete(self) -> bool:
        return self.connection.execute("SELECT 1 FROM gaps LIMIT 1").fetchone() is None

    def value(self, key: str) -> str | None:
        row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def store(self, key: str, value: str) -> None:
        self.connection.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, value))

    def lose_coverage(self, reason: str, *, after: str | None = None) -> None:
        """Keep a bounded diagnostic and a recoverable lower bound on exact intervals.

        Call inside the caller's transaction. Losing an old interval must not
        permanently poison every future month on the node.
        """
        if not re.fullmatch(r"[a-z_]{1,48}", reason):
            raise ValueError("Invalid coverage reason")
        self.connection.execute(
            "INSERT INTO gaps SELECT ? WHERE NOT EXISTS (SELECT 1 FROM gaps WHERE reason=?)", (reason, reason)
        )
        boundary = after or (datetime.fromisoformat(utc_now()) + timedelta(microseconds=1)).isoformat()
        self.store("last_loss_reason", reason)
        prior = self.value("coverage_start")
        if prior is None or epoch_us(prior) < epoch_us(boundary):
            self.store("coverage_start", boundary)

    def interval_complete(self, start: int) -> bool:
        boundary = self.value("coverage_start")
        return bool(boundary is not None and start >= epoch_us(boundary) and self.value("caught_up") == "1")

    def _insert_record(self, line: bytes, unbound_members: dict[str, int]) -> None:
        match = RECORD.fullmatch(line)
        if match is None:
            self.lose_coverage("invalid_record")
            return
        installation, domain, completed, size = match.groups()
        timestamp, amount = int(completed), int(size)
        if timestamp > MAX_INTEGER or amount > MAX_INTEGER:
            self.lose_coverage("integer_overflow")
            return
        domain_id = domain.decode("ascii")
        if domain_id in unbound_members and timestamp >= unbound_members[domain_id]:
            self.lose_coverage("unbound_child_identity")
            return
        self.connection.execute(
            "INSERT INTO traffic VALUES (?,?,?,?)", (installation.decode("ascii"), domain_id, timestamp, amount)
        )

    def ingest(self, path: Path, *, budget_seconds: float = 20) -> None:
        """Ingest complete lines only, checking the prior tail to detect rewritten files.

        Callers pass rotated files before the current file. Rename rotation retains
        inode identity, so a second visit never counts the same bytes twice.
        """
        deadline = time.monotonic() + budget_seconds
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source, self.connection:
            # A connection context alone starts a transaction only on the first
            # write. Serialize before reading the cursor, or concurrent collectors
            # can both ingest the same old offset.
            self.connection.execute("BEGIN IMMEDIATE")
            unbound_members = json.loads(self.value("unbound_members") or "{}")
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Usage input must be a regular file")
            identity = (metadata.st_dev, metadata.st_ino)
            previous = self.connection.execute(
                "SELECT offset,tail FROM files WHERE device=? AND inode=?", identity
            ).fetchone()
            offset, tail = previous if previous else (0, b"")
            source.seek(max(0, offset - len(tail)))
            rewritten = metadata.st_size < offset or source.read(len(tail)) != tail
            if rewritten:
                self.lose_coverage("rewritten_input")
                # Do not replay a replacement prefix: old bytes could be counted twice.
                source.seek(metadata.st_size)
            else:
                source.seek(offset)
                consumed = 0
                consumed_records = 0
                while True:
                    start = source.tell()
                    line = source.readline(MAX_RECORD_BYTES)
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        if len(line) == MAX_RECORD_BYTES:
                            raise ValueError("Usage record exceeds protocol bound")
                        source.seek(start)
                        break
                    if consumed and (
                        consumed + len(line) > MAX_REPLAY_BYTES
                        or consumed_records >= MAX_INGEST_RECORDS
                        or time.monotonic() > deadline
                    ):
                        # Commit this bounded prefix. Rolling back on a budget boundary
                        # would replay the same prefix forever on a busy node.
                        source.seek(start)
                        break
                    consumed += len(line)
                    consumed_records += 1
                    self._insert_record(line, unbound_members)
            end = source.tell()
            source.seek(max(0, end - 128))
            tail = source.read(end - source.tell())
            self.connection.execute(
                "INSERT INTO files VALUES (?,?,?,?) ON CONFLICT(device,inode) DO UPDATE SET offset=excluded.offset,tail=excluded.tail",
                (*identity, end, tail),
            )

    def total(self, installation: str, domain: str, start: int, end: int, *, deadline: float | None = None) -> int:
        """Return a half-open interval total; caller separately checks completeness."""
        if not 0 <= start <= end <= MAX_INTEGER:
            raise ValueError("Invalid usage interval")
        # Sum in Python: SQLite's signed SUM can overflow before the protocol bound.
        stop = deadline if deadline is not None else time.monotonic() + 5
        total = 0
        for count, (amount,) in enumerate(
            self.connection.execute(
                "SELECT bytes FROM traffic WHERE installation=? AND domain=? AND completed>=? AND completed<?",
                (installation, domain, start, end),
            ),
            start=1,
        ):
            if count > MAX_QUERY_ROWS or time.monotonic() > stop:
                raise TimeoutError("Usage query budget exceeded")
            total += amount
            if total > MAX_INTEGER:
                raise ValueError("Usage interval exceeds protocol bound")
        return total


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def epoch_us(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("An interval requires UTC-aware timestamps")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = parsed - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def log_files() -> list[Path]:
    """Only files produced by the managed rename/create rotation policy."""
    files = []
    for path in LOG_ROOT.glob("usage.log*"):
        if not re.fullmatch(r"usage\.log(?:\.[0-9]+)?", path.name):
            raise ValueError("Unrecognized private log rotation")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Private logs must be regular files")
        files.append(path)
    return sorted(files, key=lambda path: -int(path.name.rsplit(".", 1)[1]) if path.name != "usage.log" else 1)


def file_identity(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Private logs must be regular files")
    return json.dumps([info.st_dev, info.st_ino])


def ingest_logs(ledger: Ledger, *, deadline: float, retention_deadline: float | None = None) -> bool:
    """Advance bounded prefixes and verify the current file's rotation lineage.

    Age pruning between prefixes stops at `retention_deadline` (default: `deadline`); storage
    pressure is still relieved until `deadline`.
    """
    paths = log_files()
    current = LOG_ROOT / "usage.log"
    caught_up = current in paths
    with ledger.connection:
        if not caught_up:
            ledger.lose_coverage("current_input_missing")
        else:
            actual = file_identity(current)
            previous = ledger.value("current_identity")
            if previous is not None and actual != previous:
                pending = ledger.value("rotation_pending")
                retained = {file_identity(path) for path in paths if path != current}
                if pending != previous or previous not in retained:
                    ledger.lose_coverage("unmanaged_rotation")
                else:
                    # A just-created current file may reuse an old deleted inode.
                    ledger.connection.execute("DELETE FROM files WHERE device=? AND inode=?", json.loads(actual))
            ledger.store("current_identity", actual)
    for path in paths:
        info = path.lstat()
        previous = -1
        file_caught_up = False
        while True:
            if time.monotonic() >= deadline:
                break
            enforce_retention(ledger, deadline=deadline, now=utc_now(), age_deadline=retention_deadline)
            ledger.ingest(path, budget_seconds=min(20, deadline - time.monotonic()))
            row = ledger.connection.execute(
                "SELECT offset FROM files WHERE device=? AND inode=?", (info.st_dev, info.st_ino)
            ).fetchone()
            current_size = path.lstat().st_size
            if row is not None and row[0] >= current_size:
                file_caught_up = True
                break
            if row is None or row[0] <= previous:
                break  # An unfinished line must wait for its writer.
            previous = row[0]
        caught_up = caught_up and file_caught_up
    return caught_up


def telemetry_size(ledger: Ledger) -> int:
    """Count private state and logs, including SQLite's temporary journal."""
    paths = list(ledger.path.parent.iterdir()) + list(LOG_ROOT.glob("usage.log*"))
    return sum(path.lstat().st_size for path in set(paths) if stat.S_ISREG(path.lstat().st_mode))


def discard_current_for_pressure(ledger: Ledger, current: Path) -> None:
    """Explicit loss is safer than letting optional telemetry fill tenant disks.

    Normal rotation never truncates. This emergency path records an outstanding
    loss before truncating the open append-only file; a crash leaves that marker
    for the next refresh to advance the coverage boundary again.
    """
    with ledger.connection:
        ledger.store("pending_pressure_loss", "1")
        ledger.lose_coverage("storage_pressure")
    descriptor = os.open(current, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Private logs must be regular files")
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        with ledger.connection:
            ledger.connection.execute("INSERT OR REPLACE INTO files VALUES (?,?,0,?)", (info.st_dev, info.st_ino, b""))
            ledger.lose_coverage("storage_pressure")
            ledger.connection.execute("DELETE FROM metadata WHERE key='pending_pressure_loss'")
    finally:
        os.close(descriptor)


def prune_rotations(ledger: Ledger, *, cutoff: int, now: str) -> None:
    # Consumed old rotations can go without losing anything retained in SQLite.
    for path in log_files():
        if path.name == "usage.log":
            continue
        info = path.lstat()
        if info.st_mtime * 1_000_000 >= cutoff and telemetry_size(ledger) <= MAX_TELEMETRY_BYTES:
            continue
        offset = ledger.connection.execute(
            "SELECT offset FROM files WHERE device=? AND inode=?", (info.st_dev, info.st_ino)
        ).fetchone()
        with ledger.connection:
            if offset is None or offset[0] < info.st_size:
                ledger.lose_coverage("discarded_unread_rotation", after=now)
            path.unlink()
            ledger.connection.execute("DELETE FROM files WHERE device=? AND inode=?", (info.st_dev, info.st_ino))


def enforce_retention(ledger: Ledger, *, deadline: float, now: str, age_deadline: float | None = None) -> None:
    """Enforce age and combined byte budgets at collection/rotation checkpoints.

    Age pruning stops at `age_deadline` (default: `deadline`); relieving storage pressure, which
    only runs when the private budget is nearly used, keeps the full `deadline`.
    """
    age_stop = deadline if age_deadline is None else age_deadline
    cutoff = epoch_us(now) - RETENTION_SECONDS * 1_000_000
    with ledger.connection:
        if ledger.value("pending_pressure_loss") is not None:
            ledger.lose_coverage("interrupted_pressure_loss", after=now)
            ledger.connection.execute("DELETE FROM metadata WHERE key='pending_pressure_loss'")
        boundary = datetime.fromtimestamp(max(0, cutoff) / 1_000_000, timezone.utc).isoformat()
        prior = ledger.value("coverage_start")
        if prior is not None and epoch_us(prior) < cutoff:
            ledger.store("coverage_start", boundary)
    while time.monotonic() < age_stop:
        with ledger.connection:
            removed = ledger.connection.execute(
                "DELETE FROM traffic WHERE rowid IN (SELECT rowid FROM traffic WHERE completed<? ORDER BY completed LIMIT 10000)",
                (cutoff,),
            ).rowcount
        if removed < PRUNE_BATCH:
            break
    with ledger.connection:
        ledger.connection.execute(
            "DELETE FROM gauges WHERE domain IN (SELECT domain FROM inventory WHERE seen_at<?)", (cutoff,)
        )
        ledger.connection.execute("DELETE FROM inventory WHERE seen_at<?", (cutoff,))
    prune_rotations(ledger, cutoff=cutoff, now=now)
    current = LOG_ROOT / "usage.log"
    if current.exists() and telemetry_size(ledger) > MAX_TELEMETRY_BYTES:
        discard_current_for_pressure(ledger, current)
    while time.monotonic() < deadline:
        pages = ledger.connection.execute("PRAGMA page_count").fetchone()[0]
        free = ledger.connection.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = ledger.connection.execute("PRAGMA page_size").fetchone()[0]
        used = (pages - free) * page_size
        if used < MAX_DATABASE_BYTES * 0.8 and telemetry_size(ledger) <= MAX_TELEMETRY_BYTES:
            break
        with ledger.connection:
            rows = ledger.connection.execute(
                "SELECT rowid,completed FROM traffic ORDER BY completed LIMIT 10000"
            ).fetchall()
            if not rows:
                break
            boundary = datetime.fromtimestamp((rows[-1][1] + 1) / 1_000_000, timezone.utc).isoformat()
            ledger.lose_coverage("history_storage_pressure", after=boundary)
            ledger.connection.execute(
                "DELETE FROM traffic WHERE rowid IN (SELECT rowid FROM traffic ORDER BY completed LIMIT 10000)"
            )
        ledger.connection.execute("PRAGMA incremental_vacuum(10000)")
    ledger.connection.execute("PRAGMA incremental_vacuum(10000)")
    if telemetry_size(ledger) > MAX_TELEMETRY_BYTES:
        raise OSError("Private usage storage budget exceeded")


def prepare_rotation(ledger: Ledger, *, deadline: float) -> None:
    """Normal managed rotation may delete a file only after all inputs committed."""
    if not ingest_logs(ledger, deadline=deadline):
        raise TimeoutError("Private logs have an uncommitted backlog; rotation refused")
    with ledger.connection:
        ledger.store("rotation_pending", file_identity(LOG_ROOT / "usage.log"))


def finish_rotation(ledger: Ledger) -> None:
    current = LOG_ROOT / "usage.log"
    expected = ledger.value("rotation_pending")
    actual = file_identity(current)
    retained = {file_identity(path) for path in log_files() if path != current}
    with ledger.connection:
        if expected is None or (expected != actual and expected not in retained):
            ledger.lose_coverage("unverified_rotation")
        elif expected != actual and ledger.value("current_identity") != actual:
            ledger.connection.execute("DELETE FROM files WHERE device=? AND inode=?", json.loads(actual))
        ledger.store("current_identity", actual)
        ledger.connection.execute("DELETE FROM metadata WHERE key='rotation_pending'")
        living = {tuple(json.loads(identity)) for identity in retained | {actual}}
        for identity in ledger.connection.execute("SELECT device,inode FROM files").fetchall():
            if identity not in living:
                ledger.connection.execute("DELETE FROM files WHERE device=? AND inode=?", identity)


def read_metadata(*, deadline: float, action: str | None = None) -> bytes:
    """Bound the native adapter while it is running, and reap it on every exit."""
    if action not in (None, "reconcile-locked"):
        raise ValueError("Invalid native usage action")
    stop = min(deadline, time.monotonic() + 60)
    arguments = ["/usr/bin/perl", "/usr/local/libexec/praho-usage-metadata.pl"]
    if action is not None:
        arguments.append(action)
    process = subprocess.Popen(  # noqa: S603 -- fixed executable and closed action allowlist, without a shell
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    completed = False
    try:
        if process.stdout is None:
            raise ValueError("Node inventory output unavailable")
        buffer = bytearray()
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                remaining = stop - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("Node inventory collection timed out")
                chunk = os.read(descriptor, min(65536, MAX_SNAPSHOT_BYTES + 1 - len(buffer)))
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Node inventory exceeds collection bound")
        try:
            process.wait(timeout=max(0, stop - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Node inventory collection timed out") from error
        if process.returncode != 0:
            raise ValueError("Node inventory collection failed")
        completed = True
        return bytes(buffer)
    finally:
        if not completed or process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


def refresh(ledger: Ledger) -> None:
    """One bounded local collection; no credentials or raw metadata are exported."""
    started = utc_now()  # Includes every database measurement in the Perl batch.
    deadline = time.monotonic() + COLLECTION_SECONDS
    disk_deadline = deadline - TRAFFIC_RESERVE_SECONDS
    retention_deadline = deadline - INGEST_RESERVE_SECONDS
    # Hooks defer rather than holding a customer's API request behind this lock.
    # Reconcile here before attesting bindings, with no second flock in Perl.
    read_metadata(deadline=deadline, action="reconcile-locked")
    raw = read_metadata(deadline=deadline)
    accounts = json.loads(raw)["accounts"]
    if not isinstance(accounts, list) or len(accounts) > MAX_INTERVALS:
        raise ValueError("Node inventory exceeds account bound")
    accounts.sort(key=lambda account: account["id"])
    identifiers = [account["id"] for account in accounts]
    cursor = ledger.value("gauge_cursor")
    if cursor in identifiers:
        offset = identifiers.index(cursor) + 1
        accounts = accounts[offset:] + accounts[:offset]
    unbound = {
        member: epoch_us(account.get("binding_started_at") or started)
        for account in accounts
        for member in account.get("members", [])
        if member != account["id"]
    }
    with ledger.connection:
        ledger.connection.execute("DELETE FROM gaps")
        ledger.store("unbound_members", json.dumps(unbound))
    # Inventory identity is independent of successful disk measurements.
    for account in accounts:
        prior = ledger.connection.execute("SELECT payload FROM gauges WHERE domain=?", (account["id"],)).fetchone()
        row = (
            json.loads(prior[0])
            if prior
            else {
                "scan_started_at": None,
                "scan_finished_at": None,
                "disk_files_bytes": None,
                "disk_db_bytes": None,
                "disk_total_bytes": None,
                "databases": None,
                "mailboxes": None,
            }
        )
        row.update(
            {
                "domain": account["domain"],
                "domain_id": account["id"],
                "username": account["username"],
                "identity_observed_at": started,
                "mailboxes": account.get("mailboxes"),
                "binding_verified": account.get("binding_verified") is True,
                "binding_started_at": account.get("binding_started_at"),
            }
        )
        budget = 0.0
        measured_now = False
        try:
            remaining = disk_deadline - time.monotonic()
            if not account.get("unavailable") and remaining > 0:
                budget = min(HOME_SCAN_SECONDS, remaining)
                measured = disk_measurement(
                    Path(account["home"]),
                    [(Path(db["path"]), db["bytes"]) for db in account["databases"]],
                    budget_seconds=budget,
                )
                row.update({"scan_started_at": started, "scan_finished_at": utc_now(), **measured})
                measured_now = True
        except (OSError, ValueError, TimeoutError):
            pass  # Keep the last good gauge and its original collection interval.
        row.pop("members", None)
        with ledger.connection:
            ledger.connection.execute(
                "INSERT INTO gauges VALUES (?,?) ON CONFLICT(domain) DO UPDATE SET payload=excluded.payload",
                (account["id"], json.dumps(row)),
            )
            ledger.connection.execute(
                "INSERT INTO inventory VALUES (?,?) ON CONFLICT(domain) DO UPDATE SET seen_at=excluded.seen_at",
                (account["id"], epoch_us(started)),
            )
            # A home cut short by the disk deadline keeps its turn; one that failed with its full
            # budget does not, or it would hold every later home back.
            if remaining > 0 and (measured_now or account.get("unavailable") or budget >= HOME_SCAN_SECONDS):
                ledger.store("gauge_cursor", account["id"])
    observed_at = utc_now()
    enforce_retention(ledger, deadline=deadline, now=observed_at, age_deadline=retention_deadline)
    caught_up = ingest_logs(ledger, deadline=deadline, retention_deadline=retention_deadline)
    with ledger.connection:
        ledger.store("observed_at", observed_at)
        ledger.store("caught_up", str(int(caught_up)))
        ledger.store("inventory_epoch", str(epoch_us(started)))
        if ledger.value("coverage_start") is None:
            ledger.store("coverage_start", started)


def read_binding_state(installation: str) -> dict:
    """A minute repair can supersede the attestation in an hourly cached gauge."""
    try:
        descriptor = os.open(STATE_ROOT / "bindings.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                return {}
            raw = source.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            return {}
        state = json.loads(raw)
        if (
            isinstance(state, dict)
            and state.get("installation") == installation
            and isinstance(state.get("accounts"), dict)
        ):
            return state["accounts"]
    except (OSError, ValueError):
        pass
    return {}


def export_snapshot(ledger: Ledger, installation: str, request: dict) -> dict:
    observed = ledger.connection.execute("SELECT value FROM metadata WHERE key='observed_at'").fetchone()
    coverage = ledger.connection.execute("SELECT value FROM metadata WHERE key='coverage_start'").fetchone()
    if observed is None or coverage is None:
        raise ValueError("No completed node collection")
    intervals = request.get("intervals", [])
    if (
        not isinstance(intervals, list)
        or len(intervals) > MAX_INTERVALS
        or any(not isinstance(item, dict) for item in intervals)
    ):
        raise ValueError("Invalid interval request")
    deadline = time.monotonic() + 20
    records = []
    requested_ids = tuple(
        {item.get("domain_id") for item in intervals if isinstance(item.get("domain_id"), str) and item["domain_id"]}
    )
    ledger.connection.execute("PRAGMA temp_store=MEMORY")
    ledger.connection.execute("CREATE TEMP TABLE IF NOT EXISTS snapshot_domains(domain TEXT PRIMARY KEY)")
    ledger.connection.execute("DELETE FROM snapshot_domains")
    ledger.connection.executemany("INSERT INTO snapshot_domains VALUES (?)", ((value,) for value in requested_ids))
    epoch = ledger.value("inventory_epoch")
    repairing = reconciliation_pending()
    bindings = read_binding_state(installation)
    query = (
        "SELECT gauges.payload,inventory.seen_at FROM gauges LEFT JOIN inventory ON gauges.domain=inventory.domain "
        "WHERE gauges.domain IN (SELECT domain FROM inventory WHERE seen_at=? UNION SELECT domain FROM snapshot_domains)"
    )
    for raw, seen_at in ledger.connection.execute(query, (int(epoch) if epoch is not None else -1,)):
        if time.monotonic() > deadline:
            raise TimeoutError("Usage snapshot query timed out")
        row = json.loads(raw)
        row["present"] = seen_at is not None and str(seen_at) == epoch
        row["segments"] = []
        row.pop("members", None)
        binding_state = bindings.get(row["domain_id"])
        binding_current = (
            isinstance(binding_state, dict)
            and binding_state.get("verified") is True
            and binding_state.get("started_at") == row.get("binding_started_at")
        )
        for interval in intervals:
            if interval.get("domain_id") not in (row["domain_id"], ""):
                continue
            if interval.get("domain") != row["domain"]:
                continue
            end_text = min(interval["end"], observed[0], key=epoch_us)
            start, end = epoch_us(interval["start"]), epoch_us(end_text)
            if end < start:
                continue
            complete = (
                ledger.interval_complete(start)
                and row.get("binding_verified") is True
                and binding_current
                and not repairing
            )
            binding = row.get("binding_started_at")
            if binding is not None and start < epoch_us(binding):
                complete = False
            try:
                # Log literals already identify the request-time top-level owner.
                # Today's children must not rewrite historical attribution.
                amount = ledger.total(installation, row["domain_id"], start, end, deadline=deadline)
            except (TimeoutError, ValueError):
                amount, complete = 0, False
            row["segments"].append(
                {
                    "id": interval["id"],
                    "start": interval["start"],
                    "end": end_text,
                    "bytes": amount,
                    "complete": complete,
                }
            )
        row.pop("members", None)
        records.append(row)
    mask_pending_reconciliation(records)
    return {"version": 1, "installation": installation, "observed_at": observed[0], "records": records}


def reconciliation_pending() -> bool:
    """A deferred route update invalidates cached coverage until it is attested."""
    return any((STATE_ROOT / name).exists() for name in ("reconciliation-pending", "reconciliation-processing"))


def mask_pending_reconciliation(records: list[dict]) -> None:
    """Recheck after the bounded query because hooks can queue without our lock."""
    if reconciliation_pending():
        for row in records:
            for segment in row["segments"]:
                segment["complete"] = False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("init", "refresh", "export", "prepare-rotation", "rotated", "retention"))
    action = parser.parse_args().action
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE_ROOT.is_symlink() or STATE_ROOT.stat().st_mode & 0o077:
        raise ValueError("Unsafe usage state directory")
    installation_file = STATE_ROOT / "installation"
    if not installation_file.exists():
        descriptor = os.open(installation_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(str(uuid.uuid4()))
    installation = str(uuid.UUID(installation_file.read_text().strip()))
    with (STATE_ROOT / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger = Ledger(STATE_ROOT / "ledger.sqlite3")
        try:
            if action == "refresh":
                refresh(ledger)
            elif action == "prepare-rotation":
                prepare_rotation(ledger, deadline=time.monotonic() + 45)
            elif action == "rotated":
                finish_rotation(ledger)
            elif action == "retention":
                if reconciliation_pending():
                    with suppress(OSError, ValueError, TimeoutError):
                        read_metadata(deadline=time.monotonic() + 20, action="reconcile-locked")
                enforce_retention(ledger, deadline=time.monotonic() + 30, now=utc_now())
            elif action == "export":
                raw_request = sys.stdin.buffer.read(MAX_SNAPSHOT_BYTES + 1)
                if len(raw_request) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Usage request exceeds protocol bound")
                request = json.loads(raw_request)
                if not isinstance(request, dict):
                    raise ValueError("Invalid usage request")
                encoded = json.dumps(export_snapshot(ledger, installation, request))
                if len(encoded.encode()) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Usage snapshot exceeds response bound")
                print(encoded)
        finally:
            ledger.close()


if __name__ == "__main__":
    main()
