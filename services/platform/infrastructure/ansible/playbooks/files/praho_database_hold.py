#!/usr/bin/env python3
"""Database write hold for one hosting account: revoke the write privileges, keep reads and deletes (#776).

One action per run: probe | hold | release | verify | fence, under the migration barrier's own lock, both
component fence locks and a hold lock, in that order. A per-domain journal (fsynced at every phase change, kept
across episodes) records each mysql.db row's original image, so release restores the exact original bits even
for rows MariaDB deleted when their last privilege went. Anything the helper cannot qualify is refused by name
before any change; a failure after a change exits non-zero, and Platform treats the outcome as uncertain.

Output: one JSON receipt line. Never grant text: a SHOW GRANTS line can carry a password hash.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

# mysql.db privilege columns. REVOKED stops growth; KEPT leaves reads, DELETE, DROP and the customer's dumps.
REVOKED = {
    "Insert_priv": "INSERT",
    "Update_priv": "UPDATE",
    "Create_priv": "CREATE",
    "Alter_priv": "ALTER",
    "Index_priv": "INDEX",
    "Create_view_priv": "CREATE VIEW",
    "Create_routine_priv": "CREATE ROUTINE",
    "Alter_routine_priv": "ALTER ROUTINE",
    "Event_priv": "EVENT",
    "Grant_priv": "GRANT OPTION",
    "Create_tmp_table_priv": "CREATE TEMPORARY TABLES",  # Temporary tables are writes (plan revision 3).
}
KEPT = {
    "Select_priv": "SELECT",
    "Delete_priv": "DELETE",
    "Drop_priv": "DROP",
    "Show_view_priv": "SHOW VIEW",
    "Execute_priv": "EXECUTE",
    "Trigger_priv": "TRIGGER",  # So DELETE keeps working on tables with triggers.
    "References_priv": "REFERENCES",
    "Lock_tables_priv": "LOCK TABLES",  # For the customer's own mysqldump.
    "Delete_history_priv": "DELETE HISTORY",
    "Show_create_routine_priv": "SHOW CREATE ROUTINE",  # MariaDB 11.3+.
}
SQL_NAMES = {**REVOKED, **KEPT}
ACTIONS = frozenset({"probe", "hold", "release", "verify", "fence"})
RECEIPT_KEYS = frozenset(
    {"outcome", "action", "identity", "token", "generation", "phase", "held_digest", "sessions_remaining", "drift"}
)
REFUSAL_KEYS = frozenset({"outcome", "action", "identity", "token", "generation", "code", "detail"})
DOMAIN_ID = re.compile(r"[0-9]{1,30}")
DOMAIN = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
DATABASE = re.compile(r"[A-Za-z0-9_]{1,64}")
STORED_DATABASE = re.compile(r"(?:[A-Za-z0-9%_]|\\[_%]){1,64}")
USER = re.compile(r"[A-Za-z0-9_.@-]{1,80}")
HOST = re.compile(r"[A-Za-z0-9.%_:-]{1,255}")
SAVED = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
MAX_STATE_BYTES = 262144
MAX_REQUEST_BYTES = 16384
MAX_ROWS = 500
MAX_DOMAINS = 1000

Image = dict[str, str]
Principal = tuple[str, str]
# The only accounts allowed a global privilege, and whose sessions in a held database are left alone: the exact
# user@host identities of the server's own administration (MariaDB and its Debian packaging), as in
# mysql.global_priv. Any other account with a global privilege refuses the hold.
DBA: frozenset[Principal] = frozenset({("root", "localhost"), ("mysql", "localhost"), ("mariadb.sys", "localhost")})
# Global privileges that cannot change a held database: reading, monitoring and server operation. Every other one
# (the revoked write set, DELETE, DROP, FILE, GRANT OPTION, SUPER, CREATE USER, ALL PRIVILEGES, or a name this
# list does not know) lets its account write around the hold, and refuses it. The write barrier's
# database_global_writer check counts INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, SUPER and FILE; this is a
# superset of it.
READ_ONLY_GLOBALS = frozenset(
    {
        "USAGE",
        "SELECT",
        "SHOW DATABASES",
        "SHOW VIEW",
        "SHOW CREATE ROUTINE",
        "EXECUTE",
        "LOCK TABLES",
        "PROCESS",
        "RELOAD",
        "REPLICATION CLIENT",
        "BINLOG MONITOR",
        "SLAVE MONITOR",
        "REPLICA MONITOR",
    }
)


class HoldRefusal(Exception):  # noqa: N818 -- A named refusal, reported in the receipt, not an error.
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code)
        self.code, self.detail = code, detail


class Database(Protocol):
    def columns(self) -> list[str]: ...

    def principals(self, databases: list[str]) -> set[Principal]: ...

    def hosts(self, user: str) -> set[str]: ...

    def grants(self, user: str, host: str) -> list[str]: ...

    def principal_rows(self, user: str, host: str) -> list[tuple[str, Image]]: ...

    def object_privileges(self, principals: list[Principal]) -> int: ...

    def roles_and_proxies(self, principals: list[Principal]) -> tuple[int, int]: ...

    def definers_of(self, databases: list[str]) -> set[str]: ...

    def revoke(self, user: str, host: str, db: str, columns: list[str]) -> None: ...

    def grant(self, user: str, host: str, db: str, columns: list[str]) -> None: ...

    def global_privileges(self) -> dict[Principal, set[str]]: ...

    def sessions_on(self, databases: list[str], users: list[str]) -> dict[int, str]: ...

    def kill_soft(self, number: int) -> None: ...


@dataclass(frozen=True)
class Paths:
    run: Path = Path("/run/praho")
    migration: Path = Path("/var/lib/praho/migration")
    component_fences: Path = Path("/var/lib/praho/component-fences")
    component_database_fences: Path = Path("/var/lib/praho/component-database-fences")
    state: Path = Path("/var/lib/praho/database-hold")
    domains: Path = Path("/etc/webmin/virtual-server/domains")
    installation: Path = Path("/var/lib/praho/usage/installation")


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Database hold state must be an owned private directory")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Database hold state must be an owned private regular file")
        content = stream.read(MAX_STATE_BYTES + 1)
    if len(content.encode()) > MAX_STATE_BYTES:
        raise ValueError("Database hold state exceeds its bound")
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("Database hold state has an invalid shape")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    """Fsync the file and its directory entry: every phase change survives a crash."""
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(content) > MAX_STATE_BYTES:
        raise ValueError("Database hold state exceeds its bound")
    temporary = path.with_name(".hold-" + path.name)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
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


def _fields(path: Path) -> dict[str, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("Native domain metadata must be owned and protected")
        text = stream.read(MAX_STATE_BYTES + 1)
    if len(text.encode()) > MAX_STATE_BYTES:
        raise ValueError("Native domain metadata exceeds its bound")
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key not in result:
            result[key] = value
    return result


def _unescaped(stored: str) -> str:
    return stored.replace("\\_", "_").replace("\\%", "%")


def _is_wildcard(stored: str) -> bool:
    """A stored Db with % or an unescaped _ could cover a database created later."""
    return "%" in stored.replace("\\%", "") or "_" in stored.replace("\\_", "")


def _image(columns: list[str], found: Image | None) -> Image:
    """A row's privileges over the server's known columns; a deleted row is all N."""
    return {column: (found or {}).get(column, "N") for column in columns}


_IDENTITY = r"(?:`[^`]*`|'[^']*')@(?:`[^`]*`|'[^']*')"
# One SHOW GRANTS line -> its refusal code, or None for a supported USAGE or schema grant. First match decides.
GRANT_CLASSES: tuple[tuple[re.Pattern[str], str | None], ...] = tuple(
    (re.compile(pattern), code)
    for pattern, code in (
        (r"SET DEFAULT ROLE .*", "default_role"),
        (r"GRANT (?:`[^`]*`|'[^']*') TO " + _IDENTITY + r"(?: WITH ADMIN OPTION)?", "role"),
        (r"GRANT PROXY ON .*", "proxy"),
        (r"GRANT USAGE ON \*\.\* TO " + _IDENTITY + r"(?: IDENTIFIED BY PASSWORD '[^'\r\n]*')?(?: WITH .*)?", None),
        (r"GRANT .+ ON \*\.\* TO " + _IDENTITY + r".*", "global_privilege"),
        (r"GRANT [A-Z ,]+ ON `[^`]+`\.\* TO " + _IDENTITY + r"(?: WITH GRANT OPTION)?", None),
        (r"GRANT .+ ON (?:(?:PROCEDURE|FUNCTION|PACKAGE(?: BODY)?) )?`[^`]+`\.`[^`]+` TO .*", "object_privilege"),
        (r"GRANT .*\(.*\).* ON .*", "object_privilege"),
    )
)


def _classify(line: str) -> str | None:
    """The refusal code of one SHOW GRANTS line; anything unrecognised is refused, never allowed."""
    for pattern, code in GRANT_CLASSES:
        if pattern.fullmatch(line):
            return code
    return "unsupported_grant"


def _journalled(journal: dict[str, Any] | None) -> set[Principal]:
    """The journal's rows' principals: a row MariaDB deleted when its last privilege went is still in scope."""
    if not journal:
        return set()
    return {(row["user"], row["host"]) for row in journal.get("rows", [])}


def _written_states(row: dict[str, Any], columns: list[str]) -> list[Image]:
    """Every image this helper itself can leave a journalled row in, including between two of its statements."""
    states = [_image(columns, row.get(name)) for name in ("before", "pre", "held", "restore_from") if row.get(name)]
    if row.get("pre"):
        # The REVOKE took effect but the node died before the row was journalled held.
        states.append(_image(columns, {c: ("N" if c in REVOKED else v) for c, v in row["pre"].items()}))
    if row.get("restore_from"):
        # A release's REVOKE took effect but its GRANT did not: the original bits less anything extra.
        before, start = _image(columns, row["before"]), _image(columns, row["restore_from"])
        states.append({c: ("N" if before[c] == "N" else start[c]) for c in columns})
    return states


class DatabaseHold:
    def __init__(  # noqa: PLR0913 -- Every native boundary is explicit, so tests can double each one.
        self,
        paths: Paths,
        database: Database,
        *,
        drain_seconds: float = 60,
        lock_seconds: float = 30,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.paths, self.database = paths, database
        self.drain_seconds, self.lock_seconds = drain_seconds, lock_seconds
        self.sleep, self.clock = sleep, clock

    # -- request -------------------------------------------------------------------------------------------------
    @staticmethod
    def _request(request: object) -> tuple[str, dict[str, str], str | None, int | None]:
        if not isinstance(request, dict) or request.get("action") not in ACTIONS:
            raise ValueError("Unsupported database hold action")
        action = request["action"]
        needs_token = action in {"probe", "hold", "fence"}
        needs_generation = action != "fence"
        expected = {"action", "identity"} | ({"token"} if needs_token else set())
        expected |= {"generation"} if needs_generation else set()
        if set(request) != expected:
            raise ValueError("The database hold request has unsupported terms")
        identity = request["identity"]
        if (
            not isinstance(identity, dict)
            or set(identity) != {"domain_id", "domain", "installation"}
            or not isinstance(identity["domain_id"], str)
            or DOMAIN_ID.fullmatch(identity["domain_id"]) is None
            or not isinstance(identity["domain"], str)
            or DOMAIN.fullmatch(identity["domain"]) is None
            or not isinstance(identity["installation"], str)
            or str(UUID(identity["installation"])) != identity["installation"]
        ):
            raise ValueError("An exact native hold identity is required")
        token = request.get("token")
        if needs_token and (not isinstance(token, str) or re.fullmatch(SAVED, token) is None):
            raise ValueError("An exact hold token is required")
        generation = request.get("generation")
        if needs_generation and (type(generation) is not int or not 0 < generation < 1 << 62):
            raise ValueError("The hold generation must be a positive integer")
        return action, dict(identity), token, generation

    def perform(self, request: object) -> dict[str, Any]:
        action, identity, token, generation = self._request(request)
        self._in_scope: list[Principal] = []  # The principals the latest qualification accepted.
        receipt: dict[str, Any] = {"action": action, "identity": identity, "token": token, "generation": generation}
        try:
            with self._locked(identity["domain_id"]):
                databases = self._identity(identity)
                scope = self.paths.state / identity["installation"] / identity["domain_id"]
                _private_directory(scope)
                journal = _read_json(scope / "journal.json")
                if journal is not None and (
                    journal.get("domain") != identity["domain"]
                    or journal.get("installation") != identity["installation"]
                ):
                    raise HoldRefusal("journal_mismatch", "the hold journal belongs to another domain")
                handler = getattr(self, "_" + action)
                return {"outcome": "ok", **receipt, **handler(identity, databases, scope, journal, token, generation)}
        except HoldRefusal as refusal:
            return {"outcome": "refused", **receipt, "code": refusal.code, "detail": refusal.detail[:200]}

    # -- locks and identity ----------------------------------------------------------------------------------------
    @contextmanager
    def _locked(self, domain_id: str) -> Iterator[None]:
        with ExitStack() as stack:
            for directory, name in (
                (self.paths.run, f"migration-{domain_id}.lock"),  # The write barrier's own lock.
                (self.paths.component_fences, f"{domain_id}.lock"),
                (self.paths.component_database_fences, f"{domain_id}.lock"),
                (self.paths.run, f"database-hold-{domain_id}.lock"),
            ):
                _private_directory(directory)
                descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stack.callback(os.close, descriptor)
                deadline = self.clock() + self.lock_seconds
                while True:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if self.clock() >= deadline:
                            raise HoldRefusal("lock_busy", f"{name} is held") from None
                        self.sleep(0.05)
            yield

    def _identity(self, identity: dict[str, str]) -> list[str]:
        """The domain's databases, after its native identity matched the request exactly."""
        try:
            fields = _fields(self.paths.domains / identity["domain_id"])
            installation = self.paths.installation.read_text().strip()
        except FileNotFoundError:
            raise HoldRefusal("identity_mismatch", "the native domain is missing") from None
        if (
            fields.get("id") != identity["domain_id"]
            or fields.get("dom") != identity["domain"]
            or fields.get("parent")
            or installation != identity["installation"]
        ):
            raise HoldRefusal("identity_mismatch", "the native domain or installation changed")
        names = fields.get("db_mysql", "").split()
        for number, path in enumerate(sorted(self.paths.domains.iterdir())):
            if number >= MAX_DOMAINS:
                raise ValueError("The native domain inventory exceeds its bound")
            if path.name != identity["domain_id"] and DOMAIN_ID.fullmatch(path.name):
                child = _fields(path)
                if child.get("parent") == identity["domain_id"]:
                    names.extend(child.get("db_mysql", "").split())
        if any(DATABASE.fullmatch(name) is None for name in names):
            raise ValueError("A registered database name is unsupported")
        return sorted(set(names))

    def _admission(self, domain_id: str) -> None:
        """A hold may not change grants under an active migration barrier or component fence."""
        if self.paths.migration.is_dir():
            for record in self.paths.migration.glob(f"migration-{domain_id}.*.crontab"):
                match = re.fullmatch(rf"migration-{domain_id}\.({SAVED})\.crontab", record.name)
                if match is None:
                    continue
                saved = match[1]
                completed = (self.paths.migration / f"migration-{domain_id}.{saved}.release-completed").exists()
                started = (self.paths.migration / f"migration-{domain_id}.{saved}.release-started").exists()
                cancelled = (self.paths.migration / f"migration-{domain_id}.cancelled.{saved}").exists()
                # A release cancels its own token and may still have accounts locked: in progress is active.
                if not completed and (started or not cancelled):
                    raise HoldRefusal("barrier_active", "a migration write barrier is active")
        for directory in (self.paths.component_fences, self.paths.component_database_fences):
            path = directory / f"{domain_id}.json"
            if path.exists() or path.is_symlink():
                try:
                    state = _read_json(path)
                except (ValueError, OSError):
                    state = None
                if state is None or state.get("phase") != "released":
                    raise HoldRefusal("component_fence_active", f"a component fence in {directory.name} is active")

    # -- scope ---------------------------------------------------------------------------------------------------
    def _columns(self) -> list[str]:
        columns = [column for column in self.database.columns() if column.endswith("_priv")]
        unknown = sorted(set(columns) - set(SQL_NAMES))
        if unknown:
            raise HoldRefusal("unknown_privilege_column", "mysql.db has " + ", ".join(unknown[:5]))
        return columns

    def _principals(self, databases: list[str], known: set[Principal] | None = None) -> list[Principal]:
        """The in-scope principals, after every principal-level refusal was checked.

        `known` are the journal's principals: a host whose only row this hold deleted is still in scope.
        """
        discovered = self.database.principals(databases)
        scoped = discovered | (known or set())
        if any(USER.fullmatch(user) is None or HOST.fullmatch(host) is None for user, host in scoped):
            raise HoldRefusal("unsupported_grant", "a principal identity is unsupported")
        # A global write or grant privilege reaches every database, in scope or not; only the exact DBA
        # identities may hold one.
        if writers := sorted(
            principal
            for principal, names in self.database.global_privileges().items()
            if principal not in DBA and names - READ_ONLY_GLOBALS
        ):
            raise HoldRefusal("global_privilege", "{}@{}".format(*writers[0]))
        # A journalled principal since dropped has no grants left to qualify.
        principals = sorted(
            (user, host) for user, host in scoped if (user, host) in discovered or host in self.database.hosts(user)
        )
        for user in sorted({user for user, _host in principals}):
            if self.database.hosts(user) - {host for name, host in principals if name == user}:
                raise HoldRefusal("shared_username", f"username {user} has hosts outside the scope")
        self._in_scope = principals
        roles, proxies = self.database.roles_and_proxies(principals)
        if roles:
            raise HoldRefusal("role", "a principal has a role")
        if proxies:
            raise HoldRefusal("proxy", "a principal has a proxy grant")
        if self.database.object_privileges(principals):
            raise HoldRefusal("object_privilege", "a principal has table, column or routine privileges")
        for user, host in principals:
            for line in self.database.grants(user, host):
                if code := _classify(line):
                    raise HoldRefusal(code, f"{user}@{host}")
        return principals

    def _scope(
        self, databases: list[str], columns: list[str], known: set[Principal] | None = None
    ) -> dict[tuple[str, str, str], Image]:
        """Every mysql.db row of the in-scope principals, after each named refusal was checked."""
        principals = self._principals(databases, known)
        rows: dict[tuple[str, str, str], Image] = {}
        for user, host in principals:
            for stored, found in self.database.principal_rows(user, host):
                if STORED_DATABASE.fullmatch(stored) is None or _is_wildcard(stored):
                    raise HoldRefusal("wildcard_database", f"{user}@{host} on a wildcard database")
                if _unescaped(stored) not in databases:
                    raise HoldRefusal("outside_scope", f"{user}@{host} has another database")
                rows[(user, host, stored)] = _image(columns, found)
        if len(rows) > MAX_ROWS:
            raise ValueError("The database hold scope exceeds its bound")
        allowed = {f"{user}@{host}" for user, host in principals}
        if self.database.definers_of(databases) - allowed:
            raise HoldRefusal("definer_outside_scope", "a routine, trigger, event or view runs as another principal")
        return rows

    @staticmethod
    def _digest(rows: dict[tuple[str, str, str], Image]) -> str:
        canonical = [[user, host, db, rows[(user, host, db)]] for user, host, db in sorted(rows)]
        return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _live(self, key: tuple[str, str, str], columns: list[str]) -> Image:
        user, host, db = key
        found = dict(self.database.principal_rows(user, host)).get(db)
        return _image(columns, found)

    # -- actions ---------------------------------------------------------------------------------------------------
    @staticmethod
    def _generation(journal: dict[str, Any] | None) -> int:
        return int(journal.get("generation", 0)) if journal else 0

    def _probe(self, identity, databases, scope, journal, token, generation) -> dict[str, Any]:  # noqa: ANN001, PLR0913
        if (scope / f"cancelled-{token}.json").exists():
            raise HoldRefusal("cancelled_token", "the hold token was fenced")
        self._admission(identity["domain_id"])
        rows = self._scope(databases, self._columns())
        return self._result("probed", self._digest(rows), [], [])

    def _hold(self, identity, databases, scope, journal, token, generation) -> dict[str, Any]:  # noqa: ANN001, PLR0913
        if (scope / f"cancelled-{token}.json").exists():
            raise HoldRefusal("cancelled_token", "the hold token was fenced")
        previous = self._generation(journal)
        # An unfinished release still owns the original images: a new hold continues from them (review finding).
        active = journal is not None and journal.get("phase") in {"holding", "held", "releasing"}
        if generation < previous or (generation == previous and not active):
            raise HoldRefusal("obsolete_generation", "a newer hold or release exists")
        if generation == previous and journal is not None and journal.get("token") != token:
            raise HoldRefusal("generation_conflict", "this generation holds with another token")
        self._admission(identity["domain_id"])
        columns = self._columns()
        known = _journalled(journal) if active else set()
        try:
            live = self._scope(databases, columns, known)
        except Exception:
            if active and journal is not None:
                # The scope changed since the record: write access may have come and gone, and a session that
                # entered a held database meanwhile kept it. Every session in one counts until a hold succeeds.
                _write_json(scope / "journal.json", {**journal, "sessions_recorded": False})
            raise
        # The original image of a row already journalled survives every re-hold (plan revision 3).
        journalled = {(row["user"], row["host"], row["db"]): row for row in (journal or {}).get("rows", []) if active}
        rows = []
        for key in sorted(set(live) | set(journalled)):
            user, host, db = key
            row = dict(journalled.get(key) or {"user": user, "host": host, "db": db, "before": live[key]})
            row["phase"] = row.get("phase", "open") if key in journalled else "open"
            rows.append(row)
        state = {
            "domain": identity["domain"],
            "installation": identity["installation"],
            "generation": generation,
            "token": token,
            "phase": "holding",
            "rows": rows,
            "sessions": list((journal or {}).get("sessions", [])) if active else [],
            # Until the sessions in a held database at revoke time are recorded, every one of them may still write.
            "sessions_recorded": False,
            "held_digest": None,
        }
        path = scope / "journal.json"
        _write_json(path, state)
        try:
            return self._apply_hold(databases, columns, known, rows, state, path)
        except HoldRefusal as refusal:
            # Privileges may already have changed: a refusal found now is an uncertain outcome, never a clean one.
            # The journal still says sessions_recorded false, so verify counts every session in a held database.
            raise ValueError(f"The hold scope changed during the hold ({refusal.code})") from refusal

    def _writers(self, databases: list[str]) -> set[int]:
        """Sessions that may still write a held database after the revoke:
        - every session whose current database is held, since MariaDB 11.8.3 caches its database privileges per
          current database (a qualified statement or a fresh USE is checked again);
        - every executing session of an in-scope username, wherever it sits: a statement started before the
          revoke runs to its end, and an in-scope principal has rows on held databases only, its username on no
          other account (shared_username).
        A username is exempt only when every one of its accounts is a DBA identity, since the process list shows
        the username, not which of its hosts the session authenticated as."""
        users = sorted({user for user, _host in self._in_scope})
        exempt: dict[str, bool] = {}
        found = set()
        for number, user in self.database.sessions_on(databases, users).items():
            if user not in exempt:
                hosts = self.database.hosts(user) if USER.fullmatch(user) else set()
                exempt[user] = bool(hosts) and {(user, host) for host in hosts} <= DBA
            if not exempt[user]:
                found.add(number)
        return found

    def _apply_hold(  # noqa: PLR0913 -- The journal and the scope it was qualified against.
        self,
        databases: list[str],
        columns: list[str],
        known: set[Principal],
        rows: list[dict[str, Any]],
        state: dict[str, Any],
        path: Path,
    ) -> dict[str, Any]:
        for row in rows:
            key = (row["user"], row["host"], row["db"])
            current = self._live(key, columns)
            revoke = [column for column in REVOKED if current.get(column) == "Y"]
            row["pre"] = current
            if revoke:
                row["phase"] = "revoke_intent"
                _write_json(path, state)
                self.database.revoke(*key, revoke)
            row["held"] = self._live(key, columns)
            row["phase"] = "held"
            _write_json(path, state)
        # Every session in a held database now, after the revokes, is ended and must be gone before the hold is
        # confirmed. The ids come from this run's own read, never from the journal: after a restart a recorded id
        # may be another account's.
        # Until this hold succeeds, the journal says sessions_recorded false: verify then counts every one of them.
        recorded = self._writers(databases)
        for number in sorted(recorded):
            self.database.kill_soft(number)
        deadline = self.clock() + self.drain_seconds
        remaining = recorded & self._writers(databases)
        while remaining and self.clock() < deadline:
            self.sleep(min(1.0, max(0.0, deadline - self.clock())))
            remaining = recorded & self._writers(databases)
        state["sessions"] = sorted(remaining)
        # The whole scope again: a principal or privilege added during the revokes was never held.
        final = self._scope(databases, columns, known | {(r["user"], r["host"]) for r in rows})
        journalled = {(r["user"], r["host"], r["db"]) for r in rows}
        if set(final) - journalled or any(image.get(c) == "Y" for image in final.values() for c in REVOKED):
            raise ValueError("The hold scope changed during the hold; verify, then hold again")
        state["phase"] = "holding" if remaining else "held"
        state["held_digest"] = self._digest(final)
        state["sessions_recorded"] = True
        _write_json(path, state)
        return self._result(state["phase"], state["held_digest"], state["sessions"], [])

    def _release(self, identity, databases, scope, journal, token, generation) -> dict[str, Any]:  # noqa: ANN001, PLR0913
        previous = self._generation(journal)
        if generation < previous:
            raise HoldRefusal("obsolete_generation", "a newer hold exists")
        hold_token = journal.get("token") if journal else None
        if journal is None or journal.get("phase") == "released" or not journal.get("rows"):
            if journal is not None and generation > previous:
                _write_json(scope / "journal.json", {**journal, "generation": generation, "phase": "released"})
            return {**self._result("released", None, [], []), "token": hold_token}
        columns = self._columns()
        rows = [row for row in journal["rows"] if row.get("phase") != "open"]
        # Automatic only when every row is in a state this helper wrote; anything else is someone else's change.
        for row in rows:
            current = self._live((row["user"], row["host"], row["db"]), columns)
            if current not in _written_states(row, columns):
                raise HoldRefusal(
                    "operator_inspection_required", f"{row['user']}@{row['host']} changed during the hold"
                )
        path = scope / "journal.json"
        state = {**journal, "generation": generation, "phase": "releasing"}
        _write_json(path, state)
        for row in rows:
            key = (row["user"], row["host"], row["db"])
            before = _image(columns, row["before"])
            current = self._live(key, columns)
            if not row.get("restore_from"):
                row["restore_from"] = current
                _write_json(path, state)
            extra = [column for column in columns if current[column] == "Y" and before[column] == "N"]
            if extra:
                self.database.revoke(*key, extra)
            missing = [
                column for column in columns if before[column] == "Y" and self._live(key, columns)[column] == "N"
            ]
            if missing:
                self.database.grant(*key, missing)
            if self._live(key, columns) != before:
                raise ValueError("A released row does not read back as its original image")
        state.update({"phase": "released", "rows": [], "sessions": [], "held_digest": None})
        _write_json(path, state)
        return {**self._result("released", None, [], []), "token": hold_token}

    def _verify(self, identity, databases, scope, journal, token, generation) -> dict[str, Any]:  # noqa: ANN001, PLR0913
        previous = self._generation(journal)
        if generation < previous:
            raise HoldRefusal("obsolete_generation", "a newer hold exists")
        hold_token = journal.get("token") if journal else None
        if journal is None or journal.get("phase") not in {"holding", "held"} or generation > previous:
            return {**self._result("verified", None, [], ["not_held"]), "token": hold_token}
        columns = self._columns()
        known = _journalled(journal)
        drift = []
        try:
            # The whole scope is qualified again, definers included: a global, role, proxy or object grant, or a
            # routine running as someone else, can add write access that no mysql.db row shows.
            self._scope(databases, columns, known)
        except HoldRefusal as refusal:
            drift.append(f"unqualified:{refusal.code}")
        scoped = self.database.principals(databases) | known
        live: dict[tuple[str, str, str], Image] = {}
        for user, host in sorted(scoped):
            for stored, found in self.database.principal_rows(user, host):
                live[(user, host, stored)] = _image(columns, found)
        # Every live row of the scope, not only the journalled ones, must be without the write set.
        drift.extend(
            f"regranted:{user}@{host}:{db}"
            for (user, host, db), image in sorted(live.items())
            if any(image.get(column) == "Y" for column in REVOKED)
        )
        drift.extend(f"new_principal:{user}@{host}" for user, host in sorted(scoped - known))
        current = self._writers(databases)
        # Until a hold succeeded, any session in a held database may be one that kept its write privileges. Once
        # recorded, only those count: a session that entered a held database later was checked against the hold.
        recorded = journal.get("sessions_recorded")
        outstanding = set(journal.get("sessions", [])) & current if recorded else current
        return {**self._result("verified", self._digest(live), sorted(outstanding), drift), "token": hold_token}

    def _fence(self, identity, databases, scope, journal, token, generation) -> dict[str, Any]:  # noqa: ANN001, PLR0913
        # Never expires: a hold queued before a reboot may arrive later. The locks prove an old hold has exited.
        _write_json(scope / f"cancelled-{token}.json", {"token": token})
        return {**self._result("fenced", None, [], []), "generation": self._generation(journal)}

    @staticmethod
    def _result(phase: str, digest: str | None, sessions: list[int], drift: list[str]) -> dict[str, Any]:
        return {"phase": phase, "held_digest": digest, "sessions_remaining": list(sessions), "drift": list(drift)}


class NativeDatabase:
    """The production seam: SQL through the local DBA socket, discovery shared with component migration."""

    def __init__(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "praho_component_mysql", Path(__file__).with_name("praho-component-mysql.py")
        )
        if spec is None or spec.loader is None:
            raise ValueError("The component MySQL discovery helper is not installed")
        self.mysql = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mysql)
        self.execute = self.mysql.native_sql

    @staticmethod
    def _principal(user: str, host: str) -> str:
        if USER.fullmatch(user) is None or HOST.fullmatch(host) is None:
            raise ValueError("A principal identity is unsupported")
        return f"'{user}'@'{host}'"

    @staticmethod
    def _target(db: str) -> str:
        if STORED_DATABASE.fullmatch(db) is None:
            raise ValueError("A stored database value is unsupported")
        return f"`{db}`.*"  # The exact stored value, escapes included: never re-quoted.

    def _pairs(self, principals: list[Principal]) -> str:
        return ",".join(f"('{user}','{host}')" for user, host in principals if self._principal(user, host))

    def columns(self) -> list[str]:
        return [row[0] for row in self.execute("SHOW COLUMNS FROM mysql.db LIKE '%\\_priv'")]

    def principals(self, databases: list[str]) -> set[Principal]:
        if not databases:
            return set()
        accounts = {name: self.mysql._accounts(self.execute, name) for name in databases}  # Shared discovery.
        return {(row[0], row[1]) for rows in accounts.values() for row in rows}

    def hosts(self, user: str) -> set[str]:
        if USER.fullmatch(user) is None:
            raise ValueError("A principal identity is unsupported")
        return {row[0] for row in self.execute(f"SELECT Host FROM mysql.global_priv WHERE User = '{user}'")}  # noqa: S608

    def grants(self, user: str, host: str) -> list[str]:
        return [row[0] for row in self.execute(f"SHOW GRANTS FOR {self._principal(user, host)}")]

    def principal_rows(self, user: str, host: str) -> list[tuple[str, Image]]:
        self._principal(user, host)
        columns = self.columns()
        rows = self.execute(
            f"SELECT Db, {', '.join(columns)} FROM mysql.db WHERE User = '{user}' AND Host = '{host}'"  # noqa: S608 -- Validated identifiers.
        )
        return [(row[0], dict(zip(columns, row[1:], strict=True))) for row in rows]

    def object_privileges(self, principals: list[Principal]) -> int:
        if not principals:
            return 0
        pairs = self._pairs(principals)
        query = " + ".join(
            f"(SELECT COUNT(*) FROM mysql.{table} WHERE (User, Host) IN ({pairs}))"  # noqa: S608 -- Validated identifiers.
            for table in ("tables_priv", "columns_priv", "procs_priv")
        )
        return int(self.execute("SELECT " + query)[0][0])

    def roles_and_proxies(self, principals: list[Principal]) -> tuple[int, int]:
        if not principals:
            return 0, 0
        pairs = self._pairs(principals)
        roles = self.execute(f"SELECT COUNT(*) FROM mysql.roles_mapping WHERE (User, Host) IN ({pairs})")  # noqa: S608
        proxies = self.execute(f"SELECT COUNT(*) FROM mysql.proxies_priv WHERE (User, Host) IN ({pairs})")  # noqa: S608
        return int(roles[0][0]), int(proxies[0][0])

    def definers_of(self, databases: list[str]) -> set[str]:
        if not databases:
            return set()
        names = ",".join(f"'{name}'" for name in databases if DATABASE.fullmatch(name))
        rows = self.execute(
            f"SELECT DEFINER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA IN ({names}) UNION "  # noqa: S608 -- Validated names.
            f"SELECT DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA IN ({names}) UNION "
            f"SELECT DEFINER FROM information_schema.EVENTS WHERE EVENT_SCHEMA IN ({names}) UNION "
            f"SELECT DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA IN ({names})"
        )
        return {row[0] for row in rows}

    # One statement each, GRANT OPTION included, so a crash never leaves a row half changed (review finding).
    def revoke(self, user: str, host: str, db: str, columns: list[str]) -> None:
        names = [SQL_NAMES[column] for column in columns]
        self.execute(f"REVOKE {', '.join(names)} ON {self._target(db)} FROM {self._principal(user, host)}")

    def grant(self, user: str, host: str, db: str, columns: list[str]) -> None:
        names = [SQL_NAMES[column] for column in columns if column != "Grant_priv"] or ["USAGE"]
        option = " WITH GRANT OPTION" if "Grant_priv" in columns else ""
        self.execute(f"GRANT {', '.join(names)} ON {self._target(db)} TO {self._principal(user, host)}{option}")

    def global_privileges(self) -> dict[Principal, set[str]]:
        rows = self.execute("SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES")
        found: dict[Principal, set[str]] = {}
        for grantee, name, grantable in rows:
            # An identity outside the supported shape is still an account with a global privilege.
            match = re.fullmatch(r"'([^']*)'@'([^']*)'", grantee)
            names = found.setdefault((match.group(1), match.group(2)) if match else (grantee, ""), set())
            names.add(name)
            if grantable == "YES":
                names.add("GRANT OPTION")
        return found

    def sessions_on(self, databases: list[str], users: list[str]) -> dict[int, str]:
        names = ",".join(f"'{name}'" for name in databases if DATABASE.fullmatch(name))
        if not names:
            return {}
        accounts = ",".join(f"'{user}'" for user in users if USER.fullmatch(user))
        # BINARY: the process list compares case-insensitively, but `Shop` is another tenant's account.
        busy = f" OR (BINARY USER IN ({accounts}) AND COMMAND <> 'Sleep')" if accounts else ""
        # The helper's own connection and the server's own threads are never a customer's writer.
        rows = self.execute(
            "SELECT ID, USER FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID() "  # noqa: S608 -- Validated names.
            f"AND COMMAND <> 'Daemon' AND USER <> 'system user' AND (BINARY DB IN ({names}){busy})"
        )
        return {int(row[0]): row[1] for row in rows if row[0].isdecimal()}

    def kill_soft(self, number: int) -> None:
        # Already gone is fine: the drain decides from the process list, not from this statement.
        with suppress(ValueError):
            self.execute(f"KILL SOFT CONNECTION {int(number)}")


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError("A root-owned database hold operation is required")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("The database hold request exceeds its bound")
    receipt = DatabaseHold(Paths(), NativeDatabase()).perform(json.loads(raw))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
