#!/usr/bin/env python3
"""Read-only MySQL/MariaDB component qualification; raw credentials never enter evidence."""

# ruff: noqa: S608 -- Native CLI has no driver parameters. All substituted identities are
# restricted by DATABASE/USER/HOST; table names are literal enumerations, never remote input.

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from typing import Any

SQLRows = list[tuple[str, ...]]
SQLExecutor = Callable[[str], SQLRows]
MAX_DATABASES = 100
MAX_SQL_ROWS = 2000
MAX_SQL_BYTES = 2 * 1024 * 1024
MAX_NATIVE_PASSWORD_BYTES = 4096
NATIVE_ACCOUNT_COLUMNS = 4
NATIVE_SCHEMA_COLUMNS = 4
NATIVE_PRINCIPAL_COLUMNS = 2
DATABASE = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
USER = re.compile(r"[A-Za-z0-9_.@-]{1,80}\Z")
HOST = re.compile(r"[A-Za-z0-9.%_:-]{1,255}\Z")
SCHEMA_PRIVILEGES = frozenset(
    {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "CREATE",
        "DROP",
        "REFERENCES",
        "INDEX",
        "ALTER",
        "CREATE TEMPORARY TABLES",
        "LOCK TABLES",
        "EXECUTE",
        "CREATE VIEW",
        "SHOW VIEW",
        "CREATE ROUTINE",
        "ALTER ROUTINE",
        "EVENT",
        "TRIGGER",
        "DELETE HISTORY",
    }
)


def exact_schema(database: str) -> str:
    """Backticks alone do not make underscores literal in schema-level GRANT patterns."""
    if DATABASE.fullmatch(database) is None:
        raise ValueError("Only a qualified exact schema may receive selected application grants")
    return "`" + database.replace("_", "\\_") + "`"


def _pattern(pattern: str, database: str) -> bool:
    expression = []
    escaped = False
    for character in pattern:
        if escaped:
            expression.append(re.escape(character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            expression.append(".*" if character == "%" else "." if character == "_" else re.escape(character))
    if escaped:
        raise ValueError("Native schema grant has an incomplete escaped pattern")
    return re.fullmatch("".join(expression), database) is not None


def selected_schema_grants(
    grants: list[str], user: str, host: str, selected: tuple[str, ...]
) -> list[tuple[str, str, bool]]:
    """Parse qualified schema privileges, then expand ONLY into the approved existing schemas.

    Source SHOW GRANTS text is never executed on the destination. Table/column,
    proxy, role and unqualified extensions require explicit source preparation.
    """
    if USER.fullmatch(user) is None or HOST.fullmatch(host) is None:
        raise ValueError("Selected SQL grants have an unqualified principal")
    _names(selected, selected)
    identity = (
        r"(?:`"
        + re.escape(user)
        + r"`|'"
        + re.escape(user)
        + r"')@(?:`"
        + re.escape(host)
        + r"`|'"
        + re.escape(host)
        + r"')"
    )
    usage = re.compile(
        r"GRANT USAGE ON \*\.\* TO "
        + identity
        + r"(?: IDENTIFIED BY PASSWORD '[^'\r\n]*')?(?: WITH MAX_USER_CONNECTIONS [0-9]+)?\Z"
    )
    schema = re.compile(r"GRANT (.+?) ON `([A-Za-z0-9_\\%]+)`\.\* TO " + identity + r"( WITH GRANT OPTION)?\Z")
    result = set()
    for grant in grants:
        if usage.fullmatch(grant):
            continue
        match = schema.fullmatch(grant)
        if match is None:
            raise ValueError(
                "Prepare explicit supported schema-only privileges before migrating application principals"
            )
        privileges = match[1]
        if privileges != "ALL PRIVILEGES" and any(part not in SCHEMA_PRIVILEGES for part in privileges.split(", ")):
            raise ValueError("Selected native SQL privileges require qualification before migration")
        databases = [database for database in selected if _pattern(match[2], database)]
        if not databases:
            raise ValueError("A native schema grant does not belong to the selected application scope")
        result.update((privileges, database, bool(match[3])) for database in databases)
    if not result:
        raise ValueError("Selected application principal has no qualified schema privileges")
    return sorted(result)


def native_sql(query: str) -> SQLRows:
    """The local DBA's socket/config identity stays on the source; SQL goes through stdin."""
    result = subprocess.run(
        ["/usr/bin/mysql", "--batch", "--raw", "--skip-column-names", "--connect-timeout=10"],
        input=query + ";\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ValueError("Native MySQL component inventory is unreadable; inspect local DBA permissions")
    if len(result.stdout.encode()) > MAX_SQL_BYTES:
        raise ValueError("Native MySQL evidence exceeds its qualification limit")
    rows = [tuple(line.split("\t")) for line in result.stdout.splitlines() if line]
    if len(rows) > MAX_SQL_ROWS:
        raise ValueError("Native MySQL inventory exceeds its qualification limit")
    return rows


def _names(selected: tuple[str, ...], owned: tuple[str, ...]) -> str:
    if len(selected) > MAX_DATABASES or len(set(selected)) != len(selected):
        raise ValueError("Select a bounded set of unique native databases")
    if any(not isinstance(name, str) or DATABASE.fullmatch(name) is None for name in selected):
        raise ValueError("Selected database names require native preparation")
    if not set(selected) <= set(owned):
        raise ValueError("Select only databases registered to the exact native source domain")
    return ",".join("'" + name + "'" for name in selected)


def _count(execute: SQLExecutor, query: str) -> int:
    rows = execute(query)
    if len(rows) != 1 or len(rows[0]) != 1 or not rows[0][0].isdecimal():
        raise ValueError("Native MySQL count is incomplete; absence is unproven")
    return int(rows[0][0])


def _accounts(execute: SQLExecutor, database: str) -> SQLRows:
    sources = [f"SELECT User, Host FROM mysql.db WHERE '{database}' LIKE Db"]
    sources.extend(
        f"SELECT User, Host FROM mysql.{table} WHERE Db = '{database}'"
        for table in ("tables_priv", "columns_priv", "procs_priv")
    )
    return execute(
        "SELECT DISTINCT User, Host FROM (" + " UNION ".join(sources) + ") AS component_accounts ORDER BY User, Host"
    )


def _outside_scope(execute: SQLExecutor, user: str, host: str, selected_sql: str) -> bool:
    # Let the server evaluate wildcard database grants, including escaped underscores.
    queries = [
        "SELECT s.SCHEMA_NAME AS Db FROM information_schema.SCHEMATA s "
        "JOIN mysql.db d ON s.SCHEMA_NAME LIKE d.Db "
        f"WHERE d.User = '{user}' AND d.Host = '{host}' AND s.SCHEMA_NAME NOT IN ({selected_sql})"
    ]
    queries.extend(
        f"SELECT Db FROM mysql.{table} WHERE User = '{user}' AND Host = '{host}' AND Db NOT IN ({selected_sql})"
        for table in ("tables_priv", "columns_priv", "procs_priv")
    )
    return bool(execute("SELECT DISTINCT Db FROM (" + " UNION ".join(queries) + ") AS outside_scope"))


def _authentication(execute: SQLExecutor, user: str, host: str, maria: bool) -> tuple[str, ...]:
    if USER.fullmatch(user) is None or HOST.fullmatch(host) is None:
        raise ValueError("A native database principal has an unsupported identity; prepare it before migration")
    if maria:
        query = (
            "SELECT IFNULL(JSON_VALUE(Priv, '$.plugin'), ''), "
            "IFNULL(JSON_VALUE(Priv, '$.authentication_string'), ''), "
            "IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false'), "
            "IFNULL(JSON_QUERY(Priv, '$.auth_or'), '[]') "
            f"FROM mysql.global_priv WHERE User = '{user}' AND Host = '{host}'"
        )
    else:
        query = (
            "SELECT plugin, authentication_string, account_locked, '[]' "
            f"FROM mysql.user WHERE User = '{user}' AND Host = '{host}'"
        )
    rows = execute(query)
    if len(rows) != 1 or len(rows[0]) != NATIVE_ACCOUNT_COLUMNS:
        raise ValueError("Native database authentication evidence is incomplete")
    return rows[0]


def _grants(execute: SQLExecutor, user: str, host: str) -> list[str]:
    rows = execute(f"SHOW GRANTS FOR '{user}'@'{host}'")
    if not rows or any(len(row) != 1 for row in rows):
        raise ValueError("Native database grants are incomplete")
    return sorted(row[0] for row in rows)


def private_credentials(principals: list[dict[str, Any]], *, execute: SQLExecutor = native_sql) -> list[dict[str, Any]]:
    """Root-private export input ONLY; never include these values in inspection evidence or logs."""
    maria = _is_mariadb(execute)
    return [
        {
            "user": principal["user"],
            "host": principal["host"],
            "plugin": auth[0],
            "authentication_string": auth[1],
            "alternatives": auth[3],
            "grants": _grants(execute, principal["user"], principal["host"]),
        }
        for principal in principals
        for auth in [_authentication(execute, principal["user"], principal["host"], maria)]
    ]


def native_owner_password(native: dict[str, str], databases: list[dict[str, Any]]) -> str | None:
    """Private callers only: retain plaintext solely when bound to every selected native-owner hash.

    Virtualmin's hash-only enable callback writes mysql.user, a read-only view on
    qualified MariaDB. A source whose native credential metadata is already stale
    needs explicit preparation before it can promise ordinary billing recovery.
    Independent application principals never export a retained owner's password.
    """
    principals = [row for database in databases for row in database["principals"] if row["user"] == native["user"]]
    if not principals:
        return None
    password = native.get("mysql_pass") or native.get("pass", "")
    if (
        native.get("mysql_user", native["user"]) != native["user"]
        or not password
        or len(password) > MAX_NATIVE_PASSWORD_BYTES
        or any(char in password for char in "\0\r\n")
    ):
        raise ValueError("Prepare current recoverable native owner SQL credentials or an independent application login")
    # nosemgrep: insecure-hash-algorithm-sha1 — Protocol verification of existing mysql_native_password double-SHA1, not a new hash scheme.
    first = hashlib.sha1(password.encode(), usedforsecurity=False).digest()
    # nosemgrep: insecure-hash-algorithm-sha1 — Protocol verification of existing mysql_native_password double-SHA1, not a new hash scheme.
    secret = "*" + hashlib.sha1(first, usedforsecurity=False).hexdigest().upper()
    compatible = {
        hashlib.sha256(
            json.dumps(["mysql_native_password", secret, alternatives], separators=(",", ":")).encode()
        ).hexdigest()
        for alternatives in ("[]", "[{}]")
    }
    if any(row["auth_digest"] not in compatible for row in principals):
        raise ValueError("Prepare current recoverable native owner SQL credentials or an independent application login")
    return password


def _principal(
    execute: SQLExecutor,
    user: str,
    host: str,
    maria: bool,
    selected: tuple[str, ...],
) -> tuple[dict[str, Any], list[str]]:
    plugin, secret, locked, alternatives = _authentication(execute, user, host, maria)
    if locked not in {"true", "false", "1", "0", "Y", "N"}:
        raise ValueError("Native database lock state is unrecognized")
    preparation = []
    if plugin != "mysql_native_password" or alternatives not in {"[]", "[{}]"}:
        preparation.append(f"Prepare a qualified independent authentication plugin for {user}@{host}.")
    grants = _grants(execute, user, host)
    try:
        selected_schema_grants(grants, user, host, selected)
    except ValueError:
        preparation.append(f"Prepare qualified explicit schema-only grants for {user}@{host} before migration.")
    if any(grant.startswith("GRANT PROXY ") for grant in grants):
        preparation.append(f"Remove proxy access for {user}@{host} before qualifying isolated website grants.")
    global_access = any(
        (match := re.match(r"GRANT (.+?) ON \*\.\* TO ", grant)) is not None and match[1] != "USAGE" for grant in grants
    )
    if global_access or _outside_scope(execute, user, host, _names(selected, selected)):
        preparation.append(f"Separate {user}@{host} from retained database grants before fencing the website.")
    roles = execute(
        f"SELECT Role FROM mysql.roles_mapping WHERE User = '{user}' AND Host = '{host}'"
        if maria
        else f"SELECT FROM_USER FROM mysql.role_edges WHERE (FROM_USER = '{user}' AND FROM_HOST = '{host}') "
        f"OR (TO_USER = '{user}' AND TO_HOST = '{host}')"
    )
    if roles:
        preparation.append(f"Prepare explicit isolated grants for {user}@{host}; role-derived access is unqualified.")
    auth = json.dumps([plugin, secret, alternatives], separators=(",", ":")).encode()
    return {
        "user": user,
        "host": host,
        "locked": locked in {"true", "1", "Y"},
        "auth_digest": hashlib.sha256(auth).hexdigest(),
        "grants_digest": hashlib.sha256(json.dumps(grants, separators=(",", ":")).encode()).hexdigest(),
    }, preparation


def _is_mariadb(execute: SQLExecutor) -> bool:
    version = execute("SELECT VERSION()")
    if len(version) != 1 or len(version[0]) != 1:
        raise ValueError("Native MySQL version is unreadable")
    maria = "MariaDB" in version[0][0]
    if not (maria or version[0][0].startswith("8.")):
        raise ValueError("Qualify this database server version before component migration")
    complete_dba = _count(
        execute,
        "SELECT COUNT(*) FROM (SELECT User FROM mysql.user "
        "WHERE CONCAT(User, '@', Host) = CURRENT_USER() AND Select_priv = 'Y' AND Process_priv = 'Y' "
        "AND Super_priv = 'Y' AND Create_user_priv = 'Y') AS component_dba",
    )
    if complete_dba != 1:
        raise ValueError(
            "Native component inventory requires direct global DBA privileges for complete session visibility"
        )
    return maria


def _account_scope(execute: SQLExecutor, selected: tuple[str, ...]) -> tuple[dict[str, SQLRows], set[str]]:
    accounts = {name: _accounts(execute, name) for name in selected}
    scoped: set[tuple[str, str]] = set()
    for rows in accounts.values():
        for row in rows:
            if len(row) != NATIVE_PRINCIPAL_COLUMNS or USER.fullmatch(row[0]) is None or HOST.fullmatch(row[1]) is None:
                raise ValueError("Native database principal inventory is incomplete or unsupported")
            scoped.add((row[0], row[1]))
    shared_usernames = set()
    for user in sorted({user for user, _host in scoped}):
        hosts = execute(f"SELECT Host FROM mysql.user WHERE User = '{user}' ORDER BY Host")
        if any(len(row) != 1 or HOST.fullmatch(row[0]) is None for row in hosts):
            raise ValueError("Native database host account inventory is incomplete")
        all_hosts = {row[0] for row in hosts}
        if not {host for candidate, host in scoped if candidate == user} <= all_hosts:
            raise ValueError("Selected native principal is missing from its complete host account inventory")
        if any((user, host) not in scoped for host in all_hosts):
            shared_usernames.add(user)
    return accounts, shared_usernames


def inspect_databases(
    selected: tuple[str, ...],
    native_owned: tuple[str, ...],
    *,
    execute: SQLExecutor = native_sql,
) -> dict[str, Any]:
    """Inspect selected schemas and their complete privilege dependencies without taking locks."""
    selected_sql = _names(selected, native_owned)
    if not selected:
        return {"databases": [], "preparation": []}
    maria = _is_mariadb(execute)
    query = (
        "SELECT s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME, s.DEFAULT_COLLATION_NAME, "
        "COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0) "
        "FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME "
        f"WHERE s.SCHEMA_NAME IN ({selected_sql}) "
        "GROUP BY s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME, s.DEFAULT_COLLATION_NAME ORDER BY s.SCHEMA_NAME"
    )
    metadata = execute(query)
    if len(metadata) != len(selected) or any(
        len(row) != NATIVE_SCHEMA_COLUMNS or row[0] not in selected for row in metadata
    ):
        raise ValueError("Selected native database inventory is incomplete")
    preparation: list[str] = []
    global_writers = _count(
        execute,
        (
            "SELECT COUNT(*) FROM (SELECT User, Host FROM mysql.user WHERE "
            "(Insert_priv = 'Y' OR Update_priv = 'Y' OR Delete_priv = 'Y' OR Create_priv = 'Y' OR Drop_priv = 'Y' "
            "OR Alter_priv = 'Y' OR Super_priv = 'Y' OR File_priv = 'Y' OR Grant_priv = 'Y') "
            "AND NOT (Host = 'localhost' AND User IN ('root', 'mysql', 'debian-sys-maint', 'mariadb.sys', 'mysql.sys', 'mysql.session'))) AS global_writers"
        ),
    )
    if global_writers:
        preparation.append("Prepare unclassified global database writers before taking a component-only source fence.")
    accounts, shared_usernames = _account_scope(execute, selected)
    databases = []
    for name, charset, collation, size in metadata:
        if not size.isdecimal() or DATABASE.fullmatch(charset) is None or DATABASE.fullmatch(collation) is None:
            raise ValueError("Native database size or character set is unrecognized")
        principals = []
        local_preparation: list[str] = []
        for row in accounts[name]:
            account, account_preparation = _principal(execute, row[0], row[1], maria, selected)
            principals.append(account)
            local_preparation.extend(account_preparation)
            if row[0] in shared_usernames:
                local_preparation.append(
                    f"Separate {row[0]} from retained host accounts; live sessions cannot be classified by grant Host."
                )
        if not principals:
            local_preparation.append(f"Prepare explicit isolated application principals for {name}.")
        events = _count(
            execute,
            f"SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = '{name}' AND STATUS = 'ENABLED'",
        )
        if events:
            local_preparation.append(f"Disable and prepare the selected database events in {name} before migration.")
        safe_definers = ",".join("'" + principal["user"] + "@" + principal["host"] + "'" for principal in principals)
        if safe_definers:
            definers = _count(
                execute,
                (
                    "SELECT COUNT(*) FROM (SELECT DEFINER FROM information_schema.TRIGGERS "
                    f"WHERE TRIGGER_SCHEMA = '{name}' UNION ALL SELECT DEFINER FROM information_schema.ROUTINES "
                    f"WHERE ROUTINE_SCHEMA = '{name}' UNION ALL SELECT DEFINER FROM information_schema.VIEWS "
                    f"WHERE TABLE_SCHEMA = '{name}' UNION ALL SELECT DEFINER FROM information_schema.EVENTS "
                    f"WHERE EVENT_SCHEMA = '{name}') AS unsafe_definers WHERE DEFINER NOT IN ({safe_definers})"
                ),
            )
            if definers:
                local_preparation.append(
                    f"Prepare isolated routine, trigger, view and event definers for {name}; retained-service access is unqualified."
                )
        databases.append(
            {
                "name": name,
                "bytes": int(size),
                "charset": charset,
                "collation": collation,
                "principals": principals,
                "isolated": not local_preparation and not global_writers,
            }
        )
        preparation.extend(local_preparation)
    return {"databases": databases, "preparation": sorted(set(preparation))}
