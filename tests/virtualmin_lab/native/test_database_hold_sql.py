"""The database write hold against a real MariaDB 11.8 (#776, plan 7A.4).

The production helper (praho_database_hold.py, run by virtualmin_database_hold.yml) executes unchanged; only its
SQL client transport goes through `docker exec` into a disposable container private to this run. Each case is an
assumption tests/provisioning/test_database_hold_node.py encodes in its FakeDatabase, checked on the real server.
Run through make test-virtualmin-database-hold-sql.
"""

# ruff: noqa: S608 -- Every SQL text here is built from generated fixture names in a disposable container.

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
from typing import Any
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[3]
FILES = ROOT / "services/platform/infrastructure/ansible/playbooks/files"
IMAGE = "mariadb:11.8.3"
OFFICIAL_MIRROR = "public.ecr.aws/docker/library/mariadb:11.8.3"
LABEL = "praho.task=database-hold-sql-776"
FIXTURE_PASSWORD = "private-disposable-database-hold-fixture"
TENANT_PASSWORD = "private-disposable-tenant-fixture"
INSTALLATION = "12345678-1234-1234-1234-123456789abc"
DENIED = re.compile(r"denied|not allowed", re.IGNORECASE)


def command(arguments: list[str], *, timeout: int = 30, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- Fixed Docker CLI and private test identity.
        arguments, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )


def checked(arguments: list[str], *, timeout: int = 30) -> str:
    result = command(arguments, timeout=timeout)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def database_image() -> str:
    for image in (IMAGE, OFFICIAL_MIRROR):
        if command(["docker", "image", "inspect", image]).returncode == 0:
            return image
    for image in (OFFICIAL_MIRROR, IMAGE):
        if command(["docker", "pull", image], timeout=180).returncode == 0:
            return image
    raise AssertionError("The pinned official MariaDB image is unavailable from both registries")


def load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # Dataclasses resolve their annotations through the module registry.
    spec.loader.exec_module(module)
    return module


class Server:
    """The disposable MariaDB: root over its socket, tenant sessions, and the helper's SQL transport."""

    def __init__(self, cid: str) -> None:
        self.cid = cid

    def client(self, user: str = "root", password: str = FIXTURE_PASSWORD) -> list[str]:
        login = [] if user == "root" else ["-u", user]
        return [
            "docker",
            "exec",
            "-i",
            "--env",
            "MYSQL_PWD=" + password,
            self.cid,
            "/usr/bin/mariadb",
            "--protocol=socket",
            *login,
            "--batch",
            "--raw",
            "--skip-column-names",
        ]

    def sql(self, query: str) -> str:
        result = command(self.client(), stdin=query + ";\n")
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout.strip()

    def tenant(self, user: str, query: str) -> subprocess.CompletedProcess[str]:
        return command(self.client(user, TENANT_PASSWORD), stdin=query + ";\n", timeout=60)

    def background(self, user: str, query: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(  # noqa: S603 -- Fixed Docker CLI and private test identity.
            self.client(user, TENANT_PASSWORD),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None
        process.stdin.write(query + ";\n")
        process.stdin.close()
        return process

    def alive(self, user: str) -> bool:
        return self.sql(f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE BINARY USER = '{user}'") != "0"

    def wait_for(self, user: str, state: str) -> None:
        """Until the user's session is inside its statement, so the hold meets it mid-flight."""
        deadline = monotonic() + 20
        while monotonic() < deadline:
            if self.sql(
                f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE BINARY USER = '{user}' "
                f"AND STATE = '{state}'"
            ) != "0":
                return
            Event().wait(0.1)
        raise AssertionError(f"{user} never reached {state}")

    def native(self, hold: types.ModuleType) -> Any:
        """The production NativeDatabase, its SQL client pointed at the container."""
        database = hold.NativeDatabase()
        prefix = self.client()[: self.client().index("/usr/bin/mariadb")]

        def run(arguments, **options):
            assert arguments[0] == "/usr/bin/mysql", arguments
            check = options.pop("check", False)
            return subprocess.run([*prefix, "/usr/bin/mariadb", *arguments[1:]], check=check, **options)  # noqa: S603

        database.mysql.subprocess = types.SimpleNamespace(run=run)
        return database


@pytest.fixture(scope="module")
def server():
    cid = checked(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--label",
            LABEL,
            "--env",
            "MARIADB_ROOT_PASSWORD=" + FIXTURE_PASSWORD,
            # Only root@localhost: the image's default root@'%' is a non-DBA global writer, refused by name.
            "--env",
            "MARIADB_ROOT_HOST=localhost",
            "--tmpfs",
            "/var/lib/mysql",
            database_image(),
        ],
        timeout=180,
    )
    if len(cid) != 64 or any(character not in "0123456789abcdef" for character in cid):
        raise AssertionError("Docker did not return an exact disposable container identity")
    instance = Server(cid)
    try:
        deadline = monotonic() + 60
        while True:
            try:
                version = instance.sql("SELECT VERSION()")
                break
            except AssertionError:
                if monotonic() >= deadline:
                    raise
                Event().wait(0.2)
        assert version.startswith("11.8.3-"), version
        yield instance
    finally:
        actual = json.loads(checked(["docker", "inspect", cid]))[0]
        assert actual["Config"]["Labels"].get("praho.task") == "database-hold-sql-776"
        checked(["docker", "rm", "--force", "--volumes", cid])


@pytest.fixture(scope="module")
def hold() -> types.ModuleType:
    return load("database_hold_lab", FILES / "praho_database_hold.py")


class Account:
    """One hosting account as Virtualmin leaves it: a domain file, its databases and its escaped grants."""

    def __init__(self, server: Server, hold: types.ModuleType, root: Path) -> None:
        self.server, self.hold = server, hold
        suffix = uuid4().hex[:8]
        self.user = f"h{suffix}"
        self.db, self.logs = f"h{suffix}_db", f"h{suffix}_logs"
        self.escaped = {name: name.replace("_", "\\_") for name in (self.db, self.logs)}
        self.paths = hold.Paths(
            run=root / "run",
            migration=root / "migration",
            component_fences=root / "component-fences",
            component_database_fences=root / "component-database-fences",
            state=root / "database-hold",
            domains=root / "domains",
            installation=root / "installation",
        )
        self.paths.domains.mkdir()
        self.paths.installation.write_text(INSTALLATION + "\n")
        domain = self.paths.domains / "42"
        domain.write_text(f"id=42\ndom={self.user}.test\ndb_mysql={self.db} {self.logs}\n")
        os.chmod(domain, 0o600)
        self.identity = {"domain_id": "42", "domain": f"{self.user}.test", "installation": INSTALLATION}
        server.sql(
            f"CREATE DATABASE {self.db}; CREATE TABLE {self.db}.t (x INT) ENGINE=InnoDB; "
            f"CREATE DATABASE {self.logs}; CREATE TABLE {self.logs}.t (x INT) ENGINE=InnoDB; "
            f"CREATE USER '{self.user}'@'localhost' IDENTIFIED BY '{TENANT_PASSWORD}'; "
            f"GRANT ALL PRIVILEGES ON `{self.escaped[self.db]}`.* TO '{self.user}'@'localhost'; "
            f"GRANT ALL PRIVILEGES ON `{self.escaped[self.logs]}`.* TO '{self.user}'@'localhost'"
        )

    def node(self, **options: Any) -> Any:
        options.setdefault("drain_seconds", 15)
        options.setdefault("lock_seconds", 1)
        return self.hold.DatabaseHold(self.paths, self.server.native(self.hold), **options)

    def act(self, action: str, *, generation: int = 1, token: str | None = None, **options: Any) -> dict[str, Any]:
        request: dict[str, Any] = {"action": action, "identity": self.identity}
        if action in {"probe", "hold", "fence"}:
            request["token"] = token or self.token
        if action != "fence":
            request["generation"] = generation
        return self.node(**options).perform(request)

    def rows(self) -> str:
        return self.server.sql(f"SELECT * FROM mysql.db WHERE User = '{self.user}' ORDER BY Db")

    def count(self, database: str | None = None) -> int:
        return int(self.server.sql(f"SELECT COUNT(*) FROM {database or self.db}.t"))


@pytest.fixture
def account(server, hold):
    with TemporaryDirectory() as directory:
        created = Account(server, hold, Path(directory))
        created.token = str(uuid4())
        yield created


def test_the_stock_server_has_no_global_writer_outside_the_dba_list(server, hold):
    """Evidence for both the hold and the barrier: every account and its global privileges on a fresh 11.8.3."""
    rows = server.sql("SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES")
    print("USER_PRIVILEGES on mariadb:11.8.3 (MARIADB_ROOT_HOST=localhost):\n" + rows)
    native = server.native(hold).global_privileges()
    writers = {p for p, names in native.items() if p not in hold.DBA and names - hold.READ_ONLY_GLOBALS}
    assert writers == set(), native
    # Both encode the GRANTEE spelling: 'user'@'host'.
    assert "'root'@'localhost'\t" in rows


def test_a_held_tenant_reads_and_deletes_but_cannot_grow(server, account):
    server.tenant(account.user, f"INSERT INTO {account.db}.t VALUES (1), (2), (3)")
    receipt = account.act("hold")
    assert (receipt["outcome"], receipt["phase"]) == ("ok", "held"), receipt
    attempts = {
        "INSERT": f"INSERT INTO {account.db}.t VALUES (4)",
        "UPDATE": f"UPDATE {account.db}.t SET x = 9",
        "CREATE TABLE": f"CREATE TABLE {account.db}.grown (y INT)",
        "ALTER": f"ALTER TABLE {account.db}.t ADD COLUMN y INT",
        "CREATE VIEW": f"CREATE VIEW {account.db}.v AS SELECT x FROM {account.db}.t",
        "CREATE TEMPORARY TABLE": f"CREATE TEMPORARY TABLE {account.db}.tmp (y INT)",
        "CREATE PROCEDURE": f"CREATE PROCEDURE {account.db}.p() SELECT 1",
        "LOAD DATA": f"LOAD DATA LOCAL INFILE '/etc/hostname' INTO TABLE {account.db}.t",
        "INSERT after USE": f"USE {account.db}; INSERT INTO t VALUES (5)",
    }
    for name, statement in attempts.items():
        result = server.tenant(account.user, statement)
        assert result.returncode != 0, name
        assert DENIED.search(result.stderr), (name, result.stderr)
    assert account.count() == 3
    assert server.tenant(account.user, f"SELECT COUNT(*) FROM {account.db}.t").stdout.strip() == "3"
    assert server.tenant(account.user, f"DELETE FROM {account.db}.t WHERE x = 1").returncode == 0
    assert account.count() == 2
    assert server.tenant(account.user, f"DROP TABLE {account.logs}.t").returncode == 0
    assert server.tenant(account.user, f"DROP DATABASE {account.logs}").returncode == 0


def test_without_the_drain_a_session_in_the_database_keeps_writing(server, account):
    """Why the drain exists: MariaDB caches database privileges per session's current database."""
    session = server.background(account.user, f"USE {account.db}; SELECT SLEEP(4); INSERT INTO t VALUES (1)")
    server.wait_for(account.user, "User sleep")
    server.sql(f"REVOKE INSERT ON `{account.escaped[account.db]}`.* FROM '{account.user}'@'localhost'")
    session.wait(timeout=30)
    assert session.returncode == 0, session.stderr.read()
    assert account.count() == 1
    # A fresh session is checked against the grants.
    assert server.tenant(account.user, f"USE {account.db}; INSERT INTO t VALUES (2)").returncode != 0


def test_a_session_that_ran_use_before_the_hold_cannot_insert_once_it_is_held(server, account):
    session = server.background(account.user, f"USE {account.db}; SELECT SLEEP(20); INSERT INTO t VALUES (1)")
    server.wait_for(account.user, "User sleep")
    receipt = account.act("hold")
    assert (receipt["phase"], receipt["sessions_remaining"]) == ("held", []), receipt
    session.wait(timeout=30)
    assert session.returncode != 0
    assert account.count() == 0


def test_a_statement_in_flight_from_no_current_database_is_ended(server, account):
    session = server.background(account.user, f"INSERT INTO {account.db}.t SELECT SLEEP(20)")
    server.wait_for(account.user, "User sleep")
    receipt = account.act("hold")
    assert receipt["phase"] == "held", receipt
    session.wait(timeout=30)
    assert session.returncode != 0
    assert account.count() == 0  # The killed statement rolled back.


def test_another_tenants_busy_session_with_the_same_name_in_other_case_survives(server, account):
    other = account.user.upper()
    database = f"o{account.user}"
    server.sql(
        f"CREATE DATABASE {database}; CREATE TABLE {database}.t (x INT) ENGINE=InnoDB; "
        f"CREATE USER '{other}'@'localhost' IDENTIFIED BY '{TENANT_PASSWORD}'; "
        f"GRANT ALL PRIVILEGES ON `{database}`.* TO '{other}'@'localhost'"
    )
    # Busy for longer than the hold can take, so the hold meets it whatever its own timing.
    session = server.background(other, f"USE {database}; SELECT SLEEP(25); INSERT INTO t VALUES (1)")
    server.wait_for(other, "User sleep")
    assert account.act("hold")["phase"] == "held"
    assert session.poll() is None and server.alive(other), "the other tenant's session was ended"
    session.wait(timeout=40)
    assert session.returncode == 0, session.stderr.read()
    assert account.count(database) == 1


def test_a_definer_routine_and_an_event_of_the_tenant_cannot_write(server, account):
    server.sql("SET GLOBAL event_scheduler = ON")
    try:
        created = server.tenant(
            account.user,
            f"CREATE PROCEDURE {account.db}.grow() SQL SECURITY DEFINER INSERT INTO {account.db}.t VALUES (7); "
            f"CREATE EVENT {account.db}.slow ON SCHEDULE AT CURRENT_TIMESTAMP "
            f"DO INSERT INTO {account.db}.t SELECT 8 FROM (SELECT SLEEP(25)) AS held; "
            f"CREATE EVENT {account.db}.tick ON SCHEDULE EVERY 1 SECOND DO INSERT INTO {account.db}.t VALUES (9)",
        )
        assert created.returncode == 0, created.stderr
        deadline = monotonic() + 10
        while account.count() == 0 and monotonic() < deadline:
            Event().wait(0.2)
        assert account.count() > 0, "the recurring event never ran"
        # The one-shot event is inside its write, past every privilege check, when the hold starts.
        server.wait_for(account.user, "User sleep")
        assert account.act("hold")["phase"] == "held"
        settled = account.count()
        Event().wait(30)  # Past the end of the one-shot event's sleep, and many recurring runs.
        assert account.count() == settled
        assert server.sql(f"SELECT COUNT(*) FROM {account.db}.t WHERE x = 8") == "0"
        assert server.tenant(account.user, f"CALL {account.db}.grow()").returncode != 0
        assert account.count() == settled
    finally:
        server.sql("SET GLOBAL event_scheduler = OFF")


def test_release_restores_partial_grants_and_a_row_mariadb_deleted(server, account):
    server.sql(
        f"REVOKE ALL PRIVILEGES ON `{account.escaped[account.db]}`.* FROM '{account.user}'@'localhost'; "
        f"REVOKE ALL PRIVILEGES ON `{account.escaped[account.logs]}`.* FROM '{account.user}'@'localhost'; "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{account.escaped[account.db]}`.* TO '{account.user}'@'localhost' "
        "WITH GRANT OPTION; "
        f"GRANT INSERT ON `{account.escaped[account.logs]}`.* TO '{account.user}'@'localhost'"
    )
    before = account.rows()
    grants = server.sql(f"SHOW GRANTS FOR '{account.user}'@'localhost'")
    assert account.act("hold")["phase"] == "held"
    held = account.rows()
    assert account.escaped[account.logs] not in held  # Its only privilege went, so MariaDB deleted the row.
    assert "\\_db" in held  # The stored value stays escaped: never re-quoted into a wildcard.
    assert account.act("release")["phase"] == "released"
    assert account.rows() == before
    assert server.sql(f"SHOW GRANTS FOR '{account.user}'@'localhost'") == grants


def test_the_barriers_owner_probe_passes_after_release(server, account):
    assert account.act("hold")["phase"] == "held"
    assert account.act("release")["phase"] == "released"
    probe = server.tenant(
        account.user, f"CREATE TABLE {account.db}.probe (x INT); INSERT INTO {account.db}.probe VALUES (1); "
        f"DROP TABLE {account.db}.probe",
    )
    assert probe.returncode == 0, probe.stderr


def test_global_privileges_are_read_and_classified_as_the_server_names_them(server, account, hold):
    name = account.user
    server.sql(
        f"CREATE USER 'm{name}'@'localhost'; GRANT PROCESS, RELOAD ON *.* TO 'm{name}'@'localhost'; "
        f"CREATE USER 'ro''{name}'@'localhost'; GRANT SELECT ON *.* TO 'ro''{name}'@'localhost'"
    )
    try:
        rows = server.sql("SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES")
        assert f"'m{name}'@'localhost'\tPROCESS\tNO" in rows
        # GRANTEE does not escape an apostrophe in a name; the barrier compares the whole string, never root.
        assert f"'ro'{name}'@'localhost'\tSELECT\tNO" in rows
        assert account.act("probe")["outcome"] == "ok"
        server.sql(f"GRANT EXECUTE ON *.* TO 'm{name}'@'localhost'")
        refused = account.act("probe")
        assert (refused["outcome"], refused["code"]) == ("refused", "global_privilege"), refused
    finally:
        server.sql(f"DROP USER 'm{name}'@'localhost'; DROP USER 'ro''{name}'@'localhost'")


def test_the_existence_query_proves_a_drop_only_to_an_identity_that_sees_mysql(server, account):
    """7A.1's collector and quota pre-check: exactly `1<TAB>0` proves a database dropped."""
    quota = load("quota_native_lab", FILES / "praho_quota_native.py")
    prefix = server.client()[: server.client().index("/usr/bin/mariadb")]

    def run(arguments, **options):
        assert arguments[0] == "/usr/bin/mariadb"
        result = command([*prefix, *arguments], timeout=options.get("timeout", 10))
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert quota.schema_presence(account.db, run=run) is True
    assert quota.schema_presence(f"gone_{account.user}", run=run) is False
    # The collector's own query text, read from the Perl source, gives the same answers.
    perl = (FILES / "praho-usage-metadata.pl").read_text()
    parts = re.search(r'my \$query = "([^"]+)"\s*\n\s*\."([^"]+)";', perl)
    assert parts is not None
    query = (parts[1] + parts[2]).replace("$name", f"gone_{account.user}")
    assert server.sql(query) == "1\t0"
    # An identity that cannot see `mysql` gets 0 for every name: unknown, never a drop.
    server.sql(f"CREATE USER 'n{account.user}'@'localhost' IDENTIFIED BY '{TENANT_PASSWORD}'")
    blind = server.tenant(f"n{account.user}", query.replace(f"gone_{account.user}", account.db))
    assert blind.stdout.strip() == "0\t0"
