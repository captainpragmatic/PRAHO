"""Execute the actual quota inventory SQL against the managed MariaDB schema.

This proves SQL and existing-table classification, not Linux quota enforcement.
Run through make test-virtualmin-quota-sql; the container is private to this run.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
from unittest.mock import patch
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[3]
IMAGE = "mariadb:11.8.3"
OFFICIAL_MIRROR = "public.ecr.aws/docker/library/mariadb:11.8.3"
LABEL = "praho.task=quota-sql-776"
FIXTURE_PASSWORD = "private-disposable-quota-sql-fixture"


def command(arguments: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 -- Fixed Docker CLI and private test identity.
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def database_image() -> str:
    for image in (IMAGE, OFFICIAL_MIRROR):
        try:
            command(["docker", "image", "inspect", image])
            return image
        except AssertionError:
            continue
    for image in (OFFICIAL_MIRROR, IMAGE):
        try:
            command(["docker", "pull", image], timeout=180)
            return image
        except AssertionError:
            continue
    raise AssertionError("The pinned official MariaDB image is unavailable from both registries")


@pytest.fixture(scope="module")
def database():
    cid = command(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--label",
            LABEL,
            "--env",
            "MARIADB_ROOT_PASSWORD=" + FIXTURE_PASSWORD,
            "--tmpfs",
            "/var/lib/mysql",
            database_image(),
        ],
        timeout=180,
    )
    if len(cid) != 64 or any(character not in "0123456789abcdef" for character in cid):
        raise AssertionError("Docker did not return an exact disposable container identity")
    prefix = ["docker", "exec", "--env", "MYSQL_PWD=" + FIXTURE_PASSWORD, cid]

    def sql(query: str) -> str:
        return command(
            [
                *prefix,
                "/usr/bin/mariadb",
                "--protocol=socket",
                "--batch",
                "--raw",
                "--skip-column-names",
                "--execute",
                query,
            ]
        )

    try:
        deadline = monotonic() + 60
        poll = Event()
        while True:
            try:
                version = sql("SELECT VERSION()")
                break
            except AssertionError:
                if monotonic() >= deadline:
                    raise
                poll.wait(0.2)
        assert version.startswith("11.8.3-"), version
        yield prefix, sql
    finally:
        actual = json.loads(command(["docker", "inspect", cid]))[0]
        assert actual["Config"]["Labels"].get("praho.task") == "quota-sql-776"
        command(["docker", "rm", "--force", "--volumes", cid])


def test_actual_inventory_refuses_historical_shared_tablespaces(database):
    prefix, sql = database
    schema = "quota_" + uuid4().hex[:12]
    sql(
        f"CREATE DATABASE {schema}; SET GLOBAL innodb_file_per_table=OFF; CREATE TABLE {schema}.old_table (id INT PRIMARY KEY); SET GLOBAL innodb_file_per_table=ON; CREATE TABLE {schema}.new_table (id INT PRIMARY KEY)"
    )
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho_quota_native.py"
    spec = importlib.util.spec_from_file_location("quota_sql_contract", source)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)

    def transport(arguments, **options):
        assert arguments[0] == "/usr/bin/mariadb"
        return command(prefix + arguments)

    # Only the CLI transport changes. The production SQL is executed unchanged.
    with patch.object(native, "_run", side_effect=transport):
        rows = {row["table"]: row for row in native._table_inventory(schema)}
    assert set(rows) == {"old_table", "new_table"}
    assert rows["old_table"]["space"] == 0
    assert rows["new_table"]["space"] > 0
    assert rows["new_table"]["space_type"] == "Single"
    with TemporaryDirectory() as directory:
        target = Path(directory) / schema
        target.mkdir()
        with pytest.raises(ValueError, match="isolated per-table"):
            native.qualify_table_storage(
                target,
                [rows["old_table"]],
                uid=target.stat().st_uid,
                gid=target.stat().st_gid,
                device=target.stat().st_dev,
            )


def test_actual_principal_lookup_finds_every_grant_spelling_only(database):
    prefix, sql = database
    suffix = uuid4().hex[:8]
    name = f"shop_{suffix}"
    other = f"other_{suffix}"
    escaped = name.replace("_", "\\_")
    sql(
        f"CREATE DATABASE {name}; CREATE TABLE {name}.t (id INT); CREATE DATABASE {other}; "
        f"CREATE USER 'plain{suffix}'@'localhost', 'wild{suffix}'@'%', 'tbl{suffix}'@'localhost', "
        f"'foreign{suffix}'@'localhost'; CREATE USER 'locked{suffix}'@'localhost' ACCOUNT LOCK; "
        f"GRANT ALL ON `{escaped}`.* TO 'plain{suffix}'@'localhost'; "
        f"GRANT SELECT ON `shop\\_%`.* TO 'wild{suffix}'@'%'; "
        f"GRANT INSERT ON {name}.t TO 'tbl{suffix}'@'localhost'; "
        f"GRANT ALL ON `{escaped}`.* TO 'locked{suffix}'@'localhost'; "
        f"GRANT ALL ON `{other}`.* TO 'foreign{suffix}'@'localhost'"
    )
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho_hosting_node.py"
    spec = importlib.util.spec_from_file_location("quota_sql_node", source)
    node = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(node)

    def transport(arguments, **options):
        assert arguments[0] == "/usr/bin/mariadb"
        return command(prefix + arguments)

    for mode in ("", "NO_BACKSLASH_ESCAPES"):
        sql(f"SET GLOBAL sql_mode='{mode}'")
        with patch.object(node, "_run", side_effect=transport):
            found = {user: locked for user, _host, locked in node._database_principals([name])}
        assert found == {
            f"plain{suffix}": False,
            f"wild{suffix}": False,
            f"tbl{suffix}": False,
            f"locked{suffix}": True,
        }
    sql("SET GLOBAL sql_mode=DEFAULT")


def test_the_acceptance_fill_is_a_full_random_megabyte(database):
    _prefix, sql = database
    source = ROOT / "tests/virtualmin_lab/native/quota_acceptance.py"
    spec = importlib.util.spec_from_file_location("quota_acceptance_fill", source)
    acceptance = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", list(sys.path)):
        spec.loader.exec_module(acceptance)
    schema = "fill_" + uuid4().hex[:12]
    fill = acceptance.FILL_VALUE.format(schema=schema)
    output = sql(
        f"CREATE DATABASE {schema}; CREATE TABLE {schema}.quota_fill (id BIGINT PRIMARY KEY AUTO_INCREMENT, "  # noqa: S608 -- Generated fixture schema.
        "data LONGBLOB) ENGINE=InnoDB; "
        f"SET STATEMENT group_concat_max_len=2097152 FOR INSERT INTO {schema}.quota_fill (data) {fill}; "
        f"SET STATEMENT group_concat_max_len=2097152 FOR INSERT INTO {schema}.quota_fill (data) {fill}; "
        f"SELECT MIN(LENGTH(data)), COUNT(DISTINCT data), "
        f"LENGTH(COMPRESS(MIN(data))) > 1000000 FROM {schema}.quota_fill"
    )
    assert output.split()[-3:] == ["1048576", "2", "1"]


def test_actual_access_paths_a_login_lock_cannot_stop_are_named(database):
    prefix, sql = database
    suffix = uuid4().hex[:8]
    name, other = f"shop_{suffix}", f"other_{suffix}"
    sql(
        f"CREATE DATABASE {name}; CREATE TABLE {name}.t (id INT); CREATE DATABASE {other}; "  # noqa: S608 -- Generated fixture names.
        f"CREATE USER 'own{suffix}'@'localhost', 'exec{suffix}'@'localhost', 'glob{suffix}'@'%'; "
        f"CREATE ROLE 'role{suffix}'; GRANT ALL ON {name}.* TO 'own{suffix}'@'localhost'; "
        f"GRANT ALL ON {name}.* TO 'role{suffix}'; GRANT INSERT ON *.* TO 'glob{suffix}'@'%'; "
        f"CREATE DEFINER='own{suffix}'@'localhost' PROCEDURE {other}.p() SQL SECURITY DEFINER "
        f"INSERT INTO {name}.t VALUES (1); "
        f"CREATE DEFINER='own{suffix}'@'localhost' PROCEDURE {name}.q() SQL SECURITY DEFINER "
        f"INSERT INTO {name}.t VALUES (2); "
        f"GRANT EXECUTE ON PROCEDURE {name}.q TO 'exec{suffix}'@'localhost'; "
        f"CREATE DEFINER='own{suffix}'@'localhost' EVENT {name}.e ON SCHEDULE EVERY 1 DAY DISABLE "
        f"DO INSERT INTO {name}.t VALUES (3)"
    )
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho_hosting_node.py"
    spec = importlib.util.spec_from_file_location("quota_sql_paths", source)
    node = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(node)

    def transport(arguments, **options):
        assert arguments[0] == "/usr/bin/mariadb"
        return command(prefix + arguments)

    with patch.object(node, "_run", side_effect=transport):
        principals = node._database_principals([name])
        found = node._unsupported_access_paths([name], principals)
    users = {user for user, _host, _locked in principals}
    assert {f"own{suffix}", f"exec{suffix}", f"role{suffix}"} <= users
    assert f"role 'role{suffix}'" in found
    assert f"global privileges 'glob{suffix}'@'%'" in found
    assert f"routine {other}.p runs as own{suffix}@localhost" in found
    assert f"event {name}.e runs as own{suffix}@localhost" in found
    assert not any(f"{name}.q" in item for item in found)


def test_actual_root_events_and_cross_schema_cascades_are_named(database):
    prefix, sql = database
    suffix = uuid4().hex[:8]
    name, other = f"shop_{suffix}", f"crm_{suffix}"
    sql(
        f"CREATE DATABASE {name}; CREATE DATABASE {other}; "  # noqa: S608 -- Generated fixture names.
        f"CREATE TABLE {other}.customers (id INT PRIMARY KEY) ENGINE=InnoDB; "
        f"CREATE TABLE {name}.orders (id INT PRIMARY KEY, customer INT, CONSTRAINT fk_cascade FOREIGN KEY (customer) "
        f"REFERENCES {other}.customers (id) ON DELETE CASCADE) ENGINE=InnoDB; "
        f"CREATE TABLE {name}.notes (id INT PRIMARY KEY, customer INT, CONSTRAINT fk_restrict FOREIGN KEY (customer) "
        f"REFERENCES {other}.customers (id)) ENGINE=InnoDB; "
        f"CREATE TABLE {name}.lines (id INT PRIMARY KEY, ord INT, CONSTRAINT fk_inside FOREIGN KEY (ord) "
        f"REFERENCES {name}.orders (id) ON DELETE CASCADE) ENGINE=InnoDB; "
        f"CREATE DEFINER='root'@'localhost' EVENT {other}.nightly ON SCHEDULE EVERY 1 DAY ENABLE "
        f"DO DELETE FROM {name}.orders; "
        f"CREATE DEFINER='root'@'localhost' EVENT {other}.parked ON SCHEDULE EVERY 1 DAY DISABLE DO DO 1"
    )
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho_hosting_node.py"
    spec = importlib.util.spec_from_file_location("quota_sql_cascades", source)
    node = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(node)

    def transport(arguments, **options):
        assert arguments[0] == "/usr/bin/mariadb"
        return command(prefix + arguments)

    with patch.object(node, "_run", side_effect=transport):
        found = node._unsupported_access_paths([name], [])
    assert f"event {other}.nightly runs as root@localhost" in found
    assert not any(f"{other}.parked" in item for item in found)
    assert f"foreign key {name}.orders.fk_cascade cascades from {other}.customers" in found
    assert not any("fk_restrict" in item or "fk_inside" in item for item in found)
