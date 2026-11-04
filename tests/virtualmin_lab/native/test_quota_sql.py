"""Execute the actual quota inventory SQL against the managed MariaDB schema.

This proves SQL and existing-table classification, not Linux quota enforcement.
Run through make test-virtualmin-quota-sql; the container is private to this run.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
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
                target, [rows["old_table"]], gid=target.stat().st_gid, device=target.stat().st_dev
            )
