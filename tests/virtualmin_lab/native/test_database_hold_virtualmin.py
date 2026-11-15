"""The database write hold on a stock Virtualmin 8.3.0 node (#776, plan 7A.4).

A disposable container of the lab image (praho-virtualmin-lab:8.3.0, Debian 12, its MariaDB 10.11) creates a real
hosting account whose domain name gives an underscore database, then runs praho_database_hold.py inside it as root
from a private directory, the way virtualmin_database_hold.yml does. It records the stock server's global privileges
as evidence that a fresh node passes both the hold and the write barrier.
Run through make test-virtualmin-database-hold-node (needs the lab image: make virtualmin-lab-build).
"""

# ruff: noqa: S608 -- Every SQL text here is built from fixed fixture names in a disposable container.

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[3]
FILES = ROOT / "services/platform/infrastructure/ansible/playbooks/files"
IMAGE = "praho-virtualmin-lab:8.3.0"
LABEL = "praho.task=database-hold-virtualmin-776"
DOMAIN = "shop-hold.test"
DATABASE = "shop_hold"  # Virtualmin's name for the domain's database: the hyphen becomes an underscore.
USER = "shop-hold"
PASSWORD = "private-disposable-hold-fixture"
INSTALLATION = "12345678-1234-1234-1234-123456789abc"
HELPER = f"/root/praho-database-hold-{uuid4().hex[:8]}"


def command(arguments: list[str], *, timeout: int = 60, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- Fixed Docker CLI and private test identity.
        arguments, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )


def checked(arguments: list[str], *, timeout: int = 60, stdin: str | None = None) -> str:
    result = command(arguments, timeout=timeout, stdin=stdin)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


def load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # Dataclasses resolve their annotations through the module registry.
    spec.loader.exec_module(module)
    return module


class Node:
    def __init__(self, cid: str) -> None:
        self.cid = cid

    def run(self, *arguments: str, stdin: str | None = None, timeout: int = 120) -> str:
        return checked(["docker", "exec", "-i", self.cid, *arguments], stdin=stdin, timeout=timeout)

    def sql(self, query: str) -> str:
        return self.run("/usr/bin/mariadb", "--batch", "--raw", "--skip-column-names", stdin=query + ";\n")

    def tenant(self, query: str) -> subprocess.CompletedProcess[str]:
        return command(
            [
                "docker",
                "exec",
                "-i",
                "--env",
                "MYSQL_PWD=" + PASSWORD,
                self.cid,
                "/usr/bin/mariadb",
                "-u",
                USER,
                "--batch",
                "--raw",
                "--skip-column-names",
            ],
            stdin=query + ";\n",
        )

    def act(self, action: str, identity: dict[str, str], *, token: str, generation: int = 1) -> dict[str, Any]:
        request: dict[str, Any] = {"action": action, "identity": identity}
        if action in {"probe", "hold", "fence"}:
            request["token"] = token
        if action != "fence":
            request["generation"] = generation
        output = self.run("/usr/bin/python3", f"{HELPER}/praho_database_hold.py", stdin=json.dumps(request), timeout=180)
        return json.loads(output)


@pytest.fixture(scope="module")
def node():
    if command(["docker", "image", "inspect", IMAGE]).returncode:
        raise AssertionError(f"{IMAGE} is not built: make virtualmin-lab-build")
    cid = checked(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--privileged",
            "--cgroupns=host",
            "--volume",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--stop-signal",
            "SIGRTMIN+3",
            # Virtualmin needs a default address; the bridge gives one and the test reaches nothing through it.
            "--network",
            "bridge",
            "--label",
            LABEL,
            IMAGE,
        ],
        timeout=120,
    )
    if len(cid) != 64 or any(character not in "0123456789abcdef" for character in cid):
        raise AssertionError("Docker did not return an exact disposable container identity")
    instance = Node(cid)
    try:
        deadline = monotonic() + 300
        while command(["docker", "exec", cid, "/usr/local/sbin/virtualmin-lab-health"]).returncode:
            if monotonic() >= deadline:
                raise AssertionError("The Virtualmin lab node never became healthy")
            Event().wait(2)
        instance.evidence = instance.sql(
            "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES ORDER BY 1, 2"
        )
        instance.run(
            "virtualmin", "create-domain", "--domain", DOMAIN, "--pass", PASSWORD, "--unix", "--dir", "--mysql"
        )
        instance.domain_id = instance.run(
            "sh", "-c", f"grep -lx 'dom={DOMAIN}' /etc/webmin/virtual-server/domains/* | xargs -n1 basename"
        )
        # Virtualmin generates the database password; the test logs in as the tenant with a known one. One
        # statement per account: on this 10.11 a two-account ALTER USER changed only the last one.
        instance.sql(
            f"ALTER USER '{USER}'@'localhost' IDENTIFIED BY '{PASSWORD}'; "
            f"ALTER USER '{USER}'@'127.0.0.1' IDENTIFIED BY '{PASSWORD}'"
        )
        instance.run("install", "-d", "-m", "0700", "/var/lib/praho/usage", HELPER)
        instance.run("sh", "-c", f"umask 077; echo {INSTALLATION} > /var/lib/praho/usage/installation")
        for name in ("praho_database_hold.py", "praho-component-mysql.py"):
            checked(["docker", "cp", str(FILES / name), f"{cid}:{HELPER}/{name}"])
        yield instance
    finally:
        actual = json.loads(checked(["docker", "inspect", cid]))[0]
        assert actual["Config"]["Labels"].get("praho.task") == "database-hold-virtualmin-776"
        checked(["docker", "rm", "--force", "--volumes", cid])


@pytest.fixture
def identity(node) -> dict[str, str]:
    return {"domain_id": node.domain_id, "domain": DOMAIN, "installation": INSTALLATION}


def test_a_stock_node_has_no_global_writer_for_the_hold_or_the_barrier(node):
    print(f"USER_PRIVILEGES on a stock {IMAGE} node before any account:\n{node.evidence}")
    hold = load("database_hold_virtualmin", FILES / "praho_database_hold.py")
    granted: dict[str, set[str]] = {}
    for line in node.evidence.splitlines():
        grantee, privilege, grantable = line.split("\t")
        granted.setdefault(grantee, set()).update({privilege, "GRANT OPTION"} if grantable == "YES" else {privilege})
    dba = {f"'{user}'@'{host}'" for user, host in hold.DBA}
    # The barrier's lists are pinned equal to these by test_migration_barrier_script.
    writers = {grantee for grantee, names in granted.items() if grantee not in dba and names - hold.READ_ONLY_GLOBALS}
    assert writers == set(), granted


def test_virtualmin_stores_the_underscore_database_escaped_for_every_host(node):
    rows = node.sql(f"SELECT Host, Db FROM mysql.db WHERE User = '{USER}' ORDER BY Host")
    assert rows.splitlines() == ["127.0.0.1\tshop\\_hold", "localhost\tshop\\_hold"]


def test_a_hold_and_release_on_the_real_account(node, identity):
    token = str(uuid4())
    created = node.tenant(f"CREATE TABLE {DATABASE}.t (x INT); INSERT INTO {DATABASE}.t VALUES (1)")
    assert created.returncode == 0, created.stderr
    before = node.sql(f"SELECT * FROM mysql.db WHERE User = '{USER}' ORDER BY Host, Db")
    assert node.act("probe", identity, token=token)["outcome"] == "ok"
    receipt = node.act("hold", identity, token=token)
    assert (receipt["outcome"], receipt["phase"]) == ("ok", "held"), receipt
    assert node.sql(f"SELECT Host, Insert_priv, Create_priv FROM mysql.db WHERE User = '{USER}' ORDER BY Host") == (
        "127.0.0.1\tN\tN\nlocalhost\tN\tN"
    )
    denied = node.tenant(f"INSERT INTO {DATABASE}.t VALUES (2)")
    assert denied.returncode != 0 and "denied" in denied.stderr, denied.stderr
    assert node.tenant(f"SELECT COUNT(*) FROM {DATABASE}.t").stdout.strip() == "1"
    verified = node.act("verify", identity, token=token)
    assert (verified["phase"], verified["drift"], verified["sessions_remaining"]) == ("verified", [], [])
    assert node.act("release", identity, token=token)["phase"] == "released"
    assert node.sql(f"SELECT * FROM mysql.db WHERE User = '{USER}' ORDER BY Host, Db") == before
    probe = node.tenant(
        f"CREATE TABLE {DATABASE}.probe (x INT); INSERT INTO {DATABASE}.probe VALUES (1); DROP TABLE {DATABASE}.probe"
    )
    assert probe.returncode == 0, probe.stderr
