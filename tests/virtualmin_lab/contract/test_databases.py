"""Contract: databases of a domain."""

from __future__ import annotations

from apps.common.types import Retriability
from tests.virtualmin_lab.contract.harness import (
    SANDBOX_DOMAIN,
    Lab,
    assert_accepted,
    assert_mutating,
    assert_refused,
    covers,
)

ABSENT = "contract-absent.praho.test"


def _database_names(lab: Lab) -> list[str]:
    listing = lab.quiet("list-databases", {"domain": SANDBOX_DOMAIN, "name-only": ""})
    assert_accepted(listing)
    return [row["name"] for row in listing.response.data["data"]]


def _drop(lab: Lab, name: str) -> None:
    if name in _database_names(lab):
        assert_accepted(lab.quiet("delete-database", {"domain": SANDBOX_DOMAIN, "name": name, "type": "mysql"}))


@covers("list-databases")
def test_list_databases(lab: Lab) -> None:
    def run() -> None:
        table = lab.call("list-databases", {"domain": SANDBOX_DOMAIN}, case="table", note="the plain table")
        assert_accepted(table)
        names = lab.call(
            "list-databases",
            {"domain": SANDBOX_DOMAIN, "name-only": ""},
            case="name_only",
            note="the lab's database check",
        )
        assert_accepted(names)
        assert [row["name"] for row in names.response.data["data"]] == ["contract"]

        absent = lab.call("list-databases", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )

    lab.prove_read_only("list-databases", run)


@covers("create-database")
def test_create_database(lab: Lab) -> None:
    assert_mutating("create-database")
    params = {"domain": SANDBOX_DOMAIN, "name": "contractdbnew", "type": "mysql"}
    _drop(lab, "contractdbnew")
    try:
        created = lab.call("create-database", params, case="success", note="a MySQL database for the domain")
        assert_accepted(created)
        assert "contractdbnew" in _database_names(lab)

        again = lab.call("create-database", params, case="already_associated", note="the same database twice")
        assert_refused(
            again,
            error="A database with the same name and type is already associated with this server",
            retriability=Retriability.UNKNOWN,
            exact=True,
        )
    finally:
        _drop(lab, "contractdbnew")
    absent = lab.call("create-database", {**params, "domain": ABSENT}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("delete-database")
def test_delete_database(lab: Lab) -> None:
    assert_mutating("delete-database")
    params = {"domain": SANDBOX_DOMAIN, "name": "contractdbold", "type": "mysql"}
    assert_accepted(lab.quiet("create-database", params))
    try:
        deleted = lab.call("delete-database", params, case="success", note="an existing database")
        assert_accepted(deleted)
        assert "contractdbold" not in _database_names(lab)

        again = lab.call("delete-database", params, case="not_associated", note="the database deleted above")
        assert_refused(
            again,
            error="The specified database is not associated with this server",
            retriability=Retriability.UNKNOWN,
            exact=True,
        )
    finally:
        _drop(lab, "contractdbold")
