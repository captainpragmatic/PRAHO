"""Contract: mail aliases and mailbox users.

The lab node installs Virtualmin's minimal LAMP bundle, which has no mail feature, so an alias cannot be
created there: the contract for create-alias and delete-alias is the refusal PRAHO must read as definite.
Users are created without mail (the node's FTP-less, mail-less domain) and work fine.
"""

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


def _listed_users(lab: Lab) -> list[str]:
    """The user names in the plain `list-users` table (header and separator rows skipped)."""
    listing = lab.quiet("list-users", {"domain": SANDBOX_DOMAIN})
    assert_accepted(listing)
    rows = [row["name"].split() for row in listing.response.data["data"]]
    return [row[0] for row in rows if row and row[0] not in {"User"} and not row[0].startswith("-")]


def _remove_user(lab: Lab, user: str) -> None:
    if user in _listed_users(lab):
        assert_accepted(lab.quiet("delete-user", {"domain": SANDBOX_DOMAIN, "user": user}))


@covers("list-aliases")
def test_list_aliases(lab: Lab) -> None:
    def run() -> None:
        listing = lab.call("list-aliases", {"domain": SANDBOX_DOMAIN}, case="success", note="a domain with no aliases")
        assert_accepted(listing)
        absent = lab.call("list-aliases", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )

    lab.prove_read_only("list-aliases", run)


@covers("create-alias")
def test_create_alias(lab: Lab) -> None:
    assert_mutating("create-alias")
    params = {"domain": SANDBOX_DOMAIN, "from": "hello", "to": "owner@example.com"}
    refused = lab.call("create-alias", params, case="mail_not_enabled", note="the lab domain has no mail feature")
    assert_refused(
        refused,
        error=f"Virtual server {SANDBOX_DOMAIN} does not have email enabled",
        retriability=Retriability.UNKNOWN,
        exact=True,
    )
    absent = lab.call("create-alias", {**params, "domain": ABSENT}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("delete-alias")
def test_delete_alias(lab: Lab) -> None:
    assert_mutating("delete-alias")
    missing = lab.call(
        "delete-alias", {"domain": SANDBOX_DOMAIN, "from": "hello"}, case="no_such_alias", note="an alias that was never made"
    )
    assert_refused(
        missing,
        error=f"No alias for the email address hello@{SANDBOX_DOMAIN} exists",
        retriability=Retriability.UNKNOWN,
        exact=True,
    )
    absent = lab.call("delete-alias", {"domain": ABSENT, "from": "hello"}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("list-users")
def test_list_users(lab: Lab) -> None:
    def run() -> None:
        empty = lab.call("list-users", {"domain": SANDBOX_DOMAIN}, case="no_users", note="a domain with no users")
        assert_accepted(empty)
        assert _listed_users(lab) == []

        assert_accepted(
            lab.quiet("create-user", {"domain": SANDBOX_DOMAIN, "user": "dave", "pass": lab.password, "real": "Dave"})
        )
        try:
            listing = lab.call("list-users", {"domain": SANDBOX_DOMAIN}, case="success", note="a domain with one user")
            assert_accepted(listing)
            assert _listed_users(lab) == ["dave"]
        finally:
            _remove_user(lab, "dave")

        absent = lab.call("list-users", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )
        nothing = lab.call("list-users", {}, case="no_domain", note="neither a domain nor a user to list")
        assert_refused(
            nothing, error="No domains or users specified", retriability=Retriability.UNKNOWN, exact=True
        )

    lab.prove_read_only("list-users", run)


@covers("create-user")
def test_create_user(lab: Lab) -> None:
    assert_mutating("create-user")
    params = {"domain": SANDBOX_DOMAIN, "user": "carol", "pass": lab.password, "real": "Carol"}
    _remove_user(lab, "carol")
    try:
        created = lab.call("create-user", params, case="success", note="a plain user with a real name")
        assert_accepted(created)
        assert _listed_users(lab) == ["carol"]

        again = lab.call("create-user", params, case="already_exists", note="the same user twice")
        assert_refused(
            again,
            error="A user or mail alias with the same name and domain already exists",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )
    finally:
        _remove_user(lab, "carol")
    absent = lab.call("create-user", {**params, "domain": ABSENT}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("modify-user")
def test_modify_user(lab: Lab) -> None:
    assert_mutating("modify-user")
    assert_accepted(
        lab.quiet("create-user", {"domain": SANDBOX_DOMAIN, "user": "erin", "pass": lab.password, "real": "Erin"})
    )
    try:
        changed = lab.call(
            "modify-user",
            {"domain": SANDBOX_DOMAIN, "user": "erin", "real": "Erin Smith"},
            case="success",
            note="a real-name change",
        )
        assert_accepted(changed)
        listing = lab.quiet("list-users", {"domain": SANDBOX_DOMAIN})
        assert any("Erin Smith" in row["name"] for row in listing.response.data["data"])
    finally:
        _remove_user(lab, "erin")
    ghost = lab.call(
        "modify-user", {"domain": SANDBOX_DOMAIN, "user": "ghost", "real": "x"}, case="no_such_user", note="a user that is not there"
    )
    assert_refused(
        ghost,
        error=f"No user named ghost was found in the server {SANDBOX_DOMAIN}",
        retriability=Retriability.UNKNOWN,
        exact=True,
    )


@covers("delete-user")
def test_delete_user(lab: Lab) -> None:
    assert_mutating("delete-user")
    assert_accepted(
        lab.quiet("create-user", {"domain": SANDBOX_DOMAIN, "user": "frank", "pass": lab.password, "real": "Frank"})
    )
    try:
        deleted = lab.call("delete-user", {"domain": SANDBOX_DOMAIN, "user": "frank"}, case="success", note="an existing user")
        assert_accepted(deleted)
        assert _listed_users(lab) == []
    finally:
        _remove_user(lab, "frank")
    ghost = lab.call("delete-user", {"domain": SANDBOX_DOMAIN, "user": "ghost"}, case="no_such_user", note="a user that is not there")
    assert_refused(
        ghost,
        error=f"No user named ghost was found in the server {SANDBOX_DOMAIN}",
        retriability=Retriability.UNKNOWN,
        exact=True,
    )
