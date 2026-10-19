"""Lab test: virtualmin_account_name_link.yml, run through PRAHO's own link call on the lab node (ADR-0061 P1.15).

The account name is a sub-server of the customer's domain. Linking replaces the sub-server's empty
`public_html` with `../../public_html`, the customer's own site, running as the customer and never
following a link it did not make. A second run changes nothing, and a home that is not the given user's
is refused without touching it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from apps.common.types import Retriability, retriability_of
from apps.provisioning.account_name_node import link_account_name_web_root
from apps.provisioning.virtualmin_gateway import listing_attribute
from tests.virtualmin_lab.contract.harness import SANDBOX_DOMAIN, SANDBOX_USER, Lab, assert_accepted

CHILD = "contractlink.praho.test"
TARGET = "../../public_html"


@pytest.fixture
def child_home(lab: Lab) -> Iterator[str]:
    lab.remove_domain(CHILD)
    created = lab.quiet(
        "create-domain",
        {"domain": CHILD, "parent": SANDBOX_DOMAIN, "dir": "", "web": "", "ssl": "", "desc": "PRAHO account name"},
    )
    assert_accepted(created)
    try:
        home = listing_attribute(lab.domain_values(CHILD), "Home directory")
        assert home, "the sub-server's listing reports no home"
        yield str(home)
    finally:
        lab.remove_domain(CHILD)


def _link_target(lab: Lab, home: str) -> str:
    return lab.exec("sh", "-c", f"readlink '{home}/public_html' || true").strip()


def test_the_web_root_is_linked_once_and_a_second_run_changes_nothing(lab: Lab, child_home: str) -> None:
    first = link_account_name_web_root(lab.server, home=child_home, customer_user=SANDBOX_USER)
    assert first.is_ok(), first.unwrap_err() if first.is_err() else ""
    assert first.unwrap() is True
    assert _link_target(lab, child_home) == TARGET

    second = link_account_name_web_root(lab.server, home=child_home, customer_user=SANDBOX_USER)
    assert second.is_ok(), second.unwrap_err() if second.is_err() else ""
    assert second.unwrap() is False
    assert _link_target(lab, child_home) == TARGET


def test_a_home_that_is_not_the_users_is_refused_and_left_alone(lab: Lab, child_home: str) -> None:
    refused = link_account_name_web_root(lab.server, home=child_home, customer_user="nobody")
    assert refused.is_err()
    assert retriability_of(refused) is Retriability.NOT_RETRIABLE
    assert _link_target(lab, child_home) == "", "a refused link must leave the web root as it was"
