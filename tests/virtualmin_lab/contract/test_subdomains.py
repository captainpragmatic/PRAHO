"""Contract: sub-domains. Virtualmin 8.3 has no create-subdomain, delete-subdomain or list-subdomains (a
sub-domain is made with create-domain --parent and listed with list-domains --subdomain), so the three
programs that stay on PRAHO's allowlist are pinned as unavailable, with the parameters a caller would use."""

from __future__ import annotations

from tests.virtualmin_lab.contract.harness import (
    SANDBOX_DOMAIN,
    Lab,
    assert_mutating,
    assert_unavailable_command,
    covers,
)


@covers("create-subdomain")
def test_create_subdomain(lab: Lab) -> None:
    assert_mutating("create-subdomain")
    exchange = lab.call(
        "create-subdomain",
        {"parent": SANDBOX_DOMAIN, "subdomain": "blog"},
        case="unavailable",
        note="8.3 makes a sub-domain with create-domain --parent",
    )
    assert_unavailable_command(exchange)


@covers("delete-subdomain")
def test_delete_subdomain(lab: Lab) -> None:
    assert_mutating("delete-subdomain")
    exchange = lab.call(
        "delete-subdomain",
        {"domain": f"blog.{SANDBOX_DOMAIN}"},
        case="unavailable",
        note="8.3 removes a sub-domain with delete-domain",
    )
    assert_unavailable_command(exchange)


@covers("list-subdomains")
def test_list_subdomains(lab: Lab) -> None:
    exchange = lab.prove_read_only(
        "list-subdomains",
        lambda: lab.call(
            "list-subdomains",
            {"parent": SANDBOX_DOMAIN},
            case="unavailable",
            note="8.3 lists sub-domains with list-domains --subdomain",
        ),
    )
    assert_unavailable_command(exchange)
