"""Contract: certificates and DNS.

The lab has no public DNS and no BIND, so a certificate cannot be issued and a DNS record cannot be edited
there. What the contract pins is the answer PRAHO gets and how it classifies it. Virtualmin 8.3 also lacks
request-letsencrypt-cert, create-dns, delete-dns and list-dns (its commands are generate-letsencrypt-cert
and get-dns), so those programs, which stay on PRAHO's allowlist, are pinned as unavailable.
"""

from __future__ import annotations

import json

from apps.common.types import Retriability
from apps.provisioning.virtualmin_gateway import explicit_rejection
from tests.virtualmin_lab.contract.harness import (
    SANDBOX_DOMAIN,
    Lab,
    assert_accepted,
    assert_mutating,
    assert_refused,
    assert_unavailable_command,
    covers,
)

ABSENT = "contract-absent.praho.test"
CERT = "/tmp/contract-cert.pem"  # noqa: S108  # A path on the throwaway lab node
KEY = "/tmp/contract-key.pem"  # noqa: S108  # A path on the throwaway lab node


@covers("list-certs")
def test_list_certs(lab: Lab) -> None:
    def run() -> None:
        listing = lab.call("list-certs", {"domain": SANDBOX_DOMAIN}, case="success", note="a domain with a certificate")
        assert_accepted(listing)
        rows = listing.response.data["data"]
        assert rows[0]["name"] == SANDBOX_DOMAIN
        assert any(str(row.get("name", "")).startswith("-----BEGIN CERTIFICATE-----") for row in rows)

        absent = lab.call("list-certs", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )

    lab.prove_read_only("list-certs", run)


@covers("install-cert")
def test_install_cert(lab: Lab) -> None:
    assert_mutating("install-cert")
    lab.exec(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", CERT,
        "-days", "30", "-subj", f"/CN={SANDBOX_DOMAIN}",
    )  # fmt: skip
    try:
        installed = lab.call(
            "install-cert",
            {"domain": SANDBOX_DOMAIN, "cert": CERT, "key": KEY},
            case="success",
            note="a certificate and key that are files on the node",
        )
        assert_accepted(installed)
        pem = lab.quiet("list-certs", {"domain": SANDBOX_DOMAIN})
        assert pem.response.data["data"][0]["name"] == SANDBOX_DOMAIN

        missing = lab.call(
            "install-cert",
            {"domain": SANDBOX_DOMAIN, "cert": "/nonexistent.pem"},
            case="missing_file",
            note="a certificate file that is not on the node",
        )
        assert_refused(
            missing,
            error="File /nonexistent.pem does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )
        absent = lab.call(
            "install-cert", {"domain": ABSENT, "cert": CERT}, case="absent_domain", note="a domain that is not there"
        )
        assert_refused(
            absent,
            error=f"No virtual server named {ABSENT} found",
            retriability=Retriability.UNKNOWN,
            exact=True,
        )
    finally:
        lab.exec("rm", "-f", CERT, KEY)


@covers("request-letsencrypt-cert")
def test_request_letsencrypt_cert(lab: Lab) -> None:
    """No public DNS here, so no certificate is issued; what is pinned is acceptance and the failure's class."""
    assert_mutating("request-letsencrypt-cert")
    unavailable = lab.call(
        "request-letsencrypt-cert",
        {"domain": SANDBOX_DOMAIN},
        case="unavailable",
        note="8.3 names the command generate-letsencrypt-cert",
    )
    assert_unavailable_command(unavailable)

    # The command a caller would reach on 8.3: its parameters are accepted, and the failure is a definite
    # status "failure" envelope that explicit_rejection reads (the reason is in full_error, not in error).
    answer = lab.gateway._execute_http_request(
        {"program": "generate-letsencrypt-cert", "domain": SANDBOX_DOMAIN, "json": "1"},
        auth=lab.gateway._get_credentials().unwrap(),
        timeout_seconds=120,
    )
    body = json.loads(answer.text)
    assert answer.status_code == 200
    assert body["status"] == "failure"
    assert "none of the certificate names could be resolved" in body["full_error"]
    assert explicit_rejection(answer.text) is not None


@covers("modify-dns")
def test_modify_dns(lab: Lab) -> None:
    assert_mutating("modify-dns")
    refused = lab.call(
        "modify-dns",
        {"domain": SANDBOX_DOMAIN, "spf": ""},
        case="dns_not_enabled",
        note="the lab has no BIND; success cannot be exercised here",
    )
    assert_refused(
        refused,
        error="The BIND DNS server is not enabled for Virtualmin",
        retriability=Retriability.UNKNOWN,
        exact=True,
    )


@covers("create-dns")
def test_create_dns(lab: Lab) -> None:
    assert_mutating("create-dns")
    exchange = lab.call(
        "create-dns",
        {"domain": SANDBOX_DOMAIN, "type": "A", "name": "www2", "value": "192.0.2.10"},
        case="unavailable",
        note="8.3 edits records with modify-dns",
    )
    assert_unavailable_command(exchange)


@covers("delete-dns")
def test_delete_dns(lab: Lab) -> None:
    assert_mutating("delete-dns")
    exchange = lab.call(
        "delete-dns", {"domain": SANDBOX_DOMAIN, "name": "www2"}, case="unavailable", note="8.3 edits records with modify-dns"
    )
    assert_unavailable_command(exchange)


@covers("list-dns")
def test_list_dns(lab: Lab) -> None:
    exchange = lab.prove_read_only(
        "list-dns",
        lambda: lab.call("list-dns", {"domain": SANDBOX_DOMAIN}, case="unavailable", note="8.3 reads records with get-dns"),
    )
    assert_unavailable_command(exchange)
