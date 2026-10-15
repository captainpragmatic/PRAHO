"""Contract: the read-only catalogue programs (info, templates, plans, bandwidth)."""

from __future__ import annotations

from apps.common.types import Retriability
from tests.virtualmin_lab.contract.harness import (
    SANDBOX_DOMAIN,
    Lab,
    assert_accepted,
    assert_refused,
    assert_unavailable_command,
    covers,
)

ABSENT = "contract-absent.praho.test"
TEMPLATES = ["Default Settings", "Settings For Sub-Servers"]


@covers("info")
def test_info(lab: Lab) -> None:
    def run() -> None:
        reply = lab.call("info", {}, case="success", note="the health probe and the version read")
        assert_accepted(reply)
        output = str(reply.response.data["output"])
        assert "virtualmin version:" in output

        connection, _ = lab.observe(lambda gateway: gateway.test_connection())
        assert connection.unwrap()["healthy"] is True
        details, _ = lab.observe(lambda gateway: gateway.get_server_info())
        assert "output" in details.unwrap()

        # The command ignores parameters it does not know: a stray one is not a refusal.
        stray = lab.call("info", {"bogus": ""}, case="ignored_parameter", note="info does not check its parameters")
        assert_accepted(stray)

    lab.prove_read_only("info", run)


@covers("list-templates")
def test_list_templates(lab: Lab) -> None:
    def run() -> None:
        names = lab.call("list-templates", {"name-only": ""}, case="success", note="list_templates")
        assert_accepted(names)
        parsed, _ = lab.observe(lambda gateway: gateway.list_templates())
        assert parsed.unwrap() == TEMPLATES

        table = lab.call("list-templates", {}, case="table", note="the plain table, header rows included")
        assert_accepted(table)

        refused = lab.call("list-templates", {"bogus": ""}, case="unknown_parameter", note="a parameter the command lacks")
        assert_refused(refused, error="Unknown parameter --bogus", retriability=Retriability.UNKNOWN, exact=True)

    lab.prove_read_only("list-templates", run)


@covers("get-template")
def test_get_template(lab: Lab) -> None:
    def run() -> None:
        by_name = lab.call("get-template", {"name": "Default Settings"}, case="by_name", note="a template by name")
        assert_accepted(by_name)
        assert "default: 1" in str(by_name.response.data["output"])
        by_id = lab.call("get-template", {"id": "0"}, case="by_id", note="a template by id")
        assert_accepted(by_id)

        no_id = lab.call("get-template", {"id": "99"}, case="unknown_id", note="an id with no template")
        assert_refused(no_id, error="No template with ID 99 found", retriability=Retriability.UNKNOWN, exact=True)
        no_name = lab.call("get-template", {"name": "No Such"}, case="unknown_name", note="a name with no template")
        assert_refused(
            no_name, error="No template with name No Such found", retriability=Retriability.UNKNOWN, exact=True
        )
        neither = lab.call("get-template", {}, case="no_selector", note="neither a name nor an id")
        assert_refused(
            neither, error="Missing --name or --id parameter", retriability=Retriability.UNKNOWN, exact=True
        )

    lab.prove_read_only("get-template", run)


@covers("list-plans")
def test_list_plans(lab: Lab) -> None:
    def run() -> None:
        plans = lab.call("list-plans", {}, case="success", note="the plain plan table")
        assert_accepted(plans)
        assert any("Default Plan" in row["name"] for row in plans.response.data["data"])

        refused = lab.call("list-plans", {"bogus": ""}, case="unknown_parameter", note="a parameter the command lacks")
        assert_refused(refused, error="Unknown parameter --bogus", retriability=Retriability.UNKNOWN, exact=True)

    lab.prove_read_only("list-plans", run)


@covers("get-plan")
def test_get_plan(lab: Lab) -> None:
    """Virtualmin 8.3 has no get-plan: `list-plans --id` or `--name` reads one plan."""
    exchange = lab.prove_read_only(
        "get-plan", lambda: lab.call("get-plan", {"id": "0"}, case="unavailable", note="8.3 reads a plan with list-plans")
    )
    assert_unavailable_command(exchange)


@covers("list-bandwidth")
def test_list_bandwidth(lab: Lab) -> None:
    def run() -> None:
        window = {"start": "2026-10-01", "end": "2026-10-15"}
        usage = lab.call(
            "list-bandwidth",
            {"domain": SANDBOX_DOMAIN, **window},
            case="success",
            note="the gateway's usage read, with a fixed window",
        )
        assert_accepted(usage)
        assert usage.response.data["data"][0]["name"] == SANDBOX_DOMAIN
        info, _ = lab.observe(lambda gateway: gateway.get_domain_info(SANDBOX_DOMAIN))
        assert info.unwrap()["bandwidth_usage_mb"] == 0

        absent = lab.call(
            "list-bandwidth", {"domain": ABSENT, **window}, case="absent_domain", note="a domain that is not there"
        )
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )
        no_domain = lab.call("list-bandwidth", {}, case="no_domain", note="no domain to report on")
        assert_refused(
            no_domain, error="No domain names specified", retriability=Retriability.UNKNOWN, exact=True
        )
        bad_date = lab.call(
            "list-bandwidth",
            {"domain": SANDBOX_DOMAIN, "start": "2026-13-45"},
            case="invalid_date",
            note="a date that is no date: the envelope carries no error text at all",
        )
        assert_refused(bad_date, error="failure", retriability=Retriability.UNKNOWN, exact=True)

    lab.prove_read_only("list-bandwidth", run)
