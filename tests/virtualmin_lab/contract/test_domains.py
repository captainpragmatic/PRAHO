"""Contract: the domain lifecycle programs (create, delete, list, modify, enable, disable, get).

Each test sends PRAHO's parameters to the real node and checks what PRAHO decides on the answer.
Refusal texts are Virtualmin 8.3's own, observed on the lab node.
"""

from __future__ import annotations

from apps.common.types import Retriability
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_gateway import is_absent_domain_rejection, listing_attribute, listing_enabled
from apps.provisioning.virtualmin_service import create_domain_params
from apps.provisioning.virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE
from tests.virtualmin_lab.contract.harness import (
    DELETE_TIMEOUT,
    SANDBOX_DOMAIN,
    Lab,
    assert_accepted,
    assert_mutating,
    assert_refused,
    assert_unavailable_command,
    covers,
)

ABSENT = "contract-absent.praho.test"
SEED = "contract-recovery-seed"
DEFAULT_FEATURES = {"unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"}


@covers("create-domain")
def test_create_domain(lab: Lab) -> None:
    assert_mutating("create-domain")
    domain, user = "contract-create.praho.test", "contractcreate"
    params = create_domain_params(
        domain=domain,
        username=user,
        password=lab.password,
        template=DEFAULT_VIRTUALMIN_TEMPLATE,
        recovery_seed=SEED,
        disk_quota_mb=1024,
        bandwidth_quota_mb=10240,
    )
    lab.remove_domain(domain)
    try:
        created = lab.call(
            "create-domain",
            params,
            case="success",
            note="PRAHO's own parameters: default template, default features, the recovery seed as description",
        )
        assert_accepted(created)

        values = lab.domain_values(domain)
        assert listing_attribute(values, "Template") == DEFAULT_VIRTUALMIN_TEMPLATE
        assert listing_attribute(values, "Description") == SEED
        assert set(listing_attribute(values, "Features").split()) >= DEFAULT_FEATURES
        assert listing_enabled(values) is True

        again = lab.call("create-domain", params, case="already_hosted", note="the same domain created twice")
        assert_refused(
            again, error="You are already hosting this domain", retriability=Retriability.UNKNOWN, exact=True
        )

        other = {**params, "domain": "contract-other.praho.test", "user": "contractother"}
        bad_template = lab.call(
            "create-domain",
            {**other, "template": "Default"},
            case="unknown_template",
            note="there is no template called Default on 8.x",
        )
        assert_refused(bad_template, error="Unknown template name", retriability=Retriability.UNKNOWN, exact=True)

        bad_parameter = lab.call(
            "create-domain", {**other, "bogus-flag": ""}, case="unknown_parameter", note="a parameter the command lacks"
        )
        assert_refused(
            bad_parameter, error="Unknown parameter --bogus-flag", retriability=Retriability.UNKNOWN, exact=True
        )
        assert not lab.domain_exists("contract-other.praho.test"), "a refused create must leave nothing behind"
    finally:
        lab.remove_domain(domain)


@covers("delete-domain")
def test_delete_domain(lab: Lab) -> None:
    assert_mutating("delete-domain")
    with lab.domain("contract-delete.praho.test", "contractdelete") as domain:
        deleted = lab.call(
            "delete-domain", {"domain": domain}, case="success", timeout_seconds=DELETE_TIMEOUT, note="an existing domain"
        )
        assert_accepted(deleted)
        assert not lab.domain_exists(domain)

        gone = lab.call("delete-domain", {"domain": domain}, case="absent_domain", note="the domain deleted above")
        assert_refused(
            gone,
            error=f"Virtual server {domain} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )


@covers("list-domains")
def test_list_domains(lab: Lab) -> None:
    def run() -> None:
        # The call PRAHO makes to read one domain (get_domain_state, the backup service, the migration check).
        one = lab.call(
            "list-domains",
            {"domain": SANDBOX_DOMAIN, "multiline": ""},
            case="one_domain",
            note="get_domain_state, get_domain_owner and the backup service's feature and id reads",
        )
        assert_accepted(one)
        (row,) = one.response.data["data"]
        assert row["name"] == SANDBOX_DOMAIN
        assert listing_attribute(row["values"], "Username") == "contract"
        assert listing_enabled(row["values"]) is True
        state, _ = lab.observe(lambda gateway: gateway.get_domain_state(SANDBOX_DOMAIN))
        assert state.unwrap() == {"exists": True, "enabled": True, "owner": "contract"}

        everything = lab.call(
            "list-domains", {"multiline": ""}, case="all_domains", note="list_domains_with_owners and the lab checks"
        )
        assert_accepted(everything)
        owners, _ = lab.observe(lambda gateway: gateway.list_domains_with_owners())
        assert owners.unwrap() == [{"domain": SANDBOX_DOMAIN, "username": "contract"}]

        table = lab.call("list-domains", {}, case="table", note="list_domains: the plain table, header rows included")
        assert_accepted(table)
        domains, _ = lab.observe(lambda gateway: gateway.list_domains(name_only=True))
        assert domains.unwrap() == [SANDBOX_DOMAIN], "the header and separator rows must not read as domains"

        names = lab.call("list-domains", {"name-only": ""}, case="name_only", note="the lab's domain existence check")
        assert_accepted(names)

        absent = lab.call(
            "list-domains", {"domain": ABSENT, "multiline": ""}, case="absent_domain", note="the create retry's probe"
        )
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )
        assert is_absent_domain_rejection(absent.response, ABSENT), "the one answer that proves absence"
        assert not is_absent_domain_rejection(absent.response, "contract-another.praho.test")
        probed, _ = lab.observe(lambda gateway: gateway.get_domain_state(ABSENT))
        assert probed.unwrap() == {"exists": False, "enabled": None, "owner": ""}

        refused = lab.call(
            "list-domains",
            {"format": "json"},
            case="unknown_parameter",
            note="the old credential probe: a refusal is a 200 failure envelope, never a success",
        )
        assert_refused(refused, error="Unknown parameter --format", retriability=Retriability.UNKNOWN, exact=True)
        assert not is_absent_domain_rejection(refused.response, "format")

    lab.prove_read_only("list-domains", run)


@covers("modify-domain")
def test_modify_domain(lab: Lab) -> None:
    assert_mutating("modify-domain")
    # Disaster recovery's own quota restore, run against the node through the recording gateway.
    sent = lab.produced_by(
        "apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway",
        lambda: VirtualminDisasterRecoveryService()._restore_quotas(lab.server, SANDBOX_DOMAIN, 2048, 100),
    )
    (restore,) = sent
    assert restore.program == "modify-domain"
    assert set(restore.params) == {"domain", "quota", "bw"}, restore.params
    lab.record(restore, "success", "disaster recovery's quota restore: the bandwidth limit is --bw on modify-domain")
    assert_accepted(restore)

    absent = lab.call(
        "modify-domain", {"domain": ABSENT, "quota": "1024"}, case="absent_domain", note="a domain that is not there"
    )
    assert_refused(
        absent,
        error=f"Virtual server {ABSENT} does not exist.",
        retriability=Retriability.NOT_RETRIABLE,
        exact=True,
    )

    create_style = lab.call(
        "modify-domain",
        {"domain": SANDBOX_DOMAIN, "quota": "1024", "bandwidth": "0"},
        case="unknown_parameter",
        note="create-domain's --bandwidth sent to modify-domain, which names it --bw (the pre-fix recovery call)",
    )
    assert_refused(create_style, error="Unknown parameter --bandwidth", retriability=Retriability.UNKNOWN, exact=True)

    bad_quota = lab.call(
        "modify-domain", {"domain": SANDBOX_DOMAIN, "quota": "abc"}, case="invalid_quota", note="a quota that is no number"
    )
    assert_refused(bad_quota, error="Quota must be a number of blocks", retriability=Retriability.UNKNOWN, exact=True)


@covers("disable-domain")
def test_disable_domain(lab: Lab) -> None:
    assert_mutating("disable-domain")
    with lab.domain("contract-disable.praho.test", "contractdisable") as domain:
        disabled = lab.call("disable-domain", {"domain": domain}, case="success", note="an enabled domain")
        assert_accepted(disabled)
        assert listing_enabled(lab.domain_values(domain)) is False

        again = lab.call("disable-domain", {"domain": domain}, case="already_disabled", note="a disabled domain")
        assert_refused(
            again,
            error=f"Virtual server {domain} is already disabled",
            retriability=Retriability.UNKNOWN,
            exact=True,
        )
    absent = lab.call("disable-domain", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("enable-domain")
def test_enable_domain(lab: Lab) -> None:
    assert_mutating("enable-domain")
    with lab.domain("contract-enable.praho.test", "contractenable") as domain:
        assert_accepted(lab.quiet("disable-domain", {"domain": domain}))

        enabled = lab.call("enable-domain", {"domain": domain}, case="success", note="a disabled domain")
        assert_accepted(enabled)
        assert listing_enabled(lab.domain_values(domain)) is True

        again = lab.call("enable-domain", {"domain": domain}, case="not_disabled", note="an enabled domain")
        assert_refused(
            again,
            error=f"Virtual server {domain} is not disabled",
            retriability=Retriability.UNKNOWN,
            exact=True,
        )
    absent = lab.call("enable-domain", {"domain": ABSENT}, case="absent_domain", note="a domain that is not there")
    assert_refused(
        absent, error=f"Virtual server {ABSENT} does not exist", retriability=Retriability.NOT_RETRIABLE, exact=True
    )


@covers("get-domain")
def test_get_domain(lab: Lab) -> None:
    """Virtualmin 8.3 has no get-domain: `list-domains --domain` is how a single domain is read."""
    exchange = lab.prove_read_only(
        "get-domain",
        lambda: lab.call("get-domain", {"domain": SANDBOX_DOMAIN}, case="unavailable", note="the command is not there"),
    )
    assert_unavailable_command(exchange)
