"""Wire-level DNS fixtures exercise the complete bounded monitoring transport."""

import json
from dataclasses import replace

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from django.test import SimpleTestCase

from apps.infrastructure.dns_probes import (
    DnsProbeTransport,
    ProbeBudget,
    ProbeError,
    ProbeTarget,
    probe_hosted_domain_dns,
)

DOMAIN = "customer.example.net"
ACCOUNT = "a1b2c3d4.accounts.example.org"
IPV4 = "95.217.0.20"
IPV6 = "2a01:4f9:c010::20"
TARGET = ProbeTarget(DOMAIN, ACCOUNT, IPV4, IPV6)


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class Wire:
    def __init__(self):
        self.calls = []
        self.records = {
            (DOMAIN, "A"): (IPV4,),
            (DOMAIN, "AAAA"): (IPV6,),
            (f"www.{DOMAIN}", "CNAME"): (f"{ACCOUNT}.",),
            (ACCOUNT, "A"): (IPV4,),
            (ACCOUNT, "AAAA"): (IPV6,),
        }
        self.overrides = {}
        self.zones = ("example.net", "accounts.example.org", "net", "org")

    def __call__(self, question):
        self.calls.append(question)
        override = self.overrides.get((question.name, question.record_type, question.server))
        if override is None:
            override = self.overrides.get((question.name, question.record_type))
        if isinstance(override, Exception):
            raise override
        if callable(override):
            return override(question)
        if override is not None:
            return override
        zone = question.zone or next(
            zone for zone in self.zones if question.name == zone or question.name.endswith(f".{zone}")
        )
        query = dns.message.make_query(question.name, question.record_type)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA if question.recursive else dns.flags.AA
        if question.recursive and question.record_type == "SOA":
            response.answer.append(self.soa(zone))
            return response
        if question.recursive and question.record_type == "NS":
            response.answer.append(
                dns.rrset.from_text(f"{question.name}.", 300, "IN", "NS", "ns1.example.net.", "ns2.example.net.")
            )
            return response
        if question.recursive and question.name in ("ns1.example.net", "ns2.example.net"):
            response.answer.append(
                dns.rrset.from_text(
                    f"{question.name}.",
                    300,
                    "IN",
                    "A",
                    "95.217.99.1" if question.name.startswith("ns1") else "95.217.99.2",
                )
            )
            return response
        alias = self.records.get((question.name, "CNAME"))
        kind = "CNAME" if alias else question.record_type
        records = alias or self.records.get((question.name, kind), ())
        if records:
            response.answer.append(dns.rrset.from_text(f"{question.name}.", 300, "IN", kind, *records))
        else:
            response.authority.append(self.soa(zone))
        return response

    @staticmethod
    def soa(zone):
        return dns.rrset.from_text(
            f"{zone}.", 300, "IN", "SOA", f"ns1.example.net. hostmaster.{zone}. 1 3600 600 86400 300"
        )


def report(wire=None, *, target=TARGET, budget=None):
    fixture = wire or Wire()
    transport = DnsProbeTransport(budget=budget, query=fixture, recursive_servers=("1.1.1.1",))
    return probe_hosted_domain_dns(target, transport=transport), fixture


def test_cname_cross_zone_and_direct_apex_are_healthy_and_report_is_json_safe():
    result, wire = report()
    assert result["components"]["apex"]["state"] == "healthy"
    assert result["components"]["www"]["state"] == "healthy"
    assert result["dns_path"] == "cname"
    assert result["components"]["dnssec"]["state"] == "not_applicable"
    assert result["components"]["mx"]["state"] == "not_applicable"
    assert json.loads(json.dumps(result))["version"] == 1
    assert any(question.name == ACCOUNT and not question.recursive for question in wire.calls)


def test_stray_aaaa_is_broken_even_when_ipv4_is_right_and_controller_uses_ipv4():
    wire = Wire()
    wire.records[(DOMAIN, "AAAA")] = ("2a01:4f9:c010::99",)
    result, fixture = report(wire)
    assert result["components"]["apex"]["state"] == "broken"
    assert result["components"]["apex"]["code"] == "stray_aaaa"
    assert all(":" not in question.server for question in fixture.calls)


def test_ipv4_only_target_still_checks_and_rejects_published_aaaa():
    result, _ = report(target=replace(TARGET, ipv6=None))
    assert result["components"]["apex"]["code"] == "stray_aaaa"


def test_opaque_proxy_addresses_are_unknown_without_http_visits():
    wire = Wire()
    wire.records[(DOMAIN, "A")] = ("104.16.0.1",)
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"
    assert result["components"]["apex"]["code"] == "external_origin_unverified"
    assert all(question.server != "104.16.0.1" for question in wire.calls)


def test_cname_cycle_is_broken_but_transport_failures_are_unknown():
    wire = Wire()
    wire.records[(ACCOUNT, "CNAME")] = (f"www.{DOMAIN}.",)
    result, _ = report(wire)
    assert result["components"]["www"]["code"] == "cname_cycle"
    wire = Wire()
    wire.overrides[(DOMAIN, "A", "95.217.99.2")] = dns.exception.Timeout()
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"
    assert result["components"]["apex"]["code"] == "dns_query_failed"


def test_no_authoritative_flag_and_unrelated_rrsets_cannot_create_health():
    wire = Wire()
    query = dns.message.make_query(DOMAIN, "A")
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text("unrelated.example.net.", 300, "IN", "A", IPV4))
    wire.overrides[(DOMAIN, "A")] = response
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"
    response.flags |= dns.flags.AA
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"


def test_authoritative_nxdomain_is_broken_but_no_negative_proof_is_unknown():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query(DOMAIN, "A"))
    response.flags |= dns.flags.AA
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.authority.append(Wire.soa("example.net"))
    wire.overrides[(DOMAIN, "A")] = response
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "broken"
    response.authority.clear()
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"


def test_private_nameserver_destinations_are_refused_before_contact():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query("ns1.example.net", "A"))
    response.answer.append(dns.rrset.from_text("ns1.example.net.", 300, "IN", "A", "127.0.0.1"))
    wire.overrides[("ns1.example.net", "A")] = response
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"
    assert all(question.server != "127.0.0.1" for question in wire.calls)


def test_one_query_budget_counts_discovery_and_never_dispatches_after_deadline():
    wire = Wire()
    clock = Clock()
    budget = ProbeBudget(seconds=90, max_queries=2, clock=clock)
    result, _ = report(wire, budget=budget)
    assert len(wire.calls) == 2
    assert result["components"]["apex"]["state"] == "unknown"
    assert all(component["state"] == "unknown" for component in result["components"].values())
    clock.value = 100
    report(wire, budget=budget)
    assert len(wire.calls) == 2


def test_expiration_during_a_query_prevents_every_following_wire_dispatch():
    wire = Wire()
    clock = Clock()
    original = wire.__call__

    def expire(question):
        response = original(question)
        clock.value = 91
        return response

    transport = DnsProbeTransport(budget=ProbeBudget(clock=clock), query=expire, recursive_servers=("1.1.1.1",))
    result = probe_hosted_domain_dns(TARGET, transport=transport)
    assert len(wire.calls) == 1
    assert all(component["state"] == "unknown" for component in result["components"].values())


def test_the_final_allowed_question_may_return_evidence_without_allowing_another_dispatch():
    wire = Wire()
    transport = DnsProbeTransport(budget=ProbeBudget(max_queries=1), query=wire, recursive_servers=("1.1.1.1",))
    assert transport.zone(DOMAIN) == "example.net"
    assert len(wire.calls) == 1


@pytest.mark.parametrize(
    "mx,code",
    [(("10 mail.external.example.org.",), "external_mail"), (("0 .",), "null_mx"), ((), "implicit_external_mail")],
)
def test_external_null_and_implicit_mail_are_valid_without_hosted_mail_mode(mx, code):
    wire = Wire()
    wire.records[(DOMAIN, "MX")] = mx
    result, _ = report(wire)
    assert result["components"]["mx"]["state"] == "not_applicable"
    assert result["components"]["mx"]["code"] == code


def test_mixed_null_mx_is_broken_even_for_external_mail():
    wire = Wire()
    wire.records[(DOMAIN, "MX")] = ("0 .", "10 mail.external.example.org.")
    result, _ = report(wire)
    assert result["components"]["mx"]["code"] == "mixed_null_mx"


@pytest.mark.parametrize(
    "records,state,code",
    [
        (('0 issue "letsencrypt.org"',), "healthy", "caa_allows_letsencrypt"),
        (('0 issue "other.example"',), "broken", "caa_excludes_letsencrypt"),
        (('0 issuewild "other.example"',), "healthy", "caa_unrestricted"),
        (('128 unknown "value"',), "broken", "caa_unknown_critical"),
        (
            ('0 issue "letsencrypt.org; accounturi=https://example.org/acme/42"',),
            "unknown",
            "caa_parameters_unverified",
        ),
        (('0 issue ";"',), "broken", "caa_excludes_letsencrypt"),
    ],
)
def test_caa_policy_and_unknown_parameters(records, state, code):
    wire = Wire()
    wire.records[("example.net", "CAA")] = records
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == state
    assert result["components"]["caa"]["code"] == code


def test_caa_alias_lookup_uses_original_parent_when_alias_has_no_policy():
    wire = Wire()
    wire.records[(DOMAIN, "CNAME")] = (f"{ACCOUNT}.",)
    wire.records[("example.net", "CAA")] = ('0 issue "other.example"',)
    wire.records[("accounts.example.org", "CAA")] = ('0 issue "letsencrypt.org"',)
    result, _ = report(wire)
    assert result["components"]["caa"]["code"] == "caa_excludes_letsencrypt"


def test_a_definitive_apex_caa_break_survives_unknown_www_policy():
    wire = Wire()
    wire.records[(DOMAIN, "CAA")] = ('0 issue "other.example"',)
    wire.overrides[(f"www.{DOMAIN}", "CAA")] = dns.exception.Timeout()
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == "broken"
    assert result["components"]["caa"]["code"] == "caa_excludes_letsencrypt"


def dnskey():
    return dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 15 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    )


def test_matching_ds_key_reports_only_consistency_and_supports_rollover():
    wire = Wire()
    key = dnskey()
    good = dns.dnssec.make_ds("example.net.", key, "SHA256")
    stale = good.replace(digest=b"\x00" * 32)
    wire.records[("example.net", "DS")] = (stale.to_text(), good.to_text())
    wire.records[("example.net", "DNSKEY")] = (key.to_text(),)
    result, _ = report(wire)
    component = result["components"]["dnssec"]
    assert component["state"] == "healthy"
    assert component["code"] == "dnssec_ds_key_consistent"
    assert component["evidence"]["validation"] == "not_performed"


def test_stale_ds_is_a_consistency_break_and_unsupported_digest_is_unknown():
    wire = Wire()
    key = dnskey()
    stale = dns.dnssec.make_ds("example.net.", key, "SHA256").replace(digest=b"\x00" * 32)
    wire.records[("example.net", "DS")] = (stale.to_text(),)
    wire.records[("example.net", "DNSKEY")] = (key.to_text(),)
    result, _ = report(wire)
    assert result["components"]["dnssec"]["code"] == "dnssec_ds_key_mismatch"
    wire.records[("example.net", "DS")] = (stale.replace(digest_type=250).to_text(),)
    result, _ = report(wire)
    assert result["components"]["dnssec"]["state"] == "unknown"


def test_servfail_never_claims_dnssec_bogus_or_healthy():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query("example.net", "DS"))
    response.flags |= dns.flags.AA
    response.set_rcode(dns.rcode.SERVFAIL)
    wire.overrides[("example.net", "DS")] = response
    result, _ = report(wire)
    assert result["components"]["dnssec"]["state"] == "unknown"
    assert result["components"]["dnssec"]["code"] == "dns_rcode_servfail"


def test_dnskey_data_is_case_sensitive_when_comparing_authorities():
    wire = Wire()
    key = dnskey()
    wire.records[("example.net", "DS")] = (dns.dnssec.make_ds("example.net.", key, "SHA256").to_text(),)
    wire.records[("example.net", "DNSKEY")] = (key.to_text(),)
    response = dns.message.make_response(dns.message.make_query("example.net", "DNSKEY"))
    response.flags |= dns.flags.AA
    changed = key.to_text().replace("AQEB", "aQEB", 1)
    response.answer.append(dns.rrset.from_text("example.net.", 300, "IN", "DNSKEY", changed))
    wire.overrides[("example.net", "DNSKEY", "95.217.99.2")] = response
    result, _ = report(wire)
    assert result["components"]["dnssec"]["state"] == "unknown"
    assert result["components"]["dnssec"]["code"] == "dns_authorities_disagree"


def test_unsupported_dnskey_algorithm_never_claims_a_supported_consistency_path():
    wire = Wire()
    key = dnskey().replace(algorithm=250)
    wire.records[("example.net", "DS")] = (dns.dnssec.make_ds("example.net.", key, "SHA256").to_text(),)
    wire.records[("example.net", "DNSKEY")] = (key.to_text(),)
    result, _ = report(wire)
    assert result["components"]["dnssec"]["state"] == "unknown"


def test_hosted_mail_mode_checks_the_owned_target_address_as_well_as_the_mx_name():
    wire = Wire()
    wire.records[(DOMAIN, "MX")] = (f"10 {ACCOUNT}.",)
    wire.records[(ACCOUNT, "A")] = ("95.217.0.99",)
    result, _ = report(wire, target=replace(TARGET, hosted_mail=True))
    assert result["components"]["mx"]["state"] == "broken"


def test_hosted_mail_mode_refuses_a_stray_aaaa_on_the_mx_target():
    wire = Wire()
    wire.records[(DOMAIN, "MX")] = (f"10 {ACCOUNT}.",)
    wire.records[(ACCOUNT, "AAAA")] = ("2a01:4f9:c010::99",)
    result, _ = report(wire, target=replace(TARGET, hosted_mail=True))
    assert result["components"]["mx"]["state"] == "broken"


def test_more_than_eight_authorities_refuses_before_any_authority_is_contacted():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query("example.net", "NS"))
    response.answer.append(
        dns.rrset.from_text("example.net.", 300, "IN", "NS", *(f"ns{index}.example.net." for index in range(9)))
    )
    wire.overrides[("example.net", "NS")] = response
    result, _ = report(wire)
    assert result["components"]["apex"]["code"] == "dns_authorities_unproven"
    assert not any(not question.recursive and question.zone == "example.net" for question in wire.calls)


def test_cname_hop_bound_is_independent_of_the_wire_budget():
    wire = Wire()
    wire.records[(f"www.{DOMAIN}", "CNAME")] = ("hop0.example.net.",)
    for index in range(9):
        wire.records[(f"hop{index}.example.net", "CNAME")] = (f"hop{index + 1}.example.net.",)
    result, _ = report(wire)
    assert result["components"]["www"]["code"] == "cname_hop_limit"
    assert len(wire.calls) <= 96


def test_truncated_authoritative_data_is_unknown_instead_of_partial_success():
    wire = Wire()
    response = wire(
        type(
            "Question",
            (),
            {"name": DOMAIN, "record_type": "A", "server": "95.217.99.1", "recursive": False, "zone": "example.net"},
        )()
    )
    response.flags |= dns.flags.TC
    wire.overrides[(DOMAIN, "A")] = response
    result, _ = report(wire)
    assert result["components"]["apex"]["state"] == "unknown"


def test_staff_evidence_is_bounded_even_for_large_valid_caa_rrsets():
    wire = Wire()
    wire.records[(DOMAIN, "CAA")] = tuple(
        f'0 iodef "mailto:report{index}@example.org?detail={"x" * 700}"' for index in range(64)
    )
    result, _ = report(wire)
    assert len(json.dumps(result)) < 65536
    assert result["components"]["caa"]["state"] == "healthy"


def test_non_internet_class_rdata_is_unknown_rather_than_an_uncaught_parser_error():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query(DOMAIN, "CAA"))
    response.flags |= dns.flags.AA
    response.answer.append(dns.rrset.from_text(f"{DOMAIN}.", 300, "CH", "CAA", "\\# 3 000161"))
    wire.overrides[(DOMAIN, "CAA")] = response
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == "unknown"


@pytest.mark.parametrize(
    "value",
    [
        "letsencrypt.org;;",
        "letsencrypt.org; ;",
        "letsencrypt.org; accounturi",
        "letsencrypt.org; x=y;",
    ],
)
def test_malformed_caa_issue_cannot_authorize_certificate_issuance(value):
    wire = Wire()
    wire.records[(DOMAIN, "CAA")] = (f'0 issue "{value}"',)
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == "broken"
    assert result["components"]["caa"]["code"] == "caa_excludes_letsencrypt"


@pytest.mark.parametrize(
    "value,state",
    [
        ("LETSENCRYPT.ORG ;", "healthy"),
        ("letsencrypt.org; x=", "unknown"),
        ("letsencrypt.org; x=a=b", "unknown"),
        ("letsencrypt.org; x=y; validationmethods=dns-01", "unknown"),
    ],
)
def test_valid_caa_issue_syntax_preserves_empty_suffix_and_unverified_parameter_semantics(value, state):
    wire = Wire()
    wire.records[(DOMAIN, "CAA")] = (f'0 issue "{value}"',)
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == state


def test_one_malformed_caa_issue_does_not_remove_a_separate_valid_authorization():
    wire = Wire()
    wire.records[(DOMAIN, "CAA")] = ('0 issue "letsencrypt.org;;"', '0 issue "letsencrypt.org"')
    result, _ = report(wire)
    assert result["components"]["caa"]["state"] == "healthy"


def test_parent_nxdomain_is_not_mistaken_for_an_unsigned_delegation():
    wire = Wire()
    response = dns.message.make_response(dns.message.make_query("example.net", "DS"))
    response.flags |= dns.flags.AA
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.authority.append(Wire.soa("net"))
    wire.overrides[("example.net", "DS")] = response
    result, _ = report(wire)
    assert result["components"]["dnssec"]["state"] == "unknown"
    assert result["components"]["dnssec"]["code"] == "dnssec_delegation_unproven"


def test_hosted_mx_exchange_names_are_case_insensitive():
    wire = Wire()
    wire.records[(DOMAIN, "MX")] = (f"10 {ACCOUNT.upper()}.",)
    result, _ = report(wire, target=replace(TARGET, hosted_mail=True))
    assert result["components"]["mx"]["state"] == "healthy"


class DnsTreeClimbStopsBelowTheRootTests(SimpleTestCase):
    """RFC 8659 climbs to the TLD and stops: the DNS root is never asked for CAA nor taken as a zone."""

    ROOT_SOA = dns.rrset.from_text(
        ".", 86400, "IN", "SOA", "a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"
    )

    def test_no_caa_anywhere_up_to_the_tld_is_unrestricted_and_the_root_is_never_asked(self):
        wire = Wire()
        self.assertEqual([key for key in wire.records if key[1] == "CAA"], [])
        result, fixture = report(wire)
        caa = result["components"]["caa"]
        self.assertEqual((caa["state"], caa["code"]), ("healthy", "caa_unrestricted"))
        asked = {question.name for question in fixture.calls if question.record_type == "CAA"}
        self.assertLessEqual({DOMAIN, "example.net", "net"}, asked)
        self.assertFalse(asked & {"", "."})

    def test_a_caa_policy_at_the_tld_or_the_parent_is_still_found(self):
        for owner in ("net", "example.net"):
            with self.subTest(owner=owner):
                wire = Wire()
                wire.records[(owner, "CAA")] = ('0 issue "other.example"',)
                result, _ = report(wire)
                caa = result["components"]["caa"]
                self.assertEqual((caa["state"], caa["code"]), ("broken", "caa_excludes_letsencrypt"))

    def test_zone_discovery_never_takes_the_dns_root_as_a_zone(self):
        for case, authority in (("root SOA only", self.ROOT_SOA), ("no SOA at all", None)):
            with self.subTest(case):
                asked = []

                def discovery(question, authority=authority, asked=asked):
                    asked.append(question.name)
                    response = dns.message.make_response(dns.message.make_query(question.name, question.record_type))
                    response.set_rcode(dns.rcode.NXDOMAIN)
                    if authority is not None:
                        response.authority.append(authority)
                    return response

                transport = DnsProbeTransport(query=discovery, recursive_servers=("1.1.1.1",))
                try:
                    outcome = f"zone {transport.zone('customer.nosuchtld')}"
                except ProbeError as error:
                    outcome = error.code
                except dns.exception.DNSException as error:
                    outcome = type(error).__name__
                self.assertEqual(outcome, "dns_zone_unknown")
                self.assertNotIn(".", asked)


def test_a_wildcard_owner_is_refused_everywhere_but_the_import_cross_check_opt_in():
    wire = Wire()
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    owner = f"*.shop.{DOMAIN}"
    for refused in (
        lambda: transport.query(owner, "A"),
        lambda: transport.query(owner, "CAA", parent=True),
        lambda: transport.zone(owner),
    ):
        with pytest.raises(ProbeError) as error:
            refused()
        assert error.value.code == "invalid_dns_name"
    # The opt-in admits exactly one whole leftmost `*` label, nothing else holding one.
    for name in (f"a.*.{DOMAIN}", f"*.*.{DOMAIN}", f"**.{DOMAIN}", f"*foo.{DOMAIN}", f"a*b.{DOMAIN}"):
        with pytest.raises(ProbeError) as error:
            transport.query(name, "A", wildcard_owner=True)
        assert error.value.code == "invalid_dns_name", name
    assert wire.calls == []


def test_the_monitor_still_refuses_a_wildcard_hosting_domain_before_any_packet():
    result, wire = report(target=replace(TARGET, domain=f"*.{DOMAIN}"))
    assert {component["code"] for component in result["components"].values()} == {"invalid_probe_target"}
    assert wire.calls == []


def wide_authority(wire, zone, count, *, prefix="a", octet=98):
    """`zone` answers its NS question with `count` public servers, as .com does with 13."""
    names = [f"{prefix}{index}.wide-servers.net." for index in range(count)]
    for index, server in enumerate(names):
        wire.records[(server.rstrip("."), "A")] = (f"95.217.{octet}.{index + 1}",)

    def answer(question):
        response = dns.message.make_response(dns.message.make_query(question.name, question.record_type))
        response.flags |= dns.flags.RA
        response.answer.append(dns.rrset.from_text(f"{zone}.", 300, "IN", "NS", *names))
        return response

    wire.overrides[(zone, "NS")] = answer


def test_a_parent_zone_with_thirteen_authorities_is_asked_like_com():
    """The CAA climb ends at the TLD and DS lives there, so its 13 servers must not make the domain unknown."""
    wire = Wire()
    wide_authority(wire, "net", 13)
    result, _ = report(wire)
    assert (result["components"]["caa"]["state"], result["components"]["caa"]["code"]) == (
        "healthy",
        "caa_unrestricted",
    )
    assert result["components"]["dnssec"]["code"] == "dnssec_unsigned"
    asked = {question.server for question in wire.calls if question.zone == "net" and not question.recursive}
    assert len(asked) == 13
    assert len(wire.calls) <= ProbeBudget().max_queries


def test_the_customer_zone_keeps_eight_authorities_and_a_parent_sixteen():
    customer = Wire()
    wide_authority(customer, "example.net", 9)
    result, _ = report(customer)
    assert result["components"]["apex"]["code"] == "dns_authorities_unproven"
    assert result["components"]["caa"]["code"] == "dns_authorities_unproven"
    parent = Wire()
    wide_authority(parent, "net", 17)
    result, _ = report(parent)
    assert result["components"]["apex"]["state"] == "healthy"
    assert result["components"]["caa"]["code"] == "dns_authorities_unproven"
    assert result["components"]["dnssec"]["code"] == "dns_authorities_unproven"


def test_a_wide_parent_cannot_starve_the_checks_of_the_accounts_own_zone():
    """CAA and DNSSEC end in the parent zones, so they run last and take only the budget that is left."""
    wire = Wire()
    wide_authority(wire, "net", 13)
    wide_authority(wire, "example.net", 6, prefix="c", octet=96)
    result, _ = report(wire)
    assert list(result["components"]) == ["apex", "www", "caa", "dnssec", "mx"]
    assert result["components"]["mx"]["code"] == "implicit_external_mail"
    assert {result["components"][key]["state"] for key in ("apex", "www")} == {"healthy"}
