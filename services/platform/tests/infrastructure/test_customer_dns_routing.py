"""Source teardown requires every customer frontend to reach the committed target."""

from __future__ import annotations

import time
from itertools import pairwise
from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
from django.test import SimpleTestCase

from apps.infrastructure import dns_agreement as service
from apps.infrastructure.dns_agreement import RoutingAnswer
from tests.infrastructure.test_dns_agreement import FQDN, _answers

CUSTOMER = "www.customer.example.com"
IPV4 = "95.217.0.10"
IPV6 = "2a01:4f8::1"


def direct(name: str, *, ipv4: str = IPV4, ipv6: str = IPV6) -> list[RoutingAnswer]:
    return [
        RoutingAnswer(ns, family, addresses, "198.51.100.1", ttl=300, queried_name=name)
        for ns in ("ns1.example.net", "ns2.example.net")
        for family, addresses in (("A", (ipv4,)), ("AAAA", (ipv6,) if ipv6 else ()))
    ]


def aliases(name: str, target: str) -> list[RoutingAnswer]:
    return [
        RoutingAnswer(ns, family, (), "198.51.100.1", ttl=600, cname=target, queried_name=name)
        for ns in ("ns1.example.net", "ns2.example.net")
        for family in ("A", "AAAA")
    ]


class CustomerRoutingTests(SimpleTestCase):
    def check(self, records: dict[str, list[RoutingAnswer]], *, ipv6: str | None = IPV6, allow_absent=False):
        calls = []

        def query(name):
            calls.append(name)
            return records[name]

        result = service.routing_agreement(CUSTOMER, IPV4, ipv6, query=query, pause=0, allow_absent=allow_absent)
        return result, calls

    def test_customer_address_still_on_source_blocks_cleanup_despite_owned_name_agreement(self):
        owned = service.authoritative_agreement(
            FQDN, IPV4, IPV6, query=lambda _name: _answers((IPV4,), (IPV6,)), pause=0
        )
        self.assertTrue(owned.agreed)

        customer, _ = self.check({CUSTOMER: direct(CUSTOMER, ipv4="95.217.0.20")})

        self.assertFalse(customer.agreed)
        self.assertIn("A", customer.detail)
        self.assertEqual(customer.ttl, 300, "Stale routing must retain the old cache lifetime")

    def test_an_unused_frontend_requires_every_authority_to_prove_both_families_absent(self):
        absent = [
            RoutingAnswer(ns, family, ttl=600, queried_name=CUSTOMER)
            for ns in ("ns1.example.net", "ns2.example.net")
            for family in ("A", "AAAA")
        ]
        result, _ = self.check({CUSTOMER: absent}, allow_absent=True)
        self.assertTrue(result.agreed, result.detail)
        self.assertEqual(result.ttl, 600)
        required, _ = self.check({CUSTOMER: absent})
        self.assertFalse(required.agreed)

    def test_allowing_an_unused_frontend_does_not_allow_an_opaque_proxy(self):
        result, _ = self.check({CUSTOMER: direct(CUSTOMER, ipv4="104.16.0.1", ipv6="")}, allow_absent=True)
        self.assertFalse(result.agreed)

    def test_every_authority_answering_target_addresses_agrees(self):
        result, calls = self.check({CUSTOMER: direct(CUSTOMER)})
        self.assertTrue(result.agreed, result.detail)
        self.assertEqual(calls, [CUSTOMER])

    def test_a_customer_zone_without_ipv6_remains_valid_with_authoritative_negative_evidence(self):
        result, _ = self.check({CUSTOMER: direct(CUSTOMER, ipv6="")})
        self.assertTrue(result.agreed, result.detail)

    def test_a_cross_zone_cname_is_followed_to_the_owned_name(self):
        result, calls = self.check({CUSTOMER: aliases(CUSTOMER, FQDN), FQDN: direct(FQDN)})
        self.assertTrue(result.agreed, result.detail)
        self.assertEqual(calls, [CUSTOMER, FQDN])
        self.assertEqual(result.ttl, 600)
        self.assertEqual({answer.queried_name for answer in result.answers}, {CUSTOMER, FQDN})

    def test_case_and_final_dot_do_not_make_equivalent_cnames_disagree(self):
        records = aliases(CUSTOMER, FQDN.upper() + ".")
        records[0] = RoutingAnswer("ns1.example.net", "A", cname=FQDN, queried_name=CUSTOMER)
        result, _ = self.check({CUSTOMER: records, FQDN: direct(FQDN)})
        self.assertTrue(result.agreed, result.detail)

    def test_a_stale_cname_at_one_nameserver_is_not_followed(self):
        records = aliases(CUSTOMER, FQDN)
        records[2:] = aliases(CUSTOMER, "old.destination.example.net")[2:]
        result, calls = self.check({CUSTOMER: records})
        self.assertFalse(result.agreed)
        self.assertIn("CNAME", result.detail)
        self.assertEqual(set(calls), {CUSTOMER})

    def test_mixed_direct_and_alias_answers_cannot_claim_convergence(self):
        records = aliases(CUSTOMER, FQDN)
        records[2:] = direct(CUSTOMER)[2:]
        result, _ = self.check({CUSTOMER: records})
        self.assertFalse(result.agreed)

    def test_a_cname_cycle_stops_without_querying_forever(self):
        result, calls = self.check({CUSTOMER: aliases(CUSTOMER, FQDN), FQDN: aliases(FQDN, CUSTOMER)})
        self.assertFalse(result.agreed)
        self.assertIn("cycle", result.detail.lower())
        self.assertLessEqual(len(calls), 2 * service.AGREEMENT_ATTEMPTS)

    def test_the_cname_hop_limit_is_enforced(self):
        names = [CUSTOMER, *(f"hop{number}.example.net" for number in range(service.ROUTING_MAX_CNAME_HOPS + 1))]
        records = {name: aliases(name, target) for name, target in pairwise(names)}
        result, calls = self.check(records)
        self.assertFalse(result.agreed)
        self.assertIn("limit", result.detail.lower())
        self.assertLessEqual(len(calls), (service.ROUTING_MAX_CNAME_HOPS + 1) * service.AGREEMENT_ATTEMPTS)

    def test_the_last_allowed_cname_hop_can_reach_a_direct_target(self):
        names = [CUSTOMER, *(f"hop{number}.example.net" for number in range(service.ROUTING_MAX_CNAME_HOPS))]
        records = {name: aliases(name, target) for name, target in pairwise(names)}
        records[names[-1]] = direct(names[-1])
        result, calls = self.check(records)
        self.assertTrue(result.agreed, result.detail)
        self.assertEqual(len(calls), service.ROUTING_MAX_CNAME_HOPS + 1)

    def test_an_expired_probe_never_dispatches_another_question_or_reports_agreement(self):
        clock = [100.0]
        calls = []

        def query(name):
            calls.append(name)
            clock[0] += service.ROUTING_TIMEOUT_SECONDS + 1
            return direct(name)

        with patch.object(service.time, "monotonic", side_effect=lambda: clock[0]):
            result = service.routing_agreement(CUSTOMER, IPV4, IPV6, query=query, pause=0)

        self.assertFalse(result.agreed)
        self.assertIn("deadline", result.detail.lower())
        self.assertEqual(calls, [CUSTOMER])

    def test_a_stale_aaaa_is_rejected_even_with_the_right_a(self):
        result, _ = self.check({CUSTOMER: direct(CUSTOMER, ipv6="2a01:4f8::2")})
        self.assertFalse(result.agreed)
        self.assertIn("AAAA", result.detail)

    def test_missing_negative_aaaa_evidence_is_not_convergence(self):
        result, _ = self.check({CUSTOMER: [answer for answer in direct(CUSTOMER) if answer.record_type == "A"]})
        self.assertFalse(result.agreed)

    def test_an_opaque_proxy_address_does_not_prove_the_origin(self):
        result, _ = self.check({CUSTOMER: direct(CUSTOMER, ipv4="104.16.0.1", ipv6="")})
        self.assertFalse(result.agreed)

    def test_a_nameserver_failure_never_counts_as_negative_evidence(self):
        records = direct(CUSTOMER, ipv6="")
        records[1] = RoutingAnswer("ns1.example.net", "AAAA", error="timed out", queried_name=CUSTOMER)
        result, _ = self.check({CUSTOMER: records})
        self.assertFalse(result.agreed)


class RoutingQueryTests(SimpleTestCase):
    def response(self, family="A"):
        message = dns.message.make_response(dns.message.make_query(CUSTOMER, family))
        message.flags |= dns.flags.AA
        return message

    def query(self, response, family="A"):
        self.assertTrue(all(rrset.name.is_absolute() for rrset in (*response.answer, *response.authority)))
        with patch.object(service.dns.query, "tcp", return_value=response):
            return service._routing_query(CUSTOMER, "ns.example.net", "95.217.0.1", family, time.monotonic() + 10)

    def test_an_authoritative_cname_is_evidence_for_this_question(self):
        response = self.response()
        response.answer.append(dns.rrset.from_text(CUSTOMER + ".", 600, "IN", "CNAME", FQDN + "."))
        answer = self.query(response)
        self.assertEqual(answer.cname, FQDN)
        self.assertEqual(answer.record_type, "A")
        self.assertEqual(answer.queried_name, CUSTOMER)
        self.assertFalse(answer.error)

    def test_nonauthoritative_aliases_are_refused(self):
        response = self.response()
        response.flags &= ~dns.flags.AA
        response.answer.append(dns.rrset.from_text(CUSTOMER + ".", 600, "IN", "CNAME", FQDN + "."))
        self.assertTrue(self.query(response).error)

    def test_the_production_probe_discovers_each_zone_and_queries_every_authority_without_recursion(self):
        def zone(name, **_kwargs):
            return dns.name.from_text("example.com." if name.to_text().startswith("www.") else "praho-sites.net.")

        def resolve(name, family, **_kwargs):
            if family == "NS":
                return dns.rrset.from_text(str(name), 300, "IN", "NS", "ns1.example.net.", "ns2.example.net.")
            self.assertEqual(family, "A")
            return dns.rrset.from_text(str(name), 300, "IN", "A", "95.217.0.1")

        def query(message, address, **_kwargs):
            self.assertEqual(address, "95.217.0.1")
            self.assertFalse(message.flags & dns.flags.RD)
            response = dns.message.make_response(message)
            response.flags |= dns.flags.AA
            question = message.question[0]
            if question.name.to_text(omit_final_dot=True) == CUSTOMER:
                response.answer.append(dns.rrset.from_text(CUSTOMER + ".", 600, "IN", "CNAME", FQDN + "."))
            else:
                family = dns.rdatatype.to_text(question.rdtype)
                response.answer.append(dns.rrset.from_text(FQDN + ".", 300, "IN", family, IPV4 if family == "A" else IPV6))
            return response

        with (
            patch.object(service.dns.resolver, "Resolver") as factory,
            patch.object(service.dns.resolver, "zone_for_name", side_effect=zone) as discovery,
            patch.object(service.dns.query, "tcp", side_effect=query) as tcp,
        ):
            factory.return_value.resolve.side_effect = resolve
            result = service.routing_agreement(CUSTOMER, IPV4, IPV6, pause=0)

        self.assertTrue(result.agreed, result.detail)
        self.assertEqual([call.args[0].to_text(omit_final_dot=True) for call in discovery.call_args_list], [CUSTOMER, FQDN])
        self.assertEqual(tcp.call_count, 8)

    def test_negative_aaaa_requires_soa_from_a_containing_zone(self):
        response = self.response("AAAA")
        response.authority.append(
            dns.rrset.from_text("unrelated.example.net.", 600, "IN", "SOA", "ns.example.net. hostmaster.example.net. 1 60 60 60 60")
        )
        self.assertTrue(self.query(response, "AAAA").error)

    def test_authoritative_nxdomain_with_containing_soa_proves_absence(self):
        response = self.response()
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.authority.append(
            dns.rrset.from_text("example.com.", 600, "IN", "SOA", "ns.example.com. hostmaster.example.com. 1 60 60 60 60")
        )
        answer = self.query(response)
        self.assertFalse(answer.error, answer.error)
        self.assertEqual(answer.addresses, ())
        self.assertEqual(answer.ttl, 600)

    def test_cname_and_direct_data_at_the_same_owner_is_refused(self):
        response = self.response()
        response.answer.extend([
            dns.rrset.from_text(CUSTOMER + ".", 600, "IN", "CNAME", FQDN + "."),
            dns.rrset.from_text(CUSTOMER + ".", 600, "IN", "A", IPV4),
        ])
        self.assertTrue(self.query(response).error)
