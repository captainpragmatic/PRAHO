"""Conservative SPF proposal budgets never become authorization or deliverability results."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rrset
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_mail_spf import (
    SpfBudget,
    SpfDnsAnswer,
    SpfDnsRecord,
    SpfSource,
    TcpSpfResolver,
    analyse_spf_proposal,
    check_spf_receipt,
)

DOMAIN = "customer.example.test"
DIGEST = "a" * 64
NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
PRIVATE = "private-provider-output"


class Resolver:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def __call__(self, question):
        self.calls.append(question)
        result = self.answers[(question.name, question.record_type)]
        if isinstance(result, Exception):
            raise result
        return result


def answer(name, kind, *rdata, ttl=300, negative_ttl=60, rcode="NOERROR"):
    return SpfDnsAnswer(name, kind, rcode, tuple(SpfDnsRecord(name, kind, ttl, value) for value in rdata), negative_ttl)


def txt(name, policy, **kwargs):
    return answer(name, "TXT", '"' + policy + '"', **kwargs)


class SpfSafetyTests(SimpleTestCase):
    def analyse(self, policy, resolver, **kwargs):
        budget = kwargs.pop("budget", SpfBudget(now=lambda: NOW))
        return analyse_spf_proposal(
            DOMAIN, policy, source=SpfSource(1, DIGEST), resolver=resolver, budget=budget, **kwargs
        )

    def test_malformed_literal_networks_are_deterministic_policy_refusals_before_dns(self):
        for term in (
            "ip4:999.1.1.1",
            "ip4:203.0.113.10/33",
            "ip4:203.0.113.10/no",
            "ip6:bad",
            "ip6:2001:db8::/129",
            "ip6:2001:db8::/no",
        ):
            with self.subTest(term=term):
                resolver = Resolver()
                self.assertEqual(self.analyse(f"v=spf1 {term} -all", resolver).unwrap_err(), "mail_spf_policy_invalid")
                self.assertEqual(resolver.calls, [])

    def test_valid_ipv4_and_ipv6_sender_mechanisms_keep_the_exact_proposal_without_dns(self):
        policy = "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all"
        resolver = Resolver()
        receipt = self.analyse(policy, resolver).unwrap()
        self.assertEqual(receipt.lookup_terms, 0)
        self.assertTrue(
            check_spf_receipt(receipt, domain=DOMAIN, proposed_txt=policy, source=SpfSource(1, DIGEST), now=NOW).is_ok()
        )
        self.assertEqual(resolver.calls, [])

    def test_ten_lookup_terms_are_accepted_but_the_eleventh_is_refused_before_more_dns(self):
        records = {}
        for index in range(11):
            name = f"sender{index}.example.test"
            records[(name, "A")] = answer(name, "A", "203.0.113.10")
            records[(name, "AAAA")] = answer(name, "AAAA", "2001:db8::10")
        resolver = Resolver(records)
        policy = "v=spf1 " + " ".join(f"a:sender{index}.example.test" for index in range(10)) + " -all"
        receipt = self.analyse(policy, resolver).unwrap()
        self.assertEqual((receipt.lookup_terms, receipt.query_count), (10, 20))
        self.assertEqual(receipt.scope, "lookup_budget_upper_bound")
        self.assertNotIn("authorization", receipt.__dict__)
        resolver.calls.clear()
        bad = policy.replace(" -all", " a:sender10.example.test -all")
        self.assertEqual(self.analyse(bad, resolver).unwrap_err(), "mail_spf_lookup_limit")
        self.assertEqual(len(resolver.calls), 20)

    def test_nested_and_repeated_includes_count_terms_even_when_dns_is_cached(self):
        resolver = Resolver(
            {
                ("one.example.test", "TXT"): txt("one.example.test", "v=spf1 include:two.example.test -all"),
                ("two.example.test", "TXT"): txt("two.example.test", "v=spf1 ip4:203.0.113.0/24 -all"),
            }
        )
        policy = "v=spf1 " + " ".join(["include:one.example.test"] * 5) + " ~all"
        receipt = self.analyse(policy, resolver).unwrap()
        self.assertEqual((receipt.lookup_terms, receipt.query_count), (10, 2))
        self.assertEqual(
            self.analyse(policy.replace(" ~all", " include:one.example.test ~all"), resolver).unwrap_err(),
            "mail_spf_lookup_limit",
        )

    def test_txt_chunks_join_without_spaces_and_multiple_spf_records_refuse(self):
        resolver = Resolver(
            {("inc.example.test", "TXT"): answer("inc.example.test", "TXT", '"v=spf1 ip4:203.0." "113.0/24 -all"')}
        )
        self.assertEqual(self.analyse("v=spf1 include:inc.example.test ?all", resolver).unwrap().lookup_terms, 1)
        resolver.answers[("inc.example.test", "TXT")] = answer(
            "inc.example.test", "TXT", '"v=spf1 -all"', '"V=SPF1 ?all"'
        )
        self.assertEqual(
            self.analyse("v=spf1 include:inc.example.test ?all", resolver).unwrap_err(), "mail_spf_multiple_records"
        )

    def test_redirect_is_recursive_and_all_suppresses_redirect_regardless_of_its_position(self):
        resolver = Resolver({("redirect.example.test", "TXT"): txt("redirect.example.test", "v=spf1 -all")})
        receipt = self.analyse("v=spf1 ip4:203.0.113.0/24 redirect=redirect.example.test", resolver).unwrap()
        self.assertEqual(receipt.lookup_terms, 1)
        for policy in (
            "v=spf1 redirect=unused.example.test -all",
            "v=spf1 -all redirect=unused.example.test",
            "v=spf1 -all include:unused.example.test",
        ):
            with self.subTest(policy=policy):
                empty = Resolver()
                self.assertEqual(self.analyse(policy, empty).unwrap().lookup_terms, 0)
                self.assertEqual(empty.calls, [])

    def test_cycles_and_unobserved_sender_dependent_policies_require_review(self):
        resolver = Resolver({("cycle.example.test", "TXT"): txt("cycle.example.test", f"v=spf1 include:{DOMAIN} -all")})
        self.assertEqual(
            self.analyse("v=spf1 include:cycle.example.test -all", resolver).unwrap_err(), "mail_spf_cycle"
        )
        for policy in ("v=spf1 ptr -all", "v=spf1 exists:%{i}.example.test -all", "v=spf1 include:%{d} -all"):
            with self.subTest(policy=policy):
                empty = Resolver()
                self.assertEqual(self.analyse(policy, empty).unwrap_err(), "mail_spf_policy_unsupported")
                self.assertEqual(empty.calls, [])

    def test_void_counts_are_per_sender_family_and_keep_actual_negative_lifetimes(self):
        resolver = Resolver(
            {
                (f"a{index}.example.test", kind): answer(
                    f"a{index}.example.test", kind, *(["203.0.113.10"] if kind == "A" else []), negative_ttl=37
                )
                for index in range(3)
                for kind in ("A", "AAAA")
            }
        )
        receipt = self.analyse("v=spf1 a:a0.example.test a:a1.example.test -all", resolver).unwrap()
        self.assertEqual((receipt.void_ipv4, receipt.void_ipv6), (0, 2))
        self.assertEqual(receipt.valid_until, NOW + timedelta(seconds=37))
        self.assertEqual(
            self.analyse("v=spf1 a:a0.example.test a:a1.example.test a:a2.example.test -all", resolver).unwrap_err(),
            "mail_spf_void_limit",
        )

    def test_two_voids_in_each_family_are_not_combined_into_an_invented_four_void_path(self):
        records = {}
        for index in range(4):
            name = f"mixed{index}.example.test"
            records[name, "A"] = answer(name, "A", *([] if index < 2 else ["203.0.113.10"]))
            records[name, "AAAA"] = answer(name, "AAAA", *(["2001:db8::10"] if index < 2 else []))
        policy = "v=spf1 " + " ".join(f"a:mixed{i}.example.test" for i in range(4)) + " -all"
        receipt = self.analyse(policy, Resolver(records)).unwrap()
        self.assertEqual((receipt.void_ipv4, receipt.void_ipv6, receipt.query_count), (2, 2, 8))

    def test_static_exists_is_observed_for_both_sender_families(self):
        resolver = Resolver({("exists.example.test", "A"): answer("exists.example.test", "A")})
        receipt = self.analyse("v=spf1 exists:exists.example.test -all", resolver).unwrap()
        self.assertEqual((receipt.lookup_terms, receipt.void_ipv4, receipt.void_ipv6), (1, 1, 1))

    def test_mx_host_and_per_host_address_fanout_are_bounded(self):
        resolver = Resolver(
            {
                ("mx.example.test", "MX"): answer("mx.example.test", "MX", "10 mail.example.test."),
                ("mail.example.test", "A"): answer("mail.example.test", "A", "203.0.113.10"),
                ("mail.example.test", "AAAA"): answer("mail.example.test", "AAAA", "2001:db8::10"),
            }
        )
        self.assertEqual(self.analyse("v=spf1 mx:mx.example.test -all", resolver).unwrap().lookup_terms, 1)
        resolver.answers[("mx.example.test", "MX")] = answer(
            "mx.example.test", "MX", *(f"10 m{i}.example.test." for i in range(11))
        )
        self.assertEqual(self.analyse("v=spf1 mx:mx.example.test -all", resolver).unwrap_err(), "mail_spf_mx_limit")
        resolver.answers[("mx.example.test", "MX")] = answer("mx.example.test", "MX", "10 mail.example.test.")
        resolver.answers[("mail.example.test", "A")] = answer(
            "mail.example.test", "A", *(f"203.0.113.{i}" for i in range(11))
        )
        self.assertEqual(self.analyse("v=spf1 mx:mx.example.test -all", resolver).unwrap_err(), "mail_spf_mx_limit")

    def test_ten_mx_hosts_are_supported_and_zero_ttl_is_not_a_current_dependency(self):
        records = {
            ("mx.example.test", "MX"): answer("mx.example.test", "MX", *(f"10 m{i}.example.test." for i in range(10)))
        }
        for index in range(10):
            name = f"m{index}.example.test"
            records[name, "A"] = answer(name, "A", "203.0.113.10")
            records[name, "AAAA"] = answer(name, "AAAA", "2001:db8::10")
        self.assertEqual(self.analyse("v=spf1 mx:mx.example.test -all", Resolver(records)).unwrap().query_count, 21)
        resolver = Resolver({("inc.example.test", "TXT"): txt("inc.example.test", "v=spf1 -all", ttl=0)})
        self.assertEqual(
            self.analyse("v=spf1 include:inc.example.test -all", resolver).unwrap_err(), "mail_spf_dns_lifetime_unknown"
        )

    def test_unknown_missing_policy_and_missing_negative_lifetime_cannot_be_approved(self):
        for supplied, expected in (
            (TimeoutError(PRIVATE), "mail_spf_dns_unknown"),
            (answer("inc.example.test", "TXT", rcode="SERVFAIL"), "mail_spf_dns_unknown"),
            (answer("inc.example.test", "TXT"), "mail_spf_record_missing"),
            (answer("inc.example.test", "TXT", '"not SPF"'), "mail_spf_record_missing"),
        ):
            with self.subTest(expected=expected):
                result = self.analyse(
                    "v=spf1 include:inc.example.test -all", Resolver({("inc.example.test", "TXT"): supplied})
                )
                self.assertEqual(result.unwrap_err(), expected)
                self.assertNotIn(PRIVATE, str(result))
        resolver = Resolver({("a.example.test", "A"): answer("a.example.test", "A", negative_ttl=None)})
        self.assertEqual(
            self.analyse("v=spf1 a:a.example.test -all", resolver).unwrap_err(), "mail_spf_dns_lifetime_unknown"
        )

    def test_cname_following_uses_the_same_budget_and_shortest_actual_ttl(self):
        alias = SpfDnsAnswer(
            "alias.example.test",
            "TXT",
            "NOERROR",
            (SpfDnsRecord("alias.example.test", "CNAME", 19, "inc.example.test."),),
        )
        resolver = Resolver(
            {("alias.example.test", "TXT"): alias, ("inc.example.test", "TXT"): txt("inc.example.test", "v=spf1 -all")}
        )
        receipt = self.analyse("v=spf1 include:alias.example.test -all", resolver).unwrap()
        self.assertEqual(receipt.query_count, 2)
        self.assertEqual(receipt.valid_until, NOW + timedelta(seconds=19))

    def test_inlined_alias_and_canonical_record_dependencies_are_available_to_a_future_publisher(self):
        name, target = "alias.example.test", "canonical.example.test"
        supplied = SpfDnsAnswer(
            name,
            "TXT",
            "NOERROR",
            (
                SpfDnsRecord(name, "CNAME", 30, target + "."),
                SpfDnsRecord(target, "TXT", 60, '"v=spf1 -all"'),
            ),
        )
        receipt = self.analyse(f"v=spf1 include:{name} -all", Resolver({(name, "TXT"): supplied})).unwrap()
        self.assertEqual(receipt.query_count, 1)
        self.assertEqual(set(receipt.dependencies), {(name, "TXT"), (name, "CNAME"), (target, "TXT")})

    def test_unrelated_answer_data_is_not_proof_of_a_complete_empty_rrset(self):
        foreign = SpfDnsAnswer(
            "a.example.test", "A", "NOERROR", (SpfDnsRecord("foreign.example.test", "A", 300, "203.0.113.10"),), 60
        )
        resolver = Resolver(
            {("a.example.test", "A"): foreign, ("a.example.test", "AAAA"): answer("a.example.test", "AAAA")}
        )
        self.assertEqual(self.analyse("v=spf1 a:a.example.test -all", resolver).unwrap_err(), "mail_spf_dns_unknown")

    def test_alias_cycles_are_refused_before_repeating_the_old_dns_question(self):
        first, second = "one.example.test", "two.example.test"
        resolver = Resolver(
            {
                (first, "TXT"): SpfDnsAnswer(
                    first, "TXT", "NOERROR", (SpfDnsRecord(first, "CNAME", 60, second + "."),)
                ),
                (second, "TXT"): SpfDnsAnswer(
                    second, "TXT", "NOERROR", (SpfDnsRecord(second, "CNAME", 60, first + "."),)
                ),
            }
        )
        self.assertEqual(self.analyse(f"v=spf1 include:{first} -all", resolver).unwrap_err(), "mail_spf_alias_limit")
        self.assertEqual(len(resolver.calls), 2)

    def test_one_absolute_time_and_query_budget_prevent_further_resolver_calls(self):
        clock = [0.0]
        resolver = Resolver(
            {("inc.example.test", "TXT"): txt("inc.example.test", "v=spf1 include:other.example.test -all")}
        )
        original = resolver.__call__

        def delayed(question):
            result = original(question)
            clock[0] += 31
            return result

        result = self.analyse(
            "v=spf1 include:inc.example.test -all", delayed, budget=SpfBudget(clock=lambda: clock[0], now=lambda: NOW)
        )
        self.assertEqual(result.unwrap_err(), "mail_spf_budget_exhausted")
        self.assertEqual(len(resolver.calls), 1)
        resolver.calls.clear()
        self.assertEqual(
            self.analyse(
                "v=spf1 include:inc.example.test -all", resolver, budget=SpfBudget(max_queries=0)
            ).unwrap_err(),
            "mail_spf_budget_exhausted",
        )
        self.assertEqual(resolver.calls, [])

    def test_exhaustion_between_nested_questions_does_not_dispatch_an_extra_query(self):
        resolver = Resolver(
            {("inc.example.test", "TXT"): txt("inc.example.test", "v=spf1 include:other.example.test -all")}
        )
        self.assertEqual(
            self.analyse(
                "v=spf1 include:inc.example.test -all", resolver, budget=SpfBudget(max_queries=1)
            ).unwrap_err(),
            "mail_spf_budget_exhausted",
        )
        self.assertEqual(len(resolver.calls), 1)

    def test_alias_hop_cap_is_enforced_before_an_additional_wire_question(self):
        resolver = Resolver(
            {
                (f"n{i}.example.test", "TXT"): SpfDnsAnswer(
                    f"n{i}.example.test",
                    "TXT",
                    "NOERROR",
                    (SpfDnsRecord(f"n{i}.example.test", "CNAME", 60, f"n{i + 1}.example.test."),),
                )
                for i in range(9)
            }
        )
        self.assertEqual(
            self.analyse("v=spf1 include:n0.example.test -all", resolver).unwrap_err(), "mail_spf_alias_limit"
        )
        self.assertEqual(len(resolver.calls), 9)

    def test_expired_dependency_during_analysis_never_returns_a_fresh_receipt(self):
        when = [NOW]
        resolver = Resolver(
            {
                ("one.example.test", "TXT"): txt("one.example.test", "v=spf1 -all", ttl=1),
                ("two.example.test", "TXT"): txt("two.example.test", "v=spf1 -all"),
            }
        )

        def delayed(question):
            result = resolver(question)
            if question.name == "two.example.test":
                when[0] += timedelta(seconds=2)
            return result

        self.assertEqual(
            self.analyse(
                "v=spf1 include:one.example.test include:two.example.test -all",
                delayed,
                budget=SpfBudget(now=lambda: when[0]),
            ).unwrap_err(),
            "mail_spf_dns_lifetime_unknown",
        )

    def test_receipt_binds_exact_policy_domain_revision_digest_and_freshness(self):
        policy = "v=spf1 ip4:203.0.113.0/24 ?all"
        receipt = self.analyse(policy, Resolver()).unwrap()
        binding = {
            "domain": DOMAIN,
            "proposed_txt": policy,
            "source": SpfSource(1, DIGEST),
            "now": NOW,
        }
        self.assertTrue(check_spf_receipt(receipt, **binding).is_ok())
        for changes in (
            {"domain": "other.example.test"},
            {"proposed_txt": policy + " "},
            {"source": SpfSource(2, DIGEST)},
            {"source": SpfSource(1, "b" * 64)},
            {"now": receipt.valid_until},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    check_spf_receipt(receipt, **{**binding, **changes}).unwrap_err(), "mail_spf_binding_stale"
                )

    def test_malformed_or_incomplete_answers_and_depth_do_not_become_receipts(self):
        good = txt("inc.example.test", "v=spf1 -all")
        for bad in (
            replace(good, complete=False),
            replace(good, name="foreign.example.test"),
            replace(good, records=(SpfDnsRecord("inc.example.test", "TXT", 300, "not valid TXT \\"),)),
        ):
            with self.subTest(bad=bad):
                self.assertEqual(
                    self.analyse(
                        "v=spf1 include:inc.example.test -all", Resolver({("inc.example.test", "TXT"): bad})
                    ).unwrap_err(),
                    "mail_spf_dns_unknown",
                )
        resolver = Resolver({("inc.example.test", "TXT"): good})
        self.assertEqual(
            self.analyse("v=spf1 include:inc.example.test -all", resolver, budget=SpfBudget(max_depth=0)).unwrap_err(),
            "mail_spf_depth_limit",
        )
        self.assertEqual(resolver.calls, [])


class SpfTransportTests(SimpleTestCase):
    def test_public_tcp_adapter_has_no_retry_and_derives_negative_soa_lifetime(self):
        from apps.provisioning.virtualmin_mail_spf import SpfQuery  # noqa: PLC0415

        question = SpfQuery("empty.example.test", "A", 1.25)
        response = dns.message.make_response(dns.message.make_query(question.name, question.record_type))
        response.authority.append(
            dns.rrset.from_text(
                "example.test.", 120, "IN", "SOA", "ns.example.test. hostmaster.example.test. 1 2 3 4 37"
            )
        )
        with patch("dns.query.tcp", return_value=response) as query:
            result = TcpSpfResolver("1.1.1.1")(question)
        self.assertEqual(result.negative_ttl, 37)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(query.call_args.args[1], "1.1.1.1")
        self.assertEqual(query.call_args.kwargs["timeout"], 1.25)
        response.authority.clear()
        response.authority.append(
            dns.rrset.from_text(
                "example.test.", 20, "IN", "SOA", "ns.example.test. hostmaster.example.test. 1 2 3 4 37"
            )
        )
        with patch("dns.query.tcp", return_value=response):
            self.assertEqual(TcpSpfResolver("1.1.1.1")(question).negative_ttl, 20)

    def test_private_resolver_and_truncated_answer_are_refused_without_fallback(self):
        from apps.provisioning.virtualmin_mail_spf import SpfQuery  # noqa: PLC0415

        with patch("dns.query.tcp") as query:
            for nameserver in (
                "127.0.0.1",
                "::1",
                "192.168.1.1",
                "224.0.0.1",
                "ff02::1",
                "https://resolver.example.test",
            ):
                with self.subTest(nameserver=nameserver), self.assertRaises(ValueError):
                    TcpSpfResolver(nameserver)
        query.assert_not_called()
        question = SpfQuery("empty.example.test", "TXT", 1)
        response = dns.message.make_response(dns.message.make_query(question.name, question.record_type))
        response.flags |= dns.flags.TC
        with patch("dns.query.tcp", return_value=response):
            self.assertFalse(TcpSpfResolver("1.1.1.1")(question).complete)
