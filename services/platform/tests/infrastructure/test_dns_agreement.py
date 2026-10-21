"""Whether every authoritative server answers a name with exactly the expected addresses (ADR-0061 P2.10).

Nothing here queries real DNS: the authoritative answers are handed in, as the probe would return them.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.infrastructure.dns_agreement import Agreement, authoritative_agreement
from apps.infrastructure.panel_cert_probes import AuthoritativeAnswer

FQDN = "h7k3p2q8.praho-sites.net"


def _answers(v4: tuple[str, ...], v6: tuple[str, ...], *, ttl: int = 60) -> list[AuthoritativeAnswer]:
    return [
        answer
        for ns in ("ns1.example.net", "ns2.example.net")
        for answer in (
            AuthoritativeAnswer(ns, "A", v4, "198.51.100.1", ttl=ttl),
            AuthoritativeAnswer(ns, "AAAA", v6, "198.51.100.1", ttl=ttl),
        )
    ]


class AgreementTests(SimpleTestCase):
    def check(self, *rounds: list[AuthoritativeAnswer], v4: str = "95.217.0.10", v6: str | None = "2a01:4f8::1") -> Agreement:
        queue = list(rounds)
        return authoritative_agreement(FQDN, v4, v6, query=lambda fqdn: queue.pop(0), pause=0)

    def test_every_server_answering_exactly_the_addresses_agrees(self) -> None:
        result = self.check(_answers(("95.217.0.10",), ("2a01:4f8::1",)))

        self.assertTrue(result.agreed, result.detail)
        self.assertEqual(result.ttl, 60)

    def test_addresses_are_compared_as_addresses_not_text(self) -> None:
        result = self.check(_answers(("95.217.0.10",), ("2a01:04f8:0000::1",)))

        self.assertTrue(result.agreed, result.detail)

    def test_one_server_still_answering_the_old_node_disagrees(self) -> None:
        answers = _answers(("95.217.0.10",), ("2a01:4f8::1",))
        answers[2] = AuthoritativeAnswer("ns2.example.net", "A", ("203.0.113.9",), "198.51.100.1", ttl=60)

        result = self.check(answers, answers, answers)

        self.assertFalse(result.agreed)
        self.assertIn("ns2.example.net", result.detail)

    def test_a_failed_query_is_retried_and_then_agrees(self) -> None:
        failed = [AuthoritativeAnswer("discovery", "NS", error="Cannot discover authoritative nameservers")]

        result = self.check(failed, _answers(("95.217.0.10",), ("2a01:4f8::1",)))

        self.assertTrue(result.agreed, result.detail)

    def test_an_error_on_every_attempt_never_counts_as_agreement(self) -> None:
        failed = [AuthoritativeAnswer("discovery", "NS", error="Cannot discover authoritative nameservers")]

        result = self.check(failed, failed, failed)

        self.assertFalse(result.agreed)

    def test_no_aaaa_expected_means_no_aaaa_answered(self) -> None:
        self.assertTrue(self.check(_answers(("95.217.0.10",), ()), v6=None).agreed)
        self.assertFalse(self.check(*[_answers(("95.217.0.10",), ("2a01:4f8::1",))] * 3, v6=None).agreed)

    def test_the_highest_ttl_any_server_answered_is_reported(self) -> None:
        answers = _answers(("95.217.0.10",), ("2a01:4f8::1",), ttl=60)
        answers[0] = AuthoritativeAnswer("ns1.example.net", "A", ("95.217.0.10",), "198.51.100.1", ttl=300)

        self.assertEqual(self.check(answers).ttl, 300)
