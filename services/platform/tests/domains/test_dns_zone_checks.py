"""Old-zone checks supplement the uploaded inventory and assigned-server checks prove readiness."""

from types import SimpleNamespace
from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from apps.domains.dns_zone_checks import _Channel, handover_snapshot, probe_import_batch, probe_provider_batch
from apps.domains.dns_zone_import import parse_zone_file
from apps.infrastructure.dns_probes import DnsProbeTransport
from tests.domains.test_dns_zone_import import HEADER, ZONE
from tests.infrastructure.test_dns_probes import DOMAIN, Wire, wide_authority


class Channel:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.error = None

    def observation(self, name, kind):
        self.calls.append((name, kind))
        if self.error:
            raise self.error
        values = self.records.get((name, kind), ())
        return SimpleNamespace(
            name=name,
            record_type=kind,
            values=tuple(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(kind), text) for text in values
            ),
            alias="",
            negative="" if values else "nodata",
            ttl=300,
        )

    def query(self, name, kind, *, parent=False, wildcard_owner=False):
        return self.observation(name, kind)

    def assigned(self, name, kind, nameservers, zone):
        assert nameservers == ("ns.cloudflare.example",)
        return self.observation(name, kind)

    def parent_nameservers(self, name):
        return ("ns.old.example",)


def inventory(extra):
    return [row.as_dict() for row in parse_zone_file((HEADER + extra).encode(), ZONE).records]


def check_all(records, channel):
    cursor = 0
    for _ in range(100):
        result = probe_import_batch(ZONE, records, cursor, channel=channel)
        if not result["ok"] or result["complete"]:
            return result
        cursor = result["cursor"]
    raise AssertionError("bounded cross-check did not finish")


def test_positive_old_record_missing_from_inventory_blocks_even_if_every_imported_record_matches():
    channel = Channel()
    channel.records[("_dmarc." + ZONE, "TXT")] = ('"v=DMARC1; p=reject"',)
    result = check_all(inventory("@ A 95.217.0.20\n"), channel)
    assert result["ok"] is False
    assert result["error"] == "source_record_missing_from_inventory"


def test_unknown_never_becomes_absence_or_success_and_is_retryable():
    channel = Channel()
    channel.error = OSError("network unavailable")
    result = probe_import_batch(ZONE, inventory(""), 0, channel=channel)
    assert result["ok"] is False
    assert result["complete"] is False
    assert result["error"] == "dns_observation_unknown"


def test_crosscheck_is_checkpointed_and_covers_unusual_imported_names():
    channel = Channel()
    records = inventory('obscure-selector._domainkey TXT "value"\n')
    cursor = 0
    for _ in range(100):
        before = len(channel.calls)
        result = probe_import_batch(ZONE, records, cursor, channel=channel, batch_size=2)
        assert len(channel.calls) - before <= 3  # Two checks and the initial parent DS snapshot.
        assert result["ok"] is True
        cursor = result["cursor"]
        if result["complete"]:
            break
    assert result["complete"] is True
    assert (f"obscure-selector._domainkey.{ZONE}", "TXT") in channel.calls


def test_wildcard_expansion_is_not_incorrectly_reported_as_an_unexported_explicit_record():
    channel = Channel()
    channel.records[("mail." + ZONE, "A")] = ("95.217.0.20",)
    result = check_all(inventory("* A 95.217.0.20\n"), channel)
    assert result["ok"] is True
    assert result["complete"] is True


def test_assigned_server_proof_checks_exact_content_and_ttl_for_every_record():
    channel = Channel()
    expected = [{"name": ZONE, "record_type": "A", "rdata": {"text": "95.217.0.20"}, "ttl": 300}]
    channel.records[(ZONE, "A")] = ("95.217.0.21",)
    wrong = probe_provider_batch(ZONE, expected, ("ns.cloudflare.example",), 0, channel=channel)
    assert wrong["ok"] is False
    channel.records[(ZONE, "A")] = ("95.217.0.20",)
    correct = probe_provider_batch(ZONE, expected, ("ns.cloudflare.example",), 0, channel=channel)
    assert correct["ok"] is True
    assert correct["complete"] is True
    expected[0]["ttl"] = 3600
    assert probe_provider_batch(ZONE, expected, ("ns.cloudflare.example",), 0, channel=channel)["ok"] is False


def test_alias_answer_is_compared_as_a_cname_rather_than_disappearing():
    channel = Channel()
    original = channel.query

    def alias(name, kind, *, parent=False, wildcard_owner=False):
        if name == "www." + ZONE:
            return SimpleNamespace(
                name=name, record_type=kind, values=(), alias="other.example.org", negative="", ttl=300
            )
        return original(name, kind, parent=parent, wildcard_owner=wildcard_owner)

    channel.query = alias
    correct = check_all(inventory("www CNAME other.example.org.\n"), channel)
    assert correct["ok"] is True
    missing = check_all(inventory(""), channel)
    assert missing["error"] == "source_record_missing_from_inventory"


def _parent_referral(question):
    response = dns.message.make_response(dns.message.make_query(question.name, question.record_type))
    response.flags &= ~dns.flags.AA
    response.authority.append(dns.rrset.from_text(DOMAIN + ".", 86400, "IN", "NS", "ns.cloudflare.example."))
    return response


def test_real_wire_parent_referral_does_not_require_child_aa_and_preserves_the_delegation_ttl():
    wire = Wire()
    wire.overrides[(DOMAIN, "NS")] = _parent_referral
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    with patch("apps.infrastructure.dns_probes.DnsProbeTransport", return_value=transport):
        proof = handover_snapshot(DOMAIN, channel=_Channel())
    assert proof["state"] == "verified"
    assert proof["nameservers"] == ["ns.cloudflare.example"]
    assert proof["ns_ttl"] == 86400
    assert proof["ds"] == []


def test_assigned_authority_resolution_never_sends_a_packet_to_a_private_address():
    wire = Wire()
    wire.records[("ns.private.example.net", "A")] = ("10.0.0.1",)
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    with patch("apps.infrastructure.dns_probes.DnsProbeTransport", return_value=transport):
        proof = probe_provider_batch(
            DOMAIN,
            [{"name": DOMAIN, "record_type": "A", "rdata": {"text": "95.217.0.20"}, "ttl": 300}],
            ("ns.private.example.net",),
            0,
            channel=_Channel(),
        )
    assert proof["ok"] is False
    assert all(question.server != "10.0.0.1" for question in wire.calls)


def _crosscheck_over_wire(wire, records):
    """Every batch over the real transport and channel, as the worker runs them; observations accumulate."""
    wire.overrides[(DOMAIN, "NS")] = _parent_referral
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    observations = {}
    cursor = 0
    with patch("apps.infrastructure.dns_probes.DnsProbeTransport", return_value=transport):
        channel = _Channel()
        for _ in range(100):
            result = probe_import_batch(ZONE, records, cursor, channel=channel)
            observations.update(result["observations"])
            if not result["ok"] or result["complete"]:
                return result, observations
            cursor = result["cursor"]
    raise AssertionError("bounded cross-check did not finish")


def test_an_imported_wildcard_owner_is_cross_checked_by_its_own_name_over_the_real_transport():
    """A query naming `*.shop` matches the wildcard RRset itself (RFC 4592), so the import can finish."""
    owner = f"*.shop.{ZONE}"
    wire = Wire()
    wire.records = {(owner, "A"): ("95.217.0.11",), (owner, "TXT"): ('"wildcard-proof"',)}
    records = inventory('*.shop A 95.217.0.11\n*.shop TXT "wildcard-proof"\n')
    result, observations = _crosscheck_over_wire(wire, records)
    assert result["ok"] is True, result
    assert result["complete"] is True
    assert len(observations[f"{owner}|A"]["digests"]) == 1
    assert len(observations[f"{owner}|TXT"]["digests"]) == 1
    # Only the zone's authorities are asked the literal owner; discovery climbs from its parent.
    asked = [question for question in wire.calls if question.name == owner]
    assert asked
    assert not any(question.recursive for question in asked)


def test_an_owner_the_cross_check_cannot_ask_is_a_terminal_refusal_not_an_unknown():
    """`a*b` is a literal label the probe refuses to ask; retrying could never prove it, so say so."""
    wire = Wire()
    wire.records = {}
    result, _observations = _crosscheck_over_wire(wire, inventory('a*b TXT "proof"\n'))
    assert result["ok"] is False
    assert result["error"] == "source_owner_uncheckable", result
    assert not any("*" in question.name for question in wire.calls)


def test_an_uncheckable_owner_is_reported_before_any_packet_even_when_dns_is_failing():
    """Network trouble must not hide a refusal no retry can clear: every owner is checked first."""
    wire = Wire()
    wire.overrides[(DOMAIN, "NS")] = OSError("parent unreachable")
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    with patch("apps.infrastructure.dns_probes.DnsProbeTransport", return_value=transport):
        result = probe_import_batch(ZONE, inventory('a*b TXT "proof"\n'), 0, channel=_Channel())
    assert (result["ok"], result.get("error")) == (False, "source_owner_uncheckable")
    assert wire.calls == []


def test_handover_reads_a_parent_zone_with_thirteen_authorities():
    """Every .com import asks the 13 registry servers for the delegation and DS before anything else."""
    wire = Wire()
    wide_authority(wire, "example.net", 13)  # The parent zone of DOMAIN in this fixture.
    wire.overrides[(DOMAIN, "NS")] = _parent_referral
    transport = DnsProbeTransport(query=wire, recursive_servers=("1.1.1.1",))
    with patch("apps.infrastructure.dns_probes.DnsProbeTransport", return_value=transport):
        proof = handover_snapshot(DOMAIN, channel=_Channel())
    assert proof["state"] == "verified", proof
    assert proof["nameservers"] == ["ns.cloudflare.example"]
    assert len({question.server for question in wire.calls if question.record_type == "DS"}) == 13
