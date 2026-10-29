"""Complete zone staging preserves every input record before provider mutation is possible."""

from unittest.mock import patch

import pytest

from apps.domains.dns_zone_import import ZoneImportError, parse_zone_file

ZONE = "customer.example.net"
HEADER = """$ORIGIN customer.example.net.
$TTL 3600
@ IN SOA ns.old.example. hostmaster.customer.example.net. (1 3600 600 86400 300)
@ IN NS ns.old.example.
"""


def parse(extra="", header=HEADER):
    return parse_zone_file((header + extra).encode(), ZONE)


def test_complete_inventory_keeps_unusual_names_multivalue_records_and_provider_replacements():
    result = parse("""@ A 95.217.0.10
@ MX 10 mail.example.org.
@ MX 20 backup.example.org.
odd-selector-2026._domainkey TXT ("v=DKIM1; " "p=ObscureValue")
_sip._tcp SRV 1 10 5061 sip.example.org.
www CNAME @
*.shop A 95.217.0.11
""")
    assert result.source_count == 9
    assert len(result.records) == 9
    assert len(result.replacements) == 2
    assert {record.record_type for record in result.replacements} == {"SOA", "NS"}
    assert {record.rdata for record in result.records if record.record_type == "MX"} == {
        "10 mail.example.org.",
        "20 backup.example.org.",
    }
    assert next(record for record in result.records if record.name == f"www.{ZONE}").rdata == f"{ZONE}."
    txt = next(record for record in result.records if record.record_type == "TXT")
    assert txt.rdata == '"v=DKIM1; " "p=ObscureValue"'


def test_out_of_zone_owners_are_rejected_before_dnspython_can_silently_discard_them():
    with pytest.raises(ZoneImportError) as error:
        parse('outside.other.example. TXT "private-value"\n')
    assert error.value.code == "out_of_zone_owner"
    assert error.value.line == 5
    assert "private-value" not in str(error.value)


def test_conflicting_rrset_ttls_are_rejected_before_union_and_duplicates_remain_visible():
    with pytest.raises(ZoneImportError) as error:
        parse("@ 300 A 95.217.0.10\n@ 600 A 95.217.0.11\n")
    assert error.value.code == "conflicting_rrset_ttl"
    result = parse("@ 300 A 95.217.0.10\n@ 300 A 95.217.0.10\n")
    assert result.source_count == 4
    assert len(result.records) == 3
    assert len(result.duplicates) == 1


@pytest.mark.parametrize(
    "record",
    [
        "child NS ns.child.example.\n",
        "child DS 12345 13 2 " + "00" * 32 + "\n",
        "@ DNSKEY 257 3 15 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
        "service TYPE65400 \\# 3 010203\n",
        "www HTTPS 1 . alpn=h2\n",
    ],
)
def test_unsupported_delegation_signed_or_opaque_rdata_is_retained_in_the_rejected_inventory(record):
    with pytest.raises(ZoneImportError) as error:
        parse(record + 'obscure TXT "must-not-be-dropped"\n')
    assert error.value.code == "unsupported_records"
    assert len(error.value.records) == 4
    assert any(item.name == f"obscure.{ZONE}" for item in error.value.records)


@pytest.mark.parametrize(
    "directive", ["$INCLUDE /etc/passwd", "$GENERATE 1-1000000000 host$ A 95.217.0.10", "$UNKNOWN ignored"]
)
def test_include_generate_and_unknown_directives_never_run(directive):
    with (
        patch("builtins.open", side_effect=AssertionError("upload attempted filesystem include")),
        pytest.raises(ZoneImportError) as error,
    ):
        parse(directive + "\n")
    assert error.value.code == "invalid_zone_file"


def test_soa_and_apex_ns_are_required_and_non_apex_soa_is_refused():
    with pytest.raises(ZoneImportError, match="missing_apex_infrastructure"):
        parse("www A 95.217.0.10\n", "$ORIGIN customer.example.net.\n$TTL 300\n")
    with pytest.raises(ZoneImportError) as error:
        parse("wrong SOA ns.old.example. hostmaster.customer.example.net. 1 3600 600 86400 300\n")
    assert error.value.code == "soa_not_apex"


def test_record_count_and_wire_bounds_apply_before_deduplication():
    with patch("apps.domains.dns_zone_import.MAX_RECORDS", 3), pytest.raises(ZoneImportError, match="record_limit"):
        parse("@ A 95.217.0.10\n@ A 95.217.0.10\n")
    with (
        patch("apps.domains.dns_zone_import.MAX_RECORD_BYTES", 8),
        pytest.raises(ZoneImportError, match="record_too_large"),
    ):
        parse()


def test_upload_size_and_non_internet_class_are_rejected():
    with (
        patch("apps.domains.dns_zone_import.MAX_UPLOAD_BYTES", 10),
        pytest.raises(ZoneImportError, match="upload_limit"),
    ):
        parse()
    with pytest.raises(ZoneImportError, match="invalid_zone_file"):
        parse('@ CH TXT "wrong-class"\n')


def test_digest_is_order_independent_but_preserves_case_sensitive_rdata_and_ttl():
    first = parse('@ A 95.217.0.10\n@ TXT "Sensitive"\n')
    reordered = parse('@ TXT "Sensitive"\n@ A 95.217.0.10\n')
    changed = parse('@ TXT "sensitive"\n@ A 95.217.0.10\n')
    ttl_changed = parse('@ 7200 TXT "Sensitive"\n@ A 95.217.0.10\n')
    assert first.digest == reordered.digest
    assert first.digest != changed.digest
    assert first.digest != ttl_changed.digest


def test_origin_changes_omitted_owners_and_decimal_escapes_survive():
    result = parse("""$ORIGIN sub.customer.example.net.
mail 300 IN MX 10 @
     TXT "first\\255second"
odd\\045name TXT "token"
""")
    assert any(item.name == f"mail.sub.{ZONE}" and item.rdata == f"10 sub.{ZONE}." for item in result.records)
    assert any("\\255" in item.rdata for item in result.records)
    assert any(item.name == f"odd-name.sub.{ZONE}" for item in result.records)


def test_cname_exclusivity_and_apex_cname_are_enforced_during_staging():
    with pytest.raises(ZoneImportError):
        parse('www CNAME customer.example.org.\nwww TXT "conflict"\n')
    with pytest.raises(ZoneImportError, match="apex_cname"):
        parse("@ CNAME customer.example.org.\n")


@pytest.mark.parametrize("ttl", [1, 30, 86401])
def test_unrepresentable_provider_ttls_are_explicit_whole_import_refusals(ttl):
    with pytest.raises(ZoneImportError, match="ttl_out_of_range"):
        parse(f"@ {ttl} A 95.217.0.10\n")
