"""The sanitiser that stands between a real Virtualmin response and a committed fixture.

The contract suite (`make test-virtualmin-contract`) records what Virtualmin really answers, and the
platform tests replay it. A recording holds the node's address, a certificate, password hashes and
random identifiers unless the sanitiser strips them, and a fixture that still carries them is both a
leak and a diff on every run. These tests need no lab: they pin what the sanitiser removes, what it
must keep (the error text PRAHO classifies on), and that every committed fixture is already clean.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.virtualmin_lab.sanitise import (
    REDACTED,
    find_leaks,
    sanitise_body,
    sanitise_params,
    sanitise_text,
    sanitise_value,
)

pytestmark = pytest.mark.integration

PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDHTCCAgWgAwIBAgIUCvBCc/XgMpitCRM0s3dblz6RrZAwDQYJKoZIhvcNAQEL\n"
    "BQAwHjEcMBoGA1UEAwwTY29udHJhY3QucHJhaG8udGVzdDAeFw0yNjEwMTUxMDQw\n"
    "-----END CERTIFICATE-----"
)


class TestSanitiseText:
    @pytest.mark.parametrize(
        ("raw", "secret"),
        [
            ("IP address: 172.22.0.3 (Shared)", "172.22.0.3"),
            ("External IP address: 89.44.228.9", "89.44.228.9"),
            ("listening on fe80::42:acff:fe16:3 now", "fe80::42:acff:fe16:3"),
            ("hash $y$j9T$NCVK.A5ROd5l392gh1o8W.$bU3qnn.NyBOMTOmoPQFMp1pivNryGCxlZKskffB5RV1", "NCVK.A5ROd5l392"),
            ("hash $6$salt1234$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ", "abcdefghijklmnopqrstuvwxyz"),
            ("ID: 17920605682563", "17920605682563"),
            ("socket /run/php/17920605682563.sock", "17920605682563"),
            ("virtualmin_backup_00112233445566778899aabbccddeeff.tar.gz", "00112233445566778899aabbccddeeff"),
            ("Created on: 10/15/2026 10:36 AM", "10/15/2026"),
            ("started 2026-10-15 10:36:12 UTC", "10:36:12"),
            ("Created Unix time: 1792060568", "1792060568"),
            ("Final size: 1.5 MiB", "1.5 MiB"),
            ("allocated user ID is 1003 and group ID is 1002", "1003"),
            ("Password for mysql: YFOId13iLKMFPA9feknycPswR", "YFOId13iLKMFPA9feknycPswR"),
            (PEM, "MIIDHTCCAgWgAwIBAgIUCvBCc"),
        ],
    )
    def test_secrets_and_volatile_values_are_stripped(self, raw: str, secret: str) -> None:
        assert secret not in sanitise_text(raw)

    def test_a_domain_id_is_one_placeholder_whatever_its_length(self) -> None:
        for identifier in ("17920605682563", "1792060568256312", "179206056825631234"):
            assert sanitise_text(f"/etc/webmin/virtual-server/domains/{identifier}") == (
                "/etc/webmin/virtual-server/domains/<id>"
            )

    def test_the_feature_counts_of_info_do_not_depend_on_what_ran_before(self) -> None:
        few = "cpu: x\nfcount: \n    dir: 1\n    web: 1\nhost: \n    hostname: vm\n"
        many = "cpu: x\nfcount: \n    aliases: 0\n    dbs: 1\n    dir: 1\n    users: 2\n    web: 1\nhost: \n    hostname: vm\n"
        assert sanitise_text(few) == sanitise_text(many) == "cpu: x\nfcount: <counts>\nhost: \n    hostname: vm\n"

    def test_the_text_the_gateway_classifies_on_is_untouched(self) -> None:
        for text in (
            "Virtual server nope.praho.test does not exist",
            "Remote program get-domain does not exist",
            "Unknown parameter --format",
            "Virtual server contract.praho.test is already disabled",
            "The BIND DNS server is not enabled for Virtualmin",
        ):
            assert sanitise_text(text) == text

    def test_sanitising_twice_changes_nothing(self) -> None:
        raw = f"IP 10.1.2.3 id 17920605682563 {PEM} Created on: 10/15/2026 10:36 AM"
        once = sanitise_text(raw)
        assert sanitise_text(once) == once


class TestSanitiseValue:
    def test_secret_keys_lose_their_value_and_keep_their_name(self) -> None:
        cleaned = sanitise_value(
            {
                "hashed_password": ["$y$j9T$abcdefghijklmnopqrstuvwxyz"],
                "password_for_mysql": ["YFOId13iLKMFPA9feknycPswR"],
                "ssl_key_file": ["/etc/ssl/virtualmin/1/ssl.key"],
                "description": ["recovery-seed-value"],
                "username": ["contract"],
            }
        )
        assert cleaned["hashed_password"] == [REDACTED]
        assert cleaned["password_for_mysql"] == [REDACTED]
        assert cleaned["ssl_key_file"] == [REDACTED]
        assert cleaned["description"] == [REDACTED]
        assert cleaned["username"] == ["contract"]

    def test_certificate_rows_of_a_listing_collapse_to_one_marker(self) -> None:
        rows = [
            {"name": "contract.praho.test", "value": ""},
            {"name": "-----BEGIN CERTIFICATE-----", "values": {}},
            {"name": "MIIDHTCCAgWgAwIBAgIUCvBCc/XgMpitCRM0s3dblz6RrZAwDQYJKoZIhvcNAQEL", "values": {}},
            {"name": "BQAwHjEcMBoGA1UEAwwTY29udHJhY3QucHJhaG8udGVzdDAeFw0yNjEwMTUxMDQw", "values": {}},
            {"name": "-----END CERTIFICATE-----", "values": {}},
        ]
        cleaned = sanitise_value({"data": rows})
        assert cleaned["data"] == [{"name": "contract.praho.test", "value": ""}, {"name": "<pem>", "values": {}}]

    def test_the_description_column_of_the_domain_table_is_redacted(self) -> None:
        rows = [
            {"name": "Domain                         Username        Description                   ", "values": {}},
            {"name": "------------------------------ --------------- ------------------------------", "values": {}},
            {"name": "contract.praho.test            contract        the-recovery-seed             ", "values": {}},
        ]
        cleaned = sanitise_value({"data": rows})["data"]
        assert cleaned[0] == rows[0]
        assert cleaned[1] == rows[1]
        assert cleaned[2]["name"] == "contract.praho.test contract <redacted>"
        assert sanitise_value({"data": cleaned})["data"] == cleaned

    def test_the_status_and_error_of_a_refusal_survive(self) -> None:
        body = {
            "status": "failure",
            "command": "list-domains",
            "error": "Virtual server nope.praho.test does not exist",
            "full_error": "Virtual server nope.praho.test does not exist\n\nLists the virtual servers.\n",
        }
        assert sanitise_value(body) == body


class TestSanitiseParams:
    def test_the_password_and_the_description_are_redacted_the_rest_is_kept(self) -> None:
        cleaned = sanitise_params(
            {
                "domain": "contract.praho.test",
                "pass": "Zz9!contractPw1x",
                "desc": "recovery-seed",
                "start": "2026-10-01",
                "default-features": "",
                "except-feature": ["mail", "ssl"],
            }
        )
        assert cleaned == {
            "domain": "contract.praho.test",
            "pass": REDACTED,
            "desc": REDACTED,
            "start": "2026-10-01",
            "default-features": "",
            "except-feature": ["mail", "ssl"],
        }


class TestSanitiseBody:
    def test_a_json_body_comes_back_as_data_in_a_stable_order(self) -> None:
        raw = '{"b" : 1, "a" : {"y": "89.44.228.9", "x": "ok"}}\n\n'
        assert sanitise_body(raw) == {"a": {"x": "ok", "y": "<ip>"}, "b": 1}

    def test_a_body_that_is_not_json_comes_back_as_sanitised_text(self) -> None:
        assert sanitise_body("<html>proxy 10.0.0.1</html>") == "<html>proxy <ip></html>"


class TestLeakDetection:
    def test_a_planted_secret_is_reported(self) -> None:
        planted: dict[str, Any] = {
            "ip": "external 89.44.228.9",
            "hash": "$6$salt1234$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
            "cert": PEM,
            "id": "17920605682563",
            "password": "hunter2hunter2",
        }
        leaks = find_leaks(planted)
        assert len(leaks) == 5, leaks

    def test_sanitised_output_has_no_leaks(self) -> None:
        raw = {
            "ip": "external 89.44.228.9",
            "hash": "$6$salt1234$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
            "cert": PEM,
            "id": "17920605682563",
            "password": "hunter2hunter2",
        }
        assert find_leaks(sanitise_value(raw)) == []
