"""The sanitiser that stands between a real Virtualmin response and a committed fixture.

The contract suite (`make test-virtualmin-contract`) records what Virtualmin really answers, and the
platform tests replay it. A recording holds the node's address, a certificate, password hashes and
random identifiers unless the sanitiser strips them, and a fixture that still carries them is both a
leak and a diff on every run. These tests need no lab: they pin what the sanitiser removes, what it
must keep (the error text PRAHO classifies on), and that every committed fixture is already clean.
"""

from __future__ import annotations

import json
from pathlib import Path
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
            "Remote program frobnicate-domain does not exist",
            "Unknown parameter --format",
            "Virtual server contract.praho.test is already disabled",
            "The BIND DNS server is not enabled for Virtualmin",
        ):
            assert sanitise_text(text) == text

    def test_sanitising_twice_changes_nothing(self) -> None:
        raw = f"IP 10.1.2.3 id 17920605682563 {PEM} Created on: 10/15/2026 10:36 AM"
        once = sanitise_text(raw)
        assert sanitise_text(once) == once


class TestHostIndependence:
    """Recordings made on one machine must match those made on another (a laptop, a CI runner)."""

    def test_a_webmin_log_timestamp_is_replaced_whole(self) -> None:
        line = "[16/Oct/2026:06:53:56 +0000] [10.0.0.7] Failed to open /tmp/x"
        assert sanitise_text(line) == "[<timestamp>] [<ip>] Failed to open /tmp/x"

    def test_the_disk_device_and_the_cpu_architecture_are_host_facts(self) -> None:
        for device, arch in (("/dev/vda1", "aarch64"), ("/dev/root", "x86_64")):
            text = f"disk_fs: \n    * \n        device: {device}\n        dir: /\nkernel: \n    arch: {arch}\n    os: Linux\n"
            assert sanitise_text(text) == (
                "disk_fs: \n    * \n        device: <device>\n        dir: /\nkernel: \n    arch: <arch>\n    os: Linux\n"
            )


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


    def test_numbers_production_sends_are_kept_exactly(self) -> None:
        """Quotas, bandwidth and sizes are what the contract pins; redacting them hides a wrong value."""
        params = {"domain": "contract.praho.test", "bw": "104857600", "bandwidth": "1073741824", "quota": "2097152"}
        assert sanitise_params(params) == params

    def test_ids_and_random_path_tokens_still_vary_freely(self) -> None:
        cleaned = sanitise_params(
            {"id": "179191667478547", "dest": "/var/lib/praho-transfer/virtualmin_backup_9f1c2e7a5b3d4c6e.tar.gz"}
        )
        assert cleaned == {"id": "<id>", "dest": "/var/lib/praho-transfer/virtualmin_backup_<hex>.tar.gz"}


class TestRecordingLeaks:
    def test_kept_numbers_are_not_leaks_but_an_unredacted_secret_is(self) -> None:
        from tests.virtualmin_lab.sanitise import find_recording_leaks  # noqa: PLC0415

        clean = {"program": "modify-domain", "cases": {"ok": {"params": {"bw": "104857600"}, "body": "ok"}}}
        assert find_recording_leaks(clean) == []
        leaked = {"program": "create-domain", "cases": {"ok": {"params": {"pass": "Zz9!contractPw1x"}, "body": "ok"}}}
        assert find_recording_leaks(leaked) == ["$.cases.ok.params.pass: not sanitised"]


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


class TestInfoIsAMachineInventory:
    """`info` prints the whole machine: the kernel, the CPU, the pending package updates, installed versions.

    Two runs of the same Virtualmin on different hosts (a laptop container and a CI runner) must record the
    same `info`. The two samples are the committed recording's body and the body a GitHub runner produced.
    """

    SAMPLES = Path(__file__).parent / "virtualmin_info_samples"

    @classmethod
    def _recorded(cls, sample: str) -> Any:
        return sanitise_body((cls.SAMPLES / sample).read_text(), program="info")

    def test_the_same_virtualmin_on_two_hosts_records_the_same_info(self) -> None:
        laptop = self._recorded("arm64-linuxkit.json")
        runner = self._recorded("x86_64-azure.json")
        assert laptop == runner

    def test_host_inventory_does_not_reach_the_recording(self) -> None:
        output = str(self._recorded("x86_64-azure.json")["output"])
        for host_fact in ("azure", "linuxkit", "EPYC", "AuthenticAMD", "10.11.", "2.4.68", "8.2.34", "libmariadb3"):
            assert host_fact not in output
        assert "poss" not in output

    def test_what_praho_reads_survives(self) -> None:
        body = self._recorded("arm64-linuxkit.json")
        assert body["command"] == "info"
        assert body["status"] == "success"
        lines = str(body["output"]).splitlines()
        for kept in ("virtualmin version: 8.3.0", "virtualmin edition: GPL", "os: Debian Linux 12"):
            assert any(line.strip() == kept for line in lines), kept
        # The gateway reads these keys by name: they stay even though their values are placeholders.
        assert {"disk_free:", "disk_total:", "disk_used:", "host:"} <= {line.split()[0] for line in lines if line}

    def test_normalising_twice_changes_nothing(self) -> None:
        once = self._recorded("x86_64-azure.json")
        assert sanitise_body(json.dumps(once), program="info") == once

    def test_a_program_that_is_not_an_inventory_is_not_reduced(self) -> None:
        raw = (self.SAMPLES / "arm64-linuxkit.json").read_text()
        assert sanitise_body(raw, program="list-domains") == sanitise_body(raw)

    def test_a_refusal_from_info_keeps_its_text(self) -> None:
        refusal = json.dumps({"status": "failure", "error": "Permission denied", "output": None})
        assert sanitise_body(refusal, program="info") == {"status": "failure", "error": "Permission denied", "output": None}


def test_the_stale_read_warning_is_run_to_run_noise() -> None:
    """Virtualmin prints this when the domain file changed under its own restore steps, depending on timing.

    It appeared in one scheduled lab run's restore-domain output and not in the next, with the same code, and
    nothing classifies on it: the drift check must not read it as a contract change (#728).
    """
    with_warning = (
        "Re-creating virtual server contract-restore.praho.test ..\n"
        "    Saving server details ..\n"
        "Domain /etc/webmin/virtual-server/domains/17612345678901 was modified since last read!\n"
        "    .. done\n"
    )
    without = (
        "Re-creating virtual server contract-restore.praho.test ..\n"
        "    Saving server details ..\n"
        "    .. done\n"
    )
    assert sanitise_text(with_warning) == sanitise_text(without)
    assert sanitise_text(sanitise_text(with_warning)) == sanitise_text(with_warning)
