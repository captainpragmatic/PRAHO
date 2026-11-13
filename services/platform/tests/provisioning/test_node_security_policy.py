"""Policy proof inspects reachable live chains, including pre-UFW bypasses."""

import copy
import json
from typing import ClassVar
from unittest import TestCase

from django.core.exceptions import ValidationError

from apps.provisioning.virtualmin_security_policy import (
    CROWDSEC_PROFILE,
    SSH_CONFIG_DIGESTS,
    _fail,
    _verify_listeners,
    verify_evidence,
    verify_filter,
)

GENERIC_POLICY_FAILURE = "Effective inbound firewall policy is incomplete or admits unreviewed traffic."
NAMED_POLICY_FAILURE = "Effective inbound firewall policy is incomplete or admits unreviewed traffic ({detail})."

OPERATOR_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
OPERATOR_FINGERPRINT = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
TUNNEL_OPTIONS = ["permitopen=127.0.0.1:10000", "port-forwarding", "restrict"]


def ssh_policy_services():
    common = {
        "port": ["9876"],
        "permitrootlogin": ["without-password"],
        "pubkeyauthentication": ["yes"],
        "authenticationmethods": ["publickey"],
        "passwordauthentication": ["no"],
        "kbdinteractiveauthentication": ["no"],
        "permitemptypasswords": ["no"],
        "hostbasedauthentication": ["no"],
        "strictmodes": ["yes"],
        "usedns": ["no"],
        "allowtcpforwarding": ["no"],
        "allowstreamlocalforwarding": ["no"],
        "allowagentforwarding": ["no"],
        "x11forwarding": ["no"],
        "permittunnel": ["no"],
        "gatewayports": ["no"],
        "permituserenvironment": ["no"],
        "authorizedkeysfile": [".ssh/authorized_keys .ssh/authorized_keys2"],
        "authorizedkeyscommand": ["none"],
        "authorizedprincipalscommand": ["none"],
        "authorizedprincipalsfile": ["none"],
        "trustedusercakeys": ["none"],
        "forcecommand": ["none"],
        "permittty": ["yes"],
        "permitopen": ["any"],
    }
    contexts = {"GLOBAL": common, "ROOT": copy.deepcopy(common), "TUNNEL": copy.deepcopy(common)}
    contexts["TUNNEL"].update(
        allowtcpforwarding=["local"], forcecommand=["/bin/false"], permittty=["no"], permitopen=["127.0.0.1:10000"]
    )
    rows = ["PRAHO_SSH_" + tag + " " + json.dumps(value, sort_keys=True) for tag, value in contexts.items()]
    rows += [
        'PRAHO_SSH_ACCOUNT {"present":true,"name":"praho-webmin-tunnel","uid":999,"gid":999,"home":"/home/praho-webmin-tunnel","shell":"/usr/sbin/nologin"}',
        'PRAHO_SSH_KEYS {"status":"complete","files":[".ssh/authorized_keys",".ssh/authorized_keys2"]}',
        "PRAHO_SSH_KEY " + json.dumps({"fingerprint": OPERATOR_FINGERPRINT, "options": TUNNEL_OPTIONS}),
        "PRAHO_SSH_CONFIG " + json.dumps({"sha256": SSH_CONFIG_DIGESTS[".ssh/authorized_keys .ssh/authorized_keys2"]}),
        'PRAHO_SSH_STARTUP {"canonical":true}',
    ]
    return rows


def filter_rules(ipv6=False):
    prefix = "ufw6" if ipv6 else "ufw"
    address = "2001:db8::1/128" if ipv6 else "192.0.2.1/32"
    return "\n".join(
        [
            "*filter",
            ":INPUT DROP [0:0]",
            ":FORWARD DROP [0:0]",
            f":{prefix}-before-input - [0:0]",
            f":{prefix}-user-input - [0:0]",
            f"-A INPUT -j {prefix}-before-input",
            f"-A {prefix}-before-input -i lo -j ACCEPT",
            f"-A {prefix}-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"-A {prefix}-before-input -j {prefix}-user-input",
            f"-A {prefix}-user-input -p tcp -m tcp --dport 80 -j ACCEPT",
            f"-A {prefix}-user-input -p tcp -m tcp --dport 443 -j ACCEPT",
            f"-A {prefix}-user-input -s {address} -p tcp -m tcp --dport 9876 -j ACCEPT",
            f"-A {prefix}-user-input -s {address} -p tcp -m tcp --dport 10000 -j ACCEPT",
            "COMMIT",
        ]
    )


ADMIN_NETWORKS = ["192.0.2.1/32", "2001:db8::1/128"]


def network_facts():
    rows = [
        "PRAHO_NETWORK_V2",
        "PRAHO_NETWORK_COMPLETE",
        'PRAHO_XTABLES_BACKEND {"ip":"nf_tables","ip6":"nf_tables"}',
        'PRAHO_FORWARDING {"ipv4":1,"ipv6":{"all":1,"default":0,"eth0":1,"br0":1}}',
    ]
    links = (
        {"name": "lo", "kind": "loopback", "up": True, "master": None, "addresses": ["127.0.0.1/8", "::1/128"]},
        {
            "name": "eth0",
            "kind": "veth",
            "up": True,
            "master": None,
            "addresses": ["192.0.2.2/24", "198.51.100.9/32", "2001:db8::2/64"],
        },
        {"name": "br0", "kind": "bridge", "up": True, "master": None, "addresses": ["10.177.0.1/24", "fd00:177::1/64"]},
    )
    rows.extend("PRAHO_NETWORK_LINK " + json.dumps(link, sort_keys=True) for link in links)
    for family in ("IPV4", "IPV6"):
        rows += [
            f"PRAHO_{family}_NAT_BEGIN",
            "*nat",
            ":PREROUTING ACCEPT [0:0]",
            ":POSTROUTING ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            "COMMIT",
            f"PRAHO_{family}_NAT_END",
        ]
        rows.append(
            "PRAHO_NETWORK_ROUTE"
            + ("6" if family == "IPV6" else "4")
            + ' {"dst":"default","dev":"eth0","type":"unicast","table":"main"}'
        )
    return rows


class FirewallProofTests(TestCase):
    networks: ClassVar[list[str]] = ADMIN_NETWORKS

    def test_both_families_require_public_web_and_exact_administrative_sources(self):
        for ipv6 in (False, True):
            verify_filter(filter_rules(ipv6), self.networks, ipv6=ipv6)

    def test_missing_rules_or_inactive_baseline_cannot_be_verified(self):
        for saved in ("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT", filter_rules().replace("--dport 443", "--dport 444")):
            with self.subTest(saved=saved), self.assertRaises(ValidationError):
                verify_filter(saved, self.networks, ipv6=False)

    def test_prechain_bypass_nested_jump_and_stale_sources_are_rejected(self):
        for rule in (
            "-A INPUT -j ACCEPT",
            "-A ufw-before-input -p tcp --dport 25 -j ACCEPT",
            "-A ufw-user-input -s 198.51.100.1/32 -p tcp --dport 10000 -j ACCEPT",
            "-A INPUT -j foreign\n-A foreign -j ACCEPT",
            "-A INPUT -g foreign\n-A foreign -j ACCEPT",
            "-A INPUT -j NFQUEUE",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValidationError):
                verify_filter(filter_rules() + "\n" + rule, self.networks, ipv6=False)


def node_policy_evidence():
    firewall = ["Status: active", "PRAHO_NFT_INPUT_INSPECTED"]
    for family, ipv6 in (("IPV4", False), ("IPV6", True)):
        firewall += [f"PRAHO_{family}_FILTER_BEGIN", *filter_rules(ipv6).splitlines(), f"PRAHO_{family}_FILTER_END"]
    firewall += network_facts()
    return {
        "schema": 1,
        "identity": "a" * 64,
        "versions": {"webmin": "2.670", "virtualmin": "8.3.0"},
        "principals": [
            {"name": "root", "access": "allow=127.0.0.1/32;deny=;modules=acl"},
            {"name": "praho-api", "access": "allow=192.0.2.1/32 2001:db8::1/128;deny=;modules=virtual-server"},
        ],
        "services": ["Native feature webmin: No", "Native default webmin: No", "Customer Webmin domains: 0"]
        + ["Native feature " + feature + ": Yes" for feature in ("unix", "dir", "web", "ssl", "logrotate", "mysql")]
        + ssh_policy_services(),
        "listeners": [f"tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*" for port in (80, 443, 9876, 10000)]
        + ["tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:*"],
        "firewall": firewall,
        "proposed_changes": [
            "Approved operator SSH key: " + OPERATOR_FINGERPRINT,
            "Administrative networks: " + ", ".join(sorted(ADMIN_NETWORKS)),
        ],
    }


class ForwardingQualificationTests(TestCase):
    def qualify(self, firewall):
        from apps.provisioning import virtualmin_security_policy as policy  # noqa: PLC0415

        return policy.verify_network_ingress(firewall)

    def facts(self):
        return node_policy_evidence()["firewall"]

    def add(self, rows, rule, *, table="FILTER", ipv6=False):
        end = rows.index(f"PRAHO_{'IPV6' if ipv6 else 'IPV4'}_{table}_END")
        rows.insert(end - 1, rule)

    def test_safe_baseline_and_outbound_masquerade_private_forwarding_are_qualified(self):
        rows = self.facts()
        self.qualify(rows)
        self.add(rows, "-A POSTROUTING -s 10.177.0.0/24 -o eth0 -j MASQUERADE", table="NAT")
        for ipv6 in (False, True):
            self.add(rows, "-A FORWARD -i br0 -j ACCEPT", ipv6=ipv6)
            self.add(rows, "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ipv6=ipv6)
        self.qualify(rows)

    def test_public_dnat_secondary_addresses_and_direct_routed_non_web_ingress_are_rejected(self):
        for ipv6, rule in (
            (
                False,
                "-A PREROUTING -i eth0 -d 198.51.100.9/32 -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080",
            ),
            (True, "-A PREROUTING -i eth0 -p tcp --dport 2525 -j DNAT --to-destination [fd00:177::2]:8080"),
        ):
            rows = self.facts()
            self.add(rows, rule, table="NAT", ipv6=ipv6)
            with self.subTest(rule=rule), self.assertRaisesRegex(ValidationError, "preparation|PREROUTING|2525"):
                self.qualify(rows)
        for ipv6 in (False, True):
            rows = self.facts()
            self.add(rows, "-A FORWARD -i eth0 -p tcp --dport 8080 -j ACCEPT", ipv6=ipv6)
            with self.subTest(ipv6=ipv6), self.assertRaisesRegex(ValidationError, "preparation|FORWARD|8080"):
                self.qualify(rows)

    def test_private_nat_and_public_web_forwarding_can_be_qualified(self):
        rows = self.facts()
        self.add(rows, "-A PREROUTING -i br0 -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080", table="NAT")
        self.add(rows, "-A FORWARD -i br0 -j ACCEPT")
        self.add(rows, "-A FORWARD -i eth0 -p tcp --dport 80 -j ACCEPT")
        self.qualify(rows)

    def test_translated_web_target_needs_exact_dnat_state_not_new_state(self):
        rows = self.facts()
        self.add(rows, "-A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.177.0.2:8080", table="NAT")
        self.add(rows, "-A FORWARD -i eth0 -p tcp --dport 8080 -m conntrack --ctstate DNAT -j ACCEPT")
        self.qualify(rows)
        unsafe = [row.replace("--ctstate DNAT", "--ctstate NEW,DNAT") for row in rows]
        with self.assertRaises(ValidationError):
            self.qualify(unsafe)

    def test_old_input_only_evidence_cannot_be_final_policy_proof(self):
        evidence = node_policy_evidence()
        evidence["firewall"] = evidence["firewall"][: evidence["firewall"].index("PRAHO_NETWORK_V2")]
        with self.assertRaises(ValidationError):
            verify_evidence(
                evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
            )

    def test_a_secondary_standalone_private_address_veth_is_not_assumed_trusted(self):
        rows = self.facts()
        rows.append(
            'PRAHO_NETWORK_LINK {"name":"eth1","kind":"veth","master":null,"up":true,"addresses":["10.1.0.2/24"]}'
        )
        self.add(rows, "-A FORWARD -i eth1 -p tcp --dport 8080 -j ACCEPT")
        with self.assertRaises(ValidationError):
            self.qualify(rows)

    def test_public_bridge_requires_preparation_even_when_ip_forwarding_is_disabled(self):
        rows = self.facts()
        for index, row in enumerate(rows):
            if row.startswith("PRAHO_FORWARDING "):
                rows[index] = 'PRAHO_FORWARDING {"ipv4":0,"ipv6":{"all":0,"default":0}}'
            if row.startswith("PRAHO_NETWORK_LINK "):
                link = json.loads(row.removeprefix("PRAHO_NETWORK_LINK "))
                if link["name"] == "eth0":
                    link["kind"], link["master"] = "ether", "br0"
                    rows[index] = "PRAHO_NETWORK_LINK " + json.dumps(link)
        with self.assertRaisesRegex(ValidationError, "bridge|preparation"):
            self.qualify(rows)

    def test_native_outbound_masquerade_is_safe_but_packet_rewrites_and_flowtables_need_preparation(self):
        rows = self.facts()
        chain = {"family": "inet", "table": "egress", "name": "out", "hook": "postrouting", "type": "nat", "prio": 100}
        rule = {"family": "inet", "table": "egress", "chain": "out", "expr": [{"masquerade": None}]}
        rows += [
            "PRAHO_NETWORK_NATIVE " + json.dumps({"chain": chain}),
            "PRAHO_NETWORK_NATIVE " + json.dumps({"rule": rule}),
        ]
        self.qualify(rows)
        for entry in (
            {"flowtable": {"family": "inet", "table": "offload", "name": "fast"}},
            {"chain": {"family": "bridge", "table": "bridged", "name": "input", "hook": "forward"}},
            {"chain": {"family": "ip", "table": "filter", "name": "redirect", "hook": "prerouting"}},
        ):
            with self.subTest(entry=entry), self.assertRaises(ValidationError):
                self.qualify([*rows, "PRAHO_NETWORK_NATIVE " + json.dumps(entry)])
        rule["expr"] = [{"dnat": {"addr": "10.177.0.2", "port": 8080}}]
        with self.assertRaisesRegex(ValidationError, "native packet rule"):
            self.qualify(
                [
                    *self.facts(),
                    "PRAHO_NETWORK_NATIVE " + json.dumps({"chain": chain}),
                    "PRAHO_NETWORK_NATIVE " + json.dumps({"rule": rule}),
                ]
            )

    def test_absent_native_nat_tables_can_be_qualified_without_inventing_rules(self):
        rows = self.facts()
        for family in ("IPV4", "IPV6"):
            begin, end = rows.index(f"PRAHO_{family}_NAT_BEGIN"), rows.index(f"PRAHO_{family}_NAT_END")
            rows[begin + 1 : end] = ["*nat", "COMMIT"]
        self.qualify(rows)


class NodePolicyProofTests(TestCase):
    networks: ClassVar[list[str]] = ADMIN_NETWORKS

    def test_complete_live_policy_is_accepted(self):
        verify_evidence(
            node_policy_evidence(), "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
        )

    def test_each_independent_missing_control_prevents_verification(self):
        for section, replacement in (
            ("principals", [{"name": "root", "access": "allow=;deny=;modules=acl"}]),
            ("services", ["Native feature webmin: Yes", "Customer Webmin domains: 1"]),
            ("listeners", ["tcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*"]),
            ("listeners", []),
            ("firewall", ["Status: active"]),
        ):
            evidence = node_policy_evidence()
            evidence[section] = replacement
            with self.subTest(section=section, replacement=replacement), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_native_input_hook_and_udp_discovery_prevent_verification(self):
        for section, addition in (
            ("firewall", "NFT input chain: inet:foreign:input"),
            ("listeners", "udp UNCONN 0 0 0.0.0.0:10000 0.0.0.0:*"),
            ("services", "usermin install ok installed 2.0"),
        ):
            evidence = node_policy_evidence()
            evidence[section].append(addition)
            with self.subTest(addition=addition), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_native_domain_lookup_daemon_is_permitted_only_on_loopback(self):
        for address in ("127.0.0.1", "[::1]"):
            evidence = node_policy_evidence()
            evidence["listeners"].append(f"tcp LISTEN 0 128 {address}:11000 0.0.0.0:*")
            verify_evidence(
                evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
            )
        for address in ("0.0.0.0", "[::]", "192.0.2.1"):
            evidence = node_policy_evidence()
            evidence["listeners"].append(f"tcp LISTEN 0 128 {address}:11000 0.0.0.0:*")
            with self.subTest(address=address), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def verify(self, evidence):
        verify_evidence(evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT])

    def rejection(self, evidence):
        with self.assertRaises(ValidationError) as caught:
            self.verify(evidence)
        return caught.exception.messages[0]

    def test_chrony_command_port_is_permitted_only_on_loopback(self):
        # Ubuntu 26.04 ships chrony, which listens on loopback UDP 323; these are -001's own lines.
        live = [
            "udp UNCONN 0      0                  [::1]:323      [::]:*",
            "udp UNCONN 0      0              127.0.0.1:323   0.0.0.0:*",
        ]
        evidence = node_policy_evidence()
        evidence["listeners"] += live
        self.verify(evidence)
        crowdsec = [*node_policy_evidence()["listeners"], "tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*", *live]
        _verify_listeners(crowdsec, CROWDSEC_PROFILE)
        for line in (
            "udp UNCONN 0 0 0.0.0.0:323 0.0.0.0:*",
            "udp UNCONN 0 0 [::]:323 [::]:*",
            "udp UNCONN 0 0 *:323 *:*",
            "udp UNCONN 0 0 192.0.2.1:323 0.0.0.0:*",
            "tcp LISTEN 0 128 127.0.0.1:323 0.0.0.0:*",
            "udp UNCONN 0 0 127.0.0.1:324 0.0.0.0:*",
        ):
            evidence = node_policy_evidence()
            evidence["listeners"].append(line)
            with self.subTest(line=line):
                self.assertEqual(
                    self.rejection(evidence), NAMED_POLICY_FAILURE.format(detail=f"unreviewed listener: {line!r}")
                )

    def test_evidence_checks_name_what_they_rejected(self):
        services = node_policy_evidence()
        services["services"].append("usermin install ok installed 2.0")
        principals = node_policy_evidence()
        principals["principals"][0] = {"name": "root", "access": "allow=0.0.0.0/0;deny=;modules=acl"}
        versions = node_policy_evidence()
        versions["versions"] = {"webmin": "2.680", "virtualmin": "8.3.0"}
        grants = node_policy_evidence()
        grants["firewall"] = [
            line for line in grants["firewall"] if not ("--dport 10000" in line and "192.0.2.1" in line)
        ]
        firewall = node_policy_evidence()
        firewall["firewall"].remove("PRAHO_NFT_INPUT_INSPECTED")
        for evidence, named in (
            (services, "usermin install ok installed 2.0"),
            (principals, "Webmin principal 'root' access: 'allow=0.0.0.0/0;deny=;modules=acl'"),
            (firewall, "PRAHO_NFT_INPUT_INSPECTED"),
            (versions, "unreviewed versions: webmin '2.680', virtualmin '8.3.0'"),
            (grants, "missing admin grants: 10000 from 192.0.2.1/32"),
        ):
            with self.subTest(named=named):
                message = self.rejection(evidence)
                self.assertTrue(message.startswith(NAMED_POLICY_FAILURE.partition("{detail}")[0]), message)
                self.assertIn(named, message)

    def test_malformed_node_rows_are_refused_with_a_name_not_a_crash(self):
        listener = node_policy_evidence()
        listener["listeners"].append("udp UNCONN 0 0 somehost 0.0.0.0:*")
        principal = node_policy_evidence()
        principal["principals"][0] = {"name": "root", "access": "allow=127.0.0.1/32;deny=;"}
        hostname = node_policy_evidence()
        hostname["listeners"].append("udp UNCONN 0 0 somehost:53 0.0.0.0:*")
        for evidence, named in (
            (listener, "unparsed listener"),
            (principal, "unparsed Webmin principal 'root'"),
            (hostname, "unparsed listener"),
        ):
            with self.subTest(named=named):
                self.assertIn(named, self.rejection(evidence))

    def test_node_supplied_detail_is_quoted_and_bounded(self):
        evidence = node_policy_evidence()
        evidence["listeners"].append("udp UNCONN 0 0 0.0.0.0:9999 0.0.0.0:* " + "x" * 2000)
        message = self.rejection(evidence)
        self.assertLess(len(message), 500)
        self.assertIn("unreviewed listener: 'udp UNCONN 0 0 0.0.0.0:9999", message)

    def test_a_failure_without_detail_keeps_the_reviewed_message(self):
        with self.assertRaises(ValidationError) as caught:
            _fail()
        self.assertEqual(caught.exception.messages, [GENERIC_POLICY_FAILURE])

    def test_missing_ssh_attestation_prevents_web_verification(self):
        evidence = node_policy_evidence()
        evidence["services"] = [row for row in evidence["services"] if not row.startswith("PRAHO_SSH_")]
        with self.assertRaises(ValidationError):
            verify_evidence(evidence, "praho-api", ADMIN_NETWORKS)

    def test_full_ssh_config_and_canonical_startup_are_required(self):
        for tag in ("CONFIG", "STARTUP"):
            evidence = node_policy_evidence()
            evidence["services"] = [row for row in evidence["services"] if not row.startswith("PRAHO_SSH_" + tag + " ")]
            with self.subTest(tag=tag), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_startup_attestation_requires_a_json_boolean(self):
        evidence = node_policy_evidence()
        evidence["services"] = [row for row in evidence["services"] if not row.startswith("PRAHO_SSH_STARTUP ")]
        evidence["services"].append('PRAHO_SSH_STARTUP {"canonical":1}')
        with self.assertRaises(ValidationError):
            verify_evidence(
                evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
            )

    def test_unreviewed_or_inexact_operator_key_sets_prevent_verification(self):
        for expected in (None, [], ["SHA256:" + "A" * 43], [OPERATOR_FINGERPRINT, OPERATOR_FINGERPRINT]):
            with self.subTest(expected=expected), self.assertRaises(ValidationError):
                verify_evidence(
                    node_policy_evidence(), "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=expected
                )

    def test_single_key_file_and_multiple_approved_operators_are_supported(self):
        for single_file in (False, True):
            evidence = node_policy_evidence()
            if single_file:
                evidence["services"] = [
                    row.replace(".ssh/authorized_keys .ssh/authorized_keys2", ".ssh/authorized_keys").replace(
                        SSH_CONFIG_DIGESTS[".ssh/authorized_keys .ssh/authorized_keys2"],
                        SSH_CONFIG_DIGESTS[".ssh/authorized_keys"],
                    )
                    for row in evidence["services"]
                    if not row.startswith("PRAHO_SSH_KEYS ")
                ]
                evidence["services"].append('PRAHO_SSH_KEYS {"status":"complete","files":[".ssh/authorized_keys"]}')
            second = "SHA256:" + "A" * 43
            evidence["services"].append(
                "PRAHO_SSH_KEY " + json.dumps({"fingerprint": second, "options": TUNNEL_OPTIONS})
            )
            verify_evidence(
                evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT, second]
            )

    def test_modern_openssh_prohibit_password_spelling_preserves_key_only_root_access(self):
        evidence = node_policy_evidence()
        evidence["services"] = [row.replace("without-password", "prohibit-password") for row in evidence["services"]]
        verify_evidence(evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT])

    def test_duplicate_missing_and_unknown_ssh_projections_are_rejected(self):
        for alter in ("duplicate", "missing", "unknown"):
            evidence = node_policy_evidence()
            row = next(value for value in evidence["services"] if value.startswith("PRAHO_SSH_TUNNEL "))
            if alter == "duplicate":
                evidence["services"].append(row)
            elif alter == "missing":
                evidence["services"].remove(row)
            else:
                evidence["services"].append('PRAHO_SSH_CUSTOM {"password":"unsafe"}')
            with self.subTest(alter=alter), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_each_effective_ssh_authentication_and_tunnel_control_is_required(self):
        for context, option, bad in (
            ("GLOBAL", "passwordauthentication", ["yes"]),
            ("ROOT", "authenticationmethods", ["any"]),
            ("ROOT", "permitrootlogin", ["yes"]),
            ("ROOT", "allowtcpforwarding", ["yes"]),
            ("ROOT", "allowstreamlocalforwarding", ["yes"]),
            ("TUNNEL", "allowtcpforwarding", ["yes"]),
            ("TUNNEL", "permitopen", ["any"]),
            ("TUNNEL", "permittty", ["yes"]),
            ("TUNNEL", "forcecommand", ["none"]),
            ("TUNNEL", "authorizedkeyscommand", ["/bin/custom"]),
            ("TUNNEL", "trustedusercakeys", ["/etc/ssh/trusted_ca"]),
            ("GLOBAL", "port", ["22", "9876"]),
        ):
            evidence = node_policy_evidence()
            prefix = "PRAHO_SSH_" + context + " "
            row = next(value for value in evidence["services"] if value.startswith(prefix))
            payload = json.loads(row.removeprefix(prefix))
            payload[option] = bad
            evidence["services"].remove(row)
            evidence["services"].append(prefix + json.dumps(payload))
            with self.subTest(context=context, option=option), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_unauthorized_keys_and_missing_key_restrictions_are_rejected(self):
        for tag, payload in (
            ("KEY", {"fingerprint": OPERATOR_FINGERPRINT, "options": []}),
            ("KEY", {"fingerprint": "SHA256:" + "A" * 43, "options": TUNNEL_OPTIONS}),
            ("KEYS", {"status": "unreviewed", "files": [".ssh/authorized_keys"]}),
            ("ACCOUNT", {"present": True, "name": "root", "uid": 0, "gid": 0}),
            ("CONFIG", {"sha256": "f" * 64}),
            ("STARTUP", {"canonical": False}),
        ):
            evidence = node_policy_evidence()
            prefix = "PRAHO_SSH_" + tag + " "
            evidence["services"] = [row for row in evidence["services"] if not row.startswith(prefix)]
            evidence["services"].append(prefix + json.dumps(payload))
            with self.subTest(tag=tag, payload=payload), self.assertRaises(ValidationError):
                verify_evidence(
                    evidence, "praho-api", ADMIN_NETWORKS, expected_operator_fingerprints=[OPERATOR_FINGERPRINT]
                )

    def test_outbound_forward_and_unreachable_chains_are_not_modified_or_misclassified(self):
        verify_filter(
            filter_rules() + "\n-A FORWARD -j ACCEPT\n-A OUTPUT -j ACCEPT\n-A unused -j ACCEPT",
            self.networks,
            ipv6=False,
        )

    def test_loopback_established_and_bounded_control_traffic_remain_valid(self):
        verify_filter(
            filter_rules()
            + "\n-A ufw-before-input -p udp -m udp --sport 67 --dport 68 -j ACCEPT\n-A ufw-before-input -p icmp -m icmp --icmp-type 8 -j ACCEPT",
            self.networks,
            ipv6=False,
        )
        verify_filter(
            filter_rules(True)
            + "\n-A ufw6-before-input -s fe80::/10 -d fe80::/10 -p udp -m udp --sport 547 --dport 546 -j ACCEPT\n"
            + "\n".join(
                f"-A ufw6-before-input -p ipv6-icmp -m icmp6 --icmpv6-type {kind} -j ACCEPT"
                for kind in (144, 145, 146, 147)
            ),
            self.networks,
            ipv6=True,
        )

    def test_unbounded_udp_and_new_connections_masquerading_as_established_fail(self):
        for rule in (
            "-A INPUT -p udp --dport 10000 -j ACCEPT",
            "-A INPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            "-A INPUT ! -i lo -j ACCEPT",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValidationError):
                verify_filter(filter_rules() + "\n" + rule, self.networks, ipv6=False)
