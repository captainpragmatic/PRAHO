"""The node inspector emits technical observations without leaking native passwords."""

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from django.test import SimpleTestCase
from jinja2 import Environment, StrictUndefined

from apps.common.types import Err, Ok
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.virtualmin_security_policy import SSH_CONFIG_DIGESTS
from tests.provisioning.test_node_security_policy import OPERATOR_FINGERPRINT, OPERATOR_KEY, ssh_policy_services


class InspectorTests(TestCase):
    def setUp(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"
        )
        spec = importlib.util.spec_from_file_location("node_inspector", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_network_inspection_retains_forward_nat_all_addresses_and_hooks_without_live_counters(self):
        backend = ["nf_tables"]
        links = [
            {"ifindex": 2, "ifname": "eth0", "flags": ["UP"], "link_type": "ether", "linkinfo": {"info_kind": "veth"}}
        ]
        addresses = [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"family": "inet", "local": "192.0.2.2", "prefixlen": 24, "valid_life_time": 60},
                    {"family": "inet", "local": "198.51.100.9", "prefixlen": 32},
                ],
            }
        ]
        routes = [{"dst": "default", "dev": "eth0", "expires": 60}]
        native = {
            "nftables": [
                {
                    "chain": {
                        "family": "inet",
                        "table": "foreign",
                        "name": "route",
                        "hook": "prerouting",
                        "prio": -100,
                        "type": "nat",
                        "handle": 1,
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "foreign",
                        "chain": "route",
                        "handle": 2,
                        "expr": [
                            {"counter": {"packets": 1, "bytes": 200}},
                            {"dnat": {"addr": "10.177.0.2", "port": 8080}},
                        ],
                    }
                },
            ]
        }

        def command(argv):
            if argv[-1] == "--version":
                return "iptables-save v1.8.9 (" + backend[0] + ")"
            if argv[0] == "ip":
                value = links if "link" in argv else addresses if "address" in argv else routes
                return json.dumps(value)
            return "*nat\n:PREROUTING ACCEPT [5:600]\n-A PREROUTING -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080\nCOMMIT"

        with (
            patch.object(self.module.shutil, "which", return_value="/sbin/present"),
            patch.object(self.module, "command", side_effect=command) as reads,
            patch.object(
                self.module, "forwarding_flags", return_value={"ipv4": 1, "ipv6": {"all": 1, "default": 0, "eth0": 1}}
            ),
        ):
            first = self.module.inspect_network(native)
            native["nftables"][1]["rule"]["expr"][0]["counter"]["packets"] = 999
            routes[0]["expires"] = 5
            addresses[0]["addr_info"][0]["valid_life_time"] = 5
            second = self.module.inspect_network(native)
            # A legacy alternatives selection does not represent native nft NAT.
            backend[0] = "legacy"
            native["nftables"][0]["chain"].update(family="ip", table="nat", name="PREROUTING")
            native["nftables"][1]["rule"].update(family="ip", table="nat", chain="PREROUTING")
            mixed = self.module.inspect_network(native)
        self.assertEqual(first, second)
        self.assertIn("PRAHO_NETWORK_COMPLETE", first)
        self.assertTrue(any("198.51.100.9/32" in row for row in first))
        self.assertTrue(any("2525" in row and "DNAT" in row for row in first))
        self.assertTrue(any('"hook":"prerouting"' in row for row in first))
        self.assertTrue(any('"counter":null' in row for row in first))
        self.assertTrue(any('"dnat"' in row for row in mixed if row.startswith("PRAHO_NETWORK_NATIVE")))
        self.assertTrue(
            all(call.args[0][0] in {"ip", "iptables-save", "ip6tables-save"} for call in reads.call_args_list)
        )

    def test_incomplete_network_inspection_is_an_inspectable_preparation_fact(self):
        with patch.object(self.module.shutil, "which", return_value=None):
            rows = self.module.inspect_network(None)
        self.assertIn("PRAHO_NETWORK_V2", rows)
        self.assertNotIn("PRAHO_NETWORK_COMPLETE", rows)
        self.assertTrue(any("preparation required" in row for row in rows))

    def test_inspection_classifies_every_observation_and_does_not_mutate(self):
        outputs = {
            "ss": "tcp LISTEN 0 128 0.0.0.0:25 0.0.0.0:*\n",
            "ufw": "Status: active\n25 ALLOW Anywhere\n",
            "systemctl": "postfix.service enabled\n",
            "dpkg-query": "fail2ban installed 1.0\n",
            "perl": '[{"name":"root","access":"allow=;deny=;modules=acl virtual-server"}]',
            "virtualmin": '{"data": []}',
            "iptables-save": "*filter\n:INPUT DROP [10:200]\nCOMMIT\n# Completed on clock one\n",
            "ip6tables-save": "*filter\n:INPUT DROP [5:100]\nCOMMIT\n# Completed on clock two\n",
            "nft": '{"nftables": []}',
        }

        def command(argv: list[str]) -> str:
            if argv[:2] == ["virtualmin", "list-domains"]:
                return ""
            if argv[0] == "ip":
                return "[]"
            if argv[-1] == "--version":
                return "iptables-save v1.8.9 (nf_tables)"
            return outputs[argv[0]]

        contents = b"#!/bin/sh\n# private hook contents\n"
        for present, executable in ((False, False), (True, False), (True, True)):
            with self.subTest(hook_present=present, executable=executable):
                hooks = {name: MagicMock(spec=Path) for name in ("/etc/ufw/before.init", "/etc/ufw/after.init")}
                before = hooks["/etc/ufw/before.init"]
                for name, hook in hooks.items():
                    hook.__str__.return_value = name
                    hook.exists.return_value = hook is before and present
                before.open.return_value = BytesIO(contents)

                def access(path: Path, mode: int, expected: Path = before, allowed: bool = executable) -> bool:
                    self.assertIs(path, expected)
                    self.assertEqual(mode, os.X_OK)
                    return allowed

                with (
                    patch.object(self.module.shutil, "which", return_value="/usr/sbin/ufw"),
                    patch.object(self.module, "command", side_effect=command),
                    patch.object(self.module, "Path", side_effect=hooks.__getitem__),
                    patch.object(self.module.os, "access", side_effect=access),
                    patch.object(self.module, "forwarding_flags", return_value={"ipv4": 0, "ipv6": {"all": 0}}),
                    patch.object(self.module, "versions", return_value={"webmin": "2.670", "virtualmin": "8.3.0"}),
                    patch.object(self.module, "inspect_ssh", return_value=ssh_policy_services()),
                ):
                    result = self.module.inspect("a" * 64)
                self.assertEqual(result["schema"], 1)
                self.assertIn("0.0.0.0:25", result["listeners"][0])
                self.assertEqual(result["principals"][0]["name"], "root")
                self.assertIn("fail2ban installed 1.0", result["services"])
                self.assertIn(":INPUT DROP [0:0]", result["firewall"])
                self.assertIn("PRAHO_NETWORK_COMPLETE", result["firewall"])
                self.assertFalse(any("clock" in line for line in result["firewall"]))
                self.assertTrue(any(row.startswith("PRAHO_SSH_TUNNEL ") for row in result["services"]))
                descriptions = [row for row in result["proposed_changes"] if row.startswith("Firewall reload hook ")]
                disable = [row for row in result["proposed_changes"] if row.startswith("Disable execution of ")]
                self.assertEqual(
                    descriptions,
                    [
                        f"Firewall reload hook /etc/ufw/before.init: sha256={hashlib.sha256(contents).hexdigest()}, executable={executable}"
                    ]
                    if present
                    else [],
                )
                self.assertEqual(len(disable), int(present and executable))
                self.assertNotIn("private hook contents", json.dumps(result))
                for hook in hooks.values():
                    hook.exists.assert_called_once_with()
                if present:
                    before.open.assert_called_once_with("rb")
                else:
                    before.open.assert_not_called()
                hooks["/etc/ufw/after.init"].open.assert_not_called()

    def test_classification_fixture_never_reads_the_host_filesystem(self):
        # Ubuntu's root-only UFW hook exposed this fixture's accidental host reads.
        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "open", side_effect=PermissionError("Host UFW hook is root-only")),
            patch.object(Path, "read_text", side_effect=AssertionError("Unexpected host file read")),
            patch.object(Path, "glob", side_effect=AssertionError("Unexpected host directory scan")),
            patch.object(Path, "stat", side_effect=AssertionError("Unexpected host file stat")),
            patch("builtins.open", side_effect=AssertionError("Unexpected host file open")),
            patch.object(os, "open", side_effect=AssertionError("Unexpected host descriptor open")),
            patch.object(os, "access", side_effect=AssertionError("Unexpected host access check")),
        ):
            self.test_inspection_classifies_every_observation_and_does_not_mutate()

    def test_effective_ssh_contexts_and_all_tunnel_key_files_are_read_without_raw_key_material(self):
        projected = {}
        for row in ssh_policy_services()[:3]:
            tag, raw = row.split(" ", 1)
            projected[tag] = "\n".join(key + " " + value for key, values in json.loads(raw).items() for value in values)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".ssh").mkdir(mode=0o700)
            public = (
                'restrict,port-forwarding,permitopen="127.0.0.1:10000" ' + OPERATOR_KEY + " SECRET operator's laptop\n"
            )
            (home / ".ssh/authorized_keys").write_text(public)
            (home / ".ssh/authorized_keys2").write_text(OPERATOR_KEY + " SECRET second-file\n")
            account = SimpleNamespace(
                pw_name="praho-webmin-tunnel",
                pw_uid=os.getuid(),
                pw_gid=os.getgid(),
                pw_dir=str(home),
                pw_shell="/usr/sbin/nologin",
            )

            def output(argv):
                context = (
                    "ROOT" if any("user=root," in value for value in argv) else "TUNNEL" if "-C" in argv else "GLOBAL"
                )
                return projected["PRAHO_SSH_" + context] + "\nauthorizedkeyscommand SECRET_TOKEN\n"

            with (
                patch.object(self.module, "TUNNEL_HOME", home, create=True),
                patch.object(self.module.pwd, "getpwnam", return_value=account),
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 9876"}),
                patch.object(self.module, "command", side_effect=output) as command,
                patch.object(self.module, "inspect_ssh_files", return_value=[]),
            ):
                result = self.module.inspect_ssh()
        serialized = json.dumps(result)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn(OPERATOR_KEY, serialized)
        self.assertIn(OPERATOR_FINGERPRINT, serialized)
        keys = [json.loads(row.split(" ", 1)[1]) for row in result if row.startswith("PRAHO_SSH_KEY ")]
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0]["options"], ["permitopen=127.0.0.1:10000", "port-forwarding", "restrict"])
        self.assertEqual(keys[1]["options"], [])
        self.assertEqual(len(command.call_args_list), 3)
        self.assertEqual(command.call_args_list[0].args[0], ["/usr/sbin/sshd", "-T"])
        self.assertTrue(
            any(
                "user=root,host=192.0.2.1,addr=192.0.2.1,laddr=192.0.2.2,lport=9876" in call.args[0]
                for call in command.call_args_list
            )
        )

    def test_native_principal_projection_never_serializes_entire_user(self):
        parts = self.module.PRINCIPALS.split("my @result;", 1)
        self.assertEqual(len(parts), 2)
        self.assertIn("foreach my $g", parts[1])
        program = r"""use strict; use warnings; use JSON::PP;
sub acl::list_users { return ({name=>'root',pass=>'SECRET_HASH',modules=>['acl'],allow=>'127.0.0.1',deny=>''}); }
sub acl::list_groups { return ({name=>'operators',members=>['root'],modules=>['acl']}); }
my @result;
""" + parts[1]
        result = subprocess.run(["perl", "-e", program], capture_output=True, text=True, check=True)  # noqa: S603,S607 -- Local native Perl projection test.
        decoded = json.loads(result.stdout)
        self.assertEqual([row["name"] for row in decoded], ["group:operators", "root"])
        self.assertIn("127.0.0.1", decoded[1]["access"])
        self.assertNotIn("SECRET_HASH", result.stdout)

    def test_unsafe_symlinked_or_oversized_tunnel_key_files_are_reported_without_reading_secrets(self):
        for scenario in ("writable", "symlink", "oversized"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                (home / ".ssh").mkdir(mode=0o700)
                keyfile = home / ".ssh/authorized_keys"
                keyfile.write_text(OPERATOR_KEY)
                account = SimpleNamespace(pw_dir=str(home), pw_uid=os.getuid())
                if scenario == "writable":
                    keyfile.chmod(0o666)
                elif scenario == "symlink":
                    keyfile.unlink()
                    keyfile.symlink_to(home / "private-credential")
                else:
                    keyfile.write_text("SECRET" * self.module.LIMIT)
                with patch.object(self.module, "TUNNEL_HOME", home):
                    rows = self.module._tunnel_keys(account, [".ssh/authorized_keys"])
                self.assertEqual(len(rows), 1)
                self.assertIn('"status":"unreviewed"', rows[0])
                self.assertNotIn("SECRET", rows[0])

    def test_key_algorithm_must_match_the_fingerprinted_wire_key(self):
        with self.assertRaises(ValueError):
            self.module._authorized_key("ssh-rsa " + OPERATOR_KEY.split()[1])

    def test_canonical_config_hashes_track_the_actual_production_template(self):
        path = Path(__file__).resolve().parents[4] / "deploy/ansible/roles/ssh-hardening/templates/sshd_config.j2"
        template = Environment(undefined=StrictUndefined, autoescape=False).from_string(path.read_text())  # noqa: S701 -- Render native SSH configuration, not HTML.
        for files, expected in SSH_CONFIG_DIGESTS.items():
            source = template.render(
                ssh_phase_ports=[9876], ssh_authorized_keys_files=files.split(), ssh_webmin_tunnel_enabled=True
            )
            with self.subTest(files=files):
                self.assertEqual(self.module.canonical_ssh_digest(source), expected)
                self.assertEqual(
                    self.module.canonical_ssh_digest(
                        "# operator comment\n\n" + "\n".join("\t" + line.strip() for line in source.splitlines())
                    ),
                    expected,
                )
                for unreviewed in (
                    "Match Address 198.51.100.1\nPasswordAuthentication yes",
                    "Include /root/extra.conf",
                ):
                    self.assertNotEqual(self.module.canonical_ssh_digest(source + "\n" + unreviewed), expected)

    def test_startup_projection_matches_the_production_adoption_check(self):
        path = Path(__file__).resolve().parents[4] / "deploy/ansible/roles/ssh-hardening/files/check_config.py"
        spec = importlib.util.spec_from_file_location("ssh_adoption", path)
        adoption = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adoption)
        properties = {
            "FragmentPath": "/usr/lib/systemd/system/ssh.service",
            "KillMode": "process",
            "DropInPaths": "",
            "Environment": "",
            "EnvironmentFiles": "/etc/default/ssh (ignore_errors=yes)",
            "ActiveState": "active",
            "ExecStart": "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; start_time=... ; }",
        }
        for options in ('SSHD_OPTS=""', "SSHD_OPTS=''", "# comment\nSSHD_OPTS=\n"):
            adoption.validate_startup(properties, options)
            self.assertTrue(self.module.canonical_ssh_startup(properties, options))
        for key, unreviewed in (
            ("FragmentPath", "/root/ssh.service"),
            ("DropInPaths", "/etc/systemd/system/ssh.service.d/override.conf"),
            ("Environment", "SECRET_TOKEN=private"),
            ("EnvironmentFiles", "/root/ssh.env"),
            (
                "ExecStart",
                "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -f /root/custom.conf ; ignore_errors=no ; }",
            ),
        ):
            changed = {**properties, key: unreviewed}
            with self.subTest(key=key), self.assertRaises(ValueError):
                adoption.validate_startup(changed, 'SSHD_OPTS=""')
            self.assertFalse(self.module.canonical_ssh_startup(changed, 'SSHD_OPTS=""'))
        self.assertFalse(self.module.canonical_ssh_startup(properties, 'SSHD_OPTS="-oPasswordAuthentication=yes"'))
        self.assertFalse(self.module.canonical_ssh_startup({**properties, "ActiveState": "inactive"}, 'SSHD_OPTS=""'))

    def test_unknown_native_startup_values_never_leave_the_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            config, defaults = Path(directory) / "sshd_config", Path(directory) / "ssh"
            config.write_text("Port 9876\n")
            defaults.write_text('SSHD_OPTS="SECRET_ARGUMENT"\n')
            with (
                patch.object(self.module, "SSHD_CONFIG", config),
                patch.object(self.module, "SSHD_DEFAULTS", defaults),
                patch.object(self.module, "command", return_value="Environment=SECRET_ENVIRONMENT\n"),
            ):
                rows = self.module.inspect_ssh_files()
            self.assertNotIn("SECRET", json.dumps(rows))
            self.assertIn('PRAHO_SSH_STARTUP {"canonical":false}', rows)

    def test_named_pipe_key_file_is_rejected_without_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".ssh").mkdir(mode=0o700)
            os.mkfifo(home / ".ssh/authorized_keys", mode=0o600)
            account = SimpleNamespace(pw_dir=str(home), pw_uid=os.getuid())
            with (
                patch.object(self.module, "TUNNEL_HOME", home),
                patch.object(Path, "open", side_effect=AssertionError("Inspector tried to open a named pipe")),
            ):
                rows = self.module._tunnel_keys(account, [".ssh/authorized_keys"])
            self.assertIn('"status":"unreviewed"', rows[0])

    def test_invalid_identity_is_rejected_before_inspection(self):
        with patch.object(self.module, "command") as command:
            with self.assertRaises(ValueError):
                self.module.inspect("not-an-identity")
            command.assert_not_called()


class InspectionTransportTests(SimpleTestCase):
    def test_archive_operations_never_recover_or_harden_the_source(self):
        for playbook, extra_vars in (
            ("virtualmin_backup_fetch.yml", None),
            ("virtualmin_chain_backup.yml", None),
            ("virtualmin_pair_restore.yml", None),
            ("virtualmin_migrate_fetch.yml", None),
            ("virtualmin_migrate_push.yml", None),
            ("virtualmin_recovery.yml", {"recovery_action": "capture-owner"}),
        ):
            with self.subTest(playbook=playbook):
                transport = object.__new__(AnsibleService)
                transport.timeout = 30
                transport._ssh_manager = Mock()
                transport._ssh_manager.get_private_key_file.return_value = Ok(Path("key"))
                transport._wait_for_ssh = Mock(return_value=Err("Offline"))
                transport._ensure_ssh_policy = Mock(return_value=Ok(None))
                deployment = SimpleNamespace(ipv4_address="192.0.2.10", ssh_host_keys="enrolled", ssh_port=9876)
                with (
                    patch("apps.infrastructure.ansible_service.trusted_node_known_hosts", return_value=Path("trust")),
                    patch("apps.infrastructure.ansible_service.recover_connection_port", return_value=22) as recover,
                ):
                    self.assertEqual(transport.run_playbook(deployment, playbook, extra_vars).unwrap_err(), "Offline")
                recover.assert_not_called()
                transport._ensure_ssh_policy.assert_not_called()
                transport._wait_for_ssh.assert_called_once_with("192.0.2.10", port=9876, timeout=10)

    def test_inspection_never_bootstraps_or_recovers_ssh(self):
        transport = object.__new__(AnsibleService)
        transport.timeout = 30
        transport._ssh_manager = Mock()
        deployment = SimpleNamespace(ipv4_address="192.0.2.10", ssh_host_keys=None, ssh_port=9876)
        self.assertIn(
            "enrolled SSH host trust", transport.run_playbook(deployment, "virtualmin_security_read.yml").unwrap_err()
        )
        transport._ssh_manager.get_private_key_file.assert_not_called()
        deployment.ssh_host_keys = "enrolled"
        transport._ssh_manager.get_private_key_file.return_value = Ok(Path("key"))
        transport._wait_for_ssh = Mock(return_value=Err("Offline"))
        transport._ensure_ssh_policy = Mock()
        with (
            patch("apps.infrastructure.ansible_service.trusted_node_known_hosts", return_value=Path("trust")),
            patch("apps.infrastructure.ansible_service.recover_connection_port") as recover,
        ):
            self.assertEqual(transport.run_playbook(deployment, "virtualmin_security_read.yml").unwrap_err(), "Offline")
        recover.assert_not_called()
        transport._ensure_ssh_policy.assert_not_called()
