"""Only the live fixed certificate action may start fully verified mail behind both fences."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
import ssl
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase

from tests.provisioning.test_virtualmin_mail_boot import HELPER, MailBootGuardFixture


class CertificateStartGuardTests(MailBootGuardFixture, SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.guard.clock = lambda: 100.0
        specification = importlib.util.spec_from_file_location(
            "mail_setup_protocol", HELPER.with_name("praho_mail_setup.py")
        )
        protocol = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(protocol)
        self.paths, self.helpers = protocol.CONFIG_PATHS, protocol.NATIVE_FILES
        self.rules = {program: self.firewall(program) for program in ("iptables-save", "ip6tables-save")}
        self.recovery()

    def private(self, name, content):
        file = self.write(name.lstrip("/"), content)
        file.chmod(0o600)
        return file

    @staticmethod
    def pem(value):
        return "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(value).decode() + "\n-----END CERTIFICATE-----\n"

    @staticmethod
    def firewall(program):
        rejection = "icmp-port-unreachable" if program == "iptables-save" else "icmp6-port-unreachable"
        return (
            "*filter\n:INPUT ACCEPT [0:0]\n:PRAHO_MAIL_SETUP - [0:0]\n"
            "-A INPUT -j PRAHO_MAIL_SETUP\n-A PRAHO_MAIL_SETUP -i lo -j RETURN\n"
            "-A PRAHO_MAIL_SETUP -p tcp -m multiport --dports 25,110,143,465,587,993,995 "
            "-j REJECT --reject-with " + rejection + "\nCOMMIT\n"
        )

    def execute(self, argv):
        self.commands.append(argv)
        return self.rules.get(argv[0], "")

    def save_marker(self):
        self.private("var/lib/praho/mail/node.json", json.dumps(self.record))

    def recovery(self, profile="debian12-dovecot23"):
        self.operation = str(uuid4())
        old_pem, new_pem = self.pem(b"old leaf"), self.pem(b"new leaf")
        for name in self.paths:
            self.private(name, "owned fixture " + name)
        self.private("etc/praho-mail/node.pem", old_pem)
        self.private("etc/praho-mail/node.key", "old fixture key")
        self.before = {
            "version": 1,
            "profile": profile,
            "node": "node.example",
            "status": "ready",
            "files": {
                name: hashlib.sha256((self.root / name.lstrip("/")).read_bytes()).hexdigest() for name in self.paths
            },
        }
        self.stage = "var/lib/praho/mail/certificate-operations/" + self.operation + ".stage"
        for name, content in {
            "before.json": json.dumps(self.before, sort_keys=True),
            "old.pem": old_pem,
            "old.key": "old fixture key",
            "new.pem": new_pem,
            "new.key": "new fixture key",
        }.items():
            self.private(self.stage + "/" + name, content)
        self.private("etc/praho-mail/node.pem", new_pem)
        self.private("etc/praho-mail/node.key", "new fixture key")
        base = {
            "version": 1,
            "profile": profile,
            "node": "node.example",
            "identity": self.operation,
            "status": "certificate_applying",
            "old_certificate_sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(old_pem)).hexdigest(),
            "new_certificate_sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(new_pem)).hexdigest(),
            "before_sha256": hashlib.sha256(json.dumps(self.before, sort_keys=True).encode()).hexdigest(),
        }
        self.operation_file = self.private(
            "var/lib/praho/mail/certificate-operations/" + self.operation + ".json",
            json.dumps({**base, "status": "applying"}),
        )
        self.script = "/run/praho-mail-owner/praho-mail.py"
        for name in self.helpers:
            self.private("run/praho-mail-owner/" + name, (self.root / "usr/lib/praho/mail" / name).read_text())
        self.private("proc/1234/stat", "1234 (python3) S " + " ".join(["0"] * 18 + ["4321"]))
        self.private("proc/sys/kernel/random/boot_id", "11111111-1111-4111-8111-111111111111\n")
        self.private("proc/self/cgroup", "0::/system.slice/dovecot.service\n")
        self.private("proc/1234/cmdline", "python3\0" + self.script + "\0")
        self.private(
            "proc/1234/environ",
            "\0".join(
                (
                    "PRAHO_MAIL_ACTION=reconcile_node_certificate",
                    "PRAHO_MAIL_ID=" + self.operation,
                    "PRAHO_MAIL_NODE=node.example",
                    "",
                )
            ),
        )
        self.lock = self.private("run/praho-mail/operation.lock", "")
        metadata = self.lock.stat()
        descriptor = self.root / "proc/1234/fd/7"
        descriptor.parent.mkdir(parents=True, exist_ok=True)
        descriptor.unlink(missing_ok=True)
        descriptor.symlink_to(self.lock)
        self.fdinfo = self.private(
            "proc/1234/fdinfo/7",
            (
                f"pos:\t0\nino:\t{metadata.st_ino}\nlock:\t1: FLOCK ADVISORY WRITE 1234 "
                f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino} 0 EOF\n"
            ),
        )
        self.record = {
            **base,
            "status": "certificate_starting",
            "fenced": True,
            "files": {
                name: hashlib.sha256((self.root / name.lstrip("/")).read_bytes()).hexdigest() for name in self.paths
            },
            "start": {
                "pid": 1234,
                "start_tick": "4321",
                "boot_id": "11111111-1111-4111-8111-111111111111",
                "lock_fd": 7,
                "issued_at": 100.0,
                "expires_at": 220.0,
                "helper_path": self.script,
                "action": "reconcile_node_certificate",
            },
        }
        self.save_marker()
        for name in (
            "var/lib/praho/mail",
            "var/lib/praho/mail/certificate-operations",
            self.stage,
            "run/praho-mail",
            "run/praho-mail-owner",
            "usr/lib/praho/mail",
            "etc/praho-mail",
        ):
            (self.root / name).chmod(0o700)

    def test_exact_live_action_can_start_behind_both_verified_fences(self):
        self.assertTrue(self.guard.allowed())
        self.assertEqual({call[0] for call in self.commands}, {"iptables-save", "ip6tables-save"})

    def test_ubuntu_uses_the_same_complete_start_authority(self):
        self.recovery("ubuntu2604-dovecot24")
        self.assertTrue(self.guard.allowed())

    def test_approval_is_limited_to_the_three_known_service_units(self):
        self.assertTrue(self.guard.allowed())
        for unit in ("postfix.service", "postfix@-.service", "dovecot.service", "unrelated.service"):
            with self.subTest(unit=unit):
                self.private("proc/self/cgroup", "0::/system.slice/" + unit + "\n")
                self.assertEqual(self.guard.allowed(), unit != "unrelated.service")

    def test_the_fixed_worker_can_prove_ownership_without_gaining_service_start_permission(self):
        self.assertTrue(self.guard.allowed())
        self.private("proc/self/cgroup", "0::/system.slice/ssh.service\n")
        self.guard.owner_process(self.record, self.record["start"])
        self.guard.operation_owner(self.record)
        self.assertFalse(self.guard.allowed())

    def test_expiry_is_checked_at_the_exact_monotonic_deadline(self):
        self.assertTrue(self.guard.allowed())
        for value, expected in ((219.999999, True), (220.0, False), (220.000001, False)):
            with self.subTest(now=value):
                self.guard.clock = lambda current=value: current
                self.assertEqual(self.guard.allowed(), expected)

    def test_invalid_owner_boot_start_tick_action_path_and_lifetime_refuse(self):
        self.assertTrue(self.guard.allowed())
        original = copy.deepcopy(self.record)
        for changes in (
            {"pid": True},
            {"pid": 1},
            {"pid": 1235},
            {"start_tick": "9999"},
            {"boot_id": "22222222-2222-4222-8222-222222222222"},
            {"lock_fd": 8},
            {"action": "setup"},
            {"helper_path": str(self.root / "unapproved.py")},
            {"issued_at": 101.0},
            {"expires_at": 100.0},
            {"expires_at": 221.0},
            {"expires_at": float("nan")},
            {"issued_at": True},
        ):
            with self.subTest(changes=changes):
                self.record = copy.deepcopy(original)
                self.record["start"].update(changes)
                self.save_marker()
                self.assertFalse(self.guard.allowed())

    def test_a_live_pid_without_its_own_exclusive_kernel_lock_cannot_start(self):
        self.assertTrue(self.guard.allowed())
        original = self.fdinfo.read_text()
        for data in (
            "",
            original.replace("WRITE", "READ"),
            original.replace("1234", "5678"),
            original.replace("FLOCK", "POSIX"),
        ):
            with self.subTest(lock=data):
                self.fdinfo.write_text(data)
                self.assertFalse(self.guard.allowed())

    def test_mutable_or_unrelated_staged_helpers_do_not_authorize_start(self):
        self.assertTrue(self.guard.allowed())
        helper = self.root / self.script.lstrip("/")
        helper.write_text("different executable")
        self.assertFalse(self.guard.allowed())

    def test_only_the_recorded_candidate_pair_and_unchanged_owned_configuration_can_start(self):
        self.assertTrue(self.guard.allowed())
        for name in ("etc/praho-mail/node.pem", "etc/praho-mail/node.key", "etc/pam.d/praho-dovecot"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(b"changed candidate or policy")
                self.assertFalse(self.guard.allowed())
                path.write_bytes(original)

    def test_original_journal_and_operation_tombstone_must_match_the_same_live_attempt(self):
        self.assertTrue(self.guard.allowed())
        original = self.operation_file.read_text()
        for changes in ({"status": "completed"}, {"identity": str(uuid4())}, {"node": "foreign.example"}):
            with self.subTest(changes=changes):
                self.operation_file.write_text(json.dumps({**json.loads(original), **changes}))
                self.assertFalse(self.guard.allowed())
        self.operation_file.write_text(original)
        before = self.root / self.stage / "before.json"
        before.write_text(before.read_text() + " ")
        self.assertFalse(self.guard.allowed())

    def test_missing_or_bypassed_ipv6_and_ipv4_fences_cannot_authorize_start(self):
        self.assertTrue(self.guard.allowed())
        for program in self.rules:
            original = self.rules[program]
            for changed in (
                "",
                original.replace("-A INPUT -j PRAHO_MAIL_SETUP\n", ""),
                original.replace("-A INPUT -j", "-A INPUT -j ACCEPT\n-A INPUT -j", 1),
                original.replace("-A PRAHO_MAIL_SETUP -i lo -j RETURN", "-A PRAHO_MAIL_SETUP -j RETURN"),
            ):
                with self.subTest(program=program, rules=changed):
                    self.rules[program] = changed
                    self.assertFalse(self.guard.allowed())
            self.rules[program] = original

    def test_current_offline_configuration_and_tls_validation_are_still_required(self):
        self.assertTrue(self.guard.allowed())
        self.guard.configured = lambda marker: False
        self.assertFalse(self.guard.allowed())

    def test_owner_death_or_expiry_during_verification_cannot_authorize_a_later_start(self):
        self.assertTrue(self.guard.allowed())

        def owner_died(marker):
            (self.root / "proc/1234/fd/7").unlink()
            return True

        self.guard.configured = owner_died
        self.assertFalse(self.guard.allowed())

    def test_other_applying_or_review_journals_never_gain_start_permission(self):
        self.assertTrue(self.guard.allowed())
        for status in ("certificate_applying", "review_required"):
            with self.subTest(status=status):
                self.record["status"] = status
                self.save_marker()
                self.assertFalse(self.guard.allowed())

    def test_malformed_record_versions_names_and_unknown_fields_refuse(self):
        self.assertTrue(self.guard.allowed())
        original = copy.deepcopy(self.record)
        for changes in ({"version": True}, {"node": "node..example"}, {"unexpected": True}, {"fenced": False}):
            with self.subTest(changes=changes):
                self.record = {**original, **changes}
                self.save_marker()
                self.assertFalse(self.guard.allowed())
        self.record = original
        self.save_marker()
        operation = json.loads(self.operation_file.read_text())
        self.operation_file.write_text(json.dumps({**operation, "version": True}))
        self.assertFalse(self.guard.allowed())

    def test_duplicate_journal_fields_do_not_get_normalized_into_start_permission(self):
        self.assertTrue(self.guard.allowed())
        path = self.root / "var/lib/praho/mail/node.json"
        path.write_text(path.read_text().removesuffix("}") + ', "fenced": true}')
        self.assertFalse(self.guard.allowed())

    def test_mutable_directories_hardlinks_and_symlinked_ancestors_refuse(self):
        self.assertTrue(self.guard.allowed())
        directory = self.root / "run/praho-mail-owner"
        directory.chmod(0o777)
        self.assertFalse(self.guard.allowed())
        directory.chmod(0o700)
        self.assertTrue(self.guard.allowed())
        alias = self.root / "lock-alias"
        os.link(self.lock, alias)
        self.assertFalse(self.guard.allowed())
        alias.unlink()
        self.assertTrue(self.guard.allowed())
        moved = directory.with_name("saved-helper-directory")
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        self.assertFalse(self.guard.allowed())

    def test_expiry_candidate_mutation_and_fence_removal_during_configuration_refuse(self):
        self.assertTrue(self.guard.allowed())
        self.guard.configured = lambda marker: setattr(self.guard, "clock", lambda: 220.0) or True
        self.assertFalse(self.guard.allowed())
        self.guard.clock = lambda: 100.0
        key = self.root / "etc/praho-mail/node.key"
        original = key.read_bytes()
        self.guard.configured = lambda marker: key.write_bytes(b"changed during inspection") or True
        self.assertFalse(self.guard.allowed())
        key.write_bytes(original)
        self.guard.configured = lambda marker: self.rules.update({"ip6tables-save": ""}) or True
        self.assertFalse(self.guard.allowed())

    def runtime(self):
        setup = Mock()
        setup.execute.side_effect = ["candidate public key", "candidate public key"]
        setup.certificate_verify_command.return_value = ["openssl", "verify", "owned-certificate"]
        node = Mock(profile_id=self.record["profile"])
        node.setup_driver.return_value = setup
        module = SimpleNamespace(MailNode=lambda: node)
        specification = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda loaded: None))
        return (
            node,
            setup,
            patch.object(self.module.importlib.util, "spec_from_file_location", return_value=specification),
            patch.object(self.module.importlib.util, "module_from_spec", return_value=module),
        )

    def test_candidate_runtime_checks_actual_profile_configuration_key_and_trust(self):
        node, setup, specification, loader = self.runtime()
        with specification, loader, patch.object(self.module, "execute") as openssl:
            self.assertTrue(self.module.configured(self.record))
            setup.check_files.assert_called_once_with(self.record)
            setup.security_configuration.assert_not_called()
            setup._security_settings.assert_called_once()
            openssl.assert_called_once_with(["openssl", "verify", "owned-certificate"])
            self.assertEqual(
                json.loads((self.root / "var/lib/praho/mail/node.json").read_text())["status"], "certificate_starting"
            )
            node.profile_id = "ubuntu2604-dovecot24"
            setup.execute.side_effect = ["candidate public key", "candidate public key"]
            self.assertFalse(self.module.configured(self.record))

    def test_candidate_runtime_rejects_a_valid_leaf_with_a_different_private_key(self):
        _, setup, specification, loader = self.runtime()
        setup.execute.side_effect = ["candidate public key", "unrelated public key"]
        with specification, loader, patch.object(self.module, "execute") as openssl:
            self.assertFalse(self.module.configured(self.record))
            openssl.assert_not_called()
