"""A stopped/crashed setup must never expose package defaults after a node reboot."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-mail-boot.py"


class MailBootGuardFixture:
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("mail_boot", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.commands = []
        self.guard = self.module.MailBootGuard(self.root, execute=self.execute, configured=lambda marker: True)

    def write(self, relative, content):
        file = self.root / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        return file

    def execute(self, argv):
        self.commands.append(argv)

    def marker(self, **changes):
        values = {
            "version": 1,
            "profile": "debian12-dovecot23",
            "node": "node.example",
            "status": "applying",
            "pid": 1234,
            "start_tick": "4321",
            "fenced": True,
            "boot_id": "boot-a",
            **changes,
        }
        self.write("var/lib/praho/mail/node.json", json.dumps(values))
        self.write("proc/sys/kernel/random/boot_id", "boot-a\n")
        return values


class MailBootGuardTests(MailBootGuardFixture, SimpleTestCase):
    def test_interrupted_or_reused_setup_pid_refuses_boot_even_with_old_fence_marker(self):
        self.marker()
        self.assertFalse(self.guard.allowed())
        self.write("proc/1234/stat", "1234 (python3) S " + " ".join(["0"] * 18 + ["9999"]))
        self.assertFalse(self.guard.allowed())
        self.assertEqual(self.commands, [])

    def test_live_setup_requires_both_exact_ipv4_and_ipv6_mail_fences(self):
        self.marker()
        self.write("proc/1234/stat", "1234 (python3) S " + " ".join(["0"] * 18 + ["4321"]))
        self.assertTrue(self.guard.allowed())
        self.assertEqual({argv[0] for argv in self.commands}, {"iptables", "ip6tables"})
        self.guard.execute = lambda argv: (_ for _ in ()).throw(OSError("missing IPv6 fence"))
        self.assertFalse(self.guard.allowed())

    def test_ready_marker_still_requires_current_owned_configuration(self):
        self.marker(status="ready")
        self.assertTrue(self.guard.allowed())
        self.guard.configured = lambda marker: False
        self.assertFalse(self.guard.allowed())

    def test_ubuntu_profile_requires_the_same_fresh_configuration_proof(self):
        self.marker(status="ready", profile="ubuntu2604-dovecot24")
        self.assertTrue(self.guard.allowed())
        self.guard.configured = lambda marker: False
        self.assertFalse(self.guard.allowed())

    def test_missing_unknown_or_unfenced_state_refuses_service_start(self):
        self.assertFalse(self.guard.allowed())
        for values in ({"status": "review_required"}, {"profile": "unknown"}, {"fenced": False}):
            with self.subTest(values=values):
                self.marker(**values)
                self.assertFalse(self.guard.allowed())

    def test_node_reboot_cannot_reuse_a_previous_setup_process_permit(self):
        self.marker()
        self.write("proc/1234/stat", "1234 (python3) S " + " ".join(["0"] * 18 + ["4321"]))
        self.write("proc/sys/kernel/random/boot_id", "boot-b\n")
        self.assertFalse(self.guard.allowed())
        self.assertEqual(self.commands, [])
