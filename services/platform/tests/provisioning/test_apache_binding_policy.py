"""Literal Apache groups and shared policy updates preserve other virtual hosts."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-apache-bindings.py"


class ApacheBindingPolicyTests(SimpleTestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("apache_binding_policy", HELPER)
        assert spec and spec.loader
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.commands = []
        self.fail_configtest = False
        self.ipv6_listener = True

        def execute(argv):
            self.commands.append(argv)
            if argv[:2] == ["ip", "-j"]:
                return json.dumps(
                    [{"addr_info": [{"local": "127.0.0.1"}, {"local": "192.0.2.20"}, {"local": "2001:db8::20"}]}]
                )
            if argv[:3] == ["ss", "-H", "-lnt"]:
                return "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n" + (
                    "LISTEN 0 511 [::]:80 [::]:*\nLISTEN 0 511 [::]:443 [::]:*\n" if self.ipv6_listener else ""
                )
            if argv == ["apache2ctl", "configtest"] and self.fail_configtest:
                self.fail_configtest = False
                raise ValueError("Observed configtest failure")
            return ""

        self.policy = self.module.ApacheBindings(self.root, execute=execute, owner_uid=os.geteuid())
        self.policy.sites.mkdir(parents=True)
        self.policy.conf.mkdir(parents=True)
        self.native = self.policy.sites / "customer.conf"
        self.native.write_text("<VirtualHost *:80 *:443>\nServerName customer.example.net\n</VirtualHost>\n")

    def test_literal_ipv4_bracketed_ipv6_and_wildcard_parse_without_dns(self) -> None:
        parsed = self.module.parse_bindings("192.0.2.20:80 [2001:0db8::20]:443 *:80")
        self.assertEqual(parsed, {"80": ["*", "192.0.2.20"], "443": ["2001:db8::20"]})
        for value in ("customer.example.net:80", "[fe80::1%eth0]:80", "192.0.2.20:wrong", "${UNTRUSTED}:80"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.parse_bindings(value)

    def test_shared_defines_use_only_existing_groups_not_new_interface_ip_groups(self) -> None:
        with self.policy.transaction():
            self.assertTrue(self.policy.refresh())
            self.policy.reload()
        text = self.policy.configuration.read_text()
        self.assertIn('Define PRAHO_NEUTRAL_HTTP_BINDINGS "*:80"', text)
        self.assertNotIn("192.0.2.20:80", text)
        self.assertIn("ServerName praho-default.invalid", text)
        self.assertIn(".well-known/acme-challenge", text)
        self.assertLess(self.policy.configuration.name, "praho-default-site.conf")
        self.assertEqual(self.policy.probe_addresses({"80": ["*"]}, "80"), ["127.0.0.1", "192.0.2.20", "2001:db8::20"])

    def test_explicit_groups_and_retained_bridges_are_observed_but_policy_groups_do_not_feed_themselves(self) -> None:
        self.native.write_text(
            "<VirtualHost 192.0.2.20:80 [2001:db8::20]:443>\nServerName customer.example.net\n</VirtualHost>\n"
        )
        bridge = self.policy.conf / "praho-migration-owned.conf"
        bridge.write_text("<VirtualHost 198.51.100.5:443>\nServerName customer.example.net\n</VirtualHost>\n")
        owned = self.policy.conf / "praho-neutral-20-zone-owned.conf"
        owned.write_text("<VirtualHost ${PRAHO_NEUTRAL_HTTP_BINDINGS}>\nServerName zone.example.net\n</VirtualHost>\n")
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        self.assertEqual(self.policy.current()["443"], ["*", "198.51.100.5", "2001:db8::20"])
        bridge.unlink()
        self.native.unlink()
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        self.assertEqual(self.policy.current(), {"80": ["*"], "443": ["*"]})

    def test_refresh_rollback_restores_config_state_and_the_callers_files(self) -> None:
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        before = self.policy.configuration.read_bytes()
        state = self.policy.metadata.read_bytes()
        caller = self.policy.conf / "caller-owned.conf"
        caller.write_text("# original\n")
        self.native.write_text("<VirtualHost 192.0.2.20:80>\nServerName customer.example.net\n</VirtualHost>\n")
        self.fail_configtest = True
        with self.assertRaisesRegex(ValueError, "configtest"), self.policy.transaction({caller: 0o644}):
            self.policy.refresh()
            caller.write_text("# changed\n")
            self.policy.reload()
        self.assertEqual(self.policy.configuration.read_bytes(), before)
        self.assertEqual(self.policy.metadata.read_bytes(), state)
        self.assertEqual(caller.read_text(), "# original\n")
        self.assertIn(["apache2ctl", "graceful"], self.commands)

    def test_unowned_or_tampered_shared_configuration_is_not_adopted(self) -> None:
        self.policy.configuration.write_text("# not PRAHO state\n")
        with self.assertRaisesRegex(ValueError, "owned|managed"), self.policy.transaction():
            self.policy.refresh()
        self.policy.configuration.unlink()
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        self.policy.configuration.write_text(self.policy.configuration.read_text() + "# changed\n")
        with self.assertRaisesRegex(ValueError, "digest|changed"):
            self.policy.current()

    def test_wildcard_backend_avoids_other_explicit_ip_groups(self) -> None:
        all_groups = {"80": ["*", "127.0.0.1"], "443": ["*"]}
        self.assertEqual(self.policy.http_backend(["*"], all_groups), "192.0.2.20")
        self.assertEqual(self.policy.http_backend(["2001:db8::20"], all_groups), "2001:db8::20")
        with self.assertRaisesRegex(ValueError, "local|binding"):
            self.policy.http_backend(["203.0.113.99"], all_groups)

    def test_assigned_ipv6_without_an_http_listener_is_not_a_wildcard_probe_destination(self) -> None:
        self.ipv6_listener = False
        self.assertEqual(self.policy.probe_addresses({"80": ["*"]}, "80"), ["127.0.0.1", "192.0.2.20"])
        # An explicit vhost still requires proof; a missing listener is an error
        # at the HTTP/TLS boundary, never silently ignored as an unused family.
        self.assertEqual(self.policy.probe_addresses({"80": ["2001:db8::20"]}, "80"), ["2001:db8::20"])

    def test_successful_commit_fsyncs_pending_unlink_before_private_cleanup_can_run(self) -> None:
        events = []
        original = os.fsync

        def observe(descriptor):
            info = os.fstat(descriptor)
            if (
                stat.S_ISDIR(info.st_mode)
                and self.policy.state.exists()
                and info.st_ino == self.policy.state.stat().st_ino
                and not self.policy.pending.exists()
            ):
                events.append("durable_commit")
            return original(descriptor)

        with patch.object(self.module.os, "fsync", observe):
            with self.policy.transaction():
                self.policy.refresh()
                self.policy.reload()
            events.append("private_cleanup")
        self.assertEqual(events[-2:], ["durable_commit", "private_cleanup"])

    def test_native_endpoint_query_is_read_only_and_preserves_real_ports(self) -> None:
        self.native.write_text(
            "<VirtualHost 192.0.2.20:80>\nServerName customer.example.net\n</VirtualHost>\n<VirtualHost [2001:db8::20]:443>\nServerName customer.example.net\n</VirtualHost>\n"
        )
        self.assertEqual(
            self.policy.native_endpoints("customer.example.net"), {"80": ["192.0.2.20"], "443": ["2001:db8::20"]}
        )
        self.assertFalse(self.policy.configuration.exists())
        self.assertFalse(self.policy.metadata.exists())
        with self.assertRaisesRegex(ValueError, "native|Native"):
            self.policy.native_endpoints("missing.example.net")

    def test_control_exceptions_rollback_caller_and_shared_config_without_suppression(self) -> None:
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        before = self.policy.configuration.read_bytes()
        caller = self.policy.conf / "caller.conf"
        caller.write_text("Original caller")
        for control in (KeyboardInterrupt, SystemExit):
            with (
                self.subTest(control=control.__name__),
                self.assertRaises(control),
                self.policy.transaction({caller: 0o644}),
            ):
                caller.write_text("Interrupted caller")
                self.native.write_text("<VirtualHost 192.0.2.20:80>\nServerName customer.example.net\n</VirtualHost>\n")
                self.policy.refresh()
                raise control("Controlled cancellation")
            self.assertEqual(caller.read_text(), "Original caller")
            self.assertEqual(self.policy.configuration.read_bytes(), before)
            self.assertFalse(self.policy.pending.exists())
            self.assertFalse(self.policy.in_transaction)

    def test_failed_rollback_retains_journal_until_a_later_recovery_can_reload(self) -> None:
        with self.policy.transaction():
            self.policy.refresh()
            self.policy.reload()
        caller = self.policy.conf / "caller.conf"
        caller.write_text("Original caller")
        with self.assertRaisesRegex(ValueError, "configtest"), self.policy.transaction({caller: 0o644}):
            caller.write_text("Interrupted caller")
            self.fail_configtest = True
            raise KeyboardInterrupt("Controlled cancellation")
        self.assertTrue(self.policy.pending.exists())
        self.assertFalse(self.policy.in_transaction)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.policy.current()
        with self.policy.transaction():
            self.assertEqual(caller.read_text(), "Original caller")
            self.policy.refresh()
            self.policy.reload()
        self.assertFalse(self.policy.pending.exists())
