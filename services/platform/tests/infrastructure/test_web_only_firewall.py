"""Convergence removes obsolete access without undoing a newer transition."""

import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch


class FirewallTests(TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[4] / "deploy/ansible/roles/virtualmin-web-only/files/firewall.py"
        spec = importlib.util.spec_from_file_location("firewall_policy", path)
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)

    def test_guard_only_returns_approved_traffic_and_drops_the_rest(self):
        networks = [ipaddress.ip_network("192.0.2.1/32"), ipaddress.ip_network("2001:db8::1/128")]
        for ipv6 in (False, True):
            rules = self.policy.guard_rules(networks, 9876, ipv6=ipv6)
            self.assertEqual(rules[-1], ["-j", "DROP"])
            self.assertTrue(all(rule[-1] == "RETURN" for rule in rules[:-1]))
            for port in ("80", "443"):
                self.assertIn(["-p", "tcp", "--dport", port, "-j", "RETURN"], rules)
            source = "2001:db8::1/128" if ipv6 else "192.0.2.1/32"
            for port in ("9876", "10000"):
                self.assertIn(["-s", source, "-p", "tcp", "--dport", port, "-j", "RETURN"], rules)
            self.assertFalse(any("25" in rule or "22" in rule or "5353" in rule for rule in rules))
            self.assertTrue(any(("546" if ipv6 else "68") in rule for rule in rules))

    def test_guard_is_complete_before_it_is_attached_to_input(self):
        with patch.object(self.policy, "run", return_value="") as execute:
            self.policy.ensure_guard("a" * 32, {"cidrs": ["192.0.2.1/32"], "port": 22})
        calls = [call.args[0] for call in execute.call_args_list]
        for executable in ("iptables", "ip6tables"):
            attached = next(index for index, call in enumerate(calls) if call[:4] == [executable, "-w", "-I", "INPUT"])
            self.assertIn("DROP", calls[attached - 1])
            self.assertTrue(all(call[0] == executable for call in calls[attached - 2 : attached]))

    def test_guard_verification_refuses_default_accept_missing_grants_and_bypasses(self):
        token = "a" * 32
        name = self.policy.guard_name(token)
        request = {"cidrs": ["192.0.2.1/32"], "port": 9876}
        rules = self.policy.guard_rules([ipaddress.ip_network("192.0.2.1/32")], 9876, ipv6=False)
        saved = "\n".join(
            [
                ":INPUT DROP [0:0]",
                f":{name} - [0:0]",
                ":ufw-user-input - [0:0]",
                f"-A INPUT -j {name}",
                "-A INPUT -j ufw-before-input",
                "-A ufw-before-input -j ufw-user-input",
            ]
            + ["-A " + name + " " + " ".join(rule) for rule in rules]
            + [
                "-A ufw-user-input " + " ".join([*rule[:-1], "ACCEPT"])
                for rule in rules
                if "--dport" in rule and "tcp" in rule
            ]
        )
        self.policy.verify_guarded_filter(saved, token, request, ipv6=False)
        # Existing reviewed grants may retain harmless operator comments in UFW.
        self.policy.verify_guarded_filter(
            saved.replace("--dport 443 -j ACCEPT", "--dport 443 -m comment --comment 'public HTTPS' -j ACCEPT"),
            token,
            request,
            ipv6=False,
        )
        for unsafe in (
            saved.replace(":INPUT DROP", ":INPUT ACCEPT"),
            saved.replace("-A ufw-user-input -p tcp --dport 443 -j ACCEPT", ""),
            saved.replace("-A ufw-before-input -j ufw-user-input", ""),
            saved + "\n-A ufw-before-input -p tcp --dport 25 -j ACCEPT",
            saved + "\n-A ufw-before-input -j ufw-unreviewed\n-A ufw-unreviewed -i lo -j ACCEPT",
            saved.replace(f"-A INPUT -j {name}", "-A INPUT -j unknown-owner\n" + f"-A INPUT -j {name}"),
        ):
            with self.assertRaisesRegex(RuntimeError, "guard|policy|INPUT"):
                self.policy.verify_guarded_filter(unsafe, token, request, ipv6=False)

    def test_prune_preserves_only_exact_current_policy(self):
        status = """[ 1] 80/tcp ALLOW IN Anywhere
[ 2] 443/tcp (v6) ALLOW IN Anywhere (v6)
[ 3] 9876/tcp ALLOW IN 192.0.2.1
[ 4] 10000/tcp ALLOW IN 198.51.100.0/24
[ 5] 53/udp ALLOW IN Anywhere
[ 6] 22/tcp ALLOW IN Anywhere
[ 7] Apache Full ALLOW IN Anywhere
"""
        self.assertEqual(self.policy.obsolete_rules(status, ["192.0.2.1/32"], 9876), [7, 6, 5, 4])

    def test_vendor_baseline_keeps_os_networking_but_removes_discovery(self):
        source = "-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT\n-A ufw-before-input -p udp --dport 5353 -j ACCEPT\n-A ufw-before-input -p icmp -j ACCEPT\n"
        result = self.policy.baseline(source)
        self.assertIn("--dport 68", result)
        self.assertIn("-p icmp", result)
        self.assertNotIn("5353", result)

    def test_inactive_firewall_saved_rules_are_pruned_before_enable(self):
        saved = """Added user rules (see 'ufw status' for running firewall):
ufw allow 80/tcp
ufw allow 443/tcp comment 'public HTTPS'
ufw allow from 192.0.2.1 to any port 9876 proto tcp
ufw allow from 198.51.100.0/24 to any port 10000 proto tcp
ufw allow 25/tcp
ufw allow 53/udp
ufw allow 22/tcp
"""
        removed = self.policy.obsolete_commands(saved, ["192.0.2.1/32"], 9876)
        self.assertEqual(
            removed,
            [
                ["allow", "from", "198.51.100.0/24", "to", "any", "port", "10000", "proto", "tcp"],
                ["allow", "25/tcp"],
                ["allow", "53/udp"],
                ["allow", "22/tcp"],
            ],
        )

    def test_stale_timer_cannot_restore_another_transitions_firewall(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE = root / "snapshots"
            self.policy.LOCK = root / "lock"
            config = root / "ufw.conf"
            config.write_text("before")
            self.policy.CONFIG_FILES = [config]
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("a" * 32)
                (self.policy.snapshot("a" * 32) / "state").write_text("pending")
                config.write_text("after")
                (self.policy.LOCK / "owner").write_text("b" * 32)
                self.policy.run.reset_mock()
                self.policy.rollback("a" * 32)
                self.policy.run.assert_not_called()
            self.assertEqual(config.read_text(), "after")

    def test_pending_rollback_restores_exact_previous_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE = root / "snapshots"
            self.policy.LOCK = root / "lock"
            config = root / "ufw.conf"
            config.write_text("before")
            self.policy.CONFIG_FILES = [config]
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("c" * 32)
                (self.policy.snapshot("c" * 32) / "state").write_text("pending")
                config.write_text("after")
                self.policy.rollback("c" * 32)
            self.assertEqual(config.read_text(), "before")
            self.assertFalse(self.policy.LOCK.exists())

    def test_route_rule_deletion_uses_native_route_subcommand(self):
        self.assertEqual(
            self.policy.delete_command(["route", "allow", "in", "on", "eth0", "to", "any", "port", "25"]),
            ["ufw", "--force", "route", "delete", "allow", "in", "on", "eth0", "to", "any", "port", "25"],
        )

    def test_firewall_commands_use_stable_locale(self):
        with patch.object(
            self.policy.subprocess, "run", return_value=SimpleNamespace(stdout="Status: active")
        ) as execute:
            self.assertEqual(self.policy.run(["ufw", "status"]), "Status: active")
        self.assertEqual(execute.call_args.kwargs["env"]["LC_ALL"], "C")

    def test_foreign_direct_input_rules_require_manual_preparation(self):
        saved = """*filter
:INPUT DROP [0:0]
-A INPUT -j ufw-before-input
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp --dport 25 -j ACCEPT
-A INPUT -j operator-firewall
-A FORWARD -j unrelated-router
COMMIT
"""
        self.assertEqual(
            self.policy.foreign_input_rules(saved, ipv6=False),
            ["-A INPUT -p tcp --dport 25 -j ACCEPT", "-A INPUT -j operator-firewall"],
        )
        self.assertEqual(self.policy.foreign_input_rules("-A INPUT -j ufw6-before-input", ipv6=True), [])
        self.assertEqual(
            self.policy.foreign_input_rules("-A INPUT -j ufw6-before-input", ipv6=False),
            ["-A INPUT -j ufw6-before-input"],
        )
        self.assertEqual(
            self.policy.foreign_input_rules(":INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT", ipv6=False),
            [":INPUT DROP [0:0]"],
        )
        self.assertEqual(self.policy.foreign_input_rules(":INPUT ACCEPT [0:0]", ipv6=False), [])

    def test_foreign_live_input_accept_prevents_activation_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ufw.conf"
            config.write_text("before")
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [config], []
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("2" * 32)
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                patch.object(self.policy, "run", return_value="-A INPUT -p tcp --dport 25 -j ACCEPT") as execute,
                patch.object(self.policy, "configure_baselines"),
                self.assertRaisesRegex(ValueError, "Foreign INPUT rules require manual reviewed preparation"),
            ):
                self.policy.activate("2" * 32, {"cidrs": ["192.0.2.1/32"]})
            execute.assert_called_once_with(["iptables-save", "-t", "filter"])
            self.assertEqual((self.policy.snapshot("2" * 32) / "state").read_text(), "prepared")
            self.assertEqual(config.read_text(), "before")

    def test_expired_activation_budget_stops_before_another_command(self):
        with (
            patch.object(self.policy, "COMMAND_DEADLINE", 10, create=True),
            patch.object(self.policy, "monotonic", return_value=11, create=True),
            patch.object(self.policy.subprocess, "run") as execute,
            self.assertRaises(TimeoutError),
        ):
            self.policy.run(["ufw", "status"])
        execute.assert_not_called()

    def test_activation_command_timeout_is_limited_to_remaining_budget(self):
        with (
            patch.object(self.policy, "COMMAND_DEADLINE", 10),
            patch.object(self.policy, "monotonic", return_value=8),
            patch.object(self.policy.subprocess, "run", return_value=SimpleNamespace(stdout="")) as execute,
        ):
            self.policy.run(["ufw", "reload"])
        self.assertEqual(execute.call_args.kwargs["timeout"], 2)

    def test_activation_failure_does_not_limit_recovery_commands(self):
        with self.assertRaisesRegex(RuntimeError, "activation interrupted"), self.policy.command_budget():
            raise RuntimeError("activation interrupted")
        self.assertIsNone(self.policy.COMMAND_DEADLINE)

    def test_hook_mode_changes_are_part_of_the_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "after.init"
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o700)
            self.policy.CONFIG_FILES = [hook]
            before = self.policy.fingerprint()
            hook.chmod(0o600)
            self.assertNotEqual(self.policy.fingerprint(), before)

    def test_unreviewed_executable_hook_stops_before_any_firewall_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = root / "after.init"
            hook.write_text("#!/bin/sh\niptables -I INPUT -p tcp --dport 25 -j ACCEPT\n")
            hook.chmod(0o700)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [hook], [hook]
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("d" * 32)
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                patch.object(self.policy, "run", return_value="Status: active") as run,
                patch.object(self.policy, "configure_baselines"),
                self.assertRaisesRegex(ValueError, "hooks require explicit review"),
            ):
                self.policy.activate("d" * 32, {"cidrs": ["192.0.2.1/32"]})
            run.assert_not_called()
            self.assertTrue(os.access(hook, os.X_OK))

    def test_boolean_approval_does_not_authorize_a_changed_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "after.init"
            original = b"#!/bin/sh\nexit 0\n"
            hook.write_bytes(original + b"# changed after the operator reviewed it\n")
            hook.chmod(0o700)
            self.policy.HOOK_FILES = [hook]
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 4567 192.0.2.2 9876"}),
                patch.object(self.policy, "run") as commands,
                self.assertRaisesRegex(ValueError, "hooks require explicit review"),
            ):
                self.policy.activate(
                    "a" * 32,
                    {
                        "cidrs": ["192.0.2.1/32"],
                        "disable_hooks": True,
                        "reviewed_hooks": {str(hook): hashlib.sha256(original).hexdigest()},
                    },
                )
            commands.assert_not_called()
            self.assertTrue(os.access(hook, os.X_OK))

    def test_failed_rollback_retains_ownership_and_is_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ufw.conf"
            config.write_text("before")
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES = [config]
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("e" * 32)
            (self.policy.snapshot("e" * 32) / "state").write_text("pending")
            config.write_text("after")
            with (
                patch.object(self.policy, "run", side_effect=subprocess.CalledProcessError(1, ["ufw", "reload"])),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                self.policy.rollback("e" * 32)
            self.assertTrue(self.policy.owned("e" * 32))
            self.assertEqual((self.policy.snapshot("e" * 32) / "state").read_text(), "pending")
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.rollback("e" * 32)
            self.assertEqual(config.read_text(), "before")
            self.assertFalse(self.policy.LOCK.exists())

    def test_reviewed_hook_is_disabled_and_reported_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = root / "after.init"
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o700)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [hook], [hook]
            self.policy.DEFAULTS = root / "defaults"
            self.policy.DEFAULTS.write_text("MANAGE_BUILTINS=no\n")
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("f" * 32)
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                patch.object(self.policy, "run", return_value="Status: active"),
                patch.object(self.policy, "configure_baselines"),
                patch.object(self.policy, "verify_guarded_filter"),
                redirect_stdout(output),
            ):
                self.policy.activate(
                    "f" * 32,
                    {
                        "cidrs": ["192.0.2.1/32"],
                        "reviewed_hooks": {str(hook): hashlib.sha256(hook.read_bytes()).hexdigest()},
                    },
                )
            self.assertFalse(os.access(hook, os.X_OK))
            self.assertEqual(json.loads(output.getvalue()), {"changed": True})

    def test_rejected_unreviewed_hook_never_runs_during_rescue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = root / "after.init"
            hook.write_text("#!/bin/sh\niptables -I INPUT -p tcp --dport 25 -j ACCEPT\n")
            hook.chmod(0o700)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [hook], [hook]
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("1" * 32)
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                self.assertRaises(ValueError),
            ):
                self.policy.activate("1" * 32, {"cidrs": ["192.0.2.1/32"]})
            with patch.object(self.policy, "run") as run:
                self.policy.rollback("1" * 32)
            run.assert_not_called()
            self.assertFalse(self.policy.LOCK.exists())

    def test_partial_guard_failure_recovers_without_restarting_ufw(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.DEFAULTS = root / "defaults"
            self.policy.DEFAULTS.write_text("MANAGE_BUILTINS=yes\n")
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [self.policy.DEFAULTS], []
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("3" * 32)
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                patch.object(self.policy, "run", return_value="Status: active"),
                patch.object(self.policy, "ensure_guard", side_effect=RuntimeError("partial guard install")),
                self.assertRaisesRegex(RuntimeError, "partial guard install"),
            ):
                self.policy.activate("3" * 32, {"cidrs": ["192.0.2.1/32"]})
            self.assertEqual((self.policy.snapshot("3" * 32) / "state").read_text(), "guarding")
            with patch.object(self.policy, "run", return_value="") as commands:
                self.policy.rollback("3" * 32)
            self.assertTrue(all(call.args[0][0] != "ufw" for call in commands.call_args_list))
            self.assertEqual(self.policy.DEFAULTS.read_text(), "MANAGE_BUILTINS=yes\n")
            self.assertFalse(self.policy.LOCK.exists())

    def test_restore_never_flushes_builtins_or_executes_restored_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.DEFAULTS = root / "defaults"
            original = "# original exact defaults\nMANAGE_BUILTINS=yes\n"
            self.policy.DEFAULTS.write_text(original)
            hook = root / "after.init"
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o700)
            self.policy.HOOK_FILES = [hook]
            self.policy.CONFIG_FILES = [self.policy.DEFAULTS, hook]

            def execute(argv):
                if argv == ["ufw", "reload"]:
                    self.assertIn("MANAGE_BUILTINS=no\n", self.policy.DEFAULTS.read_text())
                    self.assertFalse(os.access(hook, os.X_OK))
                return "Status: active" if argv == ["ufw", "status"] else ":INPUT DROP [0:0]\n"

            with patch.object(self.policy, "run", side_effect=execute):
                self.policy.begin("4" * 32)
                (self.policy.snapshot("4" * 32) / "state").write_text("pending")
                self.policy.DEFAULTS.write_text("MANAGE_BUILTINS=no\n")
                hook.chmod(0o600)
                self.policy.rollback("4" * 32)
            self.assertEqual(self.policy.DEFAULTS.read_text(), original)
            self.assertTrue(os.access(hook, os.X_OK))
            self.assertFalse(self.policy.LOCK.exists())

    def test_safe_defaults_prevent_native_ipv6_and_manage_builtins_flush_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            self.policy.DEFAULTS = Path(directory) / "defaults"
            self.policy.DEFAULTS.write_text("export MANAGE_BUILTINS=yes\nIPV6=no\n")
            self.policy.DEFAULTS.chmod(0o600)
            exists = Path.exists
            with patch.object(Path, "exists", lambda path: str(path) == "/proc/net/if_inet6" or exists(path)):
                self.policy.safe_defaults()
                self.assertEqual(self.policy.DEFAULTS.read_text(), "MANAGE_BUILTINS=no\nIPV6=yes\n")
                self.policy.safe_defaults()
            self.assertEqual(self.policy.DEFAULTS.read_text(), "MANAGE_BUILTINS=no\nIPV6=yes\n")
            self.assertEqual(self.policy.DEFAULTS.stat().st_mode & 0o777, 0o600)

    def test_every_ufw_mutation_has_both_guards_and_safe_defaults_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.DEFAULTS = root / "defaults"
            self.policy.DEFAULTS.write_text("MANAGE_BUILTINS=yes\nIPV6=no\n")
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [self.policy.DEFAULTS], []
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin("7" * 32)
            calls = []

            def execute(argv):
                if argv[0] == "ufw" and argv[1] not in {"status", "show"}:
                    self.assertIn("MANAGE_BUILTINS=no\n", self.policy.DEFAULTS.read_text())
                    for executable in ("iptables", "ip6tables"):
                        self.assertTrue(any(call[:4] == [executable, "-w", "-I", "INPUT"] for call in calls))
                calls.append(argv)
                return "Status: active" if argv == ["ufw", "status"] else ""

            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}),
                patch.object(self.policy, "run", side_effect=execute),
                patch.object(self.policy, "configure_baselines"),
                patch.object(self.policy, "verify_guarded_filter"),
                redirect_stdout(io.StringIO()),
            ):
                self.policy.activate("7" * 32, {"cidrs": ["192.0.2.1/32"]})
            self.assertIn(["ufw", "reload"], calls)

    def test_rollback_cannot_remove_guard_when_saved_effective_policy_was_not_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [], []
            token = "6" * 32
            with patch.object(self.policy, "run", return_value=":INPUT DROP [0:0]\n"):
                self.policy.begin(token)
            (self.policy.snapshot(token) / "state").write_text("pending")
            with (
                patch.object(self.policy, "run", return_value=":INPUT ACCEPT [0:0]\n") as commands,
                self.assertRaisesRegex(RuntimeError, "saved effective policy"),
            ):
                self.policy.rollback(token)
            self.assertTrue(self.policy.owned(token))
            self.assertEqual((self.policy.snapshot(token) / "state").read_text(), "pending")
            self.assertFalse(any("-D" in call.args[0] or "-X" in call.args[0] for call in commands.call_args_list))

    def test_commit_with_unverified_policy_retains_guard_and_recovery_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES = []
            token = "5" * 32
            with patch.object(self.policy, "run", return_value="Status: active"):
                self.policy.begin(token)
            target = self.policy.snapshot(token)
            (target / "state").write_text("pending")
            (target / "guard.json").write_text(json.dumps({"cidrs": ["192.0.2.1/32"], "port": 22}))
            with (
                patch.object(self.policy, "run", return_value=":INPUT ACCEPT [0:0]\n") as commands,
                self.assertRaisesRegex(RuntimeError, "INPUT policy"),
            ):
                self.policy.commit(token)
            self.assertTrue(self.policy.owned(token))
            self.assertEqual((target / "state").read_text(), "pending")
            commands.assert_called_once_with(["iptables-save", "-t", "filter"])
