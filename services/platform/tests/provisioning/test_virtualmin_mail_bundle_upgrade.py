"""In-place helper bundle upgrade: evidenced predecessors only, dry-run the installed guard, exact restore."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase

from tests.provisioning.test_virtualmin_mail_certificate_recovery import FILES, NODE, Crash, RecoveryFixture

GUARD = "/usr/lib/praho/mail/praho-mail-boot.py"
COMPAT = ["/usr/bin/python3", GUARD, "--compat-check"]


class BundleUpgradeFixture(RecoveryFixture):
    def setUp(self):
        super().setUp()
        self.compat = True
        self.bundle_paths = self.protocol.BUNDLE_PATHS
        self.predecessor = {
            "/usr/lib/praho/mail/" + name: b"# previously shipped " + name.encode() + b"\n"
            for name in self.protocol.NATIVE_FILES
        }
        for path, content in self.predecessor.items():
            self.private(path, content)
        self.ready["files"].update({path: self.digest(path) for path in self.predecessor})
        self.original = json.dumps(self.ready).encode()
        self.private("var/lib/praho/mail/node.json", self.original)
        # Long after setup: the leaf expired and the units are stopped, so nothing can be probed.
        self.units = {unit["unit"]: ("failed", "failed") for unit in self.topology}
        self.running_bundle = {
            "/usr/lib/praho/mail/" + name: (FILES / name).read_bytes() for name in self.protocol.NATIVE_FILES
        }
        self.running_bundle.update(dict.fromkeys(self.protocol.DROPIN_PATHS, self.protocol.UNIT_GUARD))

    def driver(self, *, fd=7):
        driver = super().driver(fd=fd)
        evidenced = {
            name.rsplit("/", 1)[-1]: hashlib.sha256(content).hexdigest() for name, content in self.predecessor.items()
        }
        self.enterContext(patch.dict(driver.upgrade_bundle.__globals__["PREDECESSOR_BUNDLES"], {"fixture": evidenced}))
        driver.node.public_ports = Mock(side_effect=AssertionError("an upgrade never probes listeners"))
        driver.node.probe = Mock(side_effect=AssertionError("an upgrade never probes TLS"))
        return driver

    def execute(self, argv, **kwargs):
        if argv == COMPAT:
            self.commands.append(argv)
            hook = self.hooks.get(tuple(argv[:2]))
            if hook is not None:
                hook(argv)
            if self.compat:
                return "mail_bundle_compatible\n"
            raise self.module.MailError("mail_native_inspection_failed")
        return super().execute(argv, **kwargs)

    def upgrade(self, driver=None, identity=None):
        return (driver or self.driver()).upgrade_bundle(NODE, identity or self.identity)

    def installed(self):
        return {path: (self.root / path.lstrip("/")).read_bytes() for path in self.bundle_paths}

    def node_journal(self):
        return (self.root / "var/lib/praho/mail/node.json").read_bytes()

    def assert_upgraded(self, result):
        self.assertEqual(result["outcome"], "upgraded")
        self.assertEqual(self.installed(), self.running_bundle)
        journal = self.journal()
        self.assertEqual(set(journal), {"version", "node", "profile", "status", "files"})
        self.assertEqual(journal["status"], "ready")
        self.assertEqual(
            journal["files"],
            {
                **self.ready["files"],
                **{path: hashlib.sha256(content).hexdigest() for path, content in self.running_bundle.items()},
            },
        )
        self.assertEqual([path.name for path in (self.root / "var/lib/praho/mail").iterdir()], ["node.json"])


class BundleUpgradeTests(BundleUpgradeFixture, SimpleTestCase):
    def test_an_expired_stopped_node_upgrades_helpers_and_dropins_and_dry_runs_the_installed_guard(self):
        events = []
        original = self.protocol.atomic
        driver = self.driver()

        def record(path, content, *args):
            events.append(("write", "/" + str(path.relative_to(self.root)) if path.is_relative_to(self.root) else path))
            original(path, content, *args)

        self.hooks[("systemctl", "daemon-reload")] = lambda argv: events.append(("daemon-reload",))
        self.hooks[tuple(COMPAT[:2])] = lambda argv: events.append(("compat",))
        configuration = {
            path: (self.root / path.lstrip("/")).read_bytes()
            for path in self.protocol.CONFIG_PATHS
            if path not in self.bundle_paths
        }
        with patch.dict(driver.upgrade_bundle.__globals__, atomic=record):
            result = self.upgrade(driver)
        self.assert_upgraded(result)
        replaced = [event[1] for event in events if event[0] == "write" and event[1] in self.bundle_paths]
        self.assertEqual(replaced, list(self.protocol.BUNDLE_PATHS[: len(self.protocol.NATIVE_FILES)]))
        reload_at, compat_at = events.index(("daemon-reload",)), events.index(("compat",))
        last_file = max(
            index for index, event in enumerate(events) if event[0] == "write" and event[1] in self.bundle_paths
        )
        commit = max(index for index, event in enumerate(events) if event == ("write", "/var/lib/praho/mail/node.json"))
        self.assertLess(last_file, reload_at)
        self.assertLess(reload_at, compat_at)
        self.assertLess(compat_at, commit)
        self.assertEqual(sum(event == ("daemon-reload",) for event in events), 1)
        self.assertEqual({path: (self.root / path.lstrip("/")).read_bytes() for path in configuration}, configuration)
        self.assertFalse(
            any(
                argv[0] in {"apt-get", "virtualmin", "iptables", "ip6tables"}
                or argv[:2] == ["postconf", "-e"]
                or (argv[0] == "systemctl" and argv[1] != "daemon-reload")
                for argv in self.commands
            )
        )

    def test_a_current_bundle_replay_is_idempotent_and_writes_nothing(self):
        self.assert_upgraded(self.upgrade())
        journal = self.node_journal()
        self.commands.clear()
        for identity in (self.identity, str(uuid4())):
            with self.subTest(identity=identity):
                self.assertEqual(self.upgrade(identity=identity)["outcome"], "unchanged")
                self.assertEqual(self.node_journal(), journal)
        self.assertFalse(any(argv[0] == "systemctl" or argv == COMPAT for argv in self.commands))

    def test_an_unknown_installed_digest_is_refused_without_mutation(self):
        path = "/usr/lib/praho/mail/praho-mail-boot.py"
        self.private(path, b"# an operator's local guard\n")
        self.ready["files"][path] = self.digest(path)
        self.private("var/lib/praho/mail/node.json", json.dumps(self.ready).encode())
        before, journal = self.installed(), self.node_journal()
        with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
            self.upgrade()
        self.assertEqual((self.installed(), self.node_journal()), (before, journal))
        self.assertFalse(any(argv[0] == "systemctl" or argv == COMPAT for argv in self.commands))

    def test_an_incompatible_new_guard_restores_the_predecessor_and_the_old_journal_byte_for_byte(self):
        self.compat = False
        before = self.installed()
        with self.assertRaisesRegex(self.module.MailError, "mail_node_bundle_incompatible") as raised:
            self.upgrade()
        self.assertEqual(self.installed(), before)
        self.assertEqual(self.node_journal(), self.original)
        self.assertEqual([path.name for path in (self.root / "var/lib/praho/mail").iterdir()], ["node.json"])
        self.assertEqual(sum(argv == ["systemctl", "daemon-reload"] for argv in self.commands), 2)
        self.assertEqual(str(raised.exception), "mail_node_bundle_incompatible")

    def test_another_identity_during_an_upgrade_is_in_progress(self):
        self.hooks[tuple(COMPAT[:2])] = lambda argv: (_ for _ in ()).throw(Crash("compat"))
        with self.assertRaises(Crash):
            self.upgrade()
        self.hooks.clear()
        journal = self.node_journal()
        for action in ("upgrade_bundle", "reconcile_certificate"):
            with (
                self.subTest(action=action),
                self.assertRaisesRegex(self.module.MailError, "mail_node_operation_in_progress"),
            ):
                getattr(self.driver(), action)(NODE, str(uuid4()))
            self.assertEqual(self.node_journal(), journal)


class BundleUpgradeResumeTests(BundleUpgradeFixture, SimpleTestCase):
    def crash_after_write(self, target):
        original = self.protocol.atomic
        fired = []

        def write(path, content, *args):
            original(path, content, *args)
            name = "/" + str(path.relative_to(self.root)) if path.is_relative_to(self.root) else ""
            status = json.loads(content).get("status") if path.name == "node.json" else None
            point = {"bundle_upgrading": "journal", "ready": "ready"}.get(status, name)
            if point == target and not fired:
                fired.append(point)
                raise Crash(target)

        return write

    def test_a_crash_after_each_file_replacement_resumes_and_the_guard_refuses_meanwhile(self):
        # Every evidenced bundle shipped UNIT_GUARD drop-ins, so only the helpers are ever rewritten.
        helpers = [path for path in self.protocol.BUNDLE_PATHS if path not in self.protocol.DROPIN_PATHS]
        for point in ("journal", *helpers, "daemon-reload", "compat", "ready"):
            with self.subTest(point=point):
                self.setUp()
                driver = self.driver()
                if point in {"daemon-reload", "compat"}:
                    key = ("systemctl", "daemon-reload") if point == "daemon-reload" else tuple(COMPAT[:2])
                    self.hooks[key] = lambda argv, point=point: (_ for _ in ()).throw(Crash(point))
                    with self.assertRaises(Crash):
                        self.upgrade(driver)
                    self.hooks.clear()
                else:
                    with (
                        patch.dict(driver.upgrade_bundle.__globals__, atomic=self.crash_after_write(point)),
                        self.assertRaises(Crash),
                    ):
                        self.upgrade(driver)
                status = self.journal()["status"]
                self.assertEqual(status, "ready" if point == "ready" else "bundle_upgrading")
                if status != "ready":
                    self.assertFalse(self.boot.MailBootGuard(self.root, execute=Mock(), configured=Mock()).allowed())
                result = self.upgrade()
                if point == "ready":
                    self.assertEqual(result["outcome"], "unchanged")
                    result = {**result, "outcome": "upgraded"}
                self.assert_upgraded(result)

    def test_replay_refuses_when_a_bundle_file_matches_neither_side(self):
        driver = self.driver()
        with (
            patch.dict(
                driver.upgrade_bundle.__globals__,
                atomic=self.crash_after_write("/usr/lib/praho/mail/praho_mail_setup.py"),
            ),
            self.assertRaises(Crash),
        ):
            self.upgrade(driver)
        self.private("/usr/lib/praho/mail/praho-mail-native.pl", b"# a third version\n")
        before, journal = self.installed(), self.node_journal()
        self.commands.clear()
        with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
            self.upgrade()
        self.assertEqual((self.installed(), self.node_journal()), (before, journal))
        self.assertFalse(any(argv[0] == "systemctl" or argv == COMPAT for argv in self.commands))


class CompatibilityModeTests(BundleUpgradeFixture, SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.hooks[tuple(COMPAT[:2])] = lambda argv: (_ for _ in ()).throw(Crash("compat"))
        with self.assertRaises(Crash):
            self.upgrade()
        self.hooks.clear()
        self.dry_run = Mock(return_value=True)
        self.guard = self.boot.MailBootGuard(
            self.root, execute=Mock(), configured=Mock(return_value=True), compatible_configuration=self.dry_run
        )

    def cgroup(self, value):
        self.private("proc/self/cgroup", "0::/" + value + "\n")

    def test_the_dry_run_checks_the_staged_candidate_from_outside_any_mail_unit(self):
        self.cgroup("user.slice/user-0.slice/session-4.scope")
        self.assertTrue(self.guard.compatible())
        (candidate,) = self.dry_run.call_args.args
        self.assertEqual(candidate, {**self.ready, "files": {**self.ready["files"], **self.journal()["to"]}})
        self.assertFalse(self.guard.allowed())

    def test_compatibility_mode_can_never_stand_in_for_a_start_approval(self):
        for unit in ("postfix.service", "system-postfix.slice/postfix@-.service", "dovecot.service"):
            with self.subTest(unit=unit):
                self.cgroup("system.slice/" + unit)
                self.assertFalse(self.guard.compatible())
        self.dry_run.assert_not_called()

    def test_a_candidate_that_differs_from_the_journal_target_or_a_failed_dry_run_is_incompatible(self):
        self.cgroup("user.slice/session-4.scope")
        stage = self.root / "var/lib/praho/mail/bundle-upgrade/candidate.json"
        candidate = json.loads(stage.read_text())
        changed = {**candidate, "files": {**candidate["files"], GUARD: "0" * 64}}
        stage.write_text(json.dumps(changed))
        self.assertFalse(self.guard.compatible())
        stage.write_text(json.dumps(candidate))
        self.assertTrue(self.guard.compatible())
        self.dry_run.return_value = False
        self.assertFalse(self.guard.compatible())

    def runtime(self, public_keys):
        setup = Mock()
        setup.execute.side_effect = public_keys
        setup.certificate_verify_command.side_effect = lambda *args, **kwargs: ["openssl", "verify", repr(kwargs)]
        node = Mock(profile_id="debian12-dovecot23")
        node.setup_driver.return_value = setup
        specification = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda loaded: None))
        return setup, (
            patch.object(self.boot.importlib.util, "spec_from_file_location", return_value=specification),
            patch.object(
                self.boot.importlib.util, "module_from_spec", return_value=SimpleNamespace(MailNode=lambda: node)
            ),
        )

    def test_only_the_dry_run_skips_the_validity_window_and_both_still_require_a_matching_key(self):
        candidate = {**self.ready, "files": {**self.ready["files"], **self.journal()["to"]}}
        setup, (specification, loader) = self.runtime(["public candidate", "public candidate"])
        with specification, loader, patch.object(self.boot, "execute") as openssl:
            self.assertTrue(self.boot.compatible_configuration(candidate))
            openssl.assert_called_once_with(["openssl", "verify", repr({"check_time": False})])
            setup.check_files.assert_called_once_with(candidate)
            setup._security_settings.assert_called_once()
        setup, (specification, loader) = self.runtime([])
        with specification, loader, patch.object(self.boot, "execute") as openssl:
            self.assertTrue(self.boot.configured(self.ready))
            openssl.assert_called_once_with(["openssl", "verify", repr({})])
        setup, (specification, loader) = self.runtime(["public candidate", "public other"])
        with specification, loader, patch.object(self.boot, "execute") as openssl:
            self.assertFalse(self.boot.compatible_configuration(candidate))
            openssl.assert_not_called()

    def test_upgrade_journal_paths_point_at_the_fixed_private_stage(self):
        self.assertEqual(Path(self.root / "var/lib/praho/mail/bundle-upgrade").stat().st_mode & 0o777, 0o700)

    def test_a_chain_the_installed_trust_store_rejects_fails_the_dry_run(self):
        self.cgroup("user.slice/session-4.scope")
        guard = self.boot.MailBootGuard(self.root, execute=Mock(), configured=Mock())
        for verify, expected in ((None, True), (subprocess.CalledProcessError(2, ["openssl", "verify"]), False)):
            with self.subTest(verify=verify):
                setup = Mock()
                setup.execute.side_effect = ["public candidate", "public candidate"]
                with (
                    patch.object(self.boot, "node_setup", return_value=setup),
                    patch.object(self.boot, "execute", side_effect=verify) as openssl,
                ):
                    self.assertEqual(guard.compatible(), expected)
                openssl.assert_called_once()
                self.assertEqual(setup.certificate_verify_command.call_args.kwargs, {"check_time": False})
