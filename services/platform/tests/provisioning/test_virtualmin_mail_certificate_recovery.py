"""Expired node certificate recovery: identity first, fenced owner-bound starts, exact resume."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
NODE = "node.example"
PEM = "/etc/praho-mail/node.pem"
KEY = "/etc/praho-mail/node.key"
CHAIN = "PRAHO_MAIL_SETUP"
HELPER = "/run/praho-mail-owner/praho-mail.py"


def load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def certificate(label: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(label) + b"\n-----END CERTIFICATE-----\n"


def leaf(chain: bytes) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(chain.decode())).hexdigest()


class Crash(BaseException):
    """A hard stop of the worker: no handled-failure path runs, as with SIGKILL."""


class FakeFirewall:
    """Both filter tables, changed only by the exact argv the worker issues."""

    def __init__(self):
        self.chains = {"iptables": None, "ip6tables": None}
        self.jumps = {"iptables": False, "ip6tables": False}

    def save(self, program):
        lines = ["*filter", ":INPUT ACCEPT [0:0]"]
        if self.chains[program] is not None:
            lines.append(":" + CHAIN + " - [0:0]")
        if self.jumps[program]:
            lines.append("-A INPUT -j " + CHAIN)
        lines += self.chains[program] or []
        return "\n".join([*lines, "COMMIT", ""])

    def apply(self, argv):
        program, rule = argv[0], argv[3:]
        if rule == ["-N", CHAIN]:
            assert self.chains[program] is None
            self.chains[program] = []
        elif rule[:2] == ["-A", CHAIN]:
            self.chains[program].append(" ".join(rule))
        elif rule == ["-I", "INPUT", "1", "-j", CHAIN]:
            self.jumps[program] = True
        elif rule == ["-D", "INPUT", "-j", CHAIN]:
            self.jumps[program] = False
        elif rule == ["-F", CHAIN]:
            self.chains[program] = []
        elif rule == ["-X", CHAIN]:
            self.chains[program] = None
        else:
            raise AssertionError(argv)

    def state(self):
        return {program: (self.chains[program], self.jumps[program]) for program in self.chains}


class RecoveryFixture:
    profile = ("debian", "12", "debian12-dovecot23")

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.module = load("mail_node_recovery", FILES / "praho-mail.py")
        self.protocol = load("mail_setup_recovery", FILES / "praho_mail_setup.py")
        self.boot = load("mail_boot_recovery", FILES / "praho-mail-boot.py")
        self.topology = self.protocol.UNIT_TOPOLOGY[self.profile[2]]
        self.commands = []
        self.hooks = {}
        self.firewall = FakeFirewall()
        self.old_pem, self.new_pem = certificate(b"expired old leaf"), certificate(b"renewed new leaf")
        self.old_key, self.new_key = b"old fixture key", b"new fixture key"
        self.expired = {self.old_pem}
        self.write("etc/os-release", f'ID={self.profile[0]}\nVERSION_ID="{self.profile[1]}"\n')
        self.write("usr/share/webmin/virtual-server/module.info", "version=8.3.0\n")
        for name in self.protocol.CONFIG_PATHS:
            self.private(name, b"owned fixture " + name.encode())
        for name in self.protocol.NATIVE_FILES:
            for directory in ("usr/lib/praho/mail", "run/praho-mail-owner"):
                self.private(directory + "/" + name, (FILES / name).read_bytes())
        for unit in self.protocol.UNITS:
            self.private("etc/systemd/system/" + unit + ".d/praho-mail.conf", self.protocol.UNIT_GUARD)
        self.private(PEM, self.old_pem)
        self.private(KEY, self.old_key)
        self.ready = {
            "version": 1,
            "profile": self.profile[2],
            "node": NODE,
            "status": "ready",
            "files": {name: self.digest(name) for name in self.protocol.CONFIG_PATHS},
        }
        self.private("var/lib/praho/mail/node.json", json.dumps(self.ready).encode())
        for directory in ("var/lib/praho/mail", "run/praho-mail-owner", "usr/lib/praho/mail", "etc/praho-mail"):
            (self.root / directory).chmod(0o700)
        self.process(tick="4321")
        self.write("proc/sys/kernel/random/boot_id", "11111111-1111-4111-8111-111111111111\n")
        self.units = {unit["unit"]: ("inactive", "dead") for unit in self.topology}
        self.overrides = {}
        self.identity = str(uuid4())

    def write(self, relative, content):
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def private(self, relative, content):
        path = self.write(relative, content)
        path.chmod(0o600)
        return path

    def digest(self, name):
        return hashlib.sha256((self.root / name.lstrip("/")).read_bytes()).hexdigest()

    def process(self, *, tick):
        """A fresh worker process: its own start tick and fixed helper argv."""
        self.write("proc/self/stat", "4242 (python3) S " + " ".join(["0"] * 18 + [tick]))
        self.write("proc/self/cmdline", "python3\0" + HELPER + "\0")

    def driver(self, *, fd=7):
        node = self.module.MailNode(self.root, execute=self.execute, probe=self.probe, operation_fd=fd)
        node.public_ports = self.public_ports
        driver = node.setup_driver()
        driver.bundle = self.root / "run/praho-mail-owner"
        driver.certificate = Mock(return_value=(self.new_pem, self.new_key))
        driver._security_settings = Mock()
        return driver

    def journal(self):
        return json.loads((self.root / "var/lib/praho/mail/node.json").read_text())

    def operations(self):
        return self.root / "var/lib/praho/mail/certificate-operations"

    def tombstone(self, identity=None):
        return json.loads((self.operations() / ((identity or self.identity) + ".json")).read_text())

    def running(self):
        return all(self.units[unit["unit"]] == unit["started"] for unit in self.topology if unit["start"])

    def served(self):
        return (self.root / PEM.lstrip("/")).read_bytes()

    def probe(self, name):
        if not self.running():
            return []
        served = self.served()
        expiry = datetime.now(UTC) + (timedelta(days=-1) if served in self.expired else timedelta(days=20))
        return [
            {"service": service, "hostname": name, "sha256": leaf(served), "not_after": expiry.isoformat()}
            for service in ("imap", "pop3", "submission", "smtp")
        ]

    def public_ports(self):
        return [25, 465, 993, 995] if self.running() else []

    def show(self, name):
        unit = next(unit for unit in self.topology if unit["unit"] == name)
        guard = (
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/lib/praho/mail/praho-mail-boot.py ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        )
        values = {
            "Type": unit["type"],
            "ActiveState": self.units[name][0],
            "SubState": self.units[name][1],
            "UnitFileState": unit["file_state"],
            "LoadState": "loaded",
            "FragmentPath": unit["fragment"],
            "DropInPaths": unit["dropin"],
            "NeedDaemonReload": "no",
            "ExecStartPre": guard,
            **self.overrides.get(name, {}),
        }
        return "".join(key + "=" + value + "\n" for key, value in values.items())

    def openssl(self, argv):
        target = Path(argv[argv.index("-in") + 1]).read_bytes()
        if "-enddate" in argv:
            expiry = datetime.now(UTC) + (timedelta(days=-1) if target in self.expired else timedelta(days=20))
            return "notAfter=" + expiry.strftime("%b %d %H:%M:%S %Y GMT")
        if "-pubkey" in argv:
            return {self.old_pem: "public old", self.new_pem: "public new"}.get(target, "public unknown")
        return {self.old_key: "public old", self.new_key: "public new"}.get(target, "public other")

    @staticmethod
    def command_key(argv):
        return (argv[0], argv[3]) if argv[0] in {"iptables", "ip6tables"} else tuple(argv[:2])

    def execute(self, argv, **kwargs):
        self.commands.append(argv)
        hook = self.hooks.get(self.command_key(argv))
        if hook is not None:
            hook(argv)
        result = ""
        if argv == ["hostname", "-f"]:
            result = NODE + "\n"
        elif argv[:2] == ["systemctl", "show"]:
            result = self.show(argv[2])
        elif argv[:2] == ["systemctl", "stop"]:
            self.units.update(dict.fromkeys(argv[2:], ("inactive", "dead")))
        elif argv[:2] == ["systemctl", "start"]:
            self.units[argv[2]] = next(unit["started"] for unit in self.topology if unit["unit"] == argv[2])
        elif argv[0].endswith("-save"):
            result = self.firewall.save(argv[0].removesuffix("-save"))
        elif argv[0] in {"iptables", "ip6tables"}:
            self.firewall.apply(argv)
        elif argv[:2] == ["openssl", "verify"]:
            result = "OK\n"
        elif argv[0] == "openssl":
            result = self.openssl(argv)
        return result

    def crash_on(self, command, *, after=False, count=1):
        """Stop the worker at the count-th matching command, before (or after) it takes effect."""
        seen = []

        def hook(argv):
            seen.append(argv)
            if len(seen) == count and not after:
                raise Crash(" ".join(argv))

        self.hooks[command] = hook
        if after:
            original = self.execute

            def execute(argv, **kwargs):
                result = original(argv, **kwargs)
                if self.command_key(argv) == command and len(seen) == count:
                    self.hooks.pop(command)
                    raise Crash(" ".join(argv))
                return result

            return execute
        return None

    def recover(self, driver=None, identity=None):
        return (driver or self.driver()).reconcile_certificate(NODE, identity or self.identity)

    def guard_allows(self):
        guard = self.boot.MailBootGuard(
            self.root,
            execute=lambda argv: self.firewall.save(argv[0].removesuffix("-save")),
            configured=lambda marker: True,
        )
        self.private("proc/self/cgroup", "0::/system.slice/dovecot.service\n")
        return guard.allowed()

    def assert_recovered(self, result, outcome="recovered"):
        self.assertEqual(result["outcome"], outcome)
        self.assertEqual(result["certificate_sha256"], leaf(self.new_pem))
        self.assertEqual(self.journal()["status"], "ready")
        self.assertEqual(set(self.journal()), {"version", "node", "profile", "status", "files"})
        self.assertEqual(self.journal()["files"][PEM], hashlib.sha256(self.new_pem).hexdigest())
        self.assertEqual(self.journal()["files"][KEY], hashlib.sha256(self.new_key).hexdigest())
        self.assertEqual((self.root / KEY.lstrip("/")).read_bytes(), self.new_key)
        self.assertEqual(self.firewall.state(), {"iptables": (None, False), "ip6tables": (None, False)})
        self.assertEqual(self.tombstone()["status"], "completed")
        self.assertNotIn("fence_owner", self.tombstone())
        self.assertEqual(sorted(path.name for path in self.operations().iterdir()), [self.identity + ".json"])
        self.assertTrue(self.running())


class CertificateRecoveryTests(RecoveryFixture, SimpleTestCase):
    def test_expired_stopped_node_recovers_behind_the_fence_and_publishes_ready_only_after_proof(self):
        writes = []
        original = self.protocol.atomic
        driver = self.driver()

        def record(path, content, *args):
            if path.name == "node.json":
                state = json.loads(content)["status"]
                writes.append((state, self.running(), self.firewall.state()["iptables"][1]))
            original(path, content, *args)

        with patch.dict(driver.reconcile_certificate.__globals__, atomic=record):
            result = self.recover(driver)
        self.assert_recovered(result)
        self.assertEqual(
            writes,
            [("certificate_applying", False, False), ("certificate_starting", False, True), ("ready", True, True)],
        )
        starts = [argv[2] for argv in self.commands if argv[:2] == ["systemctl", "start"]]
        self.assertEqual(starts, ["postfix@-.service", "postfix.service", "dovecot.service"])
        fence = next(index for index, argv in enumerate(self.commands) if argv[0] == "iptables")
        first_start = next(index for index, argv in enumerate(self.commands) if argv[:2] == ["systemctl", "start"])
        self.assertLess(fence, first_start)
        returns = [argv for argv in self.commands if argv[0] in {"iptables", "ip6tables"} and "RETURN" in argv]
        self.assertEqual(len(returns), 2)
        self.assertFalse(any(argv[:2] == ["systemctl", "reload"] for argv in self.commands))

    def test_the_start_permit_is_bound_to_this_live_owner_and_its_held_lock(self):
        permits = []
        original = self.protocol.atomic
        driver = self.driver(fd=9)

        def record(path, content, *args):
            data = json.loads(content) if path.name == "node.json" else {}
            if data.get("status") == "certificate_starting":
                permits.append(data)
            original(path, content, *args)

        with patch.dict(driver.reconcile_certificate.__globals__, atomic=record):
            self.recover(driver)
        (starting,) = permits
        self.assertEqual(starting["fenced"], True)
        self.assertEqual(starting["files"], self.journal()["files"])
        permit = starting["start"]
        self.assertEqual(
            {key: permit[key] for key in ("pid", "start_tick", "boot_id", "lock_fd", "helper_path", "action")},
            {
                "pid": os.getpid(),
                "start_tick": "4321",
                "boot_id": "11111111-1111-4111-8111-111111111111",
                "lock_fd": 9,
                "helper_path": HELPER,
                "action": "reconcile_node_certificate",
            },
        )
        self.assertAlmostEqual(permit["expires_at"] - permit["issued_at"], 120)

    def test_a_worker_without_its_lock_or_fixed_helper_path_cannot_issue_a_permit(self):
        for case in ("lock", "helper"):
            with self.subTest(case=case):
                self.setUp()
                if case == "helper":
                    self.write("proc/self/cmdline", "python3\0/tmp/praho-mail.py\0")
                driver = self.driver(fd=None if case == "lock" else 7)
                with self.assertRaisesRegex(self.module.MailError, "mail_native_inspection_failed"):
                    self.recover(driver)
                self.assertEqual(self.journal()["status"], "certificate_applying")
                self.assertFalse(any(argv[:2] == ["systemctl", "start"] for argv in self.commands))
                self.assertFalse(self.guard_allows())

    def test_ubuntu_starts_only_postfix_and_dovecot_never_its_disabled_instance(self):
        self.profile = ("ubuntu", "26.04", "ubuntu2604-dovecot24")
        self.setUp()
        self.assert_recovered(self.recover())
        starts = [argv[2] for argv in self.commands if argv[:2] == ["systemctl", "start"]]
        self.assertEqual(starts, ["postfix.service", "dovecot.service"])
        self.assertNotIn(
            "postfix@-.service", [argv[-1] for argv in self.commands if argv[:2] == ["systemctl", "start"]]
        )

    def test_routine_reload_still_serves_a_running_node_without_a_fence_or_a_permit(self):
        self.units = {unit["unit"]: unit["started"] for unit in self.topology}
        driver = self.driver()
        result = self.recover(driver)
        self.assertEqual(result["outcome"], "replaced")
        self.assertIn(["systemctl", "reload", "dovecot"], self.commands)
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables"} for argv in self.commands))
        self.assertFalse(any(argv[:2] in (["systemctl", "start"], ["systemctl", "stop"]) for argv in self.commands))

    def assert_refused_without_mutation(self, code, driver=None):
        journal = (self.root / "var/lib/praho/mail/node.json").read_bytes()
        with self.assertRaisesRegex(self.module.MailError, code):
            self.recover(driver)
        self.assertEqual((self.root / "var/lib/praho/mail/node.json").read_bytes(), journal)
        self.assertFalse(self.operations().exists() and any(self.operations().iterdir()))
        self.assertFalse(
            any(
                argv[0] in {"iptables", "ip6tables"} or argv[:2] in (["systemctl", "start"], ["systemctl", "stop"])
                for argv in self.commands
            )
        )
        self.assertEqual((self.root / PEM.lstrip("/")).read_bytes(), self.old_pem)

    def test_unexpired_or_partly_running_units_are_refused_with_a_byte_identical_journal(self):
        for case in ("unexpired", "mixed"):
            with self.subTest(case=case):
                self.setUp()
                if case == "unexpired":
                    self.expired = set()
                else:
                    self.units["dovecot.service"] = ("active", "running")
                self.assert_refused_without_mutation("mail_node_services_unavailable")

    def test_an_untrusted_candidate_leaves_the_expired_node_unchanged_with_a_retriable_code(self):
        driver = self.driver()
        driver.certificate.side_effect = self.module.MailError("mail_node_certificate_unproven")
        self.assert_refused_without_mutation("mail_node_certificate_unproven", driver)
        self.assertEqual(driver.node.stage, "certificate_candidate")

    def test_an_outdated_installed_bundle_must_be_upgraded_before_recovery(self):
        self.private("run/praho-mail-owner/praho-mail-boot.py", b"a newer running guard")
        self.assert_refused_without_mutation("mail_node_bundle_upgrade_required")

    def test_another_operation_in_flight_is_refused_as_retriable_without_mutation(self):
        other = str(uuid4())
        self.crash_on(("systemctl", "stop"))
        with self.assertRaises(Crash):
            self.recover(identity=other)
        self.commands.clear()
        journal = (self.root / "var/lib/praho/mail/node.json").read_bytes()
        with self.assertRaisesRegex(self.module.MailError, "mail_node_operation_in_progress"):
            self.recover()
        self.assertEqual((self.root / "var/lib/praho/mail/node.json").read_bytes(), journal)
        self.assertFalse((self.operations() / (self.identity + ".json")).exists())
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables", "systemctl"} for argv in self.commands))

    def test_an_old_completed_delivery_on_an_expired_stopped_node_is_verification_only(self):
        self.units = {unit["unit"]: unit["started"] for unit in self.topology}
        self.expired = set()
        self.assertEqual(self.recover(self.driver())["outcome"], "replaced")  # routine, completed tombstone
        journal = (self.root / "var/lib/praho/mail/node.json").read_bytes()
        tombstone = (self.operations() / (self.identity + ".json")).read_bytes()
        # Much later the delivered leaf has expired and the units are stopped.
        self.expired = {self.new_pem}
        self.units = {unit["unit"]: ("failed", "failed") for unit in self.topology}
        self.commands.clear()
        with self.assertRaisesRegex(self.module.MailError, "mail_node_certificate_unproven"):
            self.recover()
        self.assertEqual((self.operations() / (self.identity + ".json")).read_bytes(), tombstone)
        self.assertEqual((self.root / "var/lib/praho/mail/node.json").read_bytes(), journal)
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables", "systemctl"} for argv in self.commands))

    def test_a_review_journal_is_never_resumed_or_recovered(self):
        self.private(
            "var/lib/praho/mail/node.json",
            json.dumps({**self.ready, "status": "review_required"}).encode(),
        )
        with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
            self.recover()
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables", "systemctl"} for argv in self.commands))

    def test_handled_start_failure_revokes_the_permit_before_stopping_and_stays_resumable(self):
        events = []
        original = self.protocol.atomic
        driver = self.driver()

        def record(path, content, *args):
            if path.name == "node.json":
                events.append(("journal", json.loads(content)["status"]))
            original(path, content, *args)

        def refuse(argv):
            if argv[2] == "postfix.service":
                raise self.module.MailError("mail_native_inspection_failed")

        self.hooks[("systemctl", "start")] = refuse
        self.hooks[("systemctl", "stop")] = lambda argv: events.append(("stop", None))
        with (
            patch.dict(driver.reconcile_certificate.__globals__, atomic=record),
            self.assertRaisesRegex(self.module.MailError, "mail_native_inspection_failed"),
        ):
            self.recover(driver)
        failure = events.index(("journal", "certificate_starting"))
        self.assertEqual(events[failure + 1 :], [("journal", "certificate_applying"), ("stop", None)])
        self.assertEqual(self.journal()["status"], "certificate_applying")
        self.assertFalse(any(state[0] == "active" for state in self.units.values()))
        self.assertEqual(self.firewall.state()["iptables"][1], True)
        self.assertFalse(self.guard_allows())
        self.hooks.clear()
        self.process(tick="5555")
        self.assert_recovered(self.recover(self.driver(fd=8)))

    def test_a_unit_is_never_started_with_less_permit_time_than_the_guard_needs(self):
        driver = self.driver()
        clock = Mock()
        clock.monotonic = Mock(side_effect=[1000.0, 1000.0, 1101.0, 2000.0, 2000.0, 2000.0])
        clock.sleep = Mock()
        with (
            patch.dict(driver.reconcile_certificate.__globals__, time=clock),
            self.assertRaisesRegex(self.module.MailError, "mail_node_certificate_unproven"),
        ):
            self.recover(driver)
        starts = [argv[2] for argv in self.commands if argv[:2] == ["systemctl", "start"]]
        self.assertEqual(starts, ["postfix@-.service"])
        self.assertEqual(self.journal()["status"], "certificate_applying")


class CertificateResumeTests(RecoveryFixture, SimpleTestCase):
    """Each crash point leaves a state the guard refuses or a resumable one; a same-UUID replay completes."""

    def crash_at_write(self, target):
        original = self.protocol.atomic
        fired = []

        def write(path, content, *args):
            original(path, content, *args)
            name = path.name
            status = json.loads(content).get("status") if name.endswith(".json") else None
            point = {
                ("node.json", "certificate_applying"): "applying",
                ("node.json", "certificate_starting"): "starting",
                ("node.json", "ready"): "ready",
                (self.identity + ".json", "applying"): "tombstone",
            }.get((name, status))
            if name == self.identity + ".json" and status == "completed":
                point = "completed" if json.loads(content).get("fence_owner") else "marker_cleared"
            if name in {"node.pem", "node.key"} and path.parent.name == "praho-mail":
                point = name
            if point == target and not fired:
                fired.append(point)
                raise Crash(target)

        return write

    def crash(self, target):
        driver = self.driver()
        if target.startswith(("systemctl", "iptables", "ip6tables")):
            program, verb, *rest = target.split()
            execute = self.crash_on((program, verb), after="after" in rest, count=int(rest[-1]) if rest else 1)
            if execute is not None:
                driver.execute = execute
            with self.assertRaises(Crash):
                self.recover(driver)
            self.hooks.clear()
            return
        with (
            patch.dict(driver.reconcile_certificate.__globals__, atomic=self.crash_at_write(target)),
            self.assertRaises(Crash),
        ):
            self.recover(driver)

    def resume(self, *, outcome="recovered"):
        self.process(tick="9999")
        result = self.recover(self.driver(fd=11))
        self.assert_recovered(result, outcome)
        return result

    def test_every_crash_point_before_commit_leaves_a_refused_state_that_resumes(self):
        for point in (
            "applying",
            "tombstone",
            "systemctl stop",
            "node.pem",
            "node.key",
            "starting",
            "systemctl start after 1",
            "systemctl start after 3",
        ):
            with self.subTest(point=point):
                self.setUp()
                self.crash(point)
                self.assertNotEqual(self.journal()["status"], "ready")
                self.assertFalse(self.guard_allows())
                self.resume()

    def test_a_crash_after_staging_but_before_the_journal_leaves_no_intent(self):
        original = self.protocol.atomic
        driver = self.driver()

        def write(path, content, *args):
            if path.name == "node.json":
                raise Crash("before journal")
            original(path, content, *args)

        with patch.dict(driver.reconcile_certificate.__globals__, atomic=write), self.assertRaises(Crash):
            self.recover(driver)
        self.assertEqual(self.journal(), self.ready)
        self.assertEqual([path.name.startswith(".") for path in self.operations().iterdir()], [True])
        self.resume()

    def test_a_crash_after_the_pem_but_before_the_key_finishes_the_key_swap(self):
        self.crash("node.pem")
        self.assertEqual((self.root / PEM.lstrip("/")).read_bytes(), self.new_pem)
        self.assertEqual((self.root / KEY.lstrip("/")).read_bytes(), self.old_key)
        self.resume()
        self.assertEqual(
            [argv for argv in self.commands if argv[:2] == ["openssl", "pkey"]][-1][-2:],
            [str(self.root / KEY.lstrip("/")), "-pubout"],
        )

    def test_owner_death_after_approval_keeps_admitted_daemons_fenced_and_resume_publishes(self):
        self.crash("systemctl start after 1")
        self.assertEqual(self.units["postfix@-.service"], ("active", "running"))
        self.assertEqual(self.firewall.state()["iptables"][1], True)
        self.assertEqual(self.journal()["status"], "certificate_starting")
        self.assertFalse(self.guard_allows())
        self.commands.clear()
        self.resume()
        # The admitted daemon is stopped, still behind the fence, before any fresh start.
        systemctl = [argv[1] for argv in self.commands if argv[:1] == ["systemctl"] and argv[1] in {"stop", "start"}]
        self.assertEqual(systemctl[0], "stop")

    def test_a_restart_that_drops_the_live_fence_and_the_owner_resumes_with_a_new_fence_and_permit(self):
        self.crash("starting")
        first = self.journal()["start"]
        self.firewall = FakeFirewall()
        self.units = {unit["unit"]: ("failed", "failed") for unit in self.topology}
        self.assertFalse(self.guard_allows())
        permits = []
        original = self.protocol.atomic
        self.process(tick="7777")
        driver = self.driver(fd=12)

        writes = []

        def record(path, content, *args):
            data = json.loads(content) if path.name == "node.json" else {}
            writes.append(data.get("status"))
            if data.get("status") == "certificate_starting":
                permits.append(data["start"])
            original(path, content, *args)

        with patch.dict(driver.reconcile_certificate.__globals__, atomic=record):
            self.assert_recovered(self.recover(driver))
        # The dead owner's permit is revoked before anything else is written.
        self.assertEqual(writes[0], "certificate_applying")
        (permit,) = permits
        self.assertEqual((permit["start_tick"], permit["lock_fd"]), ("7777", 12))
        self.assertGreater(permit["issued_at"], first["issued_at"])

    def test_a_crash_after_commit_finalizes_without_restarting_anything(self):
        for point in ("ready", "completed", "iptables -D", "ip6tables -D", "marker_cleared"):
            with self.subTest(point=point):
                self.setUp()
                self.crash(point)
                self.assertEqual(self.journal()["status"], "ready")
                self.commands.clear()
                self.resume(outcome="unchanged" if point == "marker_cleared" else "recovered")
                self.assertFalse(
                    any(argv[:2] in (["systemctl", "start"], ["systemctl", "stop"]) for argv in self.commands)
                )
                self.assertFalse(any(argv[0] == "openssl" and "verify" in argv for argv in self.commands))

    def test_a_stale_completed_identity_never_removes_a_later_operations_fence(self):
        self.crash("completed")
        later = str(uuid4())
        with self.assertRaisesRegex(self.module.MailError, "mail_node_operation_in_progress"):
            self.recover(identity=later)
        self.assertEqual(self.firewall.state()["iptables"][1], True)
        self.resume()
        self.commands.clear()
        self.assertEqual(self.recover()["outcome"], "unchanged")
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables"} for argv in self.commands))

    def test_digest_mismatch_foreign_fence_or_unit_outside_topology_refuses_resume_without_mutation(self):
        for case in ("stage", "installed", "fence", "unit"):
            with self.subTest(case=case):
                self.setUp()
                self.crash("node.pem")
                stage = self.operations() / (self.identity + ".stage")
                if case == "stage":
                    self.private(str(stage.relative_to(self.root)) + "/new.key", b"another key")
                elif case == "installed":
                    self.private(KEY, b"operator key")
                elif case == "fence":
                    self.firewall.chains["ip6tables"].append("-A " + CHAIN + " -s 192.0.2.1 -j ACCEPT")
                else:
                    self.overrides["postfix.service"] = {"LoadState": "masked", "UnitFileState": "masked"}
                snapshot = (
                    self.journal(),
                    self.tombstone(),
                    (self.root / PEM.lstrip("/")).read_bytes(),
                    (self.root / KEY.lstrip("/")).read_bytes(),
                    self.firewall.save("iptables"),
                    self.firewall.save("ip6tables"),
                )
                self.commands.clear()
                with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
                    self.recover(self.driver(fd=11))
                self.assertEqual(
                    snapshot,
                    (
                        self.journal(),
                        self.tombstone(),
                        (self.root / PEM.lstrip("/")).read_bytes(),
                        (self.root / KEY.lstrip("/")).read_bytes(),
                        self.firewall.save("iptables"),
                        self.firewall.save("ip6tables"),
                    ),
                )
                self.assertFalse(
                    any(
                        argv[0] in {"iptables", "ip6tables"}
                        or argv[:2] in (["systemctl", "start"], ["systemctl", "stop"])
                        for argv in self.commands
                    )
                )

    def completed_before_ready(self, *, starting=False):
        """The state today's routine ordering leaves when the worker dies between its two writes."""
        before = json.dumps(self.ready, sort_keys=True).encode()
        record = {
            "version": 1,
            "node": NODE,
            "profile": self.profile[2],
            "identity": self.identity,
            "status": "certificate_applying",
            "old_certificate_sha256": leaf(self.old_pem),
            "new_certificate_sha256": leaf(self.new_pem),
            "before_sha256": hashlib.sha256(before).hexdigest(),
        }
        stage = "var/lib/praho/mail/certificate-operations/" + self.identity + ".stage"
        for name, content in {
            "before.json": before,
            "old.pem": self.old_pem,
            "old.key": self.old_key,
            "new.pem": self.new_pem,
            "new.key": self.new_key,
        }.items():
            self.private(stage + "/" + name, content)
        for directory in ("var/lib/praho/mail/certificate-operations", stage):
            (self.root / directory).chmod(0o700)
        self.private(PEM, self.new_pem)
        self.private(KEY, self.new_key)
        self.private(
            "var/lib/praho/mail/certificate-operations/" + self.identity + ".json",
            json.dumps({**record, "status": "completed"}).encode(),
        )
        if starting:
            record = {
                **record,
                "new_pem_sha256": hashlib.sha256(self.new_pem).hexdigest(),
                "new_key_sha256": hashlib.sha256(self.new_key).hexdigest(),
                "status": "certificate_starting",
                "fenced": True,
                "files": {**self.ready["files"], PEM: self.digest(PEM), KEY: self.digest(KEY)},
                "start": {"pid": 2, "start_tick": "1"},
            }
            self.driver().ensure_certificate_fence()
        self.private("var/lib/praho/mail/node.json", json.dumps(record).encode())
        self.units = {unit["unit"]: unit["started"] for unit in self.topology}

    def test_todays_completed_before_ready_ordering_rolls_forward_without_touching_certificates(self):
        self.completed_before_ready()
        result = self.recover()
        self.assertEqual(result["outcome"], "unchanged")
        self.assertEqual(self.journal()["status"], "ready")
        self.assertEqual(self.journal()["files"][PEM], hashlib.sha256(self.new_pem).hexdigest())
        self.assertEqual(self.journal()["files"][KEY], hashlib.sha256(self.new_key).hexdigest())
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables", "systemctl"} for argv in self.commands))
        self.assertFalse(any(argv[0] == "openssl" for argv in self.commands))
        self.assertFalse((self.operations() / (self.identity + ".stage")).exists())

    def test_a_completed_starting_record_rolls_forward_and_removes_only_its_own_fence(self):
        self.completed_before_ready(starting=True)
        self.commands.clear()
        self.assertEqual(self.recover()["outcome"], "unchanged")
        self.assertEqual(self.journal()["status"], "ready")
        self.assertEqual(self.firewall.state(), {"iptables": (None, False), "ip6tables": (None, False)})
        self.assertFalse(any(argv[:2] in (["systemctl", "start"], ["systemctl", "stop"]) for argv in self.commands))
