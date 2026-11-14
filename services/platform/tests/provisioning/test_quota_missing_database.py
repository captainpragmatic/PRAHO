"""A database Virtualmin still registers but MariaDB dropped is a known state, never a wedged quota lane (#776).

Only an exact-name SCHEMATA query, answered by a server that can see the `mysql` schema, proves a database
missing. Anything else is unknown, and the quota lane refuses by name before it records any running work.
"""

import importlib.util
import json
import stat
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, FILES / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SchemaPresenceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.native = _load("missing_database_native", "praho_quota_native.py")

    def presence(self, answer):
        run = Mock(return_value=answer) if not isinstance(answer, BaseException) else Mock(side_effect=answer)
        return self.native.schema_presence("tenant_db", run=run), run

    def test_a_visible_server_with_no_such_schema_proves_it_missing(self):
        present, run = self.presence("1\t0")
        self.assertIs(present, False)
        query = run.call_args.args[0][-1]
        # An exact, case-sensitive name, with the server's own `mysql` schema as the visibility control.
        self.assertIn("SCHEMA_NAME = BINARY 'mysql'", query)
        self.assertIn("SCHEMA_NAME = BINARY 'tenant_db'", query)
        self.assertEqual(run.call_args.args[0][:2], ["/usr/bin/mariadb", "--protocol=socket"])

    def test_a_schema_the_server_still_has_is_present(self):
        self.assertIs(self.presence("1\t1")[0], True)

    def test_anything_but_a_visible_exact_answer_is_unknown(self):
        # "0\t0": the asking identity cannot see `mysql`, so an empty answer proves nothing.
        for answer in ("0\t0", "0\t1", "", "1", "1\t2", "1\t0\textra", "1 0", "NULL\t0"):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                self.presence(answer)

    def test_a_failed_or_timed_out_query_is_unknown(self):
        for error in (ValueError("exit 1"), subprocess.TimeoutExpired("mariadb", 5), OSError("no socket")):
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaises((ValueError, OSError, subprocess.SubprocessError)),
            ):
                self.presence(error)

    def test_an_unsupported_name_is_never_queried(self):
        run = Mock(return_value="1\t0")
        for name in ("", "a" * 65, "x'; DROP DATABASE y; --", "has space", "dash-name"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.native.schema_presence(name, run=run)
        run.assert_not_called()


class RegisteredDatabaseQualificationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.native = _load("registered_database_native", "praho_quota_native.py")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.datadir = Path(directory.name).resolve()
        info = self.datadir.stat()  # A temp directory's group comes from its parent on macOS.
        self.writer = (info.st_uid, info.st_gid)
        self.tenant = (info.st_uid + 1, info.st_gid + 1)
        self.device = self.datadir.stat().st_dev
        self.presence = Mock(return_value=False)

    def make(self, name):
        path = self.datadir / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)  # No setgid inherited from a parent temp directory.
        return path

    def qualify(self, names):
        return self.native.qualify_registered_databases(
            names,
            self.datadir,
            writer=self.writer,
            tenant=self.tenant,
            device=self.device,
            presence=self.presence,
            inventory=lambda _name: [],
        )

    def test_a_present_database_is_qualified_without_asking_mariadb(self):
        self.make("shop")
        qualified, missing = self.qualify(["shop"])
        self.assertEqual(qualified, (self.datadir / "shop",))
        self.assertEqual(missing, ())
        self.presence.assert_not_called()

    def test_a_proven_missing_database_is_skipped_and_reported(self):
        self.make("shop")
        qualified, missing = self.qualify(["shop", "dropped"])
        self.assertEqual(qualified, (self.datadir / "shop",))
        self.assertEqual(missing, ("dropped",))
        self.presence.assert_called_once_with("dropped")

    def test_a_database_mariadb_still_has_without_a_directory_is_refused_by_name(self):
        self.presence.return_value = True
        with self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database dropped: .*still"):
            self.qualify(["dropped"])

    def test_an_unknown_answer_is_refused_by_name(self):
        for error in (ValueError("no visibility"), OSError("socket"), subprocess.TimeoutExpired("mariadb", 5)):
            self.presence.side_effect = error
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database dropped: .*could not"),
            ):
                self.qualify(["dropped"])

    def test_a_dangling_link_is_not_absent(self):
        # Only a path with nothing there is asked about: a link the tenant planted stays a refusal.
        (self.datadir / "dropped").symlink_to(self.datadir / "nowhere")
        with self.assertRaises(self.native.DatabaseStorageRefusalError):
            self.qualify(["dropped"])
        self.presence.assert_not_called()

    def test_every_call_decides_again_when_a_database_is_dropped_then_recreated(self):
        self.assertEqual(self.qualify(["shop"]), ((), ("shop",)))
        self.make("shop")
        self.assertEqual(self.qualify(["shop"]), ((self.datadir / "shop",), ()))
        (self.datadir / "shop").rmdir()
        self.presence.return_value = True  # Recreated in MariaDB, its directory not there yet.
        with self.assertRaises(self.native.DatabaseStorageRefusalError):
            self.qualify(["shop"])

    def test_a_database_that_vanishes_while_it_is_qualified_is_a_named_refusal(self):
        self.make("shop")
        with (
            patch.object(self.native, "qualify_database_directory", side_effect=FileNotFoundError("gone")),
            self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database shop: .*changed"),
        ):
            self.qualify(["shop"])

    def test_names_and_counts_keep_their_bounds(self):
        with self.assertRaises(ValueError):
            self.qualify(["bad name"])
        with self.assertRaises(ValueError):
            self.qualify([f"db{number}" for number in range(self.native.MAX_DATABASES + 1)])

    def test_the_storage_check_uses_the_existence_aware_qualification(self):
        source = (FILES / "praho_quota_native.py").read_text()
        storage = source[source.index("    def _storage(") : source.index("    def probe(")]
        self.assertIn("qualify_registered_databases(", storage)
        self.assertNotIn("qualify_database_directory(", storage)


class LaneRefusalTests(SimpleTestCase):
    """The lane qualifies storage before it records `running`, and a named refusal is terminal, not uncertain."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.module = _load("refusal_quota_coordinator", "praho_quota.py")
        cls.native = _load("refusal_quota_native", "praho_quota_native.py")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.identity = {"installation": str(uuid4()), "domain_id": "12345"}
        self.request = {
            "token": str(uuid4()),
            "generation": 1,
            "identity": self.identity,
            "disk_limit_kib": 5767168,
            "bandwidth_limit_bytes": 20 * 1024**3,
        }
        self.backend = Mock()
        self.backend.probe.return_value = {"identity": self.identity, "uid_hard_kib": 5767168}
        self.refusal = self.native.DatabaseStorageRefusalError("Database shop: MariaDB still has it")

    def perform(self, request=None):
        return self.module.QuotaCoordinator(self.root, self.backend).perform("apply", request or self.request)

    def state(self):
        path = self.root / self.identity["installation"] / self.identity["domain_id"] / "current.json"
        return json.loads(path.read_text())

    def test_a_storage_refusal_before_running_is_recorded_as_refused(self):
        self.backend.qualify_storage.side_effect = self.refusal
        receipt = self.perform()
        self.assertEqual(
            receipt,
            {
                "outcome": "refused",
                "token": self.request["token"],
                "generation": 1,
                "refusal": "Database shop: MariaDB still has it",
            },
        )
        self.backend.apply.assert_not_called()
        self.assertEqual(self.state()["phase"], "refused")

    def test_the_storage_check_runs_before_running_is_recorded(self):
        phases = []

        def observe(_request):
            path = self.root / self.identity["installation"] / self.identity["domain_id"] / "current.json"
            phases.append(json.loads(path.read_text())["phase"] if path.exists() else None)

        self.backend.qualify_storage.side_effect = observe
        self.perform()
        self.assertEqual(phases, [None])
        self.assertEqual(self.state()["phase"], "completed")

    def test_a_refused_application_replays_its_refusal_and_never_applies(self):
        self.backend.qualify_storage.side_effect = self.refusal
        first = self.perform()
        self.backend.qualify_storage.side_effect = None
        self.assertEqual(self.perform(), first)
        self.backend.apply.assert_not_called()

    def test_refused_is_terminal_so_the_next_generation_runs(self):
        self.backend.qualify_storage.side_effect = self.refusal
        self.perform()
        self.backend.qualify_storage.side_effect = None
        receipt = self.perform({**self.request, "token": str(uuid4()), "generation": 2})
        self.backend.apply.assert_called_once()
        self.assertEqual(receipt["generation"], 2)
        self.assertEqual(self.state()["phase"], "completed")

    def test_a_refusal_after_a_verified_restore_is_refused(self):
        self.backend.apply.side_effect = self.refusal
        self.assertEqual(self.perform()["outcome"], "refused")
        self.assertEqual(self.state()["phase"], "refused")

    def test_any_other_failure_stays_uncertain(self):
        self.backend.apply.side_effect = ValueError("restore could not be verified")
        with self.assertRaises(ValueError):
            self.perform()
        self.assertEqual(self.state()["phase"], "running")
        self.backend.apply.side_effect = None
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.perform()

    def test_the_backend_journals_the_metadata_change_in_the_lane_scope(self):
        self.perform()
        journal = self.backend.apply.call_args.kwargs["journal"]
        self.assertEqual(
            journal, self.root / self.identity["installation"] / "12345" / f"metadata-{self.request['token']}.json"
        )


class MetadataRestoreTests(SimpleTestCase):
    """After the Perl child changed metadata, a late storage refusal restores and verifies it, or stays uncertain."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.native = _load("restore_quota_native", "praho_quota_native.py")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.journal = self.root / "metadata.json"
        self.identity = {
            "installation": str(uuid4()),
            "domain_id": "12345",
            "domain": "shop.test",
            "uid": 1001,
            "gid": 1001,
            "filesystem_uuid": str(uuid4()),
            "boot_id": str(uuid4()),
        }
        self.request = {
            "token": str(uuid4()),
            "generation": 1,
            "identity": self.identity,
            "disk_limit_kib": 1024,
            "bandwidth_limit_bytes": 0,
        }
        self.before = {
            "quota": "2048",
            "uquota": "2048",
            "bw_limit": None,
            "bw_no_disable": "1",
            "letsencrypt_email": "2",
        }
        self.domain_file = {
            "id": "12345",
            "dom": "shop.test",
            **{k: v for k, v in self.before.items() if v is not None},
        }
        # What the child reports it saw and left under Virtualmin's domain lock. The certificate address differs
        # from the earlier unlocked read on purpose: the restore must use the locked image, not the earlier one.
        self.seen = {**self.before, "letsencrypt_email": "owner@shop.test"}
        self.left = {"quota": "1024", "uquota": "1024", "bw_limit": "0", "bw_no_disable": "1", "letsencrypt_email": "2"}
        self.output = (
            "PRAHO_QUOTA_METADATA " + json.dumps({"before": self.seen, "after": self.left}) + "\nQuota metadata persisted"
        )
        with patch.object(self.native.os, "geteuid", return_value=0):
            self.backend = self.native.NativeQuotaBackend()
        self.account = Mock(pw_uid=1001, pw_gid=1001)
        self.calls = []
        self.journal_at_child = None

    def apply(self, *, second_storage, restored=None):
        """Run _apply with every native seam doubled; returns what the child was asked to do."""

        # probe is doubled, so _storage runs once: the re-check after the child changed metadata.
        def storage(*_args):
            if isinstance(second_storage, BaseException):
                raise second_storage
            return second_storage

        restored_file = {"id": "12345", "dom": "shop.test", **{k: v for k, v in self.seen.items() if v is not None}}
        reads = iter([dict(self.domain_file), dict(restored if restored is not None else restored_file)])

        def child(arguments, **kwargs):
            kind = arguments[-1] if arguments[-1] == "restore" else "apply"
            if kind == "apply":
                # The durable pre-image must exist before the child may change anything.
                self.journal_at_child = json.loads(self.journal.read_text()) if self.journal.exists() else None
            self.calls.append((kind, json.loads(kwargs["payload"])))
            return self.output if kind == "apply" else "Quota metadata restored"

        with (
            patch.object(
                self.backend,
                "probe",
                return_value={"uid_used_bytes": 0, "gid_used_bytes": 0, "observation": {"files_bytes": 0}},
            ),
            patch.object(self.backend, "_domain", return_value=({"id": "12345", "dom": "shop.test"}, self.account)),
            patch.object(self.backend, "_storage", side_effect=storage),
            patch.object(self.native, "_fields", side_effect=lambda _path: next(reads)),
            patch.object(self.native, "_run", side_effect=child),
            patch.object(self.native, "_set_kernel_quota") as kernel,
        ):
            try:
                self.backend._apply(self.request, lock_fd=7, journal=self.journal)
            finally:
                self.kernel = kernel

    def test_the_metadata_before_image_is_journalled_durably_before_the_child_runs(self):
        self.apply(second_storage=("/dev/sda1", self.identity["filesystem_uuid"]))
        self.assertEqual(self.journal_at_child, {"before": self.before, "phase": "changing"})
        # Then the images the child saw and left under the domain lock replace the unlocked read.
        self.assertEqual(json.loads(self.journal.read_text()), {"before": self.seen, "after": self.left, "phase": "changed"})
        self.assertEqual(stat.S_IMODE(self.journal.stat().st_mode), 0o600)
        self.assertEqual([kind for kind, _ in self.calls], ["apply"])
        self.assertEqual(self.kernel.call_count, 2)

    def test_a_late_refusal_restores_the_journalled_metadata_then_refuses(self):
        refusal = self.native.DatabaseStorageRefusalError("Database shop: changed")
        with self.assertRaises(self.native.DatabaseStorageRefusalError):
            self.apply(second_storage=refusal)
        self.assertEqual([kind for kind, _ in self.calls], ["apply", "restore"])
        restore = self.calls[1][1]
        self.assertEqual(restore["restore"], self.seen)
        self.assertEqual(restore["expected"], self.left)
        self.assertEqual(restore["request"], self.request)
        self.kernel.assert_not_called()
        self.assertEqual(json.loads(self.journal.read_text())["phase"], "restored")

    def test_an_unverified_restore_stays_uncertain(self):
        refusal = self.native.DatabaseStorageRefusalError("Database shop: changed")
        drifted = {**self.domain_file, "quota": "1024"}
        with self.assertRaises(ValueError) as caught:
            self.apply(second_storage=refusal, restored=drifted)
        self.assertNotIsInstance(caught.exception, self.native.DatabaseStorageRefusalError)
        self.kernel.assert_not_called()

    def test_a_refusal_before_the_child_needs_no_restore(self):
        refusal = self.native.DatabaseStorageRefusalError("Database shop: changed")
        with (
            patch.object(self.backend, "probe", side_effect=refusal),
            patch.object(self.native, "_run") as child,
            self.assertRaises(self.native.DatabaseStorageRefusalError),
        ):
            self.backend._apply(self.request, lock_fd=7, journal=self.journal)
        child.assert_not_called()
        self.assertFalse(self.journal.exists())

    def test_any_other_late_failure_is_not_restored_and_stays_uncertain(self):
        with self.assertRaises(ValueError) as caught:
            self.apply(second_storage=ValueError("The native quota owner or filesystem changed"))
        self.assertNotIsInstance(caught.exception, self.native.DatabaseStorageRefusalError)
        self.assertEqual([kind for kind, _ in self.calls], ["apply"])

    def test_a_child_that_does_not_report_its_images_cannot_be_restored_so_it_stays_uncertain(self):
        refusal = self.native.DatabaseStorageRefusalError("Database shop: changed")
        for output in (
            "Quota metadata persisted",
            "PRAHO_QUOTA_METADATA {}\nQuota metadata persisted",
            "PRAHO_QUOTA_METADATA " + json.dumps({"before": self.seen, "after": {"quota": "1"}}),
            "PRAHO_QUOTA_METADATA " + json.dumps({"before": self.seen, "after": {**self.left, "quota": 1024}}),
            self.output + "\n" + self.output,
        ):
            with self.subTest(output=output[:60]):
                self.output, self.calls = output, []
                with self.assertRaises(ValueError) as caught:
                    self.apply(second_storage=refusal)
                self.assertNotIsInstance(caught.exception, self.native.DatabaseStorageRefusalError)
                self.assertEqual([kind for kind, _ in self.calls], ["apply"])
                self.kernel.assert_not_called()
