"""Committed source cleanup preserves current retained services and parks uncertain writes."""

import hashlib
import importlib.util
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_database_fence import FenceSQLFixture


class ComponentSourceRetirementTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-retire.py"
        spec = importlib.util.spec_from_file_location("component_source_retire", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.operation, self.boot = str(uuid4()), str(uuid4())
        self.context = {
            "manifest": {
                "source": {
                    "domain_id": "123456789",
                    "domain": "example.test",
                    "owner": "customer",
                    "home": "/home/customer",
                },
                "paths": [{"relative": "public_html"}],
                "databases": [],
            },
            "retained_digest": "old-precommit-authentication",
            "uid": 1234,
            "web_sha256": "a" * 64,
        }
        self.events = []
        self.steps = {name: MagicMock() for name in ("web", "cron", "database", "paths")}
        for name, step in self.steps.items():
            step.verify.side_effect = lambda name=name: self.events.append("verify:" + name)
        self.steps["paths"].release.side_effect = lambda: self.events.append("release:paths")
        self.steps["cron"].retire.side_effect = lambda: self.events.append("retire:cron")
        self.steps["web"].retire_after_web_absence.side_effect = lambda _sha: self.events.append("retire:ingress")
        # A retired fixture database: no selected schema or principal is left for the post-condition check.
        self.steps["database"].selected, self.steps["database"].principals = (), ()
        coordinator = self.module.native.coordinator.SourceCoordinator(
            "123456789",
            self.operation,
            "b" * 64,
            preflight=lambda: self.context,
            build=lambda _context: self.steps,
            retained=MagicMock(side_effect=ValueError("Old source mail password has legitimately rotated")),
            state_dir=self.directory,
            boot_id=self.boot,
        )
        with coordinator.journal.locked():
            coordinator.journal.create(
                {
                    "policy": self.module.native.coordinator.POLICY,
                    "phase": "committed",
                    "context": self.context,
                    "applied": ["web", "cron", "database", "paths"],
                    "pending": None,
                    "commit": {"archive_sha256": "c" * 64, "target_receipt_sha256": "d" * 64},
                }
            )
        self.source = SimpleNamespace(
            coordinator=coordinator,
            build=lambda _context: self.steps,
            request={"domain_id": "123456789"},
            operation=self.operation,
            authority="b" * 64,
        )
        self.current_retained = "current-source-mail-password-and-dns"
        self.enterContext(patch.object(self.module, "_retained", side_effect=lambda *_args: self.current_retained))
        self.web = self.enterContext(
            patch.object(
                self.module, "_retire_web", side_effect=lambda *_args: self.events.append("retire:web") or "e" * 64
            )
        )
        self.database_retirement = self.module._retire_database
        self.sql = self.enterContext(
            patch.object(
                self.module, "_retire_database", side_effect=lambda *_args: self.events.append("retire:database")
            )
        )
        self.enterContext(patch.object(self.module, "_verify_web", return_value="e" * 64))
        self.enterContext(
            patch.object(
                self.module, "_native", return_value={"domain_id": "123456789", "web_sha256": "e" * 64, "php_units": []}
            )
        )
        self.enterContext(
            patch.object(self.module, "_retire_export", side_effect=lambda *_args: self.events.append("retire:export"))
        )
        self.enterContext(patch.object(self.module.files, "capture", return_value={"private_capture": "exact"}))
        self.enterContext(
            patch.object(
                self.module.files,
                "retire",
                side_effect=lambda *_args, **_kwargs: self.events.append("retire:files") or {"phase": "retired"},
            )
        )

    def test_cleanup_uses_current_retained_baseline_and_never_releases_source_or_authentication(self):
        result = self.module.SourceRetirement(self.source).retire()
        self.assertEqual(result, {"phase": "retired", "operation_id": self.operation, "source_domain_id": "123456789"})
        self.assertEqual(
            [event for event in self.events if event.startswith(("retire:", "release:"))],
            [
                "retire:web",
                "retire:database",
                "release:paths",
                "retire:files",
                "retire:cron",
                "retire:ingress",
                "retire:export",
            ],
        )
        state = self.source.coordinator.journal.read()
        self.assertEqual(state["phase"], "retired")
        self.assertEqual(state["retirement"]["retained_digest"], self.current_retained)
        self.source.coordinator.retained.assert_not_called()
        self.steps["web"].release.assert_not_called()
        self.steps["database"].release.assert_not_called()
        self.steps["cron"].release.assert_not_called()
        with self.assertRaisesRegex(ValueError, "Committed|retir"):
            self.source.coordinator.release()

    def test_lost_web_mutation_reply_parks_without_replaying_or_dropping_sql(self):
        self.web.side_effect = TimeoutError("Lost native web retirement result")
        with self.assertRaises(TimeoutError):
            self.module.SourceRetirement(self.source).retire()
        self.sql.assert_not_called()
        state = self.source.coordinator.journal.read()
        self.assertEqual(state["phase"], "retiring")
        self.assertEqual(state["retirement"]["pending"], "web")
        with self.assertRaisesRegex(ValueError, "interrupted|uncertain"):
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(self.web.call_count, 1)
        self.sql.assert_not_called()

    def test_retained_change_during_cleanup_stops_before_sql_or_file_deletion(self):
        def changed(*_args):
            self.current_retained = "a concurrent retained mail change"
            return "e" * 64

        self.web.side_effect = changed
        with self.assertRaisesRegex(ValueError, "Retained|retained"):
            self.module.SourceRetirement(self.source).retire()
        self.sql.assert_not_called()
        self.steps["paths"].release.assert_not_called()

    def fail_after(self, step, error=None, *, digest=None, times=1):
        """Make the re-check right after `step` raise `error`, or return `digest`, `times` times."""
        remaining = {"count": times}

        def retained(*_args):
            if self.events and self.events[-1] == "retire:" + step and remaining["count"]:
                remaining["count"] -= 1
                if error is not None:
                    raise error
                return digest
            return self.current_retained

        self.module._retained.side_effect = retained

    def retirement(self):
        return self.source.coordinator.journal.read()["retirement"]

    def test_a_transient_recheck_failure_after_the_export_completes_on_retry(self):
        # A dig timeout (exit 9) in the post-step re-check, after the export's own work finished (#880).
        self.fail_after("export", ValueError("Native component evidence is unreadable or exceeds its bound"))
        with self.assertRaisesRegex(ValueError, "unreadable"):
            self.module.SourceRetirement(self.source).retire()
        retirement = self.retirement()
        self.assertEqual((retirement["pending"], retirement["step_done"]), ("export", "export"))
        self.assertEqual(retirement["last_error"]["step"], "export")
        self.assertEqual(retirement["last_error"]["type"], "ValueError")
        self.assertIn("unreadable", retirement["last_error"]["message"])
        with patch.object(self.module, "_verify_empty_export") as tombstone:
            result = self.module.SourceRetirement(self.source).retire()
        tombstone.assert_called_once()
        self.assertEqual(result["phase"], "retired")
        self.assertEqual(self.events.count("retire:export"), 1)
        self.assertEqual(self.source.coordinator.journal.read()["phase"], "retired")

    def test_a_real_retained_change_still_refuses_on_retry(self):
        for first in (ValueError("Native component evidence is unreadable"), None):
            with self.subTest(first_run="transient" if first else "changed"):
                self.setUp()
                self.fail_after("export", first, digest="a retained mail change", times=1)
                with self.assertRaises(ValueError):
                    self.module.SourceRetirement(self.source).retire()
                self.module._retained.side_effect = lambda *_args: "a retained mail change"
                with (
                    patch.object(self.module, "_verify_empty_export"),
                    self.assertRaisesRegex(ValueError, "Retained source services changed"),
                ):
                    self.module.SourceRetirement(self.source).retire()
                self.assertEqual(self.source.coordinator.journal.read()["phase"], "retiring")
                self.assertEqual(self.events.count("retire:export"), 1)

    def test_a_step_whose_work_is_not_proven_complete_still_refuses(self):
        self.fail_after("export", ValueError("Native component evidence is unreadable"))
        with self.assertRaises(ValueError):
            self.module.SourceRetirement(self.source).retire()
        with (
            patch.object(self.module, "_verify_empty_export", side_effect=ValueError("namespace was reused")),
            self.assertRaisesRegex(ValueError, "interrupted|uncertain"),
        ):
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(self.events.count("retire:export"), 1)
        # The parked retry keeps the original cause for diagnosis.
        self.assertIn("unreadable", self.retirement()["last_error"]["message"])

    def test_a_retry_re_verifies_every_completed_step_not_only_the_pending_one(self):
        # A customer can recreate retired content between the failed run and the retry.
        self.fail_after("export", ValueError("Native component evidence is unreadable"))
        with self.assertRaises(ValueError):
            self.module.SourceRetirement(self.source).retire()
        self.module.files.retire.side_effect = ValueError("The retired source path was recreated")
        with (
            patch.object(self.module, "_verify_empty_export"),
            self.assertRaisesRegex(ValueError, "interrupted|uncertain"),
        ):
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(self.source.coordinator.journal.read()["phase"], "retiring")

    def test_a_retry_between_steps_also_re_verifies_completed_steps(self):
        # The re-check before ingress fails after files and cron finished, so nothing is pending.
        calls = {"count": 0}

        def before_ingress(*_args):
            if self.events and self.events[-1] == "retire:cron":
                calls["count"] += 1
                if calls["count"] == 2:
                    raise ValueError("Native component evidence is unreadable")
            return self.current_retained

        self.module._retained.side_effect = before_ingress
        with self.assertRaisesRegex(ValueError, "unreadable"):
            self.module.SourceRetirement(self.source).retire()
        self.assertIsNone(self.retirement()["pending"])
        self.module._retained.side_effect = lambda *_args: self.current_retained
        self.module.files.retire.side_effect = ValueError("The retired source path was recreated")
        with self.assertRaisesRegex(ValueError, "interrupted|uncertain"):
            self.module.SourceRetirement(self.source).retire()
        self.assertNotIn("retire:ingress", self.events)

    def test_a_native_failure_while_re_verifying_parks_and_keeps_the_original_record(self):
        self.fail_after("export", ValueError("Native component evidence is unreadable"))
        with self.assertRaises(ValueError):
            self.module.SourceRetirement(self.source).retire()
        with (
            patch.object(self.module, "_verify_web", side_effect=RuntimeError("Source native retirement step is uncertain")),
            self.assertRaisesRegex(ValueError, "interrupted|uncertain"),
        ):
            self.module.SourceRetirement(self.source).retire()
        self.assertIn("unreadable", self.retirement()["last_error"]["message"])

    def test_a_failure_carries_its_step_and_changed_parts_for_the_receipt(self):
        def parts_retained(_source, _context, parts=None):
            changed = self.events and self.events[-1] == "retire:export"
            values = {"domain": "same", "dns": "changed" if changed else "same"}
            if parts is not None:
                parts.update({key: self.module.native.inspection._digest(value) for key, value in values.items()})
            return self.module.native.inspection._digest(values)

        self.module._retained.side_effect = parts_retained
        with self.assertRaises(ValueError) as raised:
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(raised.exception.retirement_step, "export")
        self.assertEqual(raised.exception.retained_changed, ["dns"])

    def test_a_step_without_a_completion_check_still_refuses(self):
        # Releasing the path fence has no idempotent post-condition to re-verify.
        self.steps["paths"].release.side_effect = lambda: self.events.append("retire:paths")
        self.fail_after("paths", ValueError("Native component evidence is unreadable"))
        with self.assertRaises(ValueError):
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(self.retirement()["pending"], "paths")
        with self.assertRaisesRegex(ValueError, "interrupted|uncertain"):
            self.module.SourceRetirement(self.source).retire()
        self.steps["paths"].release.assert_called_once()

    def test_the_differing_retained_parts_are_named_without_values(self):
        def parts_retained(_source, _context, parts=None):
            changed = self.events and self.events[-1] == "retire:export"
            values = {"domain": "same", "dns": "changed" if changed else "same", "mail": "same"}
            if parts is not None:
                parts.update({key: self.module.native.inspection._digest(value) for key, value in values.items()})
            return self.module.native.inspection._digest(values)

        self.module._retained.side_effect = parts_retained
        with self.assertRaisesRegex(ValueError, "dns"):
            self.module.SourceRetirement(self.source).retire()
        retirement = self.retirement()
        self.assertEqual(retirement["retained_changed"], ["dns"])
        self.assertNotIn("changed", str(retirement["retained_changed"]))

    def test_a_baseline_without_part_digests_reports_unknown(self):
        self.fail_after("export", None, digest="a retained mail change")
        with self.assertRaises(ValueError):
            self.module.SourceRetirement(self.source).retire()
        self.assertEqual(self.retirement()["retained_changed"], ["unknown"])

    def test_released_export_cleanup_only_uses_private_artifacts_and_owned_parent_phase(self):
        state = self.source.coordinator.journal.read()
        state.update(phase="released", applied=[])
        state["export"] = {"phase": "ready"}
        self.source.coordinator.journal.write(state)
        with patch.object(self.module.native, "NativeSource", return_value=self.source):
            result = self.module.cleanup_released_export(self.source.request, self.operation, self.source.authority)
        self.assertEqual(result["phase"], "released_export_retired")
        self.assertEqual(self.events, ["retire:export"])
        self.assertEqual(self.source.coordinator.journal.read()["export_retirement"], "retired")

    def test_released_export_cleanup_refuses_committed_source_or_uncertain_export(self):
        with patch.object(self.module.native, "NativeSource", return_value=self.source), self.assertRaises(ValueError):
            self.module.cleanup_released_export(self.source.request, self.operation, self.source.authority)
        state = self.source.coordinator.journal.read()
        state.update(phase="released", applied=[], export={"phase": "started"})
        self.source.coordinator.journal.write(state)
        with patch.object(self.module.native, "NativeSource", return_value=self.source), self.assertRaises(ValueError):
            self.module.cleanup_released_export(self.source.request, self.operation, self.source.authority)
        self.assertEqual(self.events, [])


class RetiringSQLFixture(FenceSQLFixture):
    def __init__(self):
        super().__init__()
        self.schema, self.principal, self.lose_drop = True, True, False

    def __call__(self, query):
        if query.startswith("DROP DATABASE"):
            self.statements.append(query)
            self.schema = False
            if self.lose_drop:
                raise TimeoutError("Lost DROP reply")
            return []
        if query.startswith("DROP USER"):
            self.statements.append(query)
            self.principal = False
            return []
        if query.startswith("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA"):
            return [("customer_web",)] if self.schema else []
        if query.startswith("SELECT User, Host FROM mysql.user"):
            return [("webapp", "localhost")] if self.principal else []
        return super().__call__(query)


class ComponentSourceSQLRetirementTests(ComponentSourceRetirementTests):
    def fence(self):
        sql = RetiringSQLFixture()
        sql.sessions[99] = "retained_mail"
        database = self.module.native.database
        manifest = database.mysql.inspect_databases(("customer_web",), ("customer_web",), execute=sql)
        fence = database.DatabaseFence(
            "123456789",
            self.operation,
            manifest["databases"],
            ("customer_web",),
            state_dir=self.directory / "sql",
            boot_id=self.boot,
            execute=sql,
        )
        fence.apply()
        return fence, sql

    def test_exact_sql_retirement_keeps_retained_session_and_forbids_late_unlock(self):
        fence, sql = self.fence()
        self.database_retirement(self.source, self.context, fence)
        self.assertEqual(
            [query for query in sql.statements if query.startswith("DROP")],
            ["DROP DATABASE `customer_web`", "DROP USER 'webapp'@'localhost'"],
        )
        self.assertEqual(sql.sessions, {99: "retained_mail"})
        self.assertEqual(fence.journal.read()["phase"], "retired")
        with self.assertRaises(ValueError):
            fence.release()

    def test_uncertain_ddl_reply_is_not_replayed_or_adopted(self):
        fence, sql = self.fence()
        sql.lose_drop = True
        with self.assertRaises(TimeoutError):
            self.database_retirement(self.source, self.context, fence)
        self.assertEqual(fence.journal.read()["phase"], "retiring")
        sql.lose_drop = False
        with self.assertRaises(ValueError):
            self.database_retirement(self.source, self.context, fence)
        self.assertEqual(len([query for query in sql.statements if query.startswith("DROP")]), 1)
        self.assertTrue(sql.principal)


class ComponentSourceExportRetirementTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-retire.py"
        spec = importlib.util.spec_from_file_location("component_export_retire", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.enterContext(patch.object(self.module.exports, "ROOT", root))
        self.source = SimpleNamespace(operation=str(uuid4()))
        self.directory = root / self.source.operation
        self.directory.mkdir(mode=0o700)
        names = [
            "native.tar.gz",
            "native.tar.gz.dom",
            "native.tar.gz.info",
            "migration_" + self.source.operation + ".tar.gz",
            "migration_" + self.source.operation + ".db_website.sql",
        ]
        for name in names:
            path = self.directory / name
            path.write_bytes(b"private native artifact")
            path.chmod(0o644 if name.startswith("native.") else 0o600)
        output = self.directory / names[3]
        self.state = {
            "export": {
                "phase": "ready",
                "path": str(output),
                "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            },
            "context": {"manifest": {"databases": [{"name": "website"}]}},
        }

    def test_exact_native_sidecars_and_selected_dump_are_removed_leaving_tombstone(self):
        self.module._retire_export(self.source, self.state, owner_uid=os.geteuid())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_unknown_or_symlinked_staging_preserves_all_artifacts(self):
        foreign = self.directory / "foreign"
        foreign.symlink_to("native.tar.gz")
        with self.assertRaises(ValueError):
            self.module._retire_export(self.source, self.state, owner_uid=os.geteuid())
        self.assertTrue((self.directory / "native.tar.gz").exists())
        self.assertTrue(foreign.is_symlink())
