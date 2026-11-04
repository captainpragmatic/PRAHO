"""A target creation retry cannot adopt foreign state or expose an unlocked native owner."""

import hashlib
import importlib.util
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_migration_manifest import component_manifest


class ComponentTargetCoordinatorTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-target.py"
        spec = importlib.util.spec_from_file_location("component_target_coordinator", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.manifest = component_manifest()
        self.operation, self.boot = str(uuid4()), str(uuid4())
        self.creation = {
            "domain": "example.test",
            "user": "customer",
            "template": "Default Settings",
            "desc": "fixture",
            **dict.fromkeys(self.module.FEATURES, ""),
        }
        self.fields = {
            "id": "987654321",
            "dom": "example.test",
            "user": "customer",
            "home": "/home/customer",
            "uid": "1201",
            "gid": "1201",
            "unix": "1",
            "dir": "1",
            "web": "1",
            "disabled": "",
        }
        self.native = self.enterContext(patch.object(self.module, "native", side_effect=self.command))
        self.enterContext(patch.object(self.module.TargetCoordinator, "_prepare_frontend_policy"))
        self.enterContext(patch.object(self.module.archives, "read_component_archive", return_value={}))
        self.namespace = self.enterContext(
            patch.object(self.module.preflight, "preflight_target", return_value={"absent": True})
        )
        self.enterContext(patch.object(self.module.archives.source.inspection, "_callbacks", return_value=({}, [])))
        self.enterContext(patch.object(self.module.preflight.mysql, "native_sql", return_value=[("localhost",)]))
        self.enterContext(
            patch.object(self.module.archives.source.inspection, "_fields", side_effect=lambda _path: self.fields)
        )
        self.shadow = self.enterContext(
            patch.object(
                self.module.archives.source.inspection, "_command", return_value="customer:!held:1:0:99999:7:::\n"
            )
        )
        self.enterContext(
            patch.object(
                self.module.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=1201, pw_gid=1201, pw_dir="/home/customer"),
            )
        )

    def command(self, program, arguments):
        if program == "disable-domain":
            self.fields["disabled"] = "unix,web,mysql"
        if program == "enable-domain":
            self.fields["disabled"] = ""
        return "987654321" if program == "list-domains" and "--id-only" in arguments else ""

    def target(self, *, checksum="b" * 64, **options):
        return self.module.TargetCoordinator(
            self.manifest,
            self.operation,
            "a" * 64,
            checksum,
            self.creation,
            state_dir=self.directory / "receipts",
            boot_id=self.boot,
            **options,
        )

    def test_prepare_is_private_owned_and_rechecks_real_suspension_on_retry(self):
        target = self.target()
        receipt = target.prepare()
        self.assertEqual(
            receipt, {"operation_id": self.operation, "target_domain_id": "987654321", "phase": "prepared"}
        )
        self.assertEqual(target.prepare(), receipt)
        self.assertEqual(sum(call.args[0] == "create-domain" for call in self.native.call_args_list), 1)
        self.assertNotIn("Qz9", target.journal.path.read_text())
        self.shadow.return_value = "customer:unlocked:1:0:99999:7:::\n"
        with self.assertRaisesRegex(ValueError, "Unix login"):
            target.prepare()

    def test_native_create_preserves_both_caps_and_suppresses_customer_mail(self):
        self.creation.update(quota="5767168", uquota="5767168", **{"no-email": ""})
        self.target().prepare()
        creation = next(call for call in self.native.call_args_list if call.args[0] == "create-domain")
        arguments = creation.args[1]
        self.assertIn("--no-email", arguments)
        for parameter in ("--quota", "--uquota"):
            self.assertEqual(arguments[arguments.index(parameter) + 1], "5767168")

    def test_unprepared_archive_retirement_seals_namespace_without_adopting_or_creating_domain(self):
        payload = b"selected private archive uploaded before native preparation"
        archive = self.directory / ("migration_" + self.operation + ".tar.gz")
        archive.write_bytes(payload)
        archive.chmod(0o600)
        target = self.target(checksum=hashlib.sha256(payload).hexdigest(), archive=archive)
        self.native.reset_mock()
        receipt = target.retire_unprepared_archive()
        self.assertEqual(receipt, {"operation_id": self.operation, "phase": "artifacts_retired"})
        self.assertFalse(archive.exists())
        self.assertIsNone(target.journal.read())
        self.assertEqual(target.retire_unprepared_archive(), receipt)
        self.native.assert_not_called()
        with self.assertRaisesRegex(ValueError, "retir|seal"):
            target.prepare()
        archive.write_bytes(payload)
        archive.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "reused"):
            target.retire_unprepared_archive()
        self.assertEqual(archive.read_bytes(), payload)

    def test_unprepared_retirement_refuses_any_native_preparation_receipt(self):
        target = self.target()
        target.prepare()
        self.native.reset_mock()
        with self.assertRaisesRegex(ValueError, "prepar|native"):
            target.retire_unprepared_archive()
        self.native.assert_not_called()

    def test_unprepared_archive_lost_unlink_reply_parks_without_adopting_absence_or_reused_name(self):
        payload = b"owned UUID selected archive"
        archive = self.directory / ("migration_" + self.operation + ".tar.gz")
        archive.write_bytes(payload)
        archive.chmod(0o600)
        target = self.target(checksum=hashlib.sha256(payload).hexdigest(), archive=archive)
        unlink = Path.unlink

        def uncertain(path, **kwargs):
            unlink(path, **kwargs)
            if path == archive:
                raise TimeoutError("Lost exact archive unlink reply")

        with patch.object(Path, "unlink", uncertain), self.assertRaises(TimeoutError):
            target.retire_unprepared_archive()
        self.assertFalse(archive.exists())
        with self.assertRaisesRegex(ValueError, "interrupted"):
            target.retire_unprepared_archive()
        archive.write_bytes(payload)
        archive.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "interrupted"):
            target.retire_unprepared_archive()
        self.assertEqual(archive.read_bytes(), payload)
        with self.assertRaisesRegex(ValueError, "seal|retir"):
            target.prepare()

    def test_unprepared_archive_replacement_after_intent_is_preserved(self):
        payload = b"same digest cannot authorize a different native inode"
        archive = self.directory / ("migration_" + self.operation + ".tar.gz")
        archive.write_bytes(payload)
        archive.chmod(0o600)
        target = self.target(checksum=hashlib.sha256(payload).hexdigest(), archive=archive)
        private = target._private_archive
        calls = 0

        def changed(expected=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                archive.rename(archive.with_suffix(".original"))
                archive.write_bytes(payload)
                archive.chmod(0o600)
            return private(expected)

        with (
            patch.object(target, "_private_archive", side_effect=changed),
            self.assertRaisesRegex(ValueError, "reused"),
        ):
            target.retire_unprepared_archive()
        self.assertEqual(archive.read_bytes(), payload)
        self.assertIsNone(target.journal.read())

    def test_lost_create_response_never_repeats_creation_or_adopts_matching_identity(self):
        target = self.target()
        self.native.side_effect = lambda program, arguments: (
            (_ for _ in ()).throw(TimeoutError()) if program == "create-domain" else ""
        )
        with self.assertRaises(TimeoutError):
            target.prepare()
        self.native.reset_mock()
        with self.assertRaisesRegex(ValueError, "unresolved"):
            target.prepare()
        self.native.assert_not_called()
        self.assertEqual(target.journal.read()["phase"], "creating")

    def test_foreign_target_namespace_and_unqualified_features_refuse_before_native_creation(self):
        self.namespace.side_effect = ValueError("Foreign SQL host account")
        with self.assertRaises(ValueError):
            self.target().prepare()
        self.native.assert_not_called()
        self.assertFalse((self.directory / "receipts/123456789.json").exists())
        self.creation["mail"] = ""
        with self.assertRaises(ValueError):
            self.target()

    def activation_target(self):
        target = self.target()
        target.prepare()
        with target.journal.locked():
            state = target._state()
            state.update(phase="held", held_receipt_sha256="c" * 64)
            target.journal.write(state)
        self.enterContext(patch.object(target, "_held", return_value={"target_receipt_sha256": "c" * 64}))
        return target

    def test_activation_requires_exact_held_receipt_before_any_native_change(self):
        target = self.activation_target()
        callback = self.enterContext(patch.object(target, "_activate_native"))
        with self.assertRaisesRegex(ValueError, "receipt"):
            target.activate("d" * 64, enabled=True)
        callback.assert_not_called()
        self.assertEqual(target.journal.read()["phase"], "held")

    def test_uncertain_activation_never_replays_credentials_or_opens_ingress(self):
        target = self.activation_target()
        target.seal("c" * 64)
        callback = self.enterContext(patch.object(target, "_activate_native", side_effect=TimeoutError()))
        with self.assertRaises(TimeoutError):
            target.activate("c" * 64, enabled=True)
        self.assertEqual(target.journal.read()["phase"], "activating")
        with self.assertRaisesRegex(ValueError, "interrupted"):
            target.activate("c" * 64, enabled=True)
        callback.assert_called_once()

    def test_held_target_cannot_activate_before_native_compensation_is_sealed(self):
        target = self.activation_target()
        callback = self.enterContext(patch.object(target, "_activate_native"))
        self.enterContext(patch.object(target, "_active", return_value={"phase": "active"}))
        with self.assertRaisesRegex(ValueError, "seal"):
            target.activate("c" * 64, enabled=True)
        callback.assert_not_called()
        self.assertEqual(target.journal.read()["phase"], "held")

    def test_target_seal_is_durable_idempotent_and_refuses_a_previously_dispatched_remove(self):
        target, web, sql, pair = self.compensation_target()
        receipt = target.seal("c" * 64)
        self.assertEqual(
            receipt,
            {
                "operation_id": self.operation,
                "target_domain_id": "987654321",
                "phase": "sealed",
                "target_receipt_sha256": "c" * 64,
            },
        )
        # Construct a fresh native coordinator as a late, already-dispatched rollback would.
        resumed = self.target()
        self.enterContext(patch.object(resumed, "_held", return_value={"target_receipt_sha256": "c" * 64}))
        self.assertEqual(resumed.seal("c" * 64), receipt)
        self.native.reset_mock()
        with self.assertRaisesRegex(ValueError, "committed"):
            resumed.remove()
        self.native.assert_not_called()
        pair.assert_not_called()
        web.release.assert_not_called()
        sql.retire.assert_not_called()

    def test_changed_target_seal_receipt_does_not_change_held_authority(self):
        target = self.activation_target()
        with self.assertRaisesRegex(ValueError, "receipt"):
            target.seal("d" * 64)
        self.assertEqual(target.journal.read()["phase"], "held")

    def test_current_policy_does_not_replay_original_credentials_or_selected_jobs(self):
        target = self.activation_target()
        with target.journal.locked():
            state = target._state()
            state.update(phase="active", enabled=True)
            target.journal.write(state)
        self.fields["disabled"] = ""
        sql = self.enterContext(patch.object(target, "_sql")).return_value
        activation = self.enterContext(patch.object(target, "_activate_native"))
        recovery = self.enterContext(patch.object(target, "_recovery"))
        policy = self.enterContext(
            patch.object(
                target,
                "_policy_native",
                side_effect=lambda _state, enabled: self.command("enable-domain" if enabled else "disable-domain", []),
            )
        )
        self.native.reset_mock()
        self.assertEqual(target.reconcile_policy(enabled=False)["phase"], "active")
        self.assertTrue(self.fields["disabled"])
        self.assertEqual(target.reconcile_policy(enabled=True)["phase"], "active")
        self.assertFalse(self.fields["disabled"])
        self.native.assert_not_called()
        self.assertEqual([call.kwargs["enabled"] for call in policy.call_args_list], [False, True])
        self.assertEqual([call.kwargs["enabled"] for call in sql.reconcile_policy.call_args_list], [False, True])
        activation.assert_not_called()
        recovery.assert_not_called()

    def test_policy_retry_does_not_repeat_native_enable_after_a_lost_sql_reply(self):
        target = self.activation_target()
        with target.journal.locked():
            state = target._state()
            state.update(phase="active", enabled=False)
            target.journal.write(state)
        sql = self.enterContext(patch.object(target, "_sql")).return_value
        sql.reconcile_policy.side_effect = [TimeoutError("Lost SQL policy reply"), None]
        policy = self.enterContext(
            patch.object(
                target,
                "_policy_native",
                side_effect=lambda _state, enabled: self.command("enable-domain" if enabled else "disable-domain", []),
            )
        )
        self.native.reset_mock()
        with self.assertRaises(TimeoutError):
            target.reconcile_policy(enabled=True)
        self.assertEqual(target.journal.read()["phase"], "policy_changing")
        target.reconcile_policy(enabled=True)
        self.native.assert_not_called()
        policy.assert_called_once()
        self.assertEqual(target.journal.read()["phase"], "active")

    def test_terminal_artifact_retirement_removes_exact_archive_and_secrets_without_native_domain_mutation(self):
        archive = self.directory / ("migration_" + self.operation + ".tar.gz")
        archive.write_bytes(b"owned selected archive")
        archive.chmod(0o600)
        target = self.target(checksum=hashlib.sha256(archive.read_bytes()).hexdigest(), archive=archive)
        target.prepare()
        with target.journal.locked():
            state = target._state()
            state.update(phase="active", enabled=True)
            target.journal.write(state)
        recovery = self.enterContext(patch.object(target, "_recovery")).return_value
        self.native.reset_mock()
        receipt = target.retire_artifacts()
        self.assertEqual(
            receipt, {"operation_id": self.operation, "target_domain_id": "987654321", "phase": "artifacts_retired"}
        )
        self.assertFalse(archive.exists())
        recovery.cleanup_staged.assert_called_once()
        self.native.assert_not_called()
        self.assertEqual(target.retire_artifacts(), receipt)
        recovery.cleanup_staged.assert_called_once()
        archive.write_bytes(b"foreign later archive")
        with self.assertRaisesRegex(ValueError, "reused"):
            target.retire_artifacts()
        self.assertEqual(archive.read_bytes(), b"foreign later archive")

    def compensation_target(self):
        target = self.activation_target()
        web = self.enterContext(patch.object(target, "_web")).return_value
        sql = self.enterContext(patch.object(target, "_sql")).return_value
        pair = self.enterContext(patch.object(target, "_pair"))
        self.enterContext(patch.object(target, "_assert_absent"))
        self.enterContext(patch.object(target, "_recovery"))
        return target, web, sql, pair

    def test_compensation_keeps_component_ingress_until_exact_native_domain_deletion(self):
        target, web, sql, pair = self.compensation_target()
        events = []
        pair.side_effect = lambda action, _state: events.append("pair_" + action)
        self.native.side_effect = lambda program, _arguments: events.append(program) or ""
        web.retire_after_domain_absence.side_effect = lambda: events.append("retire_ingress")
        receipt = target.remove()
        self.assertEqual(receipt["phase"], "removed")
        self.assertEqual(events, ["pair_release", "delete-domain", "retire_ingress"])
        self.assertEqual(target.journal.read()["phase"], "removed")
        sql.retire.assert_called_once()
        target.remove()
        self.assertEqual(events.count("delete-domain"), 1)

    def test_uncertain_native_delete_never_removes_independent_ingress_or_repeats_deletion(self):
        target, web, _sql, _pair = self.compensation_target()
        self.native.side_effect = TimeoutError("Lost native delete response")
        with self.assertRaises(TimeoutError):
            target.remove()
        self.assertEqual(target.journal.read()["phase"], "removing")
        web.retire_after_domain_absence.assert_not_called()
        self.native.reset_mock()
        with self.assertRaisesRegex(ValueError, "interrupted"):
            target.remove()
        self.native.assert_not_called()
