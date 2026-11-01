"""The native path fence owns exact site writers and mount IDs, with durable uncertain outcomes."""

import importlib.util
import json
import signal
import tempfile
from pathlib import Path
from unittest.mock import call, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class FakeFenceSystem:
    """Only the process/mount boundary is replaced; the journal and workflow run normally."""

    def __init__(self):
        self.boot_id = "c99515bb-66a3-4355-8eec-040f07c58430"
        self.writer = {
            "pid": 1234,
            "start_time": "98765",
            "mount_namespace": "555",
            "kind": "php_fpm_pool",
            "identity": "123456789",
            "uid": 123,
        }
        self.namespace = {"pid": 10, "start_time": "2", "mount_namespace": "555", "roots": []}
        self.stopped = False
        self.alive = True
        self.exit_confirmed = True
        self.old_descriptor_writes = 0
        self.mounts = {}
        self.next_id = 100
        self.calls = []
        self.unsafe = False
        self.fail_mount = False

    def scan(self, home, selected):
        return {"tree_digest": "a" * 64, "inodes": {(1, 2)}}

    def writers(self, scope, domain_id, owner_uid):
        return [dict(self.writer)] if self.alive else []

    def qualify(self, home, selected, owned_mounts=None):
        if self.unsafe:
            raise ValueError("Unclassified bind alias")
        roots = [str(home / relative) for relative in selected]
        if owned_mounts is not None and any(
            value["mount_id"] not in owned_mounts.get("555", []) or not value["read_only"]
            for value in self.mounts.values()
        ):
            raise ValueError("Foreign mount or missing read-only protection")
        if owned_mounts is not None and len(self.mounts) != len(roots):
            raise ValueError("Owned mount disappeared")
        return {"namespaces": [{**self.namespace, "roots": roots}], "mounts": list(self.mounts.values())}

    def is_stopped(self, writer):
        self.assert_writer(writer)
        return self.stopped

    def assert_writer(self, writer):
        if writer["start_time"] != self.writer["start_time"]:
            raise ValueError("PID identity changed")

    def stop(self, writer):
        self.assert_writer(writer)
        self.calls.append("stop")
        self.stopped = True

    def resume(self, writer):
        self.assert_writer(writer)
        self.calls.append("resume")
        self.stopped = False

    def terminate(self, writer):
        self.assert_writer(writer)
        self.calls.append("terminate")
        if not self.exit_confirmed:
            raise ValueError("Selected writer exit and descriptor closure are unconfirmed")
        self.alive = False
        self.stopped = False

    def exited(self, writer):
        return not self.alive

    def owner_continue(self):
        if self.alive:
            self.stopped = False
            self.old_descriptor_writes += 1

    def bind_read_only(self, namespace, path, receipt):
        self.calls.append("mount")
        if self.fail_mount:
            raise ValueError("Connection lost before a mount receipt")
        self.mounts[str(path)] = {
            "mount_namespace": "555",
            "mount_id": self.next_id,
            "read_only": True,
            "mountpoint": str(path),
        }
        receipt(self.next_id)
        self.next_id += 1

    def unmount(self, namespace, path, mount_id):
        if self.mounts[str(path)]["mount_id"] != mount_id:
            raise ValueError("Foreign top mount")
        self.calls.append("unmount")
        del self.mounts[str(path)]

    def mount_present(self, namespace, path, mount_id):
        mount = self.mounts.get(str(path))
        return mount is not None and mount["mount_id"] == mount_id


class ComponentPathFenceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-fence.py"
        spec = importlib.util.spec_from_file_location("component_path_fence", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.system = FakeFenceSystem()
        self.operation_id = str(uuid4())
        self.fence = self.build_fence()

    def build_fence(self, operation_id=None):
        return self.module.PathFence(
            self.root / "home/customer",
            ("public_html",),
            "123456789",
            123,
            operation_id or self.operation_id,
            "a" * 64,
            state_dir=self.root / "state",
            system=self.system,
        )

    def test_apply_verify_and_compensation_are_owned_and_durable(self):
        self.fence.apply()
        self.fence.verify()
        journal = json.loads(self.fence.state_file.read_text())
        self.assertEqual(journal["phase"], "held")
        self.assertEqual(journal["operation_id"], self.operation_id)
        self.assertEqual(journal["mounts"][0]["mount_id"], 100)
        self.assertFalse(self.system.alive)
        self.fence.release()
        self.assertEqual(self.system.calls, ["terminate", "mount", "unmount"])
        self.assertFalse(self.system.mounts)
        self.assertFalse(self.system.stopped)
        self.assertEqual(json.loads(self.fence.state_file.read_text())["phase"], "released")

    def test_unknown_writer_and_unsafe_mounts_refuse_before_any_signal_or_mount(self):
        for unsafe in ("writer", "mount"):
            self.system.writer["kind"] = "unknown" if unsafe == "writer" else "php_fpm_pool"
            self.system.unsafe = unsafe == "mount"
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                self.fence.apply()
            self.assertEqual(self.system.calls, [])
            self.assertFalse(self.fence.state_file.exists())

    def test_owner_continue_cannot_revive_an_old_descriptor_after_apply(self):
        self.fence.apply()
        self.system.owner_continue()
        self.assertFalse(self.system.alive)
        self.assertEqual(self.system.old_descriptor_writes, 0)
        self.fence.verify()

    def test_unconfirmed_exit_parks_before_mounting_or_claiming_a_held_fence(self):
        self.system.exit_confirmed = False
        with self.assertRaisesRegex(ValueError, "exit|closure"):
            self.fence.apply()
        self.assertEqual(self.system.calls, ["terminate"])
        self.assertFalse(self.system.mounts)
        self.assertEqual(json.loads(self.fence.state_file.read_text())["phase"], "needs_review")

    def test_second_apply_verifies_without_replaying_mutation(self):
        self.fence.apply()
        calls = list(self.system.calls)
        self.fence.apply()
        self.assertEqual(self.system.calls, calls)
        self.assertEqual(len(self.system.mounts), 1)

    def test_every_newly_visible_namespace_requires_its_exact_owned_readonly_mount(self):
        self.fence.apply()
        self.system.namespace["mount_namespace"] = "666"
        with self.assertRaisesRegex(ValueError, "Every live namespace"):
            self.fence.verify()
        self.assertEqual(self.system.calls, ["terminate", "mount"])

    def test_old_suspension_journal_cannot_be_admitted_or_automatically_compensated(self):
        self.fence.apply()
        journal = json.loads(self.fence.state_file.read_text())
        journal["schema"] = 1
        self.fence.state_file.write_text(json.dumps(journal))
        for method in (self.fence.apply, self.fence.verify, self.fence.release):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(ValueError, "schema"):
                method()
        self.assertEqual(self.system.calls, ["terminate", "mount"])

    def test_unconfirmed_mount_receipt_parks_and_cannot_guess_compensation(self):
        self.system.fail_mount = True
        with self.assertRaisesRegex(ValueError, "Connection lost"):
            self.fence.apply()
        self.assertEqual(json.loads(self.fence.state_file.read_text())["phase"], "needs_review")
        with self.assertRaises(ValueError):
            self.fence.release()
        self.assertFalse(self.system.alive)
        self.assertNotIn("resume", self.system.calls)

    def test_changed_top_mount_is_not_unmounted_or_reported_released(self):
        self.fence.apply()
        for mount in self.system.mounts.values():
            mount["mount_id"] = 999
        with self.assertRaises(ValueError):
            self.fence.release()
        self.assertNotIn("unmount", self.system.calls)
        self.assertNotIn("resume", self.system.calls)

    def test_pid_reuse_before_termination_or_reboot_revokes_the_attempt(self):
        original = self.system.terminate

        def reused(writer):
            self.system.writer["start_time"] = "new-process"
            original(writer)

        self.system.terminate = reused
        with self.assertRaisesRegex(ValueError, "PID identity"):
            self.fence.apply()
        self.assertEqual(self.system.calls, [])
        self.assertFalse(self.system.mounts)

    def test_an_exited_pid_reused_later_is_never_signaled_by_release(self):
        self.fence.apply()
        self.system.writer["start_time"] = "new-process"
        self.fence.release()
        self.assertEqual(self.system.calls, ["terminate", "mount", "unmount"])

    def test_reboot_revokes_the_fence_before_compensation(self):
        self.fence.apply()
        self.system.boot_id = str(uuid4())
        with self.assertRaises(ValueError):
            self.fence.verify()

    def test_another_operation_cannot_release_or_replace_a_live_fence(self):
        self.fence.apply()
        other = self.build_fence(str(uuid4()))
        for method in (other.apply, other.verify, other.release):
            with self.assertRaises(ValueError):
                method()
        self.assertFalse(self.system.alive)
        self.assertNotIn("unmount", self.system.calls)

    def test_previously_stopped_writer_requires_preparation_before_any_mutation(self):
        self.system.stopped = True
        with self.assertRaisesRegex(ValueError, "stopped|preparation"):
            self.fence.apply()
        self.assertTrue(self.system.stopped)
        self.assertTrue(self.system.alive)
        self.assertEqual(self.system.calls, [])
        self.assertFalse(self.fence.state_file.exists())

    def test_compensation_finishes_after_lost_unmount_receipt_without_replaying_or_resuming(self):
        self.fence.apply()
        original = self.system.unmount

        def lost_receipt(namespace, path, mount_id):
            original(namespace, path, mount_id)
            raise ValueError("lost unmount receipt")

        self.system.unmount = lost_receipt
        with self.assertRaisesRegex(ValueError, "lost unmount receipt"):
            self.fence.release()
        self.system.unmount = original
        self.fence.release()
        self.assertEqual(self.system.calls.count("unmount"), 1)
        self.assertNotIn("resume", self.system.calls)
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.stopped)
        self.assertEqual(json.loads(self.fence.state_file.read_text())["phase"], "released")


class NativeWriterExitTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-fence.py"
        spec = importlib.util.spec_from_file_location("component_writer_exit", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        from tests.provisioning.test_component_path_writers import prepare_native_php_parent  # noqa: PLC0415

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.proc = Path(temporary.name).resolve()
        self.process = self.proc / "1234"
        (self.process / "ns").mkdir(parents=True)
        (self.process / "fd").mkdir()
        (self.process / "ns/mnt").symlink_to("mnt:[555]")
        (self.process / "status").write_text("State:\tS (sleeping)\nUid:\t123\t123\t123\t123\nPPid:\t42\n")
        (self.process / "cmdline").write_bytes(b"php-fpm: pool 123456789\0")
        self.writer = FakeFenceSystem().writer
        self.system = self.module.FencingSystem(self.proc)
        self.process_state("S")
        prepare_native_php_parent(self.process)

    def process_state(self, state, start="98765"):
        (self.process / "stat").write_text("1234 (php-fpm) " + state + " 42 " + "0 " * 17 + start + " 0\n")

    def test_dead_process_requires_closed_descriptors_and_a_replacement_is_untouched(self):
        self.assertFalse(self.system.exited(self.writer))
        self.process_state("Z")
        self.assertTrue(self.system.exited(self.writer))
        (self.process / "fd/3").write_text("old descriptor remains")
        with self.assertRaisesRegex(ValueError, "descriptor closure"):
            self.system.exited(self.writer)
        self.process_state("S", "different-birth")
        self.assertTrue(self.system.exited(self.writer))

    def test_pidfd_is_opened_then_identity_checked_before_any_signal(self):
        with (
            patch("os.pidfd_open", return_value=73, create=True) as opened,
            patch("os.close") as closed,
            patch("signal.pidfd_send_signal", create=True) as sent,
            patch.object(self.system, "assert_writer", side_effect=ValueError("PID identity changed")),
            self.assertRaisesRegex(ValueError, "PID identity"),
        ):
            self.system.terminate(self.writer)
        opened.assert_called_once_with(1234)
        closed.assert_called_once_with(73)
        sent.assert_not_called()

    def test_proc_exit_race_requires_independent_directory_absence(self):
        self.assertTrue(self.process.exists())
        with patch.object(Path, "read_text", side_effect=ProcessLookupError("exited during stat read")):
            with self.assertRaisesRegex(ValueError, "unreadable exit evidence"):
                self.system.exited(self.writer)
            with patch.object(Path, "exists", return_value=False):
                self.assertTrue(self.system.exited(self.writer))

    def test_term_escalates_only_on_the_held_pidfd_and_requires_actual_closure(self):
        def send(descriptor, action):
            if action == signal.SIGKILL:
                self.process_state("Z")

        with (
            patch("os.pidfd_open", return_value=73, create=True),
            patch("os.close") as closed,
            patch("signal.pidfd_send_signal", side_effect=send, create=True) as sent,
            patch.object(self.system, "_wait_exit", side_effect=[False, True]),
        ):
            self.system.terminate(self.writer)
        self.assertEqual(sent.call_args_list, [call(73, signal.SIGTERM), call(73, signal.SIGKILL)])
        closed.assert_called_once_with(73)
        self.assertTrue(self.system.exited(self.writer))

    def test_changed_native_classification_and_missing_exit_proof_do_not_succeed(self):
        (self.process / "cmdline").write_bytes(b"imap\0")
        with (
            patch("os.pidfd_open", return_value=73, create=True),
            patch("os.close"),
            patch("signal.pidfd_send_signal", create=True) as sent,
            self.assertRaisesRegex(ValueError, "classification"),
        ):
            self.system.terminate(self.writer)
        sent.assert_not_called()
        (self.process / "cmdline").write_bytes(b"php-fpm: pool 123456789\0")
        with (
            patch("os.pidfd_open", return_value=73, create=True),
            patch("os.close"),
            patch("signal.pidfd_send_signal", create=True),
            patch.object(self.system, "_wait_exit", return_value=False),
            self.assertRaisesRegex(ValueError, "exit.*closure"),
        ):
            self.system.terminate(self.writer)
