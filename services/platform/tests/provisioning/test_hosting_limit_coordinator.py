"""Real durable journals and native locks, with only the kernel/Virtualmin seam replaced."""

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class QuotaCoordinatorTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_quota.py"
        spec = importlib.util.spec_from_file_location("native_quota_coordinator", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        native_path = path.with_name("praho_quota_native.py")
        native_spec = importlib.util.spec_from_file_location("native_quota_backend", native_path)
        cls.native = importlib.util.module_from_spec(native_spec)
        native_spec.loader.exec_module(cls.native)

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

    def coordinator(self):
        return self.module.QuotaCoordinator(self.root, self.backend)

    def native_backend(self):
        with patch.object(self.native.os, "geteuid", return_value=0):
            return self.native.NativeQuotaBackend()

    def test_a_fence_is_durable_and_prevents_the_delayed_original_application(self):
        self.coordinator().perform("fence", self.request)
        with self.assertRaisesRegex(ValueError, "cancelled"):
            self.coordinator().perform("apply", self.request)
        self.backend.apply.assert_not_called()

    def test_unknown_matching_values_do_not_authorize_replay(self):
        self.backend.apply.side_effect = TimeoutError("lost native completion")
        with self.assertRaises(TimeoutError):
            self.coordinator().perform("apply", self.request)
        self.backend.apply.side_effect = None
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.coordinator().perform("apply", self.request)
        self.assertEqual(self.backend.apply.call_count, 1)
        self.coordinator().perform("fence", self.request)
        next_request = {**self.request, "generation": 2, "token": str(uuid4())}
        self.coordinator().perform("apply", next_request)
        self.assertEqual(self.backend.apply.call_count, 2)
        with self.assertRaisesRegex(ValueError, "cancelled|generation"):
            self.coordinator().perform("apply", self.request)
        self.assertEqual(self.backend.apply.call_count, 2)

    def test_terminal_retry_reads_back_without_issuing_another_native_write(self):
        first = self.coordinator().perform("apply", self.request)
        replay = self.coordinator().perform("apply", self.request)
        self.assertEqual(first["token"], replay["token"])
        self.assertEqual(replay["generation"], 1)
        self.backend.apply.assert_called_once()
        changed = {**self.request, "disk_limit_kib": 22528 * 1024}
        with self.assertRaisesRegex(ValueError, "terms"):
            self.coordinator().perform("apply", changed)
        self.backend.apply.assert_called_once()

    def test_expired_overlay_is_refused_after_native_account_lock_before_any_write(self):
        expiry = datetime.now(UTC) + timedelta(hours=1)
        request = {
            **self.request,
            "policy": {
                "schema": 2,
                "base_revision": 2,
                "overlay_revision": 1,
                "extra_mib": 1280,
                "expires_at": expiry.isoformat(),
                "expiry_reduction": False,
                "monotonic_reduction": False,
            },
        }
        # The request was valid before it waited; the fixed native lock boundary
        # must check wall-clock expiry again before invoking any backend writer.
        with patch.object(self.module, "datetime") as clock:
            clock.fromisoformat = datetime.fromisoformat
            clock.now.return_value = expiry + timedelta(seconds=1)
            with self.assertRaisesRegex(ValueError, "expired"):
                self.coordinator().perform("apply", request)
        self.backend.apply.assert_not_called()

    def test_overlay_protocol_floor_blocks_a_delayed_base_only_worker_but_allows_fencing(self):
        expiry = datetime.now(UTC) + timedelta(hours=1)
        request = {
            **self.request,
            "policy": {
                "schema": 2,
                "base_revision": 2,
                "overlay_revision": 1,
                "extra_mib": 1280,
                "expires_at": expiry.isoformat(),
                "expiry_reduction": False,
                "monotonic_reduction": False,
            },
        }
        self.coordinator().perform("apply", request)
        stale = {**self.request, "generation": 2, "token": str(uuid4())}
        with self.assertRaisesRegex(ValueError, "protocol"):
            self.coordinator().perform("apply", stale)
        self.backend.apply.assert_called_once()
        self.coordinator().perform("fence", stale)

    def test_native_adapter_allows_only_explicit_expiry_below_current_usage(self):
        identity = {
            **self.identity,
            "domain": "example.test",
            "uid": 1001,
            "gid": 1001,
            "filesystem_uuid": str(uuid4()),
            "boot_id": str(uuid4()),
        }
        request = {
            **self.request,
            "identity": identity,
            "policy": {
                "schema": 2,
                "base_revision": 2,
                "overlay_revision": 2,
                "extra_mib": 0,
                "expires_at": (datetime.now(UTC) - timedelta(seconds=10)).isoformat(),
                "expiry_reduction": True,
                "monotonic_reduction": False,
            },
        }
        backend = self.native_backend()
        observed = {
            "uid_used_bytes": 8 * 1024**3,
            "gid_used_bytes": 8 * 1024**3,
            "observation": {"total_bytes": 8 * 1024**3},
        }
        owner = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        domain = {"id": identity["domain_id"], "dom": identity["domain"]}
        with (
            patch.object(backend, "probe", return_value=observed),
            patch.object(backend, "_domain", return_value=(domain, owner)),
            patch.object(backend, "_storage", return_value=("/dev/fixture", identity["filesystem_uuid"])),
            patch.object(self.native, "_run") as metadata,
            patch.object(self.native, "_set_kernel_quota") as kernel,
        ):
            backend._apply(request, lock_fd=3)
            self.assertEqual(kernel.call_count, 2)
            self.assertEqual(metadata.call_count, 1)
            kernel.reset_mock()
            metadata.reset_mock()
            request["policy"]["expiry_reduction"] = False
            with self.assertRaisesRegex(ValueError, "usage exceeds"):
                backend._apply(request, lock_fd=3)
            kernel.assert_not_called()
            metadata.assert_not_called()

    def test_native_cleanup_rechecks_both_hard_caps_before_any_mutation(self):
        identity = {
            **self.identity,
            "domain": "example.test",
            "uid": 1001,
            "gid": 1001,
            "filesystem_uuid": str(uuid4()),
            "boot_id": str(uuid4()),
        }
        request = {
            **self.request,
            "identity": identity,
            "policy": {
                "schema": 2,
                "base_revision": 2,
                "overlay_revision": 2,
                "extra_mib": 0,
                "expires_at": (datetime.now(UTC) - timedelta(seconds=10)).isoformat(),
                "expiry_reduction": True,
                "monotonic_reduction": True,
            },
        }
        backend = self.native_backend()
        observed = {
            "uid_used_bytes": 8 * 1024**3,
            "gid_used_bytes": 8 * 1024**3,
            "uid_hard_kib": request["disk_limit_kib"],
            "gid_hard_kib": request["disk_limit_kib"],
            "observation": {"total_bytes": 8 * 1024**3},
        }
        owner = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        domain = {"id": identity["domain_id"], "dom": identity["domain"]}
        with (
            patch.object(backend, "probe", return_value=observed),
            patch.object(backend, "_domain", return_value=(domain, owner)),
            patch.object(backend, "_storage", return_value=("/dev/fixture", identity["filesystem_uuid"])),
            patch.object(self.native, "_run") as metadata,
            patch.object(self.native, "_set_kernel_quota") as kernel,
            patch.object(
                self.native, "_kernel_quota", return_value=SimpleNamespace(hard=request["disk_limit_kib"])
            ) as current,
        ):
            for key in ("uid_hard_kib", "gid_hard_kib"):
                for cap in (0, request["disk_limit_kib"] - 1):
                    with self.subTest(key=key, cap=cap):
                        observed[key] = cap
                        with self.assertRaisesRegex(ValueError, "increase"):
                            backend._apply(request, lock_fd=3)
                        metadata.assert_not_called()
                        kernel.assert_not_called()
                    observed[key] = request["disk_limit_kib"]
            current.return_value = SimpleNamespace(hard=request["disk_limit_kib"] - 1)
            with self.assertRaisesRegex(ValueError, "increase"):
                backend._apply(request, lock_fd=3)
            metadata.assert_called_once()
            kernel.assert_not_called()
            metadata.reset_mock()
            current.return_value = SimpleNamespace(hard=request["disk_limit_kib"])
            backend._apply(request, lock_fd=3)
            self.assertEqual(metadata.call_count, 1)
            self.assertEqual(kernel.call_count, 2)

    def test_real_waiting_native_writer_rechecks_expiry_after_exact_flock_block(self):
        self.coordinator()
        context = multiprocessing.get_context("fork")
        blocked, expired = context.Event(), context.Event()
        outcome, written = self.root / "outcome", self.root / "mutation"
        expiry = datetime.now(UTC) + timedelta(hours=1)
        request = {
            **self.request,
            "policy": {
                "schema": 2,
                "base_revision": 2,
                "overlay_revision": 1,
                "extra_mib": 1280,
                "expires_at": expiry.isoformat(),
                "expiry_reduction": False,
                "monotonic_reduction": False,
            },
        }
        descriptor = os.open(self.root / "locks/chain-12345.lock", os.O_CREAT | os.O_WRONLY, 0o600)
        real_flock = fcntl.flock
        real_flock(descriptor, fcntl.LOCK_EX)

        def waiting_writer():
            os.close(descriptor)

            def observe_lock(fd, mode):
                try:
                    return real_flock(fd, mode)
                except BlockingIOError:
                    blocked.set()
                    raise

            self.backend.apply.side_effect = lambda *args, **kwargs: written.write_text("expired write")
            with (
                patch.object(self.module.fcntl, "flock", side_effect=observe_lock),
                patch.object(self.module, "datetime") as clock,
            ):
                clock.fromisoformat = datetime.fromisoformat
                clock.now.side_effect = lambda _: (
                    expiry + timedelta(seconds=1) if expired.is_set() else expiry - timedelta(seconds=1)
                )
                try:
                    self.coordinator().perform("apply", request)
                    outcome.write_text("applied")
                except ValueError as error:
                    outcome.write_text(str(error))

        process = context.Process(target=waiting_writer)
        process.start()
        try:
            self.assertTrue(blocked.wait(10), "The writer never attempted the held native account flock")
            self.assertFalse(outcome.exists())
            expired.set()
            real_flock(descriptor, fcntl.LOCK_UN)
            process.join(timeout=10)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
            self.assertIn("expired", outcome.read_text())
            self.assertFalse(written.exists())
        finally:
            os.close(descriptor)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)

    def test_killing_the_coordinator_cannot_release_an_issued_native_writer(self):
        """Observe the real flock while a real child remains poised to mutate."""
        ready, release, written = (self.root / name for name in ("ready", "release", "written"))
        helper = self.root / "native_writer.py"
        helper.write_text(
            "import os, sys, time\nfrom pathlib import Path\n"
            "Path(sys.argv[1]).write_text(str(os.getpid()))\n"
            "while not Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
            "Path(sys.argv[3]).write_text('old mutation completed')\n"
        )
        # Django's parallel runner uses daemon processes, which cannot start a
        # multiprocessing child. A real independent interpreter also avoids
        # inheriting the runner's database/thread state into this native proof.
        runner = self.root / "coordinator.py"
        runner.write_text(
            "import importlib.util, json, sys\nfrom pathlib import Path\n"
            "def load(name, path):\n"
            " spec = importlib.util.spec_from_file_location(name, path)\n"
            " module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module\n"
            "coordinator = load('coordinator', sys.argv[1])\n"
            "native = load('native', sys.argv[2])\n"
            "class Backend:\n"
            " def apply(self, request, *, lock_fd=None):\n"
            "  options = {} if lock_fd is None else {'lock_fd': lock_fd}\n"
            "  native._run([sys.executable, *sys.argv[5:]], timeout=15, **options)\n"
            " def probe(self, request): return {}\n"
            "coordinator.QuotaCoordinator(Path(sys.argv[3]), Backend()).perform('apply', json.loads(sys.argv[4]))\n"
        )
        process = subprocess.Popen(  # noqa: S603 -- Fixed interpreter and repository-owned native modules in a private fixture.
            [
                sys.executable,
                str(runner),
                str(self.module.__file__),
                str(self.native.__file__),
                str(self.root),
                json.dumps(self.request),
                str(helper),
                str(ready),
                str(release),
                str(written),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        poll = Event()
        try:
            deadline = monotonic() + 10
            while not ready.exists() and monotonic() < deadline and process.poll() is None:
                poll.wait(0.01)
            self.assertTrue(ready.exists(), "The native writer never reached its mutation boundary")
            process.kill()
            process.wait(timeout=5)
            self.assertIsNotNone(process.poll())
            descriptor = os.open(self.root / "locks/chain-12345.lock", os.O_WRONLY)
            try:
                with self.assertRaises(BlockingIOError, msg="Fencing would run while the old writer is still alive"):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)
        finally:
            release.touch()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            deadline = monotonic() + 5
            while ready.exists() and not written.exists() and monotonic() < deadline:
                poll.wait(0.01)
        self.assertEqual(written.read_text(), "old mutation completed")
        self.coordinator().perform("fence", self.request)
        self.backend.apply.side_effect = lambda request, **options: written.write_text("new desired policy")
        self.coordinator().perform("apply", {**self.request, "generation": 2, "token": str(uuid4())})
        self.assertEqual(written.read_text(), "new desired policy")
        with self.assertRaisesRegex(ValueError, "cancelled"):
            self.coordinator().perform("apply", self.request)
        self.assertEqual(written.read_text(), "new desired policy")
