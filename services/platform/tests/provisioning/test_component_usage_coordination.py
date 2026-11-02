"""The component usage guard owns the real existing OS lock and only a known writer profile."""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
_PROBE = """import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:print('blocked')
else:print('acquired')
os.close(fd)
"""
_HOLD = """import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX)
print('held',flush=True);sys.stdin.read();os.close(fd)
"""


class ComponentUsageCoordinationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        spec = importlib.util.spec_from_file_location("component_usage_guard", FILES / "praho-component-usage.py")
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = self.root / "var/lib/praho/usage"
        self.lock = self.state / "lock"
        self.config = self.root / "etc/webmin/virtual-server/config"
        self.calls: list[tuple[list[str], float]] = []

    def _write(self, relative: str, content: bytes, mode: int = 0o600) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def _profile(self) -> None:
        for name in ("praho-usage-metadata.pl", "praho-usage-hook", "praho_usage.py"):
            self._write("usr/local/libexec/" + name, (FILES / name).read_bytes(), 0o700)
        self._write("var/lib/praho/usage/installation", str(uuid4()).encode())
        self._write("var/lib/praho/usage/lock", b"retain existing lock bytes")
        (self.root / "var/lib/praho").chmod(0o700)
        self.state.chmod(0o700)
        self._write("etc/webmin/virtual-server/config", b"post_command=/usr/local/libexec/praho-usage-hook\n")

    def _probe(self, path: Path | None = None) -> str:
        result = subprocess.run(  # noqa: S603 -- actual own Python child and exact temporary lock only
            [sys.executable, "-c", _PROBE, str(path or self.lock)],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip()

    def _execute(self, arguments: list[str], timeout: float) -> str:
        self.calls.append((arguments, timeout))
        self.assertEqual(self._probe(), "blocked", "Native reconciliation must run inside the same actual OS lock")
        return "PRAHO_USAGE_RECONCILED changed=2\n"

    def _guard(self, **kwargs):
        return self.module.UsageWriterGuard(root=self.root, owner_uid=os.geteuid(), executor=self._execute, **kwargs)

    def test_absent_profile_is_noop_and_creates_no_lock_or_state(self) -> None:
        with self._guard() as usage:
            self.assertFalse(usage.installed)
            self.assertEqual(usage.reconcile(), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_supported_public_parent_and_private_usage_state_qualify(self) -> None:
        self._profile()
        self.state.parent.chmod(0o755)
        with self._guard() as usage:
            self.assertEqual(usage.reconcile(), 2)
        self.assertEqual(self.state.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)

    def test_collector_default_open_a_lock_is_supported_without_changing_its_mode_or_identity(self) -> None:
        self._profile()
        self.state.parent.chmod(0o755)
        self.lock.unlink()
        subprocess.run(  # noqa: S603 -- reproduce collector open-a with its actual umask in an isolated child
            [
                sys.executable,
                "-c",
                "import os,sys;from pathlib import Path;os.umask(0o022);Path(sys.argv[1]).open('a').close()",
                str(self.lock),
            ],
            check=True,
            timeout=5,
        )
        before = self.lock.stat()
        self.assertEqual(before.st_mode & 0o777, 0o644)
        with self._guard() as usage:
            self.assertEqual(usage.reconcile(), 2)
            self.assertEqual(self._probe(), "blocked")
        after = self.lock.stat()
        self.assertEqual(
            (after.st_ino, after.st_mtime_ns, after.st_mode), (before.st_ino, before.st_mtime_ns, before.st_mode)
        )
        self.assertEqual(self.lock.read_bytes(), b"")
        self.assertEqual(self._probe(), "acquired")

    def test_existing_lock_stays_owned_through_reconcile_then_releases_without_replacement(self) -> None:
        self._profile()
        original = self.lock.stat()
        content = self.lock.read_bytes()
        with self._guard() as usage:
            self.assertTrue(usage.installed)
            self.assertEqual(self._probe(), "blocked")
            self.assertEqual(usage.reconcile(), 2)
            self.assertEqual(self._probe(), "blocked")
        self.assertEqual(self._probe(), "acquired")
        after = self.lock.stat()
        self.assertEqual(
            (after.st_ino, after.st_mtime_ns, self.lock.read_bytes()), (original.st_ino, original.st_mtime_ns, content)
        )
        self.assertEqual(
            self.calls,
            [(["/usr/bin/perl", str(self.root / "usr/local/libexec/praho-usage-metadata.pl"), "reconcile-locked"], 60)],
        )

    def test_real_other_process_lock_refuses_without_stealing_then_can_be_reused(self) -> None:
        self._profile()
        holder = subprocess.Popen(  # noqa: S603 -- own child holds only this test's existing lock
            [sys.executable, "-u", "-c", _HOLD, str(self.lock)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout is not None
            self.assertEqual(holder.stdout.readline(), "held\n")
            before = self.lock.stat()
            with self.assertRaises(TimeoutError), self._guard(lock_timeout=0.1):
                self.fail("Contended usage lock was stolen")
            self.assertEqual(self.lock.stat().st_ino, before.st_ino)
            self.assertEqual(self.calls, [])
        finally:
            assert holder.stdin is not None
            holder.stdin.close()
            holder.wait(timeout=5)
            if holder.stdout is not None:
                holder.stdout.close()
        with self._guard() as usage:
            self.assertEqual(usage.reconcile(), 2)

    def test_exception_and_invalid_native_marker_release_the_existing_lock(self) -> None:
        self._profile()
        with self.assertRaisesRegex(RuntimeError, "owned failure"), self._guard():
            raise RuntimeError("owned failure")
        self.assertEqual(self._probe(), "acquired")
        for output in (
            "unknown native output",
            "other\nPRAHO_USAGE_RECONCILED changed=0\n",
            "PRAHO_USAGE_RECONCILED changed=-1\n",
        ):
            with self.subTest(output=output):
                with self.module.UsageWriterGuard(
                    root=self.root, owner_uid=os.geteuid(), executor=lambda _a, _t, value=output: value
                ) as usage:
                    with self.assertRaises(ValueError) as error:
                        usage.reconcile()
                    self.assertNotIn(output, str(error.exception))
                self.assertEqual(self._probe(), "acquired")

    def test_real_signal_interrupt_during_contended_entry_closes_descriptor_and_allows_reuse(self) -> None:
        self._profile()
        guard = self._guard()
        holder = subprocess.Popen(  # noqa: S603 -- own child holds only this test's existing lock
            [sys.executable, "-u", "-c", _HOLD, str(self.lock)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        previous_handler = signal.getsignal(signal.SIGALRM)

        def interrupt(_number, _frame) -> None:
            assert guard._descriptor is not None, "The actual lock descriptor must be open before interruption"
            os.fstat(guard._descriptor)
            raise KeyboardInterrupt("owned entry interruption")

        try:
            assert holder.stdout is not None
            self.assertEqual(holder.stdout.readline(), "held\n")
            signal.signal(signal.SIGALRM, interrupt)
            signal.setitimer(signal.ITIMER_REAL, 0.2)
            with self.assertRaisesRegex(KeyboardInterrupt, "owned entry interruption"), guard:
                self.fail("Contended usage lock was stolen before the interruption")
            self.assertIsNone(guard._descriptor)
            self.assertEqual(self.calls, [])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            assert holder.stdin is not None
            holder.stdin.close()
            holder.wait(timeout=5)
            if holder.stdout is not None:
                holder.stdout.close()
        with guard as usage:
            self.assertEqual(usage.reconcile(), 2)
        self.assertEqual(self._probe(), "acquired")

    def test_unknown_program_bytes_partial_profile_and_opaque_hooks_refuse_before_execution(self) -> None:
        self._profile()
        mutations = {
            "metadata": ("usr/local/libexec/praho-usage-metadata.pl", b"unknown metadata", 0o700),
            "wrapper": ("usr/local/libexec/praho-usage-hook", b"unknown wrapper", 0o700),
            "collector": ("usr/local/libexec/praho_usage.py", b"unknown collector", 0o700),
            "installation": ("var/lib/praho/usage/installation", b"not a canonical installation", 0o600),
            "previous-hook": ("var/lib/praho/usage/previous-hook", b"opaque prior command", 0o600),
            "hook": ("etc/webmin/virtual-server/config", b"post_command=/unknown/operator-hook\n", 0o600),
        }
        for name, (relative, replacement, mode) in mutations.items():
            with self.subTest(profile=name):
                path = self.root / relative
                original = path.read_bytes() if path.exists() else None
                self._write(relative, replacement, mode)
                try:
                    with self.assertRaises(ValueError), self._guard():
                        pass
                    self.assertEqual(path.read_bytes(), replacement)
                finally:
                    if original is None:
                        path.unlink()
                    else:
                        path.write_bytes(original)
        metadata = self.root / "usr/local/libexec/praho-usage-metadata.pl"
        original = metadata.read_bytes()
        metadata.unlink()
        try:
            with self.assertRaises(ValueError), self._guard():
                pass
        finally:
            self._write("usr/local/libexec/praho-usage-metadata.pl", original, 0o700)
        self.assertEqual(self.calls, [])

    def test_symlink_writable_and_unowned_profiles_do_not_modify_lock(self) -> None:
        self._profile()
        original = self.lock.stat()
        for path in (self.lock, self.state / "installation", self.root / "usr/local/libexec/praho_usage.py"):
            mode = path.stat().st_mode & 0o777
            path.chmod(mode | 0o020)
            try:
                with self.assertRaises(ValueError), self._guard():
                    pass
            finally:
                path.chmod(mode)
        replacement = self.state / "other-lock"
        self.lock.rename(replacement)
        self.lock.symlink_to(replacement)
        try:
            with self.assertRaises(ValueError), self._guard():
                pass
        finally:
            self.lock.unlink()
            replacement.rename(self.lock)
        with self.assertRaises(ValueError), self.module.UsageWriterGuard(root=self.root, owner_uid=os.geteuid() + 1):
            pass
        self.assertEqual(self.lock.stat().st_ino, original.st_ino)
        self.assertEqual(self.calls, [])

    def test_profile_is_revalidated_after_entry_and_outside_context_never_executes(self) -> None:
        self._profile()
        guard = self._guard()
        with self.assertRaises(ValueError):
            guard.reconcile()
        with guard as usage:
            self._write("var/lib/praho/usage/previous-hook", b"changed after entry")
            with self.assertRaises(ValueError):
                usage.reconcile()
        self.assertEqual(self.calls, [])
        self.assertEqual(self._probe(), "acquired")

    def test_actual_timeout_stops_descendant_writer_before_releasing_the_lock(self) -> None:
        self._profile()
        child_pid = self.root / "child.pid"
        writer_lock = self._write("writer.lock", b"owned descendant writer")
        child = "import fcntl,os,signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);fd=os.open(sys.argv[2],os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX);Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(30)"
        parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(30)"

        def execute(_arguments: list[str], timeout: float) -> str:
            return self.module.command([sys.executable, "-c", parent, child, str(child_pid), str(writer_lock)], timeout)

        try:
            with (
                self.assertRaises(TimeoutError),
                self.module.UsageWriterGuard(
                    root=self.root, owner_uid=os.geteuid(), executor=execute, command_timeout=1
                ) as usage,
            ):
                usage.reconcile()
            self.assertTrue(child_pid.is_file(), "The actual descendant writer must have started")
            deadline = monotonic() + 2
            while self._probe(writer_lock) == "blocked" and monotonic() < deadline:
                sleep(0.01)
            self.assertEqual(
                self._probe(writer_lock), "acquired", "A timed-out reconcile left its exact descendant writer active"
            )
            self.assertEqual(self._probe(), "acquired")
        finally:
            if child_pid.is_file():
                pid = int(child_pid.read_text())
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
