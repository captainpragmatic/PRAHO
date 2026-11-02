#!/usr/bin/env python3
"""Token-owned read-only website binds after exact PHP writer exit.

This is the filesystem part of a component migration, not the whole write barrier.
The caller also owns website ingress, selected jobs and isolated database fencing.
Mail, DNS, Unix authentication, home ownership and unrelated processes are untouched.
"""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import re
import select
import signal
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

MAX_JOURNAL_BYTES = 1024 * 1024
FENCE_SCHEMA = 2
PROCESS_EXIT_TIMEOUT = 5
START_TIME_INDEX = 19


class FencingSystem:
    def __init__(self, proc: Path = Path("/proc")) -> None:
        self.proc = proc
        path = Path(__file__).with_name("praho-component-paths.py")
        spec = importlib.util.spec_from_file_location("component_native_paths", path)
        if spec is None or spec.loader is None:
            raise ValueError("Component path qualification is unavailable")
        self.paths = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.paths)

    @property
    def boot_id(self) -> str:
        return str(UUID((self.proc / "sys/kernel/random/boot_id").read_text().strip()))

    def scan(self, home: Path, selected: tuple[str, ...]) -> dict[str, Any]:
        return self.paths.scan_paths(home, selected)

    def writers(self, scope: dict[str, Any], domain_id: str, owner_uid: int) -> list[dict[str, Any]]:
        return self.paths.path_writers(scope["inodes"], domain_id, owner_uid, proc=self.proc)

    def qualify(
        self, home: Path, selected: tuple[str, ...], owned_mounts: dict[str, list[int]] | None = None
    ) -> dict[str, Any]:
        return self.paths.qualify_mounts(home, selected, owned_mounts=owned_mounts, proc=self.proc)

    def assert_writer(self, witness: dict[str, Any]) -> None:
        process = self.proc / str(witness["pid"])
        fields = (process / "stat").read_text().rpartition(")")[2].split()
        namespace = os.readlink(process / "ns/mnt")
        if (
            len(fields) <= START_TIME_INDEX
            or fields[START_TIME_INDEX] != witness["start_time"]
            or namespace != f"mnt:[{witness['mount_namespace']}]"
        ):
            raise ValueError("Process or namespace identity changed; refusing a reused PID")

    def is_stopped(self, writer: dict[str, Any]) -> bool:
        if not (self.proc / str(writer["pid"])).exists():
            return False
        if self.exited(writer):
            return False
        self.assert_writer(writer)
        status = (self.proc / str(writer["pid"]) / "status").read_text()
        return re.search(r"^State:\s+[Tt]\b", status, re.MULTILINE) is not None

    def exited(self, writer: dict[str, Any]) -> bool:
        """An old PID birth must be gone or a dead process with no remaining descriptors."""
        process = self.proc / str(writer["pid"])
        try:
            fields = (process / "stat").read_text().rpartition(")")[2].split()
            if len(fields) <= START_TIME_INDEX:
                raise ValueError("Selected writer exit evidence is incomplete")
            if fields[START_TIME_INDEX] != writer["start_time"]:
                return True  # This old birth exited; never inspect or signal its replacement.
            if fields[0] not in {"Z", "X"}:
                return False
            with os.scandir(process / "fd") as descriptors:
                if next(descriptors, None) is not None:
                    raise ValueError("Dead selected writer still has unconfirmed descriptor closure")
            return True
        except (FileNotFoundError, ProcessLookupError):
            if process.exists():
                raise ValueError("A live selected writer has unreadable exit evidence") from None
            return True

    @staticmethod
    def _wait_exit(descriptor: int) -> bool:
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLHUP)
        return any(
            events & (select.POLLIN | select.POLLHUP)
            for _descriptor, events in poller.poll(PROCESS_EXIT_TIMEOUT * 1000)
        )

    def terminate(self, writer: dict[str, Any]) -> None:
        """Kill only the classified site child; a pidfd binds signals to its original birth."""
        try:
            descriptor = os.pidfd_open(writer["pid"])
        except ProcessLookupError:
            if self.exited(writer):
                return
            raise ValueError("Selected writer disappeared without confirmed exit") from None
        try:
            if self.exited(writer):
                return
            self.assert_writer(writer)
            actual = self.paths._writer_identity(self.proc / str(writer["pid"]), writer["identity"], writer["uid"])
            if actual != writer or actual["kind"] != "php_fpm_pool":
                raise ValueError("The selected PHP writer classification changed before termination")
            if self.is_stopped(writer):
                raise ValueError("A pre-existing stopped PHP writer needs explicit preparation before termination")
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                if not self._wait_exit(descriptor):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The held pidfd still independently proves this exact process exit below.
            if not self._wait_exit(descriptor) or not self.exited(writer):
                raise ValueError("Selected PHP writer exit and descriptor closure remain unconfirmed")
        except FileNotFoundError:
            if not self.exited(writer):
                raise ValueError("Selected PHP writer identity became unreadable before termination") from None
        finally:
            os.close(descriptor)

    def _command(self, namespace: dict[str, Any], argv: list[str]) -> str:
        self.assert_writer(namespace)
        return subprocess.run(  # noqa: S603 -- validated namespace witness and literal command arguments, no shell
            ["/usr/bin/nsenter", "--target", str(namespace["pid"]), "--mount", "--", *argv],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()

    def bind_read_only(self, namespace: dict[str, Any], path: Path, receipt: Callable[[int], None]) -> None:
        self._command(namespace, ["mount", "--bind", str(path), str(path)])
        identifier = self._command(namespace, ["findmnt", "-rn", "-o", "ID", "--mountpoint", str(path)])
        if not identifier.isdecimal():
            raise ValueError("Created website bind has no exact mount ID; inspection is required")
        receipt(int(identifier))  # Durable ownership before the read-only remount.
        self._command(namespace, ["mount", "-o", "remount,bind,ro", str(path)])

    def unmount(self, namespace: dict[str, Any], path: Path, mount_id: int) -> None:
        current = self._command(namespace, ["findmnt", "-rn", "-o", "ID", "--mountpoint", str(path)])
        if current != str(mount_id):
            raise ValueError("Website bind ownership changed; refusing to unmount another actor's mount")
        # Detach only this exact owned bind. Existing readers may finish on the detached read-only
        # view; new opens return to the original source tree during pre-commit compensation.
        self._command(namespace, ["umount", "--lazy", str(path)])

    def mount_present(self, namespace: dict[str, Any], path: Path, mount_id: int) -> bool:
        self.assert_writer(namespace)
        mounts = self.paths._mount_table(self.proc / str(namespace["pid"]), namespace["mount_namespace"])
        self.assert_writer(namespace)
        matches = [mount for mount in mounts if mount["mount_id"] == mount_id]
        if not matches:
            return False  # Complete native namespace inventory independently proves a lost unmount receipt.
        if len(matches) != 1 or matches[0]["mountpoint"] != str(path):
            raise ValueError("The component bind moved; reconcile its exact mount before compensation")
        return True


class PathFence:
    def __init__(  # noqa: PLR0913 -- independent native identity, exact scope, operator attempt and test boundaries
        self,
        home: Path,
        selected: tuple[str, ...],
        domain_id: str,
        owner_uid: int,
        operation_id: str,
        tree_digest: str,
        *,
        state_dir: Path = Path("/var/lib/praho/component-fences"),
        system: Any = None,
    ) -> None:
        if not re.fullmatch(r"[0-9]{1,30}", domain_id) or type(owner_uid) is not int or owner_uid <= 0:
            raise ValueError("A native domain and non-root owner are required")
        if str(UUID(operation_id)) != operation_id or not re.fullmatch(r"[0-9a-f]{64}", tree_digest):
            raise ValueError("A canonical operation UUID and reviewed tree digest are required")
        self.home, self.selected, self.domain_id = home, selected, domain_id
        self.owner_uid, self.operation_id, self.tree_digest = owner_uid, operation_id, tree_digest
        self.system = system if system is not None else FencingSystem()
        self.state_dir, self.state_file = state_dir, state_dir / f"{domain_id}.json"

    def _read(self) -> dict[str, Any] | None:
        if not self.state_file.exists() and not self.state_file.is_symlink():
            return None
        info = self.state_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("The component fence journal is not a private owned file")
        with self.state_file.open() as stream:
            content = stream.read(MAX_JOURNAL_BYTES + 1)
        if len(content) > MAX_JOURNAL_BYTES:
            raise ValueError("Component fence journal exceeds its bound")
        state = json.loads(content)
        if not isinstance(state, dict) or state.get("schema") != FENCE_SCHEMA:
            raise ValueError("Component fence journal schema is unsupported")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_JOURNAL_BYTES:
            raise ValueError("Component fence journal exceeds its bound")
        descriptor, temporary = tempfile.mkstemp(dir=self.state_dir, prefix=".component-")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_file)
            descriptor = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self.state_dir.resolve() != self.state_dir:
            raise ValueError("Component state must not have symlinked ancestors")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Component state directory is not privately owned")
        descriptor = os.open(self.state_dir / f"{self.domain_id}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _identity(self, state: dict[str, Any]) -> None:
        expected = {
            "operation_id": self.operation_id,
            "domain_id": self.domain_id,
            "home": str(self.home),
            "selected": list(self.selected),
            "owner_uid": self.owner_uid,
            "tree_digest": self.tree_digest,
            "boot_id": self.system.boot_id,
        }
        if any(state.get(key) != value for key, value in expected.items()):
            raise ValueError("Component fence identity, attempt, scope or boot changed; inspect before proceeding")

    @staticmethod
    def _owned_mounts(state: dict[str, Any]) -> dict[str, list[int]]:
        result: dict[str, list[int]] = {}
        for mount in state["mounts"]:
            if mount["phase"] == "released":
                continue
            if not isinstance(mount.get("mount_id"), int):
                raise ValueError("A mount intent has no confirmed ownership receipt; manual inspection is required")
            result.setdefault(mount["namespace"]["mount_namespace"], []).append(mount["mount_id"])
        return result

    def _preflight(self) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
        scope = self.system.scan(self.home, self.selected)
        if scope["tree_digest"] != self.tree_digest:
            raise ValueError("Selected application paths changed after review; inspect the source again")
        topology = self.system.qualify(self.home, self.selected)
        writers = self.system.writers(scope, self.domain_id, self.owner_uid)
        if any(writer["kind"] != "php_fpm_pool" for writer in writers):
            raise ValueError("Unclassified source writer: prepare it before any source mutation")
        if any(self.system.is_stopped(writer) for writer in writers):
            raise ValueError("A pre-existing stopped PHP writer needs explicit preparation before source mutation")
        return scope, writers, topology

    def apply(self) -> None:
        existing = self._read()
        if existing is not None and existing.get("operation_id") == self.operation_id:
            with self._locked():
                state = self._read()
                if state is None:
                    raise ValueError("Component fence journal disappeared")
                self._verify(state)
            return
        # Refuse incomplete topology or unclassified writers before even creating a journal.
        self._preflight()
        with self._locked():
            existing = self._read()
            if existing is not None and existing.get("phase") != "released":
                raise ValueError("Another component attempt still owns this native domain")
            _scope, writers, topology = self._preflight()
            state: dict[str, Any] = {
                "schema": FENCE_SCHEMA,
                "operation_id": self.operation_id,
                "domain_id": self.domain_id,
                "home": str(self.home),
                "selected": list(self.selected),
                "owner_uid": self.owner_uid,
                "tree_digest": self.tree_digest,
                "boot_id": self.system.boot_id,
                "phase": "applying",
                "writers": [],
                "mounts": [],
            }
            self._write(state)
            try:
                self._apply(state, writers, topology)
            except Exception:
                state["phase"] = "needs_review"
                self._write(state)
                raise

    def _apply(self, state: dict[str, Any], writers: list[dict[str, Any]], topology: dict[str, Any]) -> None:
        for writer in writers:
            record = {"witness": writer, "phase": "intent"}
            state["writers"].append(record)
            self._write(state)
            self.system.terminate(writer)
            if not self.system.exited(writer):
                raise ValueError("Selected PHP writer descriptor closure is unconfirmed")
            record["phase"] = "exited"
            self._write(state)
        # A terminated worker must never remain the namespace witness used for a mount.
        topology = self.system.qualify(self.home, self.selected)
        for namespace in topology["namespaces"]:
            for root in namespace["roots"]:
                record = {"namespace": namespace, "path": root, "phase": "intent"}
                state["mounts"].append(record)
                self._write(state)

                def receipt(identifier: int, record: dict[str, Any] = record) -> None:
                    record["mount_id"] = identifier
                    self._write(state)

                self.system.bind_read_only(namespace, Path(root), receipt)
                record["phase"] = "held"
                self._write(state)
        state["phase"] = "held"
        self._write(state)
        self._verify(state)

    def _verify(self, state: dict[str, Any]) -> dict[str, Any]:
        self._identity(state)
        if state["phase"] != "held":
            raise ValueError("Component path fence is not conclusively held")
        topology = self.system.qualify(self.home, self.selected, self._owned_mounts(state))
        expected = {
            (mount["namespace"]["mount_namespace"], mount["path"]): mount["mount_id"]
            for mount in state["mounts"]
            if mount["phase"] == "held"
        }
        observed = {
            (mount["mount_namespace"], mount["mountpoint"]): mount["mount_id"]
            for mount in topology["mounts"]
            if mount["read_only"]
        }
        for namespace in topology["namespaces"]:
            for root in namespace["roots"]:
                key = (namespace["mount_namespace"], root)
                if key not in expected or observed.get(key) != expected[key]:
                    raise ValueError("Every live namespace needs its exact owned read-only website bind")
        for record in state["writers"]:
            if record["phase"] != "exited" or not self.system.exited(record["witness"]):
                raise ValueError("An old selected writer has unconfirmed exit or descriptor closure")
        scope = self.system.scan(self.home, self.selected)
        if scope["tree_digest"] != self.tree_digest:
            raise ValueError("Selected application topology changed while fenced")
        if self.system.writers(scope, self.domain_id, self.owner_uid):
            raise ValueError("A new unclassified handle bypasses the selected website fence")
        return topology

    def verify(self) -> None:
        with self._locked():
            state = self._read()
            if state is None:
                raise ValueError("The component path fence has no journal")
            self._verify(state)

    def release(self) -> None:
        with self._locked():
            state = self._read()
            if state is None:
                raise ValueError("The component path fence has no journal")
            self._identity(state)
            if state["phase"] == "released":
                return
            if state["phase"] == "held":
                topology = self._verify(state)
            elif state["phase"] == "releasing":
                # A lost unmount receipt is resolved from the complete native mount table.
                # Process witnesses remain pinned; never remove an unrecorded mount by path.
                topology = {"namespaces": [mount["namespace"] for mount in state["mounts"]]}
            else:
                raise ValueError("Incomplete fence application requires inspection before compensation")
            namespaces = {entry["mount_namespace"]: entry for entry in topology["namespaces"]}
            state["phase"] = "releasing"
            self._write(state)
            for mount in reversed(state["mounts"]):
                if mount["phase"] == "released":
                    continue
                namespace = namespaces.get(mount["namespace"]["mount_namespace"])
                if namespace is not None and self.system.mount_present(
                    namespace, Path(mount["path"]), mount["mount_id"]
                ):
                    self.system.unmount(namespace, Path(mount["path"]), mount["mount_id"])
                mount["phase"] = "released"
                self._write(state)
            # Restore only the exact owned views. PHP-FPM may supply fresh workers;
            # an old selected process is never resumed or signalled during compensation.
            self.system.qualify(self.home, self.selected)
            for record in state["writers"]:
                if record["phase"] == "released":
                    continue
                if record["phase"] != "exited" or not self.system.exited(record["witness"]):
                    raise ValueError("Selected writer exit is unconfirmed; reconcile before compensation")
                record["phase"] = "released"
                self._write(state)
            state["phase"] = "released"
            self._write(state)
