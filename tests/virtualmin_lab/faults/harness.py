"""The means to break the lab on purpose, at a chosen moment, and to mend it.

A fault is applied by a background thread that watches the node and fires when an operation is under way (a
backup archive appearing in the staging directory, for example). The thread only drives the docker CLI; PRAHO's
code and the database stay on the test's thread. `Chaos.restore_all` undoes every fault and is idempotent, so a
fixture can call it before and after every test and a failed test cannot leave the lab broken.

Nothing here restarts a node: a restart regenerates its TLS identity and invalidates the pins (the runner checks
them and re-bootstraps if it ever happens).
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

from django.utils import timezone

from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR, VirtualminBackupService
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.virtualmin_lab.workflows.harness import Bench

logger = logging.getLogger(__name__)

NETWORK = "virtualmin-lab_default"
API_WAIT_SECONDS = 120
TRIGGER_WAIT_SECONDS = 180
# How long settle waits for a command a fault left running to finish by itself before ending it.
DRAIN_WAIT_SECONDS = 90
# Started at boot (init.d/lookup-domain, the mail filter's domain lookups) and running for the node's lifetime.
VIRTUALMIN_DAEMONS = ("/virtual-server/lookup-domain-daemon.pl",)
# Where settle records what it found on a node; the lab workflow uploads it as an artifact, green or red.
DIAGNOSTICS_DIR = Path(__file__).resolve().parents[3] / "output" / "virtualmin-lab" / "faults"
# Webmin's lock files hold the locking process's PID. A failed search fails the listing (set -e), never empties it.
LOCK_LISTING = (
    "set -e; list=$(find /etc/webmin /var/webmin -name '*.lock'); "
    "printf '%s\\n' \"$list\" | while read -r f; do [ -n \"$f\" ] || continue; "
    'pid=$(head -c 32 "$f" 2>/dev/null | tr -dc 0-9); '
    'if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then echo "$f $pid"; fi; done'
)
NODE_STATE = (
    "echo '--- processes'; ps -eo pid,ppid,etime,stat,wchan:24,args --forest; "
    "echo '--- sockets'; ss -tanp 2>/dev/null; "
    "echo '--- lock files (path: content)'; find /etc/webmin /var/webmin -name '*.lock' 2>/dev/null | "
    'while read -r f; do echo "$f: $(head -c 64 "$f")"; done'
)


def docker(*argv: str, check: bool = True) -> str:
    """Run the docker CLI; a failure is a failed test unless `check` is off."""
    completed = subprocess.run(  # noqa: S603  # Fixed argv against local lab containers
        ["docker", *argv],  # noqa: S607  # docker from PATH, dev-only
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if check:
        assert completed.returncode == 0, f"docker {' '.join(argv)}: {completed.stderr.strip()}"
    return completed.stdout


def in_flight_operations(container: str) -> list[str]:
    """The Virtualmin commands running on a node (remote.cgi runs each as virtual-server/<program>.pl).

    Virtualmin's own resident daemons live in the same directory but are not operations. A failed listing is a
    failed test, never an empty node.
    """
    listing = docker("exec", container, "ps", "-eo", "pid=,etime=,wchan:24=,args=")
    return [
        line.strip()
        for line in listing.splitlines()
        if "/virtual-server/" in line and ".pl" in line and not any(daemon in line for daemon in VIRTUALMIN_DAEMONS)
    ]


def held_locks(container: str) -> list[str]:
    """Webmin lock files whose locking process is still alive, as "<path> <pid>"."""
    return [line.strip() for line in docker("exec", container, "sh", "-c", LOCK_LISTING).splitlines() if line.strip()]


def _pids(lines: list[str], column: int) -> set[str]:
    return {line.split()[column] for line in lines}


def _process_tree(container: str) -> dict[str, str]:
    """pid -> ppid for every process on the node; a failed listing is a failed test."""
    rows = (line.split() for line in docker("exec", container, "ps", "-eo", "pid=,ppid=").splitlines())
    return {row[0]: row[1] for row in rows if len(row) == 2}


def _with_descendants(container: str, pids: set[str]) -> set[str]:
    """`pids` and every process below them, read before anything is signalled (children are reparented after)."""
    tree, cohort = _process_tree(container), set(pids)
    grew = True
    while grew:
        children = {pid for pid, ppid in tree.items() if ppid in cohort} - cohort
        cohort |= children
        grew = bool(children)
    return cohort


def _capture(container: str, script: str) -> str:
    """A diagnostic command's output, its errors and its exit status: evidence even when it fails."""
    completed = subprocess.run(  # noqa: S603  # Fixed argv against local lab containers
        ["docker", "exec", container, "sh", "-c", script],  # noqa: S607  # docker from PATH, dev-only
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return f"{completed.stdout}{completed.stderr}(exit {completed.returncode})"


@dataclass
class Fault:
    """One fault armed on a background thread; `fired` is set once it has been applied."""

    name: str
    fired: threading.Event = field(default_factory=threading.Event)
    error: str = ""


class Chaos:
    """Faults against the lab nodes, and the way back."""

    def __init__(self, bench: Bench) -> None:
        self.bench = bench

    # ------------------------------------------------------------- the faults

    def stop_webmin(self, key: str) -> None:
        docker("exec", self.bench.node(key).container, "systemctl", "stop", "webmin")

    def start_webmin(self, key: str) -> None:
        docker("exec", self.bench.node(key).container, "systemctl", "start", "webmin")

    def pause(self, key: str) -> None:
        docker("pause", self.bench.node(key).container)

    def unpause(self, key: str) -> None:
        docker("unpause", self.bench.node(key).container, check=False)

    def disconnect(self, key: str) -> None:
        docker("network", "disconnect", NETWORK, self.bench.node(key).container)

    def connect(self, key: str) -> None:
        docker("network", "connect", NETWORK, self.bench.node(key).container, check=False)

    # ---------------------------------------------------------------- timing

    def staging_has_archive(self, key: str) -> Callable[[], bool]:
        """True once an archive is being written in (or has been pushed to) the node's staging directory."""
        container = self.bench.node(key).container

        def check() -> bool:
            listing = docker(
                "exec", container, "sh", "-c", f"ls -1A {REMOTE_ARCHIVE_DIR} 2>/dev/null || true", check=False
            )
            return any(name.startswith("virtualmin_backup_") for name in listing.split())

        return check

    @contextmanager
    def during(self, when: Callable[[], bool], action: Callable[[], None], *, delay: float = 0.0) -> Iterator[Fault]:
        """Apply `action` once `when()` holds (plus `delay` seconds), while the body runs.

        The body must run an operation long enough for the condition to come true; if it never does, the
        context raises when the body ends, so a fault that never fired is a failed test, never a pass.
        """
        fault = Fault(name=getattr(action, "__name__", "fault"))
        stop = threading.Event()

        def watch() -> None:
            deadline = time.monotonic() + TRIGGER_WAIT_SECONDS
            try:
                while not stop.is_set() and time.monotonic() < deadline:
                    if when():
                        time.sleep(delay)
                        action()
                        fault.fired.set()
                        return
                    time.sleep(0.4)
            except Exception as error:  # Reported to the test, never swallowed
                fault.error = repr(error)

        thread = threading.Thread(target=watch, name=f"fault-{fault.name}", daemon=True)
        thread.start()
        try:
            yield fault
        finally:
            stop.set()
            thread.join(timeout=30)
        assert not fault.error, fault.error
        assert fault.fired.is_set(), "the operation ended before the fault could be applied"

    # ------------------------------------------------------------- the way back

    def wait_api(self, key: str) -> None:
        """Block until the node answers an authenticated API call again."""
        gateway = self.bench.lab(key).gateway
        deadline = time.monotonic() + API_WAIT_SECONDS
        last = ""
        while time.monotonic() < deadline:
            self.bench.reset_meters()
            answer = gateway.call("info")
            if answer.is_ok():
                return
            last = str(answer.unwrap_err())
            time.sleep(2)
        raise AssertionError(f"{key} does not answer the API after the restore: {last}")

    def mend(self) -> None:
        """Undo every fault on every node: unpause, reconnect, start Webmin, wait for the API.

        Jobs a fault parked are left as they are: a test asserts on them once the node answers again. What a
        fault left running on a node is `settle`'s business, after those assertions.
        """
        for node in self.bench.state.nodes:
            self.unpause(node.key)
            self.connect(node.key)
            docker("exec", node.container, "systemctl", "start", "webmin", check=False)
        for node in self.bench.state.nodes:
            self.wait_api(node.key)
        self.bench.reset_meters()

    def settle(self, key: str) -> None:
        """Wait for commands and lock holders a fault left on a node; end, by PID, what outlives the wait.

        A cut connection can strand a command on the node after PRAHO has given up on its answer, still holding
        Virtualmin's locks, so the next call that needs them waits and times out while `info` (which takes none)
        still answers. What is found is written down at once, for CI to keep, then every step is appended to it.
        """
        container = self.bench.node(key).container
        running, locks = in_flight_operations(container), held_locks(container)
        if not running and not locks:
            return
        path = self._record(key, [f"{key}: {len(running)} in-flight command(s), {len(locks)} held lock(s)", *running, *locks])
        try:
            self._append(path, [_capture(container, NODE_STATE)])
            deadline = time.monotonic() + DRAIN_WAIT_SECONDS
            while (running or locks) and time.monotonic() < deadline:
                time.sleep(2)
                running, locks = in_flight_operations(container), held_locks(container)
            if not running and not locks:
                self._append(path, ["finished by itself within the wait"])
                return
            cohort = sorted(_with_descendants(container, _pids(running, 0) | _pids(locks, 1)))
            self._append(path, [f"ended after {DRAIN_WAIT_SECONDS}s: TERM {' '.join(cohort)}"])
            docker("exec", container, "kill", "-TERM", *cohort, check=False)
            survivors = self._alive(container, cohort, wait_seconds=10)
            if survivors:
                self._append(path, [f"KILL {' '.join(survivors)}"])
                docker("exec", container, "kill", "-KILL", *survivors, check=False)
                survivors = self._alive(container, survivors, wait_seconds=10)
            left, still_locked = in_flight_operations(container), held_locks(container)
            self._append(path, [f"after: survivors={survivors} in-flight={left} locks={still_locked}"])
            assert not survivors, f"{key}: {survivors} survived TERM and KILL (see {path})"
            assert not left and not still_locked, f"{key}: work remains after settling (see {path})"
        except BaseException as error:
            self._append(path, [f"settle failed: {error!r}"])
            raise
        self.wait_api(key)

    @staticmethod
    def _alive(container: str, pids: list[str], *, wait_seconds: int) -> list[str]:
        """The PIDs still running after up to `wait_seconds`, from a checked full listing."""
        deadline = time.monotonic() + wait_seconds
        while True:
            alive = sorted(set(_process_tree(container)) & set(pids))
            if not alive or time.monotonic() >= deadline:
                return alive
            time.sleep(1)

    @staticmethod
    def _record(key: str, lines: list[str]) -> Path:
        DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
        path = DIAGNOSTICS_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}-{key}-{time.monotonic_ns()}.txt"
        path.write_text("\n".join(lines) + "\n")
        print(f"\n⚠️ [Virtualmin faults] {lines[0]}; recorded in {path}")
        logger.warning("⚠️ [Virtualmin faults] %s (recorded in %s)", lines[0], path)
        return path

    @staticmethod
    def _append(path: Path, lines: list[str]) -> None:
        with path.open("a") as record:
            record.write("\n".join(lines) + "\n")

    @contextmanager
    def hosted(self, domain: str, *, node: str = "vm-a") -> Iterator[VirtualminAccount]:
        """`Bench.hosted`, with the node mended and settled after the test body and before the account is removed.

        The body's assertions see the node as the fault left it; the removal then never waits behind a command
        the fault stranded.
        """
        with self.bench.hosted(domain, node=node) as account:
            try:
                yield account
            finally:
                self.mend()
                self.settle(node)

    def restore_all(self) -> None:
        """`mend` and `settle`, then clear the debris a fault left: parked jobs and queued tasks."""
        self.mend()
        for node in self.bench.state.nodes:
            self.settle(node.key)
        self.close_parked_jobs()
        self.bench.clear_queue()

    def close_parked_jobs(self) -> None:
        """Nobody attends the lab: close what a fault left parked, as the operator's resolve does."""
        for job in VirtualminProvisioningJob.objects.filter(
            status__in=("attention", "pending", "running"), account__domain__startswith="wf"
        ):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(  # fsm-bypass: lab cleanup of a faulted job
                status="failed", next_retry_at=None, updated_at=timezone.now()
            )

    def remove_staged(self, key: str) -> None:
        """Remove archives a fault stranded in a node's staging directory."""
        docker(
            "exec",
            self.bench.node(key).container,
            "sh",
            "-c",
            f"rm -f {REMOTE_ARCHIVE_DIR}/virtualmin_backup_* {REMOTE_ARCHIVE_DIR}/migration_*",
            check=False,
        )


@contextmanager
def count_attempts() -> Iterator[Counter[str]]:
    """Count every HTTP request any production gateway sends, by Virtualmin program.

    The gateway's replay decision happens above this seam and its transport below it, so the counter sees
    exactly what reached (or tried to reach) the node.
    """
    attempts: Counter[str] = Counter()
    original = VirtualminGateway._execute_http_request

    def counting(self: VirtualminGateway, params: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        attempts[str(params.get("program"))] += 1
        return original(self, params, *args, **kwargs)

    with patch.object(VirtualminGateway, "_execute_http_request", counting):
        yield attempts


def backup_objects(server: Any) -> set[str]:
    """Every object key under the backup prefix in the object store."""
    service = VirtualminBackupService(server)
    client, bucket = service._get_s3_client(), service._get_backup_bucket()
    keys: set[str] = set()
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="virtualmin-backups/"):
        keys.update(item["Key"] for item in page.get("Contents", []))
    return keys


def resolve_as_operator(job: VirtualminProvisioningJob, note: str) -> None:
    """The staff 'mark resolved' action for a parked job (virtualmin_job_resolve): attention to failed, audited."""
    from apps.provisioning.virtualmin_signals import audit_job_status_transition  # noqa: PLC0415

    rows = VirtualminProvisioningJob.objects.filter(
        pk=job.pk, status="attention"
    ).update(  # fsm-bypass: CharField job status; attention -> failed is the only edge
        status="failed", status_message=f"Manually resolved by workflow: {note}", next_retry_at=None
    )
    assert rows == 1, "only a job awaiting attention can be resolved"
    job.refresh_from_db()
    audit_job_status_transition(job, actor_type="user")


def exclusion_holds(account: VirtualminAccount) -> bool:
    """Whether the account's operation exclusion refuses a new operation (backup, restore, delete, migration)."""
    from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415

    return account_has_active_operation(account)
