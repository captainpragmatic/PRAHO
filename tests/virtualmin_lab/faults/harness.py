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

        Jobs a fault parked are left as they are: a test asserts on them once the node answers again.
        """
        for node in self.bench.state.nodes:
            self.unpause(node.key)
            self.connect(node.key)
            docker("exec", node.container, "systemctl", "start", "webmin", check=False)
        for node in self.bench.state.nodes:
            self.wait_api(node.key)
        self.bench.reset_meters()

    def restore_all(self) -> None:
        """`mend`, then clear the debris a fault left: parked jobs and queued tasks."""
        self.mend()
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
