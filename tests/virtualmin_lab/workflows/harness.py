"""What a workflow test uses: PRAHO's queue, the lab nodes and the two ledgers (PRAHO rows and node state).

A workflow runs PRAHO's real services, jobs and tasks against the lab. The lab has no Django-Q worker, so
`Bench.run_queue` plays the worker's part: it takes what the code under test queued from the ORM broker and
calls the task function by its dotted path, exactly as a worker does. Nothing else is stubbed; the transport
adaptations of `lab_transport` are the only difference from a production node.

Every assertion a workflow makes has two halves: what PRAHO recorded (rows, jobs, audit events) and what the
node holds (`list-domains`, file content). The node half reuses the contract suite's `Lab`.

Nothing here skips. A workflow that cannot reach the lab fails with the reason.
"""

from __future__ import annotations

import importlib
import logging
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django_q.models import OrmQ

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.management.commands._virtualmin_lab import LabNode, LabState
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR, BackupConfig, RestoreConfig
from apps.provisioning.virtualmin_gateway import VirtualminConfig
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.settings.services import SettingsService
from tests.virtualmin_lab.contract.harness import Lab, Recorder, RecordingGateway

logger = logging.getLogger(__name__)

# Leftovers of an interrupted run are domains named like this and nothing else.
WORKFLOW_DOMAIN_PREFIX = "wf"
# The provisioning pipeline refuses a domain with a "test" label (security_utils), so workflow domains live here.
WORKFLOW_SUFFIX = ".example.com"
# Only these task modules do work for the workflows; the rest of the queue (e-mail, notifications) is discarded.
WORKER_MODULES = ("apps.provisioning.virtualmin_tasks", "apps.provisioning.tasks")
QUEUE_PASSES = 20


def is_workflow_domain(name: str) -> bool:
    return name.startswith(WORKFLOW_DOMAIN_PREFIX) and name.endswith(WORKFLOW_SUFFIX)


@dataclass
class TaskRun:
    """One task a worker would have run."""

    func: str
    args: tuple[Any, ...]
    result: Any = None
    error: str = ""

    @property
    def name(self) -> str:
        return self.func.rsplit(".", 1)[-1]


@dataclass
class Bench:
    """The lab as a workflow sees it: both nodes, the queue, and the way back to a clean state."""

    state: LabState
    labs: dict[str, Lab]
    saved_settings: dict[str, Any] = field(default_factory=dict)
    saved_servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    initial_domain_counts: dict[str, int] = field(default_factory=dict)

    # ---------------------------------------------------------------- nodes

    def lab(self, key: str) -> Lab:
        return self.labs[key]

    def node(self, key: str) -> LabNode:
        return self.state.node(key)

    def key_of(self, server: VirtualminServer) -> str:
        for node in self.state.nodes:
            if node.server_hostname == server.hostname:
                return node.key
        raise AssertionError(f"{server.hostname} is not a lab node")

    def lab_of(self, account: VirtualminAccount) -> Lab:
        """The node the account lives on, according to PRAHO."""
        account.refresh_from_db()
        return self.labs[self.key_of(VirtualminServer.objects.get(pk=account.server_id))]

    def server(self, key: str) -> VirtualminServer:
        return VirtualminServer.objects.get(hostname=self.state.node(key).server_hostname)

    # ------------------------------------------------------------- settings

    def set_setting(self, key: str, value: Any) -> None:
        """Change a setting for the run; `put_back` puts every one back."""
        if key not in self.saved_settings:
            # A setting never written reads as None, which update_setting refuses: put back the type's zero
            # (False for the flags), which is what the code reads while the row is absent.
            original = SettingsService.get_setting(key)
            self.saved_settings[key] = type(value)() if original is None else original
        result = SettingsService.update_setting(key, value)
        assert result.is_ok(), f"{key}: {result.unwrap_err()}"

    def set_server_fields(self, key: str, **fields: Any) -> None:
        server = self.server(key)
        saved = self.saved_servers.setdefault(key, {})
        for name in fields:
            saved.setdefault(name, getattr(server, name))
        for name, value in fields.items():
            setattr(server, name, value)
        server.save(update_fields=[*fields, "updated_at"])

    def put_back(self) -> None:
        failures = []
        for key, value in self.saved_settings.items():
            result = SettingsService.update_setting(key, value)
            if result.is_err():
                failures.append(f"{key} -> {value!r}: {result.unwrap_err()}")
        self.saved_settings.clear()
        for key, fields in self.saved_servers.items():
            server = self.server(key)
            for name, value in fields.items():
                setattr(server, name, value)
            server.save(update_fields=[*fields, "updated_at"])
        self.saved_servers.clear()
        for key, count in self.initial_domain_counts.items():
            VirtualminServer.objects.filter(hostname=self.state.node(key).server_hostname).update(current_domains=count)
        assert not failures, f"settings not put back: {failures}"

    # ---------------------------------------------------------------- queue

    def clear_queue(self) -> None:
        OrmQ.objects.all().delete()

    def queued(self) -> list[str]:
        return [str(row.task.get("func", "")).rsplit(".", 1)[-1] for row in OrmQ.objects.order_by("id")]

    def run_queue(self, *, passes: int = QUEUE_PASSES) -> list[TaskRun]:
        """Run what the code under test queued, the way a Django-Q worker does, until the queue is empty.

        A task that raises is recorded, not propagated: production's worker records the failure and moves on,
        and a workflow asserts on the outcome in PRAHO and on the node.
        """
        ran: list[TaskRun] = []
        for _ in range(passes):
            rows = list(OrmQ.objects.order_by("id"))
            if not rows:
                return ran
            for row in rows:
                task = row.task
                OrmQ.objects.filter(pk=row.pk).delete()
                func = str(task.get("func", ""))
                module, _, name = func.rpartition(".")
                if module not in WORKER_MODULES:
                    continue  # e-mail, notifications: not part of any hosting workflow
                run = TaskRun(func=func, args=tuple(task.get("args", ())))
                try:
                    run.result = getattr(importlib.import_module(module), name)(
                        *run.args, **dict(task.get("kwargs", {}))
                    )
                except Exception:  # A worker records a failed task and carries on
                    run.error = traceback.format_exc()
                    logger.warning("⚠️ [Workflows] task %s raised:\n%s", name, run.error)
                ran.append(run)
        raise AssertionError(f"the queue was still busy after {passes} passes: {self.queued()}")

    # ------------------------------------------------------------- accounts

    def new_service(self, domain: str, *, status: str = "active") -> Service:
        customer = Customer.objects.get(primary_email="lab@praho.test")
        return Service.objects.create(
            customer=customer,
            service_plan=ServicePlan.objects.get(name="Virtualmin lab hosting"),
            currency=Currency.objects.get(code="RON"),
            service_name=domain,
            domain=domain,
            username=domain.split(".", 1)[0],
            billing_cycle="monthly",
            price=Decimal("0.00"),
            status=status,
        )

    def provision(self, domain: str) -> VirtualminAccount:
        """An active Service for `domain`, taken to a hosted account by PRAHO's own signal, reconcile and task."""
        self.clear_queue()
        service = self.new_service(domain)
        runs = self.run_queue()
        failed = [run for run in runs if run.error]
        assert not failed, failed[0].error
        account = VirtualminAccount.objects.filter(service=service).first()
        assert account is not None, f"provisioning created no account for {domain}: {[run.name for run in runs]}"
        account.refresh_from_db()
        return account

    def prefer(self, key: str) -> None:
        """Make `key` the node placement picks (the heaviest server wins)."""
        for node in self.state.nodes:
            self.set_server_fields(node.key, weight=300 if node.key == key else 100)

    @contextmanager
    def hosted(self, domain: str, *, node: str = "vm-a") -> Iterator[VirtualminAccount]:
        """An account provisioned on `node` through the real pipeline, removed from both nodes and PRAHO afterwards."""
        self.forget(domain)
        self.prefer(node)
        self.reset_meters()
        account = self.provision(domain)
        try:
            yield account
        finally:
            self.forget(domain)

    # ---------------------------------------------------------- backup jobs

    def staged(self, account: VirtualminAccount) -> list[str]:
        """Archives left in the node's staging directory: none once a backup is published or a restore is done."""
        listing = self.lab_of(account).exec("sh", "-c", 'ls -1A "$1" 2>/dev/null || true', "sh", REMOTE_ARCHIVE_DIR)
        return [name for name in listing.split() if name.startswith(("virtualmin_backup_", "migration_"))]

    def run_one(self, task: str) -> TaskRun:
        """Run the one task the admission queued, and no other."""
        assert self.queued() == [task], self.queued()
        [run] = self.run_queue()
        assert run.name == task and not run.error, run.error
        return run

    def backup(self, account: VirtualminAccount, config: BackupConfig | None = None) -> VirtualminProvisioningJob:
        """Admit a backup through the service, run its queued task, and return the job (completed or not)."""
        self.clear_queue()
        admitted = VirtualminBackupManagementService(account.server).create_backup_job(
            account, config or BackupConfig(), initiated_by="workflow"
        )
        assert admitted.is_ok(), admitted
        job = admitted.unwrap()
        assert job.status == "pending", "admission queues the work; nothing has run yet"
        self.run_one("run_virtualmin_backup")
        job.refresh_from_db()
        return job

    def restore(self, account: VirtualminAccount, backup_id: str, *, force: bool = False) -> VirtualminProvisioningJob:
        self.clear_queue()
        admitted = VirtualminBackupManagementService(account.server).create_restore_job(
            account, RestoreConfig(backup_id=backup_id, force_restore=force), initiated_by="workflow"
        )
        assert admitted.is_ok(), admitted
        job = admitted.unwrap()
        assert job.status == "pending"
        self.run_one("run_virtualmin_restore")
        job.refresh_from_db()
        return job

    def forget(self, domain: str) -> None:
        """Remove a workflow domain from both nodes and from PRAHO."""
        from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration  # noqa: PLC0415

        for lab in self.labs.values():
            lab.remove_domain(domain)
            # A migration keeps its archive on both nodes by design (removed by hand after verification).
            lab.exec("sh", "-c", 'rm -f "$1"/migration_*', "sh", REMOTE_ARCHIVE_DIR)
        migrations = VirtualminMigration.objects.filter(account__domain=domain)
        NodeDrain.objects.filter(current_migration__in=migrations).update(current_migration=None)
        migrations.delete()
        VirtualminProvisioningJob.objects.filter(account__domain=domain).delete()
        VirtualminAccount.objects.filter(domain=domain).delete()
        Service.objects.filter(domain=domain).delete()

    def remove_leftovers(self) -> None:
        self.clear_queue()
        for lab in self.labs.values():
            for name in lab.domain_names():
                if is_workflow_domain(name):
                    self.forget(name)
        rows = [
            *VirtualminAccount.objects.filter(domain__startswith=WORKFLOW_DOMAIN_PREFIX).values_list("domain", flat=True),
            *Service.objects.filter(domain__startswith=WORKFLOW_DOMAIN_PREFIX).values_list("domain", flat=True),
        ]
        for domain in sorted({name for name in rows if is_workflow_domain(name)}):
            self.forget(domain)

    def refresh_health(self) -> None:
        """Stamp both servers healthy through PRAHO's own health-check task (placement and migration require it)."""
        from apps.provisioning.virtualmin_tasks import health_check_virtualmin_servers  # noqa: PLC0415

        outcome = health_check_virtualmin_servers()
        assert outcome["success"], outcome
        assert outcome["results"]["unhealthy_servers"] == 0, outcome["results"]

    def return_to(self, account: VirtualminAccount, key: str) -> None:
        """Move an account back to `key` after a migration test, whatever state the test left it in.

        The retained source copy is deleted first (a migration refuses a target that still holds the domain),
        and a migration left for review is resolved the way an operator does.
        """
        from apps.provisioning.virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415
        from apps.provisioning.virtualmin_migration_service import (  # noqa: PLC0415
            VirtualminMigrationService,
            resolve_migration,
        )

        for stuck in VirtualminMigration.objects.filter(account=account, status="needs_review"):
            resolve_migration(stuck, resolved_by=None, note="workflow teardown")
        account.refresh_from_db()
        target = self.server(key)
        if account.server_id == target.pk:
            return
        self.lab(key).remove_domain(account.domain)
        started = VirtualminMigrationService().start_migration(account, target, initiated_by=None, reason="manual")
        assert started.is_ok(), started
        self.run_queue()
        account.refresh_from_db()
        assert account.server_id == target.pk, f"{account.domain} did not return to {key}"

    def reset_meters(self) -> None:
        """The gateway meters calls per server and program for an hour; a workflow run makes many."""
        cache.clear()

    # ----------------------------------------------------------------- PRAHO

    @staticmethod
    def jobs(account: VirtualminAccount, operation: str) -> list[VirtualminProvisioningJob]:
        return list(VirtualminProvisioningJob.objects.filter(account=account, operation=operation).order_by("created_at"))

    @staticmethod
    def audit_actions(obj: Any) -> list[str]:
        """The audit trail of one row, oldest first."""
        events = AuditEvent.objects.filter(
            content_type=ContentType.objects.get_for_model(type(obj)), object_id=str(obj.pk)
        ).order_by("timestamp")
        return [event.action for event in events]


def build_bench(state: LabState) -> Bench:
    """A gateway to each lab node, through PRAHO's production gateway."""
    labs: dict[str, Lab] = {}
    for node in state.nodes:
        server = VirtualminServer.objects.get(hostname=node.server_hostname)
        gateway = RecordingGateway(VirtualminConfig(server=server))
        gateway.call("info")
        probe = gateway.exchanges[-1]
        assert probe.result.is_ok(), f"cannot reach {node.server_hostname}: {probe.result.unwrap_err()}"
        labs[node.key] = Lab(gateway, node, server, Recorder(version="workflows", directory=None), password="unused")
    counts = {
        node.key: VirtualminServer.objects.get(hostname=node.server_hostname).current_domains for node in state.nodes
    }
    return Bench(state=state, labs=labs, initial_domain_counts=counts)


class DomainData:
    """The files and database rows of one hosted domain on its node: what a backup has to bring back."""

    TABLE = "wf_rows"

    def __init__(self, lab: Lab, account: VirtualminAccount) -> None:
        self.lab = lab
        self.domain = account.domain
        self.user = account.virtualmin_username
        self.home = f"/home/{self.user}"

    def database(self) -> str:
        names = self.lab.exec("virtualmin", "list-databases", "--domain", self.domain, "--name-only").split()
        assert names, f"{self.domain} has no database"
        return names[0]

    def sql(self, statement: str) -> str:
        return self.lab.exec("mysql", "-N", "-B", "-e", statement, self.database())

    def write(self, relative: str, content: str) -> None:
        path = f"{self.home}/public_html/{relative}"
        self.lab.exec(
            "sh",
            "-c",
            'mkdir -p "$(dirname "$1")" && printf "%s" "$2" > "$1" && chown -R "$3": "$(dirname "$1")"',
            "sh",
            path,
            content,
            self.user,
        )

    def read(self, relative: str) -> str:
        return self.lab.exec(
            "sh", "-c", 'cat "$1" 2>/dev/null || printf ABSENT', "sh", f"{self.home}/public_html/{relative}"
        )

    def add_blob(self, megabytes: int) -> None:
        """Incompressible bulk, so that a backup of the domain takes seconds, not milliseconds."""
        path = f"{self.home}/public_html/blob.bin"
        self.lab.exec(
            "sh",
            "-c",
            'dd if=/dev/urandom of="$1" bs=1M count="$2" 2>/dev/null && chown "$3": "$1"',
            "sh",
            path,
            str(megabytes),
            self.user,
        )

    def remove(self, relative: str) -> None:
        self.lab.exec("rm", "-f", f"{self.home}/public_html/{relative}")

    def seed(self, token: str) -> None:
        """Files and three rows that carry `token`, so a restore can be told from a stale copy."""
        self.write("index.html", f"<h1>{token}</h1>\n")
        self.write("data/marker.txt", f"marker {token}")
        self.sql(f"CREATE TABLE IF NOT EXISTS {self.TABLE} (id INT PRIMARY KEY, body VARCHAR(64))")
        self.sql(f"DELETE FROM {self.TABLE}")  # noqa: S608  # Constant table name
        self.sql(
            f"INSERT INTO {self.TABLE} VALUES (1, 'alpha {token}'), (2, 'beta {token}'), (3, 'gamma {token}')"  # noqa: S608
        )

    def damage(self) -> None:
        """Change what `seed` wrote and add what it did not."""
        self.write("data/marker.txt", "damaged")
        self.write("data/late.txt", "written after the backup")
        self.sql(f"DELETE FROM {self.TABLE} WHERE id = 2")  # noqa: S608  # Constant table name
        self.sql(f"UPDATE {self.TABLE} SET body = 'damaged' WHERE id = 3")  # noqa: S608

    def files(self) -> str:
        """Checksums of every file under public_html."""
        return self.lab.exec(
            "sh",
            "-c",
            'cd "$1" && find public_html -type f -print0 | sort -z | xargs -0 sha256sum',
            "sh",
            self.home,
        )

    def snapshot(self) -> dict[str, str]:
        """The content a restore must reproduce: file checksums under public_html and the table rows."""
        files = self.files()
        rows = self.sql(f"SELECT id, body FROM {self.TABLE} ORDER BY id")  # noqa: S608  # Constant table name
        return {"files": files, "rows": rows}
