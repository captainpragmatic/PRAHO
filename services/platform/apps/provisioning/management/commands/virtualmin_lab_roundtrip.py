"""Production-path backup + restore round trip against the Docker Virtualmin lab.

The opt-in gate behind `make test-virtualmin-lab`. It drives the ordinary
`manage.py virtualmin_backup backup|restore` command (job layer, inline), so
the full PRAHO path runs: remote.cgi backup-domain, Ansible fetch into the
spool, checksum and member verification, SSE-S3 upload to MinIO, download,
Ansible push, restore-domain, and post-restore verification. Only the
transport adaptations in `_virtualmin_lab.lab_transport` differ from a real
node.

Data assertions: file checksums under public_html and the rows of a table in
the domain's database must equal the pre-backup state after the restore.

Run state: the domain is restored onto a deleted domain, so no pre-restore
safety backup runs. The backup excludes the mail component because the
minimal Virtualmin install has no mail feature; see the README.
"""

from __future__ import annotations

import io
import logging
import re
import secrets
import subprocess
from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from apps.common.types import Retriability
from apps.provisioning.management.commands._virtualmin_lab import (
    LabState,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)

logger = logging.getLogger(__name__)

_TABLE = "lab_rows"


def node_exec(container: str, *argv: str) -> str:
    """Run a command on a lab node and return stdout; any failure is fatal."""
    result = subprocess.run(  # Fixed argv on a local lab container
        ["docker", "exec", container, *argv],  # noqa: S607  # docker from PATH, dev-only command
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise CommandError(f"{container}: {' '.join(argv)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


class LabDomain:
    """The lab domain's files and database on one node."""

    def __init__(self, lab: LabState, container: str) -> None:
        self.lab = lab
        self.container = container
        self.home = f"/home/{lab.domain_user}"

    def database(self) -> str:
        names = node_exec(
            self.container, "virtualmin", "list-databases", "--domain", self.lab.domain, "--name-only"
        ).split()
        if not names:
            raise CommandError(f"{self.lab.domain} has no database on {self.container}")
        return names[0]

    def sql(self, statement: str) -> str:
        return node_exec(self.container, "mysql", "-N", "-B", "-e", statement, self.database())

    def write_file(self, relative: str, content: str) -> None:
        path = f"{self.home}/public_html/{relative}"
        node_exec(self.container, "install", "-D", "-m", "0644", "/dev/null", path)
        node_exec(self.container, "sh", "-c", 'printf "%s" "$1" > "$2"', "sh", content, path)

    def fingerprint(self) -> dict[str, str]:
        files = node_exec(
            self.container,
            "sh",
            "-c",
            'cd "$1" && find public_html -type f -print0 | sort -z | xargs -0 sha256sum',
            "sh",
            self.home,
        )
        rows = self.sql(f"SELECT id, body FROM {_TABLE} ORDER BY id")  # noqa: S608  # Constant table name
        return {"files": files, "rows": rows}


class Command(BaseCommand):
    help = "Back up and restore the lab domain through the production path and assert the data (lab only)"

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        state = load_state()
        node = state.node("vm-a")
        domain = LabDomain(state, node.container)

        self._close_stale_lab_jobs(state)
        with lab_transport(state):
            self._ensure_domain(state)
            token = secrets.token_hex(8)
            domain.write_file("index.html", f"<h1>lab {token}</h1>\n")
            domain.write_file("lab/marker.txt", f"marker {token}\n")
            domain.sql(f"CREATE TABLE IF NOT EXISTS {_TABLE} (id INT PRIMARY KEY, body VARCHAR(64))")
            domain.sql(f"DELETE FROM {_TABLE}")  # noqa: S608  # Constant table name
            domain.sql(
                f"INSERT INTO {_TABLE} VALUES (1, 'alpha {token}'), (2, 'beta {token}'), (3, 'gamma {token}')"  # noqa: S608
            )
            before = domain.fingerprint()
            self.stdout.write(f"Seeded {state.domain}: {len(before['files'].splitlines())} files, 3 rows")

            backup_id = self._backup(state)
            self._assert_published(state, backup_id)

            domain.write_file("lab/marker.txt", "changed after the backup\n")
            domain.write_file("lab/extra.txt", "created after the backup\n")
            domain.sql(f"DELETE FROM {_TABLE} WHERE id = 2")  # noqa: S608  # Constant table name
            if domain.fingerprint() == before:
                raise CommandError("Mutation did not change the fingerprint; the assertion would be vacuous")

            self._delete_domain(state)
            self._restore(state, backup_id)
            after = domain.fingerprint()

        if after != before:
            raise CommandError(f"Restored data differs from the backed-up state:\nbefore={before}\nafter={after}")
        logger.info("✅ [VirtualminLab] Round trip %s restored byte-identical files and rows", backup_id)
        self.stdout.write(self.style.SUCCESS(f"Round trip OK: backup {backup_id} restored files and rows exactly"))

    def _close_stale_lab_jobs(self, state: LabState) -> None:
        """A previous failed lab run may have parked a job for attention, which
        blocks admission for the account. In the lab nobody attends: close it."""
        from apps.provisioning.virtualmin_migration_models import _ACTIVE_JOB_STATUSES  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415

        stale = VirtualminProvisioningJob.objects.filter(
            account__domain=state.domain,
            operation__in=("backup_domain", "restore_domain"),
            status__in=_ACTIVE_JOB_STATUSES,
        )
        for job in stale:
            job.mark_failed("Closed by the next lab round trip", retriability=Retriability.NOT_RETRIABLE)
            self.stdout.write(f"Closed stale lab job {job.pk} from an earlier run")

    def _gateway(self, state: LabState) -> Any:
        from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        server = VirtualminServer.objects.get(hostname=state.node("vm-a").server_hostname)
        return VirtualminGateway(VirtualminConfig(server=server))

    def _ensure_domain(self, state: LabState) -> None:
        from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

        gateway = self._gateway(state)
        # The full listing, not get_domain_state: Virtualmin 8.3.0 answers a
        # single-domain list-domains for an absent domain with a failure.
        listing = gateway.list_domains_with_owners()
        if listing.is_err():
            raise CommandError(f"Cannot list domains on vm-a: {listing.unwrap_err()}")
        if any(row["domain"] == state.domain for row in listing.unwrap()):
            return
        account = VirtualminAccount.objects.get(domain=state.domain)
        # PRAHO's provisioning call (domain/user/pass/template) is rejected by a
        # stock 8.3.0 node ("Unknown template name", then "No virtual server
        # features enabled"), so the lab creates the domain with stock defaults.
        created = gateway.call(
            "create-domain",
            {
                "domain": state.domain,
                "user": state.domain_user,
                "pass": account.get_password(),
                "default-features": "",
            },
            timeout_seconds=600,
        )
        if created.is_err() or not created.unwrap().success:
            detail = created.unwrap_err() if created.is_err() else created.unwrap().raw_response[:500]
            raise CommandError(f"create-domain failed: {detail}")
        self.stdout.write(f"Created {state.domain} on vm-a")

    def _delete_domain(self, state: LabState) -> None:
        deleted = self._gateway(state).call("delete-domain", {"domain": state.domain}, timeout_seconds=600)
        if deleted.is_err() or not deleted.unwrap().success:
            raise CommandError(f"delete-domain failed: {deleted}")
        self.stdout.write(f"Deleted {state.domain} from vm-a before the restore")

    def _backup(self, state: LabState) -> str:
        out = io.StringIO()
        call_command("virtualmin_backup", "backup", state.domain, "--no-email", stdout=out)
        match = re.search(r"^Backup ID: (\S+)$", out.getvalue(), re.MULTILINE)
        if match is None or match.group(1) == "n/a":
            raise CommandError(f"Backup reported no backup id:\n{out.getvalue()}")
        self.stdout.write(out.getvalue().rstrip())
        return match.group(1)

    def _restore(self, state: LabState, backup_id: str) -> None:
        out = io.StringIO()
        call_command("virtualmin_backup", "restore", state.domain, backup_id, stdout=out)
        self.stdout.write(out.getvalue().rstrip())

    def _assert_published(self, state: LabState, backup_id: str) -> None:
        from apps.provisioning.virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        service = VirtualminBackupService(VirtualminServer.objects.get(hostname=state.node("vm-a").server_hostname))
        client = service._get_s3_client()
        bucket = service._get_backup_bucket()
        for name in ("backup.tar.gz", "metadata.json"):
            head = client.head_object(Bucket=bucket, Key=f"virtualmin-backups/{backup_id}/{name}")
            if head.get("ServerSideEncryption") != "AES256":
                raise CommandError(f"{name} is not SSE-S3 encrypted: {head.get('ServerSideEncryption')!r}")
        self.stdout.write(f"Published to s3://{bucket}/virtualmin-backups/{backup_id}/ with SSE-S3 (AES256)")
