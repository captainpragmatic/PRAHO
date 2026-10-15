"""Lab test: the archive transfer playbooks, run through PRAHO's AnsibleService between the two lab nodes.

backup-domain on vm-b makes an archive; virtualmin_backup_fetch.yml pulls it into the controller spool,
virtualmin_backup_push.yml pushes it to vm-a, and virtualmin_remote_cleanup.yml removes it there. The migration
pair (virtualmin_migrate_fetch.yml, virtualmin_migrate_push.yml) does the same for a migration archive. The
variables are the ones the backup service and the migration service pass.
"""

from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path

from apps.infrastructure.ansible_service import AnsibleService
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_STANDALONE,
    REMOTE_ARCHIVE_DIR,
    config_backup_params,
)
from apps.provisioning.virtualmin_migration_service import migration_backup_params
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.virtualmin_lab.contract.harness import BACKUP_TIMEOUT, SANDBOX_DOMAIN, Lab, assert_accepted

SOURCE_CONTAINER = "vmlab-b"
TARGET_CONTAINER = "vmlab-a"
TRANSFER_TIMEOUT = 600


def _spool() -> Path:
    spool = Path(str(SettingsService.get_setting("provisioning.migration_spool_dir", "")))
    assert str(spool).startswith("/"), "the lab bootstrap sets provisioning.migration_spool_dir"
    spool.mkdir(mode=0o700, parents=True, exist_ok=True)
    return spool


def _staged(lab: Lab, container: str, archive_name: str) -> bool:
    listing = lab.exec_on(container, "sh", "-c", f"ls {REMOTE_ARCHIVE_DIR}")
    return archive_name in listing.split()


def _run(deployment: NodeDeployment, playbook: str, variables: dict[str, object]) -> str:
    result = AnsibleService().run_playbook(deployment, playbook, variables, timeout_seconds=TRANSFER_TIMEOUT)
    assert result.is_ok(), f"{playbook}: {result.unwrap_err()}"
    outcome = result.unwrap()
    assert outcome.success, f"{playbook} failed:\n{outcome.stdout[-2000:]}"
    return str(outcome.stdout)


def test_backup_archive_fetch_push_and_cleanup(lab: Lab) -> None:
    spool = _spool()
    archive = f"virtualmin_backup_{uuid.uuid4().hex}.tar.gz"
    source = lab.server.node_deployment
    target = VirtualminServer.objects.get(hostname="vm-a.praho.test").node_deployment
    try:
        made = lab.quiet(
            "backup-domain",
            config_backup_params(
                domain=SANDBOX_DOMAIN, dest=f"{REMOTE_ARCHIVE_DIR}/{archive}", chain_role=CHAIN_ROLE_STANDALONE
            ),
            timeout_seconds=BACKUP_TIMEOUT,
        )
        assert_accepted(made)
        assert _staged(lab, SOURCE_CONTAINER, archive)

        fetched = _run(
            source,
            "virtualmin_backup_fetch.yml",
            {"archive_name": archive, "spool_dir": str(spool), "spool_free_bytes": shutil.disk_usage(spool).free},
        )
        (checksum,) = set(re.findall(r"BACKUP_SHA256=([0-9a-f]{64})(?![0-9a-f])", fetched))
        assert (spool / archive).is_file()
        assert not _staged(lab, SOURCE_CONTAINER, archive), "the fetch deletes the node's copy"

        _run(target, "virtualmin_backup_push.yml", {"archive_name": archive, "spool_dir": str(spool), "expected_sha256": checksum})
        assert _staged(lab, TARGET_CONTAINER, archive)

        _run(target, "virtualmin_remote_cleanup.yml", {"archive_name": archive})
        assert not _staged(lab, TARGET_CONTAINER, archive)
    finally:
        (spool / archive).unlink(missing_ok=True)
        for container in (SOURCE_CONTAINER, TARGET_CONTAINER):
            lab.exec_on(container, "sh", "-c", f"rm -f {REMOTE_ARCHIVE_DIR}/{archive}*")


def test_migration_archive_fetch_and_push(lab: Lab) -> None:
    spool = _spool()
    archive = f"migration_{uuid.uuid4()}.tar.gz"
    source = lab.server.node_deployment
    target = VirtualminServer.objects.get(hostname="vm-a.praho.test").node_deployment
    try:
        made = lab.quiet(
            "backup-domain",
            {"domain": SANDBOX_DOMAIN, **migration_backup_params(archive)},
            timeout_seconds=BACKUP_TIMEOUT,
        )
        assert_accepted(made)

        fetched = _run(
            source,
            "virtualmin_migrate_fetch.yml",
            {
                "archive_name": archive,
                "spool_dir": str(spool),
                "spool_free_bytes": shutil.disk_usage(spool).free,
                "expected_sha256": "",
            },
        )
        (checksum,) = set(re.findall(r"MIGRATE_SHA256=([0-9a-f]{64})(?![0-9a-f])", fetched))
        assert (spool / archive).is_file()

        _run(
            target,
            "virtualmin_migrate_push.yml",
            {
                "archive_name": archive,
                "spool_dir": str(spool),
                "spool_free_bytes": shutil.disk_usage(spool).free,
                "expected_sha256": checksum,
            },
        )
        assert _staged(lab, TARGET_CONTAINER, archive)
    finally:
        (spool / archive).unlink(missing_ok=True)
        for container in (SOURCE_CONTAINER, TARGET_CONTAINER):
            lab.exec_on(container, "sh", "-c", f"rm -f {REMOTE_ARCHIVE_DIR}/{archive}*")
