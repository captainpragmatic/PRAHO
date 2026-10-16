"""Contract: backup-domain and restore-domain, with the parameters the backup service and the migration send.

The archives are written to PRAHO's staging directory on the node under fixed names and removed afterwards.
"""

from __future__ import annotations

from apps.common.types import Retriability
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_STANDALONE,
    REMOTE_ARCHIVE_DIR,
    config_backup_params,
    full_backup_params,
    restore_domain_params,
)
from apps.provisioning.virtualmin_migration_service import migration_backup_params
from tests.virtualmin_lab.contract.harness import (
    BACKUP_TIMEOUT,
    DELETE_TIMEOUT,
    SANDBOX_DOMAIN,
    Lab,
    assert_accepted,
    assert_mutating,
    assert_refused,
    covers,
)

ABSENT = "contract-absent.praho.test"


def _archive(number: int) -> str:
    return f"virtualmin_backup_{number:032x}.tar.gz"


def _remove_archives(lab: Lab, *numbers: int) -> None:
    for number in numbers:
        lab.exec("sh", "-c", f"rm -f {REMOTE_ARCHIVE_DIR}/{_archive(number)}*")


def _archive_size(lab: Lab, number: int) -> int:
    return int(lab.exec("stat", "-c", "%s", f"{REMOTE_ARCHIVE_DIR}/{_archive(number)}").strip())


@covers("backup-domain")
def test_backup_domain(lab: Lab) -> None:
    assert_mutating("backup-domain")
    full, config, migration = 0x101, 0x102, 0x103
    refused_archives = (0x104, 0x105)
    _remove_archives(lab, full, config, migration, *refused_archives)
    try:
        everything = lab.call(
            "backup-domain",
            full_backup_params(
                domain=SANDBOX_DOMAIN,
                dest=f"{REMOTE_ARCHIVE_DIR}/{_archive(full)}",
                chain_role=CHAIN_ROLE_STANDALONE,
                excluded_features=["mail"],
            ),
            case="full",
            timeout_seconds=BACKUP_TIMEOUT,
            note="the ordinary full backup, mail left out (the lab domain has no mail feature)",
        )
        assert_accepted(everything)
        assert _archive_size(lab, full) > 0

        structure = lab.call(
            "backup-domain",
            config_backup_params(
                domain=SANDBOX_DOMAIN, dest=f"{REMOTE_ARCHIVE_DIR}/{_archive(config)}", chain_role=CHAIN_ROLE_STANDALONE
            ),
            case="config_only",
            timeout_seconds=BACKUP_TIMEOUT,
            note="the configuration-only backup",
        )
        assert_accepted(structure)
        assert 0 < _archive_size(lab, config) <= _archive_size(lab, full)

        moved = lab.call(
            "backup-domain",
            {"domain": SANDBOX_DOMAIN, **migration_backup_params(_archive(migration))},
            case="migration",
            timeout_seconds=BACKUP_TIMEOUT,
            note="the source-node backup of a migration",
        )
        assert_accepted(moved)

        absent = lab.call(
            "backup-domain",
            full_backup_params(
                domain=ABSENT,
                dest=f"{REMOTE_ARCHIVE_DIR}/{_archive(refused_archives[0])}",
                chain_role=CHAIN_ROLE_STANDALONE,
                excluded_features=[],
            ),
            case="absent_domain",
            note="a domain that is not there",
        )
        assert_refused(
            absent,
            error=f"Virtual server {ABSENT} does not exist",
            retriability=Retriability.NOT_RETRIABLE,
            exact=True,
        )

        boolean_flag = lab.call(
            "backup-domain",
            {
                **full_backup_params(
                    domain=SANDBOX_DOMAIN,
                    dest=f"{REMOTE_ARCHIVE_DIR}/{_archive(refused_archives[1])}",
                    chain_role=CHAIN_ROLE_STANDALONE,
                    excluded_features=[],
                ),
                "all-features": "True",
            },
            case="boolean_flag",
            note="a flag sent as the text True: remote.cgi turns it into the argument --all-features True",
        )
        assert_refused(boolean_flag, error="Unknown parameter True", retriability=Retriability.UNKNOWN, exact=True)

        unwritable = lab.call(
            "backup-domain",
            {
                "domain": SANDBOX_DOMAIN,
                "dest": "/nonexistent-dir/contract.tar.gz",
                "all-features": "",
                "no-differential": "",
            },
            case="unwritable_destination",
            timeout_seconds=BACKUP_TIMEOUT,
            note="a destination directory that does not exist and was not asked for with mkdir",
        )
        # The refusal is real, but its `error` is only the command's first output line: the reason is in `full_error`.
        assert_refused(unwritable, error="Starting backup..", retriability=Retriability.UNKNOWN, exact=True)
        assert "/nonexistent-dir" in unwritable.response.data["full_error"]
    finally:
        _remove_archives(lab, full, config, migration, *refused_archives)


@covers("restore-domain")
def test_restore_domain(lab: Lab) -> None:
    assert_mutating("restore-domain")
    archive = 0x201
    source = f"{REMOTE_ARCHIVE_DIR}/{_archive(archive)}"
    domain = "contract-restore.praho.test"
    _remove_archives(lab, archive)
    try:
        with lab.domain(domain, "contractrestore"):
            assert_accepted(
                lab.quiet(
                    "backup-domain",
                    full_backup_params(
                        domain=domain, dest=source, chain_role=CHAIN_ROLE_STANDALONE, excluded_features=["mail"]
                    ),
                    timeout_seconds=BACKUP_TIMEOUT,
                )
            )
            assert_accepted(lab.quiet("delete-domain", {"domain": domain}, timeout_seconds=DELETE_TIMEOUT))
            assert not lab.domain_exists(domain)

            restored = lab.call(
                "restore-domain",
                restore_domain_params(domain=domain, source=source),
                case="success",
                timeout_seconds=BACKUP_TIMEOUT,
                note="restore onto a domain that was deleted: Virtualmin re-creates it",
            )
            assert_accepted(restored)
            assert lab.domain_exists(domain)

            over_live = lab.call(
                "restore-domain",
                restore_domain_params(domain=domain, source=source),
                case="success_over_live_domain",
                timeout_seconds=BACKUP_TIMEOUT,
                note="Virtualmin itself does not refuse a restore over a live domain; PRAHO's gate does",
            )
            assert_accepted(over_live)

            missing = lab.call(
                "restore-domain",
                restore_domain_params(domain=domain, source=f"{REMOTE_ARCHIVE_DIR}/{_archive(0x2FF)}"),
                case="missing_archive",
                note="an archive that is not on the node",
            )
            assert_refused(
                missing,
                error=f"Restore file {REMOTE_ARCHIVE_DIR}/{_archive(0x2FF)} does not exist",
                retriability=Retriability.NOT_RETRIABLE,
                exact=True,
            )
    finally:
        _remove_archives(lab, archive)
