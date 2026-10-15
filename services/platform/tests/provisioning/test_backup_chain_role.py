"""Every backup-domain call that is not a differential base keeps the base.

Virtualmin keeps one differential base per domain, and any full backup sent
without ``no-differential`` replaces it (lab evidence, Q2/Q3 in
docs/domain/virtualmin-incremental-contract.md). PRAHO's ordinary full,
config-only, pre-restore safety and migration backups are standalone, so they
must send the flag. The role travels BackupConfig -> job parameters -> worker.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.cache import cache
from django.test import override_settings

from apps.common.types import Err, Ok
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_BASE,
    CHAIN_ROLE_DIFFERENTIAL,
    CHAIN_ROLE_STANDALONE,
    REMOTE_ARCHIVE_DIR,
    BackupConfig,
    RestoreConfig,
    VirtualminBackupService,
)
from apps.provisioning.virtualmin_migration_service import migration_backup_params
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_backup_cli_contract import (
    _BACKUP_BARE,
    _BACKUP_VALUED,
    parse_like_virtualmin,
    remote_cgi_argv,
)
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class BackupDispatchChainRoleTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.backups = VirtualminBackupService(self.server)

    def _dispatch(self, config: BackupConfig) -> tuple[Any, list[dict[str, object]]]:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(cast("dict[str, object]", kwargs["params"]))
            return http_response({"status": "success"})

        metadata = self.backups._initialize_backup_metadata(self.account, config.backup_type, "role-id", config)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups._execute_backup_by_type(config, self.account, "role-id", metadata)
        return result, sent

    def test_standalone_full_and_config_only_send_no_differential(self) -> None:
        for config in (
            BackupConfig(),
            BackupConfig(include_email=False),
            BackupConfig(backup_type="config_only"),
        ):
            with self.subTest(config=config):
                result, sent = self._dispatch(config)
                self.assertTrue(result.is_ok(), result)
                argv = remote_cgi_argv(sent[0])
                self.assertIn("--no-differential", argv)
                self.assertNotIn("--differential", argv)
                self.assertEqual(parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), [])

    def test_a_base_is_never_sent_through_remote_cgi(self) -> None:
        """A plain full over remote.cgi resets the snapshot with nothing binding it to the archive.

        Bases and differentials run as locked node-side steps (test_virtualmin_chain_backup_flow);
        a remote.cgi dispatch for those roles would be an unfenced snapshot writer.
        """
        for role in (CHAIN_ROLE_BASE, CHAIN_ROLE_DIFFERENTIAL):
            with self.subTest(role=role):
                result, sent = self._dispatch(BackupConfig(chain_role=role))
                self.assertTrue(result.is_err(), result)
                self.assertEqual(sent, [])

    def test_incomplete_or_unknown_roles_are_refused_before_dispatch(self) -> None:
        for config in (
            BackupConfig(backup_type="config_only", chain_role=CHAIN_ROLE_BASE),
            BackupConfig(include_email=False, chain_role=CHAIN_ROLE_BASE),
            BackupConfig(include_ssl=False, chain_role=CHAIN_ROLE_BASE),
            BackupConfig(backup_type="config_only", chain_role=CHAIN_ROLE_DIFFERENTIAL),
            BackupConfig(include_databases=False, chain_role=CHAIN_ROLE_DIFFERENTIAL),
            BackupConfig(chain_role="bogus"),
            BackupConfig(chain_role=""),
        ):
            with self.subTest(config=config):
                result, sent = self._dispatch(config)
                self.assertTrue(result.is_err())
                self.assertEqual(sent, [])

    def test_manifest_records_the_role(self) -> None:
        metadata = self.backups._initialize_backup_metadata(self.account, "full", "m", BackupConfig())
        self.assertEqual(metadata["chain_role"], CHAIN_ROLE_STANDALONE)

    def test_pre_restore_safety_backup_is_standalone(self) -> None:
        captured: list[BackupConfig] = []

        def safety(self: VirtualminBackupService, account: object, config: BackupConfig, **kwargs: object) -> Any:
            captured.append(config)
            return Err("stop after the safety backup")

        metadata = {
            "archive_name": "virtualmin_backup_" + "b" * 32 + ".tar.gz",
            "checksum_sha256": "0" * 64,
            "praho_service_id": str(self.account.service_id),
            "domain": self.account.domain,
        }
        with (
            patch.object(
                self.backups, "_download_backup_to_spool", return_value=Ok(("/nonexistent/x.tar.gz", metadata))
            ),
            patch.object(self.backups, "_target_domain_gate", return_value=Ok(True)),
            patch.object(VirtualminBackupService, "backup_domain", autospec=True, side_effect=safety),
        ):
            result = self.backups.restore_domain(self.account, RestoreConfig(backup_id="r", force_restore=True))
        self.assertTrue(result.is_err())
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].chain_role, CHAIN_ROLE_STANDALONE)
        self.assertIsNone(captured[0].chain_role_error())


class MigrationBackupChainRoleTests(VirtualminTaskTestBase):
    def test_migration_backup_params_are_standalone_and_private(self) -> None:
        archive = f"migration_{uuid4()}.tar.gz"
        params = migration_backup_params(archive)
        argv = remote_cgi_argv({"domain": "a.test", **params})
        self.assertIn("--no-differential", argv)
        self.assertEqual(parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), [])
        self.assertEqual(params["dest"], f"{REMOTE_ARCHIVE_DIR}/{archive}")

    def test_migration_backup_step_sends_those_params(self) -> None:
        from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService  # noqa: PLC0415

        migration = cast(Any, type("M", (), {"archive_name": f"migration_{uuid4()}.tar.gz", "source_server": None}))
        with (
            patch.object(VirtualminMigrationService, "_command") as command,
            patch.object(VirtualminMigrationService, "_move"),
        ):
            VirtualminMigrationService()._backup(migration, uuid4())
        program = command.call_args.args[2]
        self.assertEqual(program, "backup-domain")
        self.assertEqual(command.call_args.kwargs, migration_backup_params(migration.archive_name))


class BackupJobChainRoleTests(VirtualminTaskTestBase):
    def test_admission_persists_the_role_and_refuses_an_invalid_one(self) -> None:
        management = VirtualminBackupManagementService(self.server)
        with patch("django_q.tasks.async_task", return_value="t"):
            job = management.create_backup_job(self.account, initiated_by="test").unwrap()
        self.assertEqual(job.parameters["chain_role"], CHAIN_ROLE_STANDALONE)

        refused = management.create_backup_job(
            self.account, BackupConfig(backup_type="config_only", chain_role=CHAIN_ROLE_BASE)
        )
        self.assertTrue(refused.is_err())

    def _run(self, **params: object) -> list[BackupConfig]:
        job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            parameters={"task_budget_seconds": 600, **params},
            status="pending",
        )
        seen: list[BackupConfig] = []

        def backup(self: VirtualminBackupService, account: object, config: BackupConfig, **kwargs: object) -> Any:
            seen.append(config)
            return Err("captured")

        with patch.object(VirtualminBackupService, "backup_domain", autospec=True, side_effect=backup):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        return seen

    def test_worker_rebuilds_the_role_from_job_parameters(self) -> None:
        self.assertEqual([c.chain_role for c in self._run()], [CHAIN_ROLE_STANDALONE])
        self.assertEqual([c.chain_role for c in self._run(chain_role="base")], [CHAIN_ROLE_BASE])
        # An unrecognised stored role reaches the service, which refuses it.
        (bogus,) = self._run(chain_role="bogus")
        self.assertIsNotNone(bogus.chain_role_error())
