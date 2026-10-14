"""Base and differential backups run as one locked node-side step, then travel like any backup.

The step is `virtualmin_chain_backup.yml`; the archive then goes through the ordinary
fetch, verification and publication. These tests fake the node (the playbook runner),
so they pin the controller side: which playbook runs with which inputs, that remote.cgi
is never used for a chain role, that the archive the step vouched for is the archive
that was fetched, and that every uncertain outcome publishes nothing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from apps.common.types import Ok, Retriability, retriability_of
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_BASE,
    CHAIN_ROLE_DIFFERENTIAL,
    BackupConfig,
    ChainContext,
    differential_flags,
)
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.provisioning.test_virtualmin_backup_transport import ARCHIVE_BYTES, BackupNodeFixture
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A, SNAP_B, result_line

DOMAIN_ID = "17919754553303"
TOKEN = "0b5f1c7e-3c1d-4f0a-9a52-6d1b3a8c2e44"
ARCHIVE_SHA = hashlib.sha256(ARCHIVE_BYTES).hexdigest()


def listing_reply(domain: str) -> Ok[VirtualminResponse]:
    return Ok(
        VirtualminResponse(
            success=True,
            data={"data": [{"name": domain, "values": {"ID": DOMAIN_ID, "Features": "web dns mail mysql dir ssl"}}]},
            raw_response="{}",
            http_status=200,
            execution_time=0.1,
            program="list-domains",
            server_hostname="vm1.example.com",
        )
    )


class ChainBackupFlowTests(BackupNodeFixture):
    def setUp(self) -> None:
        super().setUp()
        self._prepare()

    def _fake_fetch(self, deployment: Any, playbook: str, variables: dict[str, Any], **kwargs: Any) -> Any:
        """Stand in for the node: the chain step, then the ordinary fetch."""
        self.played.append((playbook, dict(variables)))
        if playbook == "virtualmin_chain_backup.yml":
            return self.chain_reply(variables)
        archive = Path(variables["spool_dir"]) / variables["archive_name"]
        archive.write_bytes(ARCHIVE_BYTES)
        return Ok(SimpleNamespace(success=True, stdout=f"BACKUP_SHA256={self.fetched_sha}\n", return_code=0))

    def _prepare(self) -> None:
        self.played: list[tuple[str, dict[str, Any]]] = []
        self.fetched_sha = ARCHIVE_SHA
        self.step_sha = ARCHIVE_SHA
        self.noted: list[dict[str, Any]] = []

        def gateway_call(program: str, params: dict[str, Any], **kwargs: Any) -> Any:
            self.programs.append(program)
            return listing_reply(self.account.domain)

        self.programs: list[str] = []
        self.gateway.call.side_effect = gateway_call
        self.ansible.run_playbook.side_effect = self._fake_fetch

        def reply(variables: dict[str, Any]) -> Any:
            ran_base = variables["chain_mode"] == "base"
            line = result_line(
                mode=variables["chain_mode"],
                domain_id=variables["chain_domain_id"],
                token=variables["chain_token"],
                archive=variables["chain_archive"],
                fp_before=SNAP_B if ran_base else SNAP_A,
                fp_after=SNAP_A,
                sha256=self.step_sha,
                size=len(ARCHIVE_BYTES),
            )
            return Ok(SimpleNamespace(success=True, stdout=f"msg: {line}\n", return_code=0))

        self.chain_reply: Callable[[dict[str, Any]], Any] = reply

    def _config(self, role: str, **chain: Any) -> BackupConfig:
        """A chain context whose pins match the account's chain state, as admission would leave it."""
        defaults: dict[str, Any] = {"token": TOKEN, "epoch": 3}
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=3, chain_base=None)
        if role == CHAIN_ROLE_DIFFERENTIAL:
            base = VirtualminProvisioningJob.objects.create(
                operation="backup_domain", account=self.account, server=self.server, status="completed"
            )
            VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_base=base, chain_base_fingerprint=SNAP_A)
            defaults |= {"base_backup_id": "base-1", "base_job_id": str(base.pk), "expected_fp": SNAP_A}
        return BackupConfig(chain_role=role, chain=ChainContext(**{**defaults, **chain}))

    def _backup(self, config: BackupConfig) -> Any:
        def note(entry: dict[str, Any]) -> int:
            self.noted.append(entry)
            return 1

        return self.svc.backup_domain(account=self.account, config=config, note_sink=note)

    def _manifest(self) -> dict[str, Any]:
        return json.loads(self.s3.put_object.call_args_list[1].kwargs["Body"])

    def test_a_base_runs_the_node_step_then_fetches_and_records_its_lineage(self) -> None:
        result = self._backup(self._config(CHAIN_ROLE_BASE))
        self.assertTrue(result.is_ok(), result)
        self.assertEqual([name for name, _ in self.played], ["virtualmin_chain_backup.yml", "virtualmin_backup_fetch.yml"])
        variables = self.played[0][1]
        self.assertEqual(
            {key: variables[key] for key in ("chain_action", "chain_mode", "chain_domain_id", "chain_token")},
            {"chain_action": "run", "chain_mode": "base", "chain_domain_id": DOMAIN_ID, "chain_token": TOKEN},
        )
        self.assertNotIn("chain_expected_fp", variables)
        self.assertNotIn("backup-domain", self.programs, "a chain role never goes through remote.cgi")
        manifest = self._manifest()
        self.assertEqual(manifest["chain_role"], "base")
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual((manifest["fp_before"], manifest["fp_after"]), (SNAP_B, SNAP_A))
        self.assertEqual(manifest["virtualmin_domain_id"], DOMAIN_ID)
        self.assertEqual(manifest["node_id"], str(self.server.pk))
        self.assertEqual(manifest["chain_epoch"], 3)
        self.assertEqual(manifest["archive_name"], variables["chain_archive"])

    def test_a_differential_carries_the_expected_fingerprint_and_names_its_base(self) -> None:
        result = self._backup(self._config(CHAIN_ROLE_DIFFERENTIAL))
        self.assertTrue(result.is_ok(), result)
        variables = self.played[0][1]
        self.assertEqual((variables["chain_mode"], variables["chain_expected_fp"]), ("differential", SNAP_A))
        manifest = self._manifest()
        self.assertEqual((manifest["chain_role"], manifest["base_backup_id"]), ("differential", "base-1"))

    def test_the_domain_id_is_durable_before_the_step_is_dispatched(self) -> None:
        order: list[str] = []
        self.noted = []

        def note(entry: dict[str, Any]) -> int:
            order.append("note")
            self.noted.append(entry)
            return 1

        original = self.ansible.run_playbook.side_effect

        def played(*args: Any, **kwargs: Any) -> Any:
            order.append(args[1])
            return original(*args, **kwargs)

        self.ansible.run_playbook.side_effect = played
        self.svc.backup_domain(account=self.account, config=self._config(CHAIN_ROLE_BASE), note_sink=note)
        self.assertEqual(order[:2], ["note", "virtualmin_chain_backup.yml"])
        self.assertEqual(self.noted, [{"virtualmin_domain_id": DOMAIN_ID}])

    def test_a_refused_step_ran_nothing_and_publishes_nothing(self) -> None:
        for reason, expected in (
            ("fingerprint_mismatch", Retriability.NOT_RETRIABLE),
            ("cancelled", Retriability.NOT_RETRIABLE),
            ("lock_busy", Retriability.RETRIABLE),
        ):
            with self.subTest(reason=reason):
                self.played.clear()

                def refuse(v: dict[str, Any], r: str = reason) -> Any:
                    line = result_line(
                        outcome="refused",
                        reason=r,
                        ran=False,
                        mode=v["chain_mode"],
                        token=v["chain_token"],
                        fp_after="",
                        sha256="",
                        size=0,
                    )
                    return Ok(SimpleNamespace(success=True, stdout=line, return_code=0))

                self.chain_reply = refuse
                result = self._backup(self._config(CHAIN_ROLE_DIFFERENTIAL))
                self.assertTrue(result.is_err(), result)
                self.assertIn(reason, result.unwrap_err())
                self.assertEqual(retriability_of(result), expected)
                self.assertEqual([name for name, _ in self.played], ["virtualmin_chain_backup.yml"])
                self.s3.put_object.assert_not_called()

    def test_an_uncertain_step_is_unknown_and_publishes_nothing(self) -> None:
        replies = {
            "playbook failed": Ok(SimpleNamespace(success=False, stdout="", return_code=2)),
            "timed out": Ok(SimpleNamespace(success=False, stdout="", return_code=-1)),
            "no result line": Ok(SimpleNamespace(success=True, stdout="PLAY RECAP", return_code=0)),
        }
        for label, reply in replies.items():
            with self.subTest(case=label):
                self.played.clear()

                def canned(v: dict[str, Any], r: Any = reply) -> Any:
                    return r

                self.chain_reply = canned
                result = self._backup(self._config(CHAIN_ROLE_BASE))
                self.assertTrue(result.is_err(), result)
                self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
                self.assertEqual([name for name, _ in self.played], ["virtualmin_chain_backup.yml"])
                self.s3.put_object.assert_not_called()

    def test_the_fetched_archive_must_be_the_one_the_step_vouched_for(self) -> None:
        # The step vouches for one archive; the fetch (self-consistent) delivers another.
        self.step_sha = hashlib.sha256(b"the archive the step made").hexdigest()
        result = self._backup(self._config(CHAIN_ROLE_BASE))
        self.assertTrue(result.is_err(), result)
        self.assertIn("chain step", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.s3.put_object.assert_not_called()

    def test_a_chain_role_without_its_admission_context_dispatches_nothing(self) -> None:
        for config in (BackupConfig(chain_role=CHAIN_ROLE_BASE), BackupConfig(chain_role=CHAIN_ROLE_DIFFERENTIAL)):
            with self.subTest(role=config.chain_role):
                result = self._backup(config)
                self.assertTrue(result.is_err(), result)
                self.assertEqual(self.played, [])
                self.assertNotIn("backup-domain", self.programs)

    def test_a_domain_the_node_script_would_reject_never_reaches_the_node(self) -> None:
        # The playbook's own assertion is looser than the script's: these pass the playbook, fail
        # the script with exit 64, and would park the job as an uncertain node step.
        for domain in ("example.com-", "example.com.", "-example.com", "exa mple.com", "a" * 254):
            with self.subTest(domain=domain):
                self.played.clear()
                self.noted.clear()
                VirtualminAccount.objects.filter(pk=self.account.pk).update(domain=domain)
                self.account.refresh_from_db()
                result = self._backup(self._config(CHAIN_ROLE_BASE))
                self.assertTrue(result.is_err(), result)
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
                self.assertEqual(self.played, [], "nothing may be dispatched for an input the node refuses")
                self.assertEqual(self.noted, [])

    def test_a_differential_is_never_dispatched_expecting_an_absent_snapshot(self) -> None:
        config = self._config(CHAIN_ROLE_DIFFERENTIAL, expected_fp="ABSENT")
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_base_fingerprint="ABSENT")
        result = self._backup(config)
        self.assertTrue(result.is_err(), result)
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertEqual(self.played, [])

    def test_remote_cgi_flags_exist_only_for_standalone_backups(self) -> None:
        self.assertEqual(differential_flags("standalone"), {"no-differential": ""})
        for role in (CHAIN_ROLE_BASE, CHAIN_ROLE_DIFFERENTIAL):
            with self.assertRaises(ValueError):
                differential_flags(role)
