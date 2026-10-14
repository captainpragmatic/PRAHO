"""No Virtualmin secret reaches PRAHO's database.

A Virtualmin 8.3.0 `list-domains --multiline` row (lab-observed key set)
carries `hashed_password` and `password_for_mysql`. The migration snapshot
used to store the whole row; job results store Virtualmin response
envelopes. Both now keep only what PRAHO reads.
"""

from __future__ import annotations

import re
from typing import Any

from django.test import SimpleTestCase

from apps.common.types import Ok, Retriability
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import list_migration_domains
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, without_secrets
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase

SECRET_KEY = re.compile(r"pass|secret|token|hash", re.I)


def secret_keys(value: Any, path: str = "") -> list[str]:
    """Every key path in a JSON-like value whose key looks secret."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}.{key}"
            if SECRET_KEY.search(str(key)):
                found.append(here)
            found.extend(secret_keys(item, here))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(secret_keys(item, f"{path}[{index}]"))
    return found


def listing_row(domain: str, username: str) -> dict[str, Any]:
    """An 8.x JSON listing row, abridged, with the secrets it really carries."""
    return {
        "name": domain,
        "values": {
            "id": ["17919089057386"],
            "username": [username],
            "features": ["unix dir web ssl logrotate mysql webmin"],
            "server_byte_quota": ["1073741824"],
            "bandwidth_limit": ["Unlimited"],
            "hashed_password": ["$y$j9T$abcdefghijklmnopqrstuv"],
            "password_for_mysql": ["not-a-real-mysql-password"],
            "password_storage": ["Only hashed"],
            "home_directory": [f"/home/{username}"],
            "description": ["PRAHO=1|CID=1|STATUS=active"],
        },
    }


class FakeGateway:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def call(self, program: str, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        data = {"status": "success", "data": self.rows}
        return Ok(VirtualminResponse(True, data, "{}", 200, 0.0, program, "node.example.com"))


class ListingAllowlistTests(SimpleTestCase):
    def test_rows_keep_only_the_verification_attributes(self) -> None:
        gateway: Any = FakeGateway([listing_row("a.example", "owner")])
        rows = list_migration_domains(gateway).unwrap()
        self.assertEqual(secret_keys(rows), [])
        self.assertEqual(
            set(rows[0]["attributes"]), {"id", "username", "features", "server_byte_quota", "bandwidth_limit"}
        )
        self.assertEqual(rows[0]["username"], "owner")
        self.assertIs(rows[0]["enabled"], True)

    def test_job_results_drop_secret_keys_at_any_depth(self) -> None:
        cleaned = without_secrets(
            {
                "success": True,
                "data": {"status": "success", "output": "done", "data": [listing_row("a.example", "o")]},
                "params": {"domain": "a.example", "pass": "x", "mysql-pass": "y", "api_key": "z"},
                "rollback_operations": [{"operation": "delete-domain", "params": {"domain": "a.example"}}],
            }
        )
        self.assertEqual(secret_keys(cleaned), [])
        self.assertEqual(cleaned["params"], {"domain": "a.example"})
        self.assertEqual(cleaned["rollback_operations"][0]["params"], {"domain": "a.example"})
        self.assertEqual(cleaned["data"]["output"], "done")


class PersistedStateTests(MigrationTestBase):
    def test_migration_snapshot_in_the_database_holds_no_secret(self) -> None:
        row = listing_row(self.account.domain, self.account.virtualmin_username)
        self.effects[("source", "list-domains")] = lambda: FakeGateway([row]).call("list-domains")
        self.effects[("target", "list-domains")] = lambda: FakeGateway([]).call("list-domains")

        migration = self._start()

        stored = VirtualminMigration.objects.values_list("pre_migration_snapshot", flat=True).get(pk=migration.pk)
        self.assertEqual(secret_keys(stored), [])
        self.assertEqual(stored["remote"]["attributes"]["features"], ["unix dir web ssl logrotate mysql webmin"])

    def test_job_results_in_the_database_hold_no_secret(self) -> None:
        response = {"success": True, "data": {"data": [listing_row("a.example", "o")]}, "pass": "x"}
        completed = VirtualminProvisioningJob.objects.create(operation="create_domain", server=self.server)
        completed.mark_completed(response, [{"operation": "delete-domain", "params": {"domain": "a.example"}}])
        failed = VirtualminProvisioningJob.objects.create(operation="create_domain", server=self.server)
        failed.mark_failed("rejected", response, retriability=Retriability.NOT_RETRIABLE)
        fenced = VirtualminProvisioningJob.objects.create(operation="backup_domain", server=self.server)
        VirtualminProvisioningJob.finish_execution(fenced.pk, fenced.execution_token, "failed", "x", response)

        for job_id in (completed.pk, failed.pk, fenced.pk):
            stored = VirtualminProvisioningJob.objects.values_list("result", flat=True).get(pk=job_id)
            with self.subTest(job=job_id):
                self.assertEqual(secret_keys(stored), [])
                self.assertIn("success", stored)
