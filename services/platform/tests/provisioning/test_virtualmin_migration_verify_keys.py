"""Migration verification compares quota, bandwidth and features in either key form.

Virtualmin 8.x JSON listings key these as "server_byte_quota",
"bandwidth_limit" and "features", not "Server byte quota", "Bandwidth limit"
and "Features". Read by label, every comparison was skipped as "not in the
snapshot", so a restored domain with different features passed verification.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.test import TestCase

from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService


def _row(features: str, *, quota: str = "1073741824", snake: bool = True) -> dict[str, Any]:
    if snake:
        attributes: dict[str, Any] = {
            "id": ["1"],
            "username": ["owner"],
            "features": [features],
            "server_byte_quota": [quota],
            "bandwidth_limit": ["Unlimited"],
        }
    else:
        attributes = {"Username": ["owner"], "Features": [features], "Server byte quota": [quota]}
    return {"domain": "a.example", "username": "owner", "enabled": False, "attributes": attributes}


class MigrationVerifyKeyFormTests(TestCase):
    def _verify(self, source: dict[str, Any], target: dict[str, Any]) -> MagicMock:
        service = VirtualminMigrationService()
        migration = MagicMock()
        migration.pre_migration_snapshot = {"remote": source}
        with (
            patch.object(service, "_domain", return_value=target),
            patch.object(service, "_move") as move,
        ):
            service._verify(migration, uuid4())
        return move

    def test_snake_case_features_mismatch_is_refused(self) -> None:
        with self.assertRaisesMessage(ValueError, "Features"):
            self._verify(_row("unix dir web mysql"), _row("unix dir web"))

    def test_snake_case_quota_mismatch_is_refused(self) -> None:
        with self.assertRaisesMessage(ValueError, "Server byte quota"):
            self._verify(_row("unix dir", quota="1"), _row("unix dir", quota="2"))

    def test_matching_rows_pass_in_any_feature_order(self) -> None:
        move = self._verify(_row("unix dir web"), _row("web unix dir"))
        self.assertEqual(move.call_args.args[2], "activating")

    def test_label_keys_still_compared(self) -> None:
        with self.assertRaisesMessage(ValueError, "Features"):
            self._verify(_row("unix dir web", snake=False), _row("unix dir", snake=False))
