"""A metadata update is insufficient to certify native kernel enforcement."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

from django.test import SimpleTestCase

from apps.provisioning.hosting_limit_native import current_verified_binding, verify_quota_receipt


class NativeQuotaReceiptTests(SimpleTestCase):
    def setUp(self) -> None:
        self.token = str(uuid4())
        self.identity = {
            "installation": str(uuid4()),
            "domain_id": "12345",
            "domain": "example.test",
            "uid": 1001,
            "gid": 1001,
            "filesystem_uuid": str(uuid4()),
            "boot_id": str(uuid4()),
        }
        self.now = datetime(2026, 11, 3, 12, tzinfo=UTC)
        self.receipt = {
            "schema": 1,
            "identity": self.identity,
            "token": self.token,
            "generation": 3,
            "observed_at": self.now.isoformat(),
            "filesystem": "ext4",
            "storage_qualified": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "uid_soft_kib": 5767168,
            "uid_hard_kib": 5767168,
            "gid_soft_kib": 5767168,
            "gid_hard_kib": 5767168,
            "uid_used_bytes": 1024,
            "gid_used_bytes": 2048,
            "available_bytes": 10 * 1024**3,
            "configured_quota_kib": 5767168,
            "configured_uquota_kib": 5767168,
            "configured_bandwidth_bytes": 20 * 1024**3,
        }

    def verify(self, receipt, *, current=False):
        return verify_quota_receipt(
            receipt,
            identity=self.identity,
            token=self.token,
            generation=3,
            disk_limit_mib=5632,
            bandwidth_limit_mib=20480,
            now=self.now,
            require_bandwidth_actions_safe=current,
        )

    def test_current_application_requires_bandwidth_safety_while_history_stays_readable(self) -> None:
        self.verify(self.receipt)
        self.verify({**self.receipt, "bandwidth_actions_safe": True}, current=True)
        for extra in ({}, {"bandwidth_actions_safe": False}, {"bandwidth_actions_safe": 1}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.verify({**self.receipt, **extra}, current=True)

    def test_historical_receipt_cannot_be_presented_as_current_bandwidth_protection(self) -> None:
        receipt = {**self.receipt, "bandwidth_actions_safe": True}
        record = {
            "phase": "completed",
            "service_id": 1,
            "owner_id": 2,
            "service_revision": 3,
            "server_id": "current-server",
            "connection_identity": "current-connection",
            "identity": self.identity,
            "receipt": receipt,
            "account_epoch": 3,
            "token": self.token,
        }
        authority = {
            "service_id": 1,
            "owner_id": 2,
            "revision": 3,
            "server_id": "current-server",
            "connection_identity": "current-connection",
            "node_identity": {key: self.identity[key] for key in ("installation", "filesystem_uuid", "boot_id")},
        }
        self.assertTrue(current_verified_binding(record=record, **authority))
        receipt.pop("bandwidth_actions_safe")
        self.assertFalse(current_verified_binding(record=record, **authority))

    def test_matching_configured_and_kernel_limits_are_required(self) -> None:
        result = self.verify(self.receipt)
        self.assertEqual(result.disk_limit_mib, 5632)
        self.assertEqual(result.safety_used_bytes, 2048)
        for field, value in (
            ("uid_enforced", False),
            ("gid_enforced", False),
            ("storage_qualified", False),
            ("uid_hard_kib", 5120 * 1024),
            ("gid_hard_kib", 0),
            ("uid_soft_kib", 5120 * 1024),
            ("configured_uquota_kib", 0),
            ("configured_bandwidth_bytes", 0),
            ("filesystem", "xfs"),
            ("token", str(uuid4())),
            ("generation", 2),
            ("generation", True),
            ("observed_at", "2026-11-03T11:00:00+00:00"),
            ("available_bytes", -1),
        ):
            with self.subTest(field=field, value=value):
                broken = {**self.receipt, field: value}
                with self.assertRaises(ValueError):
                    self.verify(broken)

    def test_unknown_and_mismatched_identity_fail_closed(self) -> None:
        for field in self.receipt:
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.verify({key: value for key, value in self.receipt.items() if key != field})
        changed = deepcopy(self.receipt)
        changed["identity"]["uid"] = 1002
        with self.assertRaises(ValueError):
            self.verify(changed)

    def test_canonical_observation_is_separate_and_never_certifies_kernel_enforcement(self) -> None:
        good = {"files_bytes": 8192, "database_bytes": 4096, "total_bytes": 12288}
        self.assertEqual(self.verify({**self.receipt, "observation": good}).safety_used_bytes, 2048)
        for observation in ({}, {**good, "total_bytes": 0}, {**good, "files_bytes": True}, {**good, "extra": 0}):
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                self.verify({**self.receipt, "observation": observation})
        with self.assertRaises(ValueError):
            self.verify({**self.receipt, "observation": good, "uid_enforced": False})
        with self.assertRaises(ValueError):
            self.verify({**self.receipt, "database_password": "must never leave the node"})
