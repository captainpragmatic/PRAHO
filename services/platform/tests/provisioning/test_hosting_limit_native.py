"""A metadata update is insufficient to certify native kernel enforcement."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

from django.test import SimpleTestCase

from apps.provisioning.hosting_limit_native import verify_quota_receipt


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

    def verify(self, receipt):
        return verify_quota_receipt(
            receipt,
            identity=self.identity,
            token=self.token,
            generation=3,
            disk_limit_mib=5632,
            bandwidth_limit_mib=20480,
            now=self.now,
        )

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
        with self.assertRaises(ValueError):
            self.verify({**self.receipt, "database_password": "must never leave the node"})
