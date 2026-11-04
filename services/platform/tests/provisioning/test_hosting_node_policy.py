"""Native readiness is explicit; importing a node never qualifies or mutes it."""

from copy import deepcopy
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.provisioning.hosting_node_policy import (
    NATIVE_ACCEPTANCE_CHECKS,
    NOTIFICATION_EMITTERS,
    verify_notification_evidence,
    verify_quota_evidence,
    verify_quota_inventory,
)


def quota_evidence():
    return {
        "schema": 1,
        "policy_version": "hosting-node-v1",
        "identity": "a" * 64,
        "installation": str(uuid4()),
        "filesystem_uuid": str(uuid4()),
        "boot_id": str(uuid4()),
        "os": "ubuntu-26.04",
        "php": "8.5",
        "filesystem": "ext4",
        "quota_format": "native",
        "root_filesystem": True,
        "uid_enforced": True,
        "gid_enforced": True,
        "mysql_cap_sys_resource": False,
        "mysql_bounding_cap_sys_resource": False,
        "physical_tables_verified": True,
        "acceptance": dict.fromkeys(NATIVE_ACCEPTANCE_CHECKS, True),
        "acceptance_id": str(uuid4()),
        "bw_auto_disable": False,
        "bw_auto_enable": False,
        "requalification_required": False,
        "qualification_id": str(uuid4()),
    }


class HostingNodeEvidenceTests(SimpleTestCase):
    def test_supported_native_and_classic_formats_are_preserved(self):
        for format_name in ("native", "classic"):
            evidence = quota_evidence()
            evidence["quota_format"] = format_name
            self.assertEqual(verify_quota_evidence(evidence, "a" * 64), evidence)

    def test_missing_kernel_database_or_native_acceptance_never_qualifies(self):
        evidence = quota_evidence()
        for key in ("uid_enforced", "gid_enforced", "root_filesystem", "physical_tables_verified"):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                verify_quota_evidence({**evidence, key: False}, "a" * 64)
        for key in ("mysql_cap_sys_resource", "mysql_bounding_cap_sys_resource"):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                verify_quota_evidence({**evidence, key: True}, "a" * 64)
        for key in NATIVE_ACCEPTANCE_CHECKS:
            changed = deepcopy(evidence)
            changed["acceptance"][key] = False
            with self.subTest(key=key), self.assertRaises(ValidationError):
                verify_quota_evidence(changed, "a" * 64)

    def test_unknown_old_or_retargeted_proof_is_not_managed_readiness(self):
        evidence = quota_evidence()
        for changed in (
            {**evidence, "os": "ubuntu-24.04"},
            {**evidence, "identity": "b" * 64},
            {**evidence, "php": "8.4"},
            {**evidence, "uid_enforced": 1},
            {**evidence, "extra": True},
            {**evidence, "acceptance_id": "unknown"},
        ):
            with self.subTest(evidence=changed), self.assertRaises(ValidationError):
                verify_quota_evidence(changed, "a" * 64)

    def test_email_handover_has_its_own_complete_proof_on_an_older_source(self):
        evidence = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": "a" * 64,
            "installation": str(uuid4()),
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        self.assertEqual(verify_notification_evidence(evidence, "a" * 64), evidence)
        for emitter in NOTIFICATION_EMITTERS:
            changed = deepcopy(evidence)
            changed["emitters"][emitter] = False
            with self.subTest(emitter=emitter), self.assertRaises(ValidationError):
                verify_notification_evidence(changed, "a" * 64)
        self.assertEqual(len(NOTIFICATION_EMITTERS), 10)
        self.assertIn("status_monitors", NOTIFICATION_EMITTERS)

    def test_uninspected_or_enabled_native_bandwidth_actions_never_qualify_managed_quota_readiness(self):
        evidence = quota_evidence()
        evidence.pop("bw_auto_disable", None)
        evidence.pop("bw_auto_enable", None)
        with self.assertRaises(ValidationError):
            verify_quota_evidence(evidence, "a" * 64)
        for key in ("bw_auto_disable", "bw_auto_enable"):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                verify_quota_evidence({**quota_evidence(), key: True}, "a" * 64)

    def test_old_boot_inventory_can_be_reviewed_but_is_never_current_readiness(self):
        old = {**quota_evidence(), "requalification_required": True}
        self.assertEqual(verify_quota_inventory(old, "a" * 64), old)
        with self.assertRaises(ValidationError):
            verify_quota_evidence(old, "a" * 64)
