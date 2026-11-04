"""An operator reviews exact resources; attachment and a familiar name confer no ownership."""

from django.test import SimpleTestCase

from apps.infrastructure.cloud_destroy_policy import build_destroy_decisions, inventory_digest
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource


class DestroyPolicyTests(SimpleTestCase):
    def test_owned_attached_auto_delete_primary_ip_is_deleted_with_its_server(self):
        resources = [
            CloudResource("server", "vm"),
            CloudResource("primary_ip", "ip", attached_to=("vm",), auto_delete=True),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:vm", "primary_ip:ip"}, ("vm",), "delete", CAPABILITIES["hetzner"]
        )
        decision = next(item for item in decisions if item.key == "primary_ip:ip")
        self.assertEqual(decision.action, "parent_delete")
        self.assertFalse(decision.blocks_parent)

    def test_owned_attached_primary_ip_without_auto_delete_requires_explicit_delete(self):
        resources = [
            CloudResource("server", "vm"),
            CloudResource("primary_ip", "ip", attached_to=("vm",), auto_delete=False),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:vm", "primary_ip:ip"}, ("vm",), "delete", CAPABILITIES["hetzner"]
        )
        decision = next(item for item in decisions if item.key == "primary_ip:ip")
        self.assertEqual(decision.action, "delete")
        self.assertFalse(decision.blocks_parent)

    def test_owned_unattached_auto_delete_primary_ip_requires_explicit_delete(self):
        resources = [
            CloudResource("server", "vm"),
            CloudResource("primary_ip", "ip", attached_to=(), auto_delete=True),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:vm", "primary_ip:ip"}, ("vm",), "delete", CAPABILITIES["hetzner"]
        )
        decision = next(item for item in decisions if item.key == "primary_ip:ip")
        self.assertEqual(decision.action, "delete")
        self.assertFalse(decision.blocks_parent)

    def test_volume_snapshot_used_by_an_unrelated_volume_is_preserved(self):
        resources = [
            CloudResource("server", "vm"),
            CloudResource("volume", "owned", attached_to=("vm",)),
            CloudResource("volume_snapshot", "point", source_ids=("owned",)),
            CloudResource("volume", "other", source_ids=("point",)),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:vm", "volume:owned"}, ("vm",), "delete", CAPABILITIES["vultr"]
        )
        self.assertEqual(next(item.action for item in decisions if item.key == "volume_snapshot:point"), "manual")

    def test_restore_point_choice_is_required_and_unknown_restore_points_stay_manual(self):
        resources = [
            CloudResource("server", "v"),
            CloudResource("snapshot", "s", source_ids=("v",)),
            CloudResource("snapshot", "unknown", name="v"),
        ]
        with self.assertRaisesRegex(ValueError, "keep or delete"):
            build_destroy_decisions(resources, {"server:v"}, ("v",), "", CAPABILITIES["hetzner"])
        decisions = build_destroy_decisions(resources, {"server:v"}, ("v",), "keep", CAPABILITIES["hetzner"])
        self.assertEqual({item.key: item.action for item in decisions}, {"server:v": "delete", "snapshot:s": "keep"})

    def test_attached_unowned_resources_are_preserved_and_shared_owned_resources_are_not_deleted(self):
        resources = [
            CloudResource("server", "v"),
            CloudResource("volume", "x", attached_to=("v",)),
            CloudResource("firewall", "f", attached_to=("v", "other")),
            CloudResource("primary_ip", "ip", attached_to=("v",), auto_delete=True),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:v", "firewall:f"}, ("v",), "delete", CAPABILITIES["hetzner"]
        )
        result = {item.key: item for item in decisions}
        self.assertEqual(result["volume:x"].action, "manual")
        self.assertEqual(result["firewall:f"].action, "manual")
        self.assertEqual(result["primary_ip:ip"].action, "manual")
        self.assertTrue(result["primary_ip:ip"].blocks_parent, "VM deletion must not auto-delete an unowned primary IP")

    def test_custom_image_used_by_another_server_is_preserved(self):
        resources = [
            CloudResource("server", "v"),
            CloudResource("server", "other", source_ids=("s",)),
            CloudResource("snapshot", "s", source_ids=("v",)),
        ]
        result = build_destroy_decisions(
            resources, {"server:v", "snapshot:s"}, ("v",), "delete", CAPABILITIES["hetzner"]
        )
        self.assertEqual(next(item.action for item in result if item.key == "snapshot:s"), "manual")

    def test_backup_conversion_and_expiry_are_distinct_from_confirmed_deletion(self):
        resources = [CloudResource("server", "v"), CloudResource("backup", "b", source_ids=("v",))]
        kept = build_destroy_decisions(resources, {"server:v"}, ("v",), "keep", CAPABILITIES["hetzner"])
        self.assertEqual(next(item.action for item in kept if item.key == "backup:b"), "convert")
        vultr = build_destroy_decisions(resources, {"server:v"}, ("v",), "delete", CAPABILITIES["vultr"])
        self.assertEqual(next(item.action for item in vultr if item.key == "backup:b"), "await_expiry")
        keep_vultr = build_destroy_decisions(resources, {"server:v"}, ("v",), "keep", CAPABILITIES["vultr"])
        self.assertTrue(next(item.blocks_parent for item in keep_vultr if item.key == "backup:b"))

    def test_manifest_binds_relationships_and_provider_identity_independent_of_order(self):
        resources = [CloudResource("server", "v"), CloudResource("volume", "x", attached_to=("v",))]
        fingerprint = inventory_digest("hetzner", "credential", resources)
        self.assertEqual(fingerprint, inventory_digest("hetzner", "credential", list(reversed(resources))))
        self.assertNotEqual(fingerprint, inventory_digest("hetzner", "other", resources))
        self.assertNotEqual(fingerprint, inventory_digest("digitalocean", "credential", resources))
        resources[1] = CloudResource("volume", "x", attached_to=("other",))
        self.assertNotEqual(fingerprint, inventory_digest("hetzner", "credential", resources))

    def test_unattended_cleanup_cannot_destroy_a_provider_backup_or_assume_unknown_attachment_safe(self):
        resources = [
            CloudResource("server", "v"),
            CloudResource("backup", "b", source_ids=("v",)),
            CloudResource("firewall", "f", attachments_known=False),
        ]
        decisions = build_destroy_decisions(
            resources, {"server:v", "firewall:f"}, ("v",), "preserve", CAPABILITIES["hetzner"]
        )
        result = {item.key: item for item in decisions}
        self.assertTrue(result["backup:b"].blocks_parent)
        self.assertEqual(result["backup:b"].action, "manual")
        self.assertEqual(result["firewall:f"].action, "manual")
