"""The operator must explicitly choose provider restore-point retention and accept its impact."""

from django.test import SimpleTestCase

from apps.infrastructure.forms import DeploymentDestroyForm


class DestroyRetentionFormTests(SimpleTestCase):
    def data(self):
        return {
            "confirm_hostname": "node",
            "resource_digest": "a" * 64,
            "provider_restore_points": "keep",
            "retention_reason": "Keep the existing restore points",
            "accepted_provider_impact": "on",
        }

    def test_hostname_alone_cannot_authorize_implicit_restore_point_deletion(self):
        form = DeploymentDestroyForm({"confirm_hostname": "node"}, hostname="node")
        self.assertFalse(form.is_valid())
        self.assertIn("provider_restore_points", form.errors)
        self.assertIn("accepted_provider_impact", form.errors)

    def test_explicit_keep_and_delete_are_both_supported(self):
        for choice in ("keep", "delete"):
            data = {**self.data(), "provider_restore_points": choice}
            with self.subTest(choice=choice):
                self.assertTrue(DeploymentDestroyForm(data, hostname="node").is_valid())

    def test_acceptance_digest_and_reason_cannot_be_omitted(self):
        for field in ("accepted_provider_impact", "resource_digest", "retention_reason"):
            data = self.data()
            del data[field]
            with self.subTest(field=field):
                self.assertFalse(DeploymentDestroyForm(data, hostname="node").is_valid())

    def test_manual_backup_preparation_is_required_only_when_keeping_restore_points(self):
        form = DeploymentDestroyForm(self.data(), hostname="node", manual_backup_ids=("b",))
        self.assertFalse(form.is_valid())
        self.assertIn("snapshot_for_backup_b", form.errors)
        data = {**self.data(), "snapshot_for_backup_b": "converted"}
        form = DeploymentDestroyForm(data, hostname="node", manual_backup_ids=("b",))
        self.assertTrue(form.is_valid())
        self.assertEqual(form.provider_snapshot_mappings(), {"b": "converted"})
        data["provider_restore_points"] = "delete"
        form = DeploymentDestroyForm(data, hostname="node", manual_backup_ids=("b",))
        self.assertTrue(form.is_valid())
        self.assertEqual(form.provider_snapshot_mappings(), {})
