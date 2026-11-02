"""Native consent binding uses exactly the same material scope as Platform."""

import importlib.util
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from apps.provisioning.component_migration_manifest import ComponentManifest
from tests.provisioning.test_component_migration_manifest import component_manifest


class ComponentNativeSourceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-native-source.py"
        spec = importlib.util.spec_from_file_location("component_native_source", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.manifest = component_manifest()
        self.request = {"domain_id": "123456789", "domain": "example.test", "owner": "customer"}
        with patch.object(self.module.coordinator.Path, "read_text", return_value=str(uuid4())):
            self.source = self.module.NativeSource(
                self.request, str(uuid4()), ComponentManifest.parse(self.manifest).authority_digest
            )

    def test_live_byte_changes_preserve_consent_but_paths_grants_and_retained_changes_do_not(self):
        digest = self.module.authority_digest(self.manifest)
        self.assertEqual(digest, ComponentManifest.parse(self.manifest).authority_digest)
        self.manifest["paths"][0]["bytes"] += 100
        self.manifest["paths"][0]["tree_digest"] = "1" * 64
        self.manifest["databases"][0]["bytes"] += 100
        self.assertEqual(self.module.authority_digest(self.manifest), digest)
        self.assertEqual(
            self.module.authority_digest(self.manifest), ComponentManifest.parse(self.manifest).authority_digest
        )
        self.manifest["paths"][0]["inode"] += 1
        self.assertNotEqual(self.module.authority_digest(self.manifest), digest)

    def test_preparation_or_material_scope_drift_stops_before_native_hold_construction(self):
        for change in ("preparation", "routing", "retained", "principal"):
            manifest = component_manifest()
            if change == "preparation":
                manifest["preparation"] = ["Separate retained mail routing"]
            elif change == "principal":
                manifest["databases"][0]["principals"][0]["grants_digest"] = "2" * 64
            else:
                manifest[change]["digest"] = "2" * 64
            with (
                self.subTest(change=change),
                patch.object(self.module.inspection, "inspect_source", return_value=manifest),
                patch.object(self.module.inspection, "_native_domain") as native,
                self.assertRaises(ValueError),
            ):
                self.source.preflight()
            native.assert_not_called()

    def test_same_attempt_cannot_rebuild_a_different_saved_native_scope(self):
        self.manifest["paths"][0]["relative"] = "another_application"
        with patch.object(self.module.inspection, "_native_domain") as native, self.assertRaises(ValueError):
            self.source.retained({"manifest": self.manifest})
        native.assert_not_called()
