"""Inspection helper installation is fenced separately from quota/email adoption."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class HostingNodePrepareTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_hosting_prepare.py"
        spec = importlib.util.spec_from_file_location("hosting_node_prepare", path)
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def test_fence_repairs_exact_approved_bundle_and_permanently_blocks_late_installer(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            files = {name: base64.b64encode(("fixture-" + name).encode()).decode() for name in self.native.FILES}
            digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            request = {"identity": "a" * 64, "token": str(uuid4()), "helper_bundle_digest": digest, "files": files}
            installer = self.native.BundleInstaller(root / "state", root / "library")
            result = installer.perform("fence", request)
            self.assertEqual(
                result, {"identity": "a" * 64, "fenced_token": request["token"], "helper_bundle_digest": digest}
            )
            self.assertEqual({p.name for p in (root / "library").iterdir()}, set(self.native.FILES))
            with self.assertRaises(ValueError):
                installer.perform("install", request)
            self.assertEqual(installer.perform("fence", request), result)
            bad = {**request, "token": str(uuid4()), "helper_bundle_digest": "b" * 64}
            with self.assertRaises(ValueError):
                installer.perform("install", bad)
            self.assertEqual((root / "library/praho_hosting_node.py").read_text(), "fixture-praho_hosting_node.py")
